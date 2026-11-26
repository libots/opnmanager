from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import ValidationError
from django.db import transaction
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST

from .credentials import encrypt_credentials
from .definition_sync import definition_plan
from .deployment import combined_plan, definitions_to_apply
from .forms import CredentialsForm, ImportRulesForm, SnapshotImportForm
from .import_rules import import_rules
from .jobs import enqueue
from .mappings import apply_default_mappings
from .models import Alias, AuditEvent, Category, DeviceJob, Firewall, InterfaceGroup, LogicalInterface, Rule, Snapshot
from .opnsense import DeviceError, OPNsenseClient
from .reconcile import Policy, plan_for
from .rule_filters import SEARCH_FIELDS, filter_rows


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def dashboard(request):
    from .system_management import update_state

    devices = []
    policy = Policy()
    latest_jobs = {}
    for job in DeviceJob.objects.filter(kind=DeviceJob.RULES_DEPLOY).order_by("-created_at", "-pk")[:200]:
        latest_jobs.setdefault(job.firewall_id, job)
    firewalls = Firewall.objects.select_related("inventory").prefetch_related("groups", "interface_mappings")
    for fw in firewalls:
        plan = plan_for(fw, policy=policy)
        inventory = getattr(getattr(fw, "inventory", None), "data", None) or {}
        firmware = inventory.get("firmware", {})
        devices.append(
            {
                "firewall": fw,
                "plan": plan,
                "drift": sum(i["status"] in ("missing", "changed", "conflict", "out_of_scope") for i in plan["items"]),
                "firmware": firmware,
                "update_state": update_state(firmware) if fw.enabled else "disabled",
                "firmware_read": parse_datetime(firmware.get("refreshed_at", "")),
                "observed": parse_datetime(plan["observed_at"] or ""),
                "deploy_job": latest_jobs.get(fw.pk),
                "mapped": len(fw.interface_mappings.all()),
            }
        )
    return render(
        request,
        "fleet/dashboard.html",
        {
            "devices": devices,
            "rule_count": Rule.objects.count(),
            "alias_count": Alias.objects.count(),
            "interface_count": LogicalInterface.objects.count(),
            "updates_count": sum(d["update_state"] in ("updates", "reboot", "major") for d in devices),
            "drift_count": sum(bool(d["drift"] or d["plan"]["errors"]) for d in devices if d["firewall"].enabled),
            "enabled_ids": [d["firewall"].pk for d in devices if d["firewall"].enabled],
        },
    )


@login_required
@permission_required(("fleet.view_firewall", "fleet.change_firewall"), raise_exception=True)
@require_POST
def reorder_firewalls(request):
    """Save the firewall order set by dragging rows on the overview: `order` lists every firewall id."""
    ids = [value for value in request.POST.getlist("order") if value.isdigit()]
    existing = set(Firewall.objects.values_list("pk", flat=True))
    if len(ids) != len(set(ids)) or {int(v) for v in ids} != existing:
        return JsonResponse(
            {"error": "The firewall list changed in the meantime. Reload the page; the order was not saved."},
            status=409,
        )
    with transaction.atomic():
        for position, pk in enumerate(ids, start=1):
            Firewall.objects.filter(pk=pk).update(position=position)
    AuditEvent.objects.create(actor=request.user.username, action="firewalls.reordered", detail=",".join(ids))
    return JsonResponse({"message": "Firewall order saved. Every page lists firewalls in this order."})


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def firewall_detail(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    return render(
        request,
        "fleet/firewall.html",
        {
            "firewall": fw,
            "plan": plan_for(fw),
            "mappings": fw.interface_mappings.select_related("logical_interface"),
            "form": SnapshotImportForm(),
        },
    )


@login_required
@permission_required(("fleet.view_firewall", "fleet.refresh_firewall"), raise_exception=True)
@require_POST
def import_snapshot(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    form = SnapshotImportForm(request.POST, request.FILES)
    if form.is_valid():
        snapshot = Snapshot.objects.create(firewall=fw, data=form.cleaned_data["snapshot"], source="import")
        if fw.auto_map_interfaces:
            apply_default_mappings(fw, snapshot.data)
        AuditEvent.objects.create(actor=request.user.username, action="snapshot.import", detail=fw.name)
        messages.success(request, "Snapshot imported. Drift report updated.")
        return redirect("firewall", pk=pk)
    return render(
        request,
        "fleet/firewall.html",
        {
            "firewall": fw,
            "plan": plan_for(fw),
            "mappings": fw.interface_mappings.select_related("logical_interface"),
            "form": form,
        },
        status=400,
    )


@login_required
@permission_required(("fleet.view_firewall", "fleet.refresh_firewall"), raise_exception=True)
@require_POST
def pull_snapshot(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    wants_json = "application/json" in request.headers.get("Accept", "")
    target = {"overview": "dashboard", "deployment": "deployment_overview"}.get(request.POST.get("return_to"))

    def finish(error=None, **result):
        if wants_json:
            return JsonResponse({"ok": not error, "error": error, **result}, status=400 if error else 200)
        if error:
            messages.error(request, error)
        return redirect(target) if target else redirect("firewall", pk=pk)

    if not fw.enabled:
        return finish("Enable this firewall before pulling a snapshot.")
    try:
        data = OPNsenseClient(fw).snapshot()
        snapshot = Snapshot.objects.create(firewall=fw, data=data, source="api")
        count = apply_default_mappings(fw, data) if fw.auto_map_interfaces else 0
        AuditEvent.objects.create(actor=request.user.username, action="snapshot.pull", detail=fw.name)
        if not wants_json:
            messages.info(request, f"Added {count} default interface mappings from unique display names.")
            messages.success(request, "Configuration read from device. No device changes made.")
        if wants_json:
            plan = plan_for(fw)
            drift = sum(item["status"] in ("missing", "changed", "conflict", "out_of_scope") for item in plan["items"])
            return finish(
                observed_at=snapshot.created_at.isoformat(),
                policy="Needs attention"
                if plan["errors"]
                else f"{drift} differences"
                if drift
                else "Managed fields match",
                attention=bool(plan["errors"] or drift),
                errors=plan["errors"],
            )
        return finish()
    except DeviceError as exc:
        return finish(str(exc))


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def download_plan(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    response = JsonResponse(plan_for(fw), json_dumps_params={"indent": 2})
    response["Content-Disposition"] = f'attachment; filename="firewall-{fw.pk}-plan.json"'
    return response


@login_required
def settings_page(request):
    from django.conf import settings

    return render(request, "fleet/settings.html", {"central_login": settings.OIDC_ENABLED})


@login_required
@permission_required(("fleet.view_firewall", "fleet.manage_credentials", "fleet.change_firewall"), raise_exception=True)
@sensitive_post_parameters("api_key", "api_secret")
def firewall_credentials(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    form = CredentialsForm(request.POST if request.method == "POST" else None)
    if request.method == "POST" and form.is_valid():
        if form.cleaned_data["clear_credentials"]:
            fw.encrypted_api_key = fw.encrypted_api_secret = ""
        elif form.cleaned_data["api_key"]:
            encrypt_credentials(fw, form.cleaned_data["api_key"], form.cleaned_data["api_secret"])
        fw.save(update_fields=["encrypted_api_key", "encrypted_api_secret"])
        AuditEvent.objects.create(actor=request.user.username, action="credentials.updated", detail=fw.name)
        messages.success(request, "Credential settings saved. Existing values are never displayed.")
        return redirect("firewall", pk=pk)
    return render(
        request, "fleet/credentials.html", {"firewall": fw, "form": form, "has_credentials": bool(fw.encrypted_api_key)}
    )


@login_required
@permission_required(("fleet.view_firewall", "fleet.sync_definitions"), raise_exception=True)
def sync_definitions(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    rule_id = request.POST.get("rule_id") if request.method == "POST" else request.GET.get("rule")
    if rule_id:
        import uuid

        try:
            rule_id = uuid.UUID(rule_id)
        except ValueError:
            from django.http import Http404

            raise Http404("Invalid rule identifier") from None
    rule = get_object_or_404(Rule, pk=rule_id) if rule_id else None
    if rule and not rule.applies_to(fw):
        from django.http import Http404

        raise Http404("Rule does not target this firewall")
    if request.method == "POST":
        params = {
            "approval_sha256": request.POST.get("approval_sha256", ""),
            "rule_id": str(rule.pk) if rule else None,
            "remove_definitions": request.POST.getlist("remove_definition") if not rule else [],
        }
        try:
            job = enqueue(fw, DeviceJob.DEFINITIONS_SYNC, params, request.user.username)
        except DeviceError as exc:
            messages.error(request, str(exc))
            return redirect("deploy_rules" if rule else "firewall", pk=pk)
        return redirect("job", pk=job.pk)
    return render(request, "fleet/sync.html", {"firewall": fw, "plan": definition_plan(fw, rule=rule), "rule": rule})


@login_required
@permission_required(
    ("fleet.view_firewall", "fleet.change_firewall", "fleet.add_interfacemapping", "fleet.add_logicalinterface"),
    raise_exception=True,
)
@require_POST
def default_mappings(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    snapshot = fw.snapshots.first()
    count = apply_default_mappings(fw, snapshot.data) if snapshot else 0
    AuditEvent.objects.create(actor=request.user.username, action="mappings.default", detail=f"{fw.name}: {count}")
    messages.success(request, f"Added {count} unambiguous name mappings. Existing mappings were preserved.")
    return redirect("firewall", pk=pk)


def tokens_of(value):
    return [v.strip() for v in str(value or "").split(",") if v.strip()]


def address_label(value, device_interfaces=None):
    """A rule address as OPNsense lists it: "@VL30:net" -> "VL30 net", device "lanip" -> "LAN address"."""
    if value == "any":
        return "*"
    if value == "(self)":
        return "This Firewall"
    if value.startswith("@") and value.endswith((":net", ":ip")):
        name, _, kind = value[1:].rpartition(":")
        return f"{name} {'net' if kind == 'net' else 'address'}"
    if device_interfaces:
        if value in device_interfaces:
            return f"{device_interfaces[value]} net"
        if value.endswith("ip") and value[:-2] in device_interfaces:
            return f"{device_interfaces[value[:-2]]} address"
    return value


# Icons rules.js draws in the OPNsense-style rule grid.
RULE_ICONS = (
    "play",
    "xmark",
    "circle-xmark",
    "sliders",
    "arrow-right-long",
    "arrow-left-long",
    "right-left",
    "bolt",
    "circle-info",
    "tag",
    "square-check-regular",
    "square-regular",
    "network-wired",
    "pencil",
    "copy-regular",
    "trash-can",
    "bell",
    "bell-slash",
    "plus",
    "square-plus-regular",
    "square-minus-regular",
    "layer-group",
    "sitemap",
    "ethernet",
    "angles-down",
    "angles-up",
    "expand",
    "compress",
)


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def rules_page(request):
    fw = get_object_or_404(Firewall, pk=request.GET["firewall"]) if request.GET.get("firewall") else None
    observed = fw.snapshots.first() if fw else None
    if fw:
        data = observed.data if observed else {"rules": [], "groups": [], "categories": [], "interfaces": []}
        rows = [{**row, "index": str(index)} for index, row in enumerate(data["rules"])]
        groups = {r["ifname"]: set(r["members"].split(",")) for r in data.get("groups", [])}
        interfaces = [(r["name"], r["label"]) for r in data.get("interfaces", [])] + [
            (name, name + " (group)") for name in groups
        ]
        categories = [(r.get("uuid", r["name"]), r["name"]) for r in data.get("categories", [])]
    else:
        rows = []
        groups = {g.name: {i.name for i in g.members.all()} for g in InterfaceGroup.objects.prefetch_related("members")}
        for rule in Rule.objects.prefetch_related(
            "interfaces",
            "interface_groups",
            "origin_interfaces",
            "origin_interface_groups",
            "categories",
            "firewalls",
            "firewall_groups",
        ):
            rows.append(
                {
                    "description": rule.name,
                    "id": str(rule.pk),
                    "interface": ",".join(
                        [i.name for i in rule.bound_interfaces()] + [g.name for g in rule.interface_groups.all()]
                    ),
                    "categories": ",".join(c.name for c in rule.categories.all()),
                    "sequence": str(rule.sequence),
                    "action": rule.action,
                    "protocol": rule.protocol,
                    "source_net": rule.source,
                    "destination_net": rule.destination,
                    "source_port": rule.source_port,
                    "destination_port": rule.destination_port,
                    "interfacenot": str(int(rule.interface_not)),
                    "received-on": ",".join(
                        [i.name for i in rule.origin_interfaces.all()]
                        + [g.name for g in rule.origin_interface_groups.all()]
                    ),
                    "ipprotocol": rule.ip_version,
                    "direction": rule.direction,
                    "quick": str(int(rule.quick)),
                    "log": str(int(rule.log)),
                    "source_not": str(int(rule.source_not)),
                    "destination_not": str(int(rule.destination_not)),
                    "enabled": str(int(rule.enabled)),
                    "icmptype": rule.icmp_types,
                    "icmp6type": rule.icmp6_types,
                    "gateway": rule.gateway,
                    "statetype": rule.state_type,
                    "received-on-not": str(int(rule.origin_not)),
                    "targets_display": "All enabled firewalls"
                    if rule.scope == Rule.ALL
                    else ", ".join(
                        [g.name + " (group)" for g in rule.firewall_groups.all()]
                        + [f.name for f in rule.firewalls.all()]
                    )
                    or "None",
                }
            )
        interfaces = [(i.name, i.name) for i in LogicalInterface.objects.all()] + [(g, g + " (group)") for g in groups]
        categories = [(c.name, c.name) for c in Category.objects.all()]
    import re

    category_names = dict(categories)
    category_colors = (
        {c.name: c.color for c in Category.objects.all()}
        if not fw
        else {r.get("uuid", r["name"]): r.get("color", "") for r in data.get("categories", [])}
    )
    origin_ids = {origin.remote_uuid: str(origin.rule_id) for origin in fw.ruleorigin_set.all()} if fw else {}
    interface_labels = dict(interfaces)
    device_labels = {r["name"]: r.get("label") or r["name"] for r in data.get("interfaces", [])} if fw else {}
    managed_ids = list(Rule.objects.values_list("pk", flat=True)) if fw else []
    from .rule_identity import matches as matches_rule

    for row in rows:
        bindings = {v.strip() for v in row.get("interface", "").split(",") if v.strip()}
        row["placement"] = (
            "floating" if len(bindings) != 1 else "group" if next(iter(bindings)) in groups else "interface"
        )
        row["section_label"] = (
            "Floating rules"
            if row["placement"] == "floating"
            else ("Group — " if row["placement"] == "group" else "Interface — ")
            + interface_labels.get(next(iter(bindings)), next(iter(bindings)))
        )
        row["interface_display"] = ", ".join(
            interface_labels.get(v.strip(), v.strip()) for v in row.get("interface", "").split(",") if v.strip()
        )
        row["binding_count"] = len(bindings)
        row["origin_count"] = len({v.strip() for v in row.get("received-on", "").split(",") if v.strip()})
        row["origin_display"] = ", ".join(
            interface_labels.get(v.strip(), v.strip()) for v in row.get("received-on", "").split(",") if v.strip()
        )
        for side in ("source", "destination"):
            # One address per line, named as OPNsense shows them ("VL30 net", "LAN address").
            lines = [address_label(v, device_labels) for v in tokens_of(row.get(side + "_net"))]
            lines = lines or ["*"]
            if row.get(side + "_not") == "1":
                lines[0] = "! " + lines[0]
            row[side + "_lines"] = lines
            row[side + "_display"] = ", ".join(lines)
        row["manager_id"] = origin_ids.get(row.get("uuid")) if fw else row["id"]
        if fw and not row["manager_id"]:
            matching_ids = [str(pk) for pk in managed_ids if matches_rule(row.get("description", ""), pk)]
            if len(matching_ids) == 1:
                row["manager_id"] = matching_ids[0]
        row["category_badges"] = [
            {
                "name": category_names.get(value, value),
                "color": category_colors.get(value, "137b66")
                if re.fullmatch("[0-9a-fA-F]{6}", category_colors.get(value, ""))
                else "137b66",
            }
            for value in row.get("categories", "").split(",")
            if value
        ]
        row["category_display"] = ", ".join(
            category_names.get(value, value) for value in row.get("categories", "").split(",") if value
        )
    all_rows = rows
    rows = filter_rows(all_rows, request.GET, groups)
    can_import = bool(
        fw
        and observed
        and request.user.has_perms(
            ["fleet.add_rule", "fleet.add_alias", "fleet.add_category", "fleet.add_interfacegroup"]
        )
    )
    rules_data = {
        "rows": all_rows,
        "search_fields": SEARCH_FIELDS,
        "groups": {name: sorted(members) for name, members in groups.items()},
        "can_import": can_import,
        "can_edit": request.user.has_perm("fleet.change_rule"),
        "can_delete": request.user.has_perm("fleet.delete_rule"),
        "can_add": request.user.has_perm("fleet.add_rule"),
        "manager": fw is None,
    }
    # The rules grid refreshes itself with this after saving a rule or running a command.
    if "application/json" in request.headers.get("Accept", ""):
        return JsonResponse(rules_data)
    return render(
        request,
        "fleet/rules.html",
        {
            "rows": rows,
            "rules_data": rules_data,
            "can_import": can_import,
            "firewall": fw,
            "snapshot": observed,
            "firewalls": Firewall.objects.all(),
            "interfaces": interfaces,
            "categories": categories,
            "import_form": ImportRulesForm(snapshot=observed) if observed else None,
            "rule_icons": RULE_ICONS,
        },
    )


@login_required
@permission_required(
    ("fleet.view_firewall", "fleet.add_rule", "fleet.add_alias", "fleet.add_category", "fleet.add_interfacegroup"),
    raise_exception=True,
)
@require_POST
def adopt_rules(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    snapshot = fw.snapshots.first()
    if not snapshot:
        messages.error(request, "Pull a snapshot before importing rules.")
        return redirect("rules")
    form = ImportRulesForm(request.POST, snapshot=snapshot)
    if form.is_valid() and form.cleaned_data["snapshot_id"] == snapshot.pk:
        try:
            with transaction.atomic():
                rules = import_rules(
                    snapshot,
                    form.cleaned_data["rule_indices"],
                    form.cleaned_data["scope"],
                    form.cleaned_data["firewalls"],
                    form.cleaned_data["firewall_groups"],
                )
                AuditEvent.objects.create(
                    actor=request.user.username, action="rules.imported", detail=f"{fw.name}: {len(rules)}"
                )
            messages.success(
                request, f"Imported {len(rules)} rules into the manager. Device configuration was unchanged."
            )
        except ValidationError as exc:
            problems = exc.messages
            if len(problems) > 1:
                messages.error(request, f"Nothing was imported. Fix these {len(problems)} problems and try again:")
            elif problems and problems[0].startswith("“"):
                messages.error(request, "Nothing was imported:")
            for problem in problems:
                messages.error(request, problem)
    else:
        messages.error(request, "Invalid selection or stale snapshot. Select rules and target firewalls again.")
    return redirect("/rules/?firewall=" + str(fw.pk))


# OPNsense's own labels for the fields a review lists (dialogFilterRule.xml, alias and group dialogs).
FIELD_LABELS = {
    "description": "Description",
    "descr": "Description",
    "interface": "Interface",
    "interfacenot": "Invert interface",
    "sequence": "Sequence",
    "action": "Action",
    "direction": "Direction",
    "ipprotocol": "TCP/IP Version",
    "protocol": "Protocol",
    "source_net": "Source",
    "source_not": "Invert source",
    "source_port": "Source port",
    "destination_net": "Destination",
    "destination_not": "Invert destination",
    "destination_port": "Destination port",
    "received-on": "Received on",
    "received-on-not": "Invert received on",
    "icmptype": "ICMP type",
    "icmp6type": "ICMPv6 type",
    "categories": "Categories",
    "log": "Log",
    "quick": "Quick",
    "statetype": "State type",
    "gateway": "Gateway",
    "enabled": "Enabled",
    "name": "Name",
    "ifname": "Name",
    "type": "Type",
    "content": "Content",
    "members": "Members",
    "nogroup": "Hide from GUI",
    "color": "Color",
}


def _labelled(changes):
    return [{**change, "label": FIELD_LABELS.get(change["field"], change["field"])} for change in changes]


def deploy_review(firewall, include_definitions, prefix=""):
    """Plan one firewall's deployment and sort it for review: what changes first, the rest folded away."""
    combined = combined_plan(firewall, include_definitions)
    rules, definitions = combined["rules"], combined["definitions"]
    definition_ops = [
        {
            **op,
            "name": op["payload"].get("name") or op["payload"].get("ifname", ""),
            "changes": _labelled(op["changes"]),
        }
        for op in (definitions or {}).get("operations", [])
    ]
    changing = [
        {**row, "changes": _labelled(row["changes"])} for row in rules["rows"] if row["operation"] and not row["errors"]
    ]
    blocked = [row for row in rules["rows"] if row["errors"]]
    unchanged = [row for row in rules["rows"] if not row["operation"] and not row["errors"]]
    notes = list((definitions or {}).get("warnings", []))
    sync_ready = definitions_to_apply(combined)
    removals = (definitions or {}).get("removals", [])
    return {
        "firewall": firewall,
        "prefix": prefix,
        "combined": combined,
        "plan": rules,
        "definitions": definitions,
        "definition_ops": definition_ops,
        "sync_ready": sync_ready,
        "removals": removals,
        "changing": changing,
        "blocked": blocked,
        "unchanged": unchanged,
        "notes": notes,
        "folded": len(unchanged) + len(notes),
        "warned": any(row["warnings"] for row in changing),
        "has_changes": bool((sync_ready and definition_ops) or changing or rules["retire"] or removals),
    }


def _deploy_params(request, include_definitions, prefix=""):
    def values(name):
        return [value for value in request.POST.getlist(prefix + name) if value]

    return {
        "combined": True,
        "include_definitions": include_definitions,
        "approval_sha256": request.POST.get(prefix + "approval_sha256", ""),
        "selected_rules": values("selected_rules"),
        "remove_definitions": values("remove_definition") if include_definitions else [],
        "accept_warnings": request.POST.get(prefix + "accept_warnings") == "yes",
        "allow_unprotected": request.POST.get(prefix + "allow_unprotected") == "yes",
    }


@login_required
@permission_required(("fleet.view_firewall", "fleet.deploy_rules"), raise_exception=True)
def deploy_rules(request, pk):
    """One review for a firewall: supporting definitions are synchronized first, then the selected rules."""
    fw = get_object_or_404(Firewall, pk=pk)
    include_definitions = request.user.has_perm("fleet.sync_definitions")
    if request.method == "POST":
        try:
            if request.POST.get("acknowledge") != "yes":
                raise DeviceError("Confirm the apply warning before deploying.")
            job = enqueue(
                fw, DeviceJob.RULES_DEPLOY, _deploy_params(request, include_definitions), request.user.username
            )
        except DeviceError as exc:
            messages.error(request, str(exc))
            return redirect("deploy_rules", pk=pk)
        return redirect("job", pk=job.pk)
    return render(request, "fleet/deploy.html", {"firewall": fw, "review": deploy_review(fw, include_definitions)})


@login_required
@permission_required(("fleet.view_firewall", "fleet.deploy_rules"), raise_exception=True)
def deploy_all(request):
    """Review every enabled firewall on one page; each included firewall gets its own deployment job."""
    include_definitions = request.user.has_perm("fleet.sync_definitions")
    firewalls = list(Firewall.objects.filter(enabled=True))
    if request.method == "POST":
        if request.POST.get("acknowledge") != "yes":
            messages.error(request, "Confirm the apply warning before deploying. Nothing was queued.")
            return redirect("deploy_all")
        included = [fw for fw in firewalls if request.POST.get(f"fw{fw.pk}-include") == "yes"]
        if not included:
            messages.error(request, "Select at least one firewall to deploy to. Nothing was queued.")
            return redirect("deploy_all")
        queued = []
        for fw in included:
            params = _deploy_params(request, include_definitions, prefix=f"fw{fw.pk}-")
            try:
                queued.append(enqueue(fw, DeviceJob.RULES_DEPLOY, params, request.user.username))
            except DeviceError as exc:
                messages.error(request, f"{fw.name}: {exc} Nothing was queued for it.")
        if queued:
            messages.success(
                request,
                f"Queued {len(queued)} deployment{'s' if len(queued) != 1 else ''} "
                f"({', '.join(job.firewall.name for job in queued)}). Each firewall is deployed, verified and "
                "reported on its own; follow them below.",
            )
        return redirect("deployment_overview")
    reviews = [deploy_review(fw, include_definitions, prefix=f"fw{fw.pk}-") for fw in firewalls]
    return render(
        request,
        "fleet/deploy_all.html",
        {
            "reviews": reviews,
            "changing": [r for r in reviews if r["has_changes"]],
            "idle": sum(not r["has_changes"] for r in reviews),
            "skipped": Firewall.objects.filter(enabled=False),
        },
    )


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def job_detail(request, pk):
    job = get_object_or_404(DeviceJob.objects.select_related("firewall"), pk=pk)
    if job.kind in (DeviceJob.VIP_APPLY, DeviceJob.VIP_DELETE):
        back = ("Return to Virtual IPs", reverse("virtual_ips"))
    elif job.kind == DeviceJob.DHCP_SYNC:
        back = ("Return to reservations", reverse("ipam_reservations") + f"?firewall={job.firewall.pk}")
    elif job.kind == DeviceJob.RULES_DEPLOY or job.params.get("rule_id"):
        back = ("Return to rule deployment", reverse("deploy_rules", args=[job.firewall.pk]))
    else:
        back = ("Return to " + job.firewall.name, reverse("firewall", args=[job.firewall.pk]))
    waiting = (timezone.now() - job.created_at).total_seconds() if job.status == DeviceJob.QUEUED else 0
    return render(request, "fleet/job.html", {"job": job, "back": back, "stalled": waiting > 15})
