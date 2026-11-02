from django.contrib import messages
from django.contrib.auth.decorators import login_required, permission_required
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST
from .forms import SnapshotImportForm
from .models import Firewall, Rule, Alias, LogicalInterface, Snapshot, AuditEvent
from .opnsense import OPNsenseClient, DeviceError
from .reconcile import plan_for

@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def dashboard(request):
    devices = []
    for fw in Firewall.objects.all():
        plan = plan_for(fw)
        devices.append({"firewall": fw, "plan": plan,
            "drift": sum(i["status"] in ("missing", "changed", "conflict", "out_of_scope") for i in plan["items"])})
    return render(request, "fleet/dashboard.html", {"devices": devices, "rule_count": Rule.objects.count(),
        "alias_count": Alias.objects.count(), "interface_count": LogicalInterface.objects.count()})

@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def firewall_detail(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    return render(request, "fleet/firewall.html", {"firewall": fw, "plan": plan_for(fw),
        "mappings": fw.interface_mappings.select_related("logical_interface"), "form": SnapshotImportForm()})

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
    return render(request, "fleet/firewall.html", {"firewall": fw, "plan": plan_for(fw),
        "mappings": fw.interface_mappings.select_related("logical_interface"), "form": form}, status=400)

@login_required
@permission_required(("fleet.view_firewall", "fleet.refresh_firewall"), raise_exception=True)
@require_POST
def pull_snapshot(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    wants_json = 'application/json' in request.headers.get('Accept', '')
    target = {'overview': 'dashboard', 'deployment': 'deployment_overview'}.get(request.POST.get('return_to'))
    def finish(error=None, **result):
        if wants_json:
            return JsonResponse({'ok': not error, 'error': error, **result}, status=400 if error else 200)
        if error: messages.error(request, error)
        return redirect(target) if target else redirect('firewall', pk=pk)
    if not fw.enabled:
        return finish('Enable this firewall before pulling a snapshot.')
    try:
        data = OPNsenseClient(fw).snapshot()
        snapshot = Snapshot.objects.create(firewall=fw, data=data, source='api')
        count = apply_default_mappings(fw, data) if fw.auto_map_interfaces else 0
        AuditEvent.objects.create(actor=request.user.username, action='snapshot.pull', detail=fw.name)
        if not wants_json:
            messages.info(request, f'Added {count} default interface mappings from unique display names.')
            messages.success(request, 'Configuration read from device. No device changes made.')
        if wants_json:
            plan = plan_for(fw)
            drift = sum(item['status'] in ('missing','changed','conflict','out_of_scope') for item in plan['items'])
            return finish(observed_at=snapshot.created_at.isoformat(),
                          policy='Needs attention' if plan['errors'] else f'{drift} differences' if drift else 'Managed fields match',
                          attention=bool(plan['errors'] or drift))
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

from django.core.exceptions import ValidationError
from django.db import transaction
from django.views.decorators.debug import sensitive_post_parameters
from .forms import CredentialsForm, ImportRulesForm
from .models import Category, InterfaceGroup
from .credentials import encrypt_credentials
from .definition_sync import definition_plan, execute_definition_plan
from .mappings import apply_default_mappings
from .import_rules import import_rules
from .rule_filters import filter_rows, SEARCH_FIELDS


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
    return render(request, "fleet/credentials.html", {"firewall": fw, "form": form, "has_credentials": bool(fw.encrypted_api_key)})


@login_required
@permission_required(("fleet.view_firewall", "fleet.sync_definitions"), raise_exception=True)
def sync_definitions(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    rule_id=request.POST.get('rule_id') if request.method=='POST' else request.GET.get('rule')
    if rule_id:
        import uuid
        try:rule_id=uuid.UUID(rule_id)
        except ValueError:
            from django.http import Http404
            raise Http404('Invalid rule identifier')
    rule=get_object_or_404(Rule,pk=rule_id) if rule_id else None
    if rule and not rule.applies_to(fw):
        from django.http import Http404
        raise Http404('Rule does not target this firewall')
    if request.method == "POST":
        try:
            count = execute_definition_plan(fw, request.POST.get("approval_sha256"), OPNsenseClient(fw), request.user.username, rule=rule)
            messages.success(request, f"Verified {count} supporting-definition changes. No manager rules were deployed.")
        except DeviceError as exc:
            messages.error(request, str(exc))
        return redirect("deploy_rules" if rule else "firewall", pk=pk)
    return render(request, "fleet/sync.html", {"firewall": fw, "plan": definition_plan(fw,rule=rule), "rule":rule})


@login_required
@permission_required(("fleet.view_firewall", "fleet.change_firewall", "fleet.add_interfacemapping", "fleet.add_logicalinterface"), raise_exception=True)
@require_POST
def default_mappings(request, pk):
    fw = get_object_or_404(Firewall, pk=pk)
    snapshot = fw.snapshots.first()
    count = apply_default_mappings(fw, snapshot.data) if snapshot else 0
    AuditEvent.objects.create(actor=request.user.username, action="mappings.default", detail=f"{fw.name}: {count}")
    messages.success(request, f"Added {count} unambiguous name mappings. Existing mappings were preserved.")
    return redirect("firewall", pk=pk)


@login_required
@permission_required("fleet.view_firewall", raise_exception=True)
def rules_page(request):
    fw = get_object_or_404(Firewall, pk=request.GET["firewall"]) if request.GET.get("firewall") else None
    observed = fw.snapshots.first() if fw else None
    if fw:
        data = observed.data if observed else {"rules": [], "groups": [], "categories": [], "interfaces": []}
        rows = [{**row, "index": str(index)} for index, row in enumerate(data["rules"])]
        groups = {r["ifname"]: set(r["members"].split(",")) for r in data.get("groups", [])}
        interfaces = [(r["name"], r["label"]) for r in data.get("interfaces", [])] + [(name, name + " (group)") for name in groups]
        categories = [(r.get("uuid", r["name"]), r["name"]) for r in data.get("categories", [])]
    else:
        rows = []
        groups = {g.name: {i.name for i in g.members.all()} for g in InterfaceGroup.objects.prefetch_related("members")}
        for rule in Rule.objects.select_related("interface").prefetch_related("interfaces", "interface_groups", "origin_interfaces", "origin_interface_groups", "categories"):
            rows.append({"description": rule.name, "id": str(rule.pk), "interface": ",".join([i.name for i in rule.bound_interfaces()] + [g.name for g in rule.interface_groups.all()]),
                "categories": ",".join(c.name for c in rule.categories.all()), "sequence": str(rule.sequence), "action": rule.action,
                "protocol": rule.protocol, "source_net": rule.source, "destination_net": rule.destination, "source_port": rule.source_port, "destination_port": rule.destination_port, "interfacenot": str(int(rule.interface_not)),
                "received-on": ",".join([i.name for i in rule.origin_interfaces.all()]+[g.name for g in rule.origin_interface_groups.all()]),
                "ipprotocol":rule.ip_version,"direction":rule.direction,"quick":str(int(rule.quick)),"log":str(int(rule.log)),
                "source_not":str(int(rule.source_not)),"destination_not":str(int(rule.destination_not)),
                "enabled": str(int(rule.enabled)), "icmptype": rule.icmp_types, "icmp6type": rule.icmp6_types})
        interfaces = [(i.name, i.name) for i in LogicalInterface.objects.all()] + [(g, g + " (group)") for g in groups]
        categories = [(c.name, c.name) for c in Category.objects.all()]
    import re
    category_names = dict(categories)
    category_colors={c.name:c.color for c in Category.objects.all()} if not fw else {r.get('uuid',r['name']):r.get('color','') for r in data.get('categories',[])}
    origin_ids={origin.remote_uuid:str(origin.rule_id) for origin in fw.ruleorigin_set.all()} if fw else {}
    interface_labels=dict(interfaces)
    managed_ids=list(Rule.objects.values_list("pk",flat=True)) if fw else []
    from .rule_identity import matches as matches_rule
    for row in rows:
        bindings={v.strip() for v in row.get('interface','').split(',') if v.strip()}
        row['placement']='floating' if len(bindings)!=1 else 'group' if next(iter(bindings)) in groups else 'interface'
        row['section_label']='Floating rules' if row['placement']=='floating' else ('Group — ' if row['placement']=='group' else 'Interface — ')+interface_labels.get(next(iter(bindings)),next(iter(bindings)))
        row['interface_display']=', '.join(interface_labels.get(v.strip(),v.strip()) for v in row.get('interface','').split(',') if v.strip())
        row['origin_display']=', '.join(interface_labels.get(v.strip(),v.strip()) for v in row.get('received-on','').split(',') if v.strip())
        for side in ('source','destination'):
            address=row.get(side+'_net','') or 'any'
            row[side+'_display']=('! ' if row.get(side+'_not')=='1' else '')+{'any':'*','(self)':'This Firewall'}.get(address,address)
        row['manager_id']=origin_ids.get(row.get('uuid')) if fw else row['id']
        if fw and not row['manager_id']:
            matching_ids=[str(pk) for pk in managed_ids if matches_rule(row.get('description',''),pk)]
            if len(matching_ids)==1:row['manager_id']=matching_ids[0]
        row['category_badges']=[{'name':category_names.get(value,value),'color':category_colors.get(value,'137b66') if re.fullmatch('[0-9a-fA-F]{6}',category_colors.get(value,'')) else '137b66'} for value in row.get('categories','').split(',') if value]
        row["category_display"] = ", ".join(category_names.get(value, value) for value in row.get("categories", "").split(",") if value)
    all_rows=rows
    rows = filter_rows(all_rows, request.GET, groups)
    can_import=bool(fw and observed and request.user.has_perms(['fleet.add_rule','fleet.add_alias','fleet.add_category','fleet.add_interfacegroup']))
    return render(request, "fleet/rules.html", {"rows": rows,"rules_data":{'rows':all_rows,'search_fields':SEARCH_FIELDS,'groups':{name:sorted(members) for name,members in groups.items()},'can_import':can_import,'can_edit':request.user.has_perm('fleet.change_rule')},'can_import':can_import, "firewall": fw, "snapshot": observed,
        "firewalls": Firewall.objects.all(), "interfaces": interfaces, "categories": categories,
        "import_form": ImportRulesForm(snapshot=observed) if observed else None})


@login_required
@permission_required(("fleet.view_firewall", "fleet.add_rule", "fleet.add_alias", "fleet.add_category", "fleet.add_interfacegroup"), raise_exception=True)
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
                rules = import_rules(snapshot, form.cleaned_data["rule_indices"], form.cleaned_data["scope"], form.cleaned_data["firewalls"], form.cleaned_data["firewall_groups"])
                AuditEvent.objects.create(actor=request.user.username, action="rules.imported", detail=f"{fw.name}: {len(rules)}")
            messages.success(request, f"Imported {len(rules)} rules into the manager. Device configuration was unchanged.")
        except (ValidationError, ValueError) as exc:
            messages.error(request, "; ".join(exc.messages) if isinstance(exc, ValidationError) else "Unsupported rule data; check the snapshot values.")
    else:
        messages.error(request, "Invalid selection or stale snapshot. Select rules and target firewalls again.")
    return redirect("/rules/?firewall=" + str(fw.pk))

from .deployment import deployment_plan, execute_deployment

@login_required
@permission_required(('fleet.view_firewall','fleet.deploy_rules'),raise_exception=True)
def deploy_rules(request,pk):
    fw=get_object_or_404(Firewall,pk=pk)
    if request.method=='POST':
        try:
            if request.POST.get('acknowledge')!='yes': raise DeviceError('Confirm the apply warning before deploying.')
            count=execute_deployment(fw,request.POST.get('approval_sha256'),request.POST.getlist('selected_rules'),OPNsenseClient(fw),request.user.username)
            messages.success(request,f'Applied and verified {count} selected rule changes.')
        except DeviceError as exc: messages.error(request,str(exc))
        return redirect('deploy_rules',pk=pk)
    return render(request,'fleet/deploy.html',{'firewall':fw,'plan':deployment_plan(fw)})
