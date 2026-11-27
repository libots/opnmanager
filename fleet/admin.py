from django import forms
from django.contrib import admin, messages
from django.contrib.admin import helpers
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.http import HttpResponseRedirect, JsonResponse
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.text import capfirst
from django.views.decorators.http import require_POST

from .forms import DhcpScopeForm, DNSProfileForm, VirtualIPForm
from .models import (
    AddressRange,
    Alias,
    AuditEvent,
    Category,
    DhcpOption,
    DhcpScope,
    DnsBase,
    DnsBaseValue,
    DnsPreference,
    DNSProfile,
    Firewall,
    FirewallGroup,
    InterfaceAddressing,
    InterfaceGroup,
    InterfaceMapping,
    LogicalInterface,
    Rule,
    Snapshot,
    StaticReservation,
    VirtualIP,
)


class PlainRelationsMixin:
    """Plain dropdowns in inline rows: the pencil/plus/x/eye links crowd every row."""

    labels = {}

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        field = super().formfield_for_dbfield(db_field, request, **kwargs)
        if field is not None and hasattr(field.widget, "can_add_related"):
            field.widget.can_add_related = field.widget.can_change_related = False
            field.widget.can_delete_related = field.widget.can_view_related = False
        if field is not None and db_field.name in self.labels:
            field.label = self.labels[db_field.name]
        return field


class MappingInline(PlainRelationsMixin, admin.TabularInline):
    """Interface mappings on the firewall page, picked from the firewall's own interface list."""

    model = InterfaceMapping
    extra = 0
    verbose_name = "Interface mapping"
    verbose_name_plural = "Interface mappings"
    fields = ["logical_interface", "device_interface"]
    ordering = ["logical_interface__sort_key", "logical_interface__name"]

    def get_formset(self, request, obj=None, **kwargs):
        from .interface_views import device_interfaces

        formset = super().get_formset(request, obj, **kwargs)
        options = device_interfaces(obj) if obj else []
        if not options:
            return formset
        base = formset.form

        class MappingForm(base):
            def __init__(self, *args, **kw):
                super().__init__(*args, **kw)
                current = self.initial.get("device_interface") or ""
                choices = [("", "— pick an interface —")] + [
                    (
                        o["name"],
                        f"{o['name']} · {o['label']}"
                        + (f" ({o['device']}{' · ' + o['ipv4'] if o.get('ipv4') else ''})" if o.get("device") else ""),
                    )
                    for o in options
                ]
                if current and current not in {o["name"] for o in options}:
                    choices.append((current, f"{current} (not on firewall)"))
                field = self.fields["device_interface"]
                field.widget = forms.Select(choices=choices)
                field.help_text = ""

        formset.form = MappingForm
        return formset


class FirewallGroupMembershipInline(PlainRelationsMixin, admin.TabularInline):
    model = FirewallGroup.firewalls.through
    labels = {"firewallgroup": "Firewall group"}
    extra = 0
    verbose_name = "Firewall group membership"
    verbose_name_plural = "Firewall group memberships"


class OpnDialogAdmin(PlainRelationsMixin, admin.ModelAdmin):
    """An editor laid out like an OPNsense dialog (sections, info icons, Cancel/Save).

    Pages open it in a dialog frame with ?_modal=1 (static/opn-dialog.js); saving then answers
    with admin/opn_modal_done.html, which asks the page to close the dialog and refresh in place.
    Outside a dialog, saving returns to a safe ?next= or to `return_view`. ?_section=<key> limits
    the form to one fieldset named in `sections` (and drops inlines), for focused dialogs.
    """

    change_form_template = "admin/opn_change_form.html"
    delete_confirmation_template = "admin/opn_delete_confirmation.html"
    MODAL_VAR = "_modal"
    return_view = None
    sections = {}
    # Address fields: field name -> (kind, other fields the hint depends on). The form shows the
    # usable range / per-site result under the field (static/subnet-tools.js, ipam_views.subnet_info)
    # and, for prefix, interface and template fields, a subnet calculator button.
    address_fields = {}

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        field = super().formfield_for_dbfield(db_field, request, **kwargs)
        if field is not None and db_field.name in self.address_fields:
            kind, context = self.address_fields[db_field.name]
            field.widget.attrs.update(
                {
                    "data-subnet-hint": kind,
                    "data-hint-url": reverse("ipam_subnet_info"),
                    "data-hint-context": " ".join(context),
                    "autocomplete": "off",
                    "spellcheck": "false",
                }
            )
            if kind in ("prefix", "interface", "template"):
                field.widget.attrs["data-calculator"] = "use" if kind != "template" else "view"
        return field

    @classmethod
    def is_modal(cls, request):
        return cls.MODAL_VAR in request.GET or cls.MODAL_VAR in request.POST

    @staticmethod
    def is_popup(request):
        return admin.options.IS_POPUP_VAR in request.POST or admin.options.IS_POPUP_VAR in request.GET

    def section(self, request):
        key = request.GET.get("_section") or request.POST.get("_section")
        return key if key in self.sections else None

    def get_fieldsets(self, request, obj=None):
        fieldsets = super().get_fieldsets(request, obj)
        key = self.section(request)
        if key:
            return [fieldset for fieldset in fieldsets if fieldset[0] == self.sections[key]]
        return fieldsets

    def get_inline_instances(self, request, obj=None):
        return [] if self.section(request) else super().get_inline_instances(request, obj)

    def get_form(self, request, obj=None, change=False, **kwargs):
        form = super().get_form(request, obj, change, **kwargs)
        # Overlap warnings in the hints leave the object being edited out of the comparison.
        if obj is not None and obj.pk:
            for name in self.address_fields:
                if name in form.base_fields:
                    form.base_fields[name].widget.attrs["data-hint-self"] = str(obj.pk)
        return form

    def framed(self, request, response):
        # Only same-origin pages may frame an editor opened as a dialog; everything else stays DENY.
        if self.is_modal(request):
            response["X-Frame-Options"] = "SAMEORIGIN"
        return response

    def modal_done(self, request, message):
        return TemplateResponse(request, "admin/opn_modal_done.html", {"result": {"message": message}})

    def changeform_view(self, request, object_id=None, form_url="", extra_context=None):
        key = self.section(request)
        extra_context = {
            **(extra_context or {}),
            "modal": self.is_modal(request),
            "section": key,
            "section_title": self.sections.get(key, ""),
            "return_url": self.return_url(request),
        }
        return self.framed(request, super().changeform_view(request, object_id, form_url, extra_context))

    def delete_view(self, request, object_id, extra_context=None):
        extra_context = {**(extra_context or {}), "modal": self.is_modal(request)}
        return self.framed(request, super().delete_view(request, object_id, extra_context))

    def return_url(self, request):
        target = request.GET.get("next") or request.POST.get("next") or ""
        if target and url_has_allowed_host_and_scheme(target, {request.get_host()}, request.is_secure()):
            return target
        return reverse(self.return_view) if self.return_view else ""

    def _finish(self, request, response, message):
        if "_continue" in request.POST or "_addanother" in request.POST or self.is_popup(request):
            return response
        if self.is_modal(request):
            return self.modal_done(request, message)
        target = self.return_url(request)
        if target:
            return HttpResponseRedirect(target)
        return response

    def response_add(self, request, obj, post_url_continue=None):
        response = super().response_add(request, obj, post_url_continue)
        return self._finish(request, response, f"{capfirst(self.opts.verbose_name)} “{obj}” added.")

    def response_change(self, request, obj):
        response = super().response_change(request, obj)
        return self._finish(request, response, f"{capfirst(self.opts.verbose_name)} “{obj}” saved.")

    def response_delete(self, request, obj_display, obj_id):
        response = super().response_delete(request, obj_display, obj_id)
        return self._finish(request, response, f"{capfirst(self.opts.verbose_name)} “{obj_display}” deleted.")


@admin.register(Firewall)
class FirewallAdmin(OpnDialogAdmin):
    list_display = ["name", "base_url", "enabled"]
    labels = {
        "base_url": "Management URL",
        "ca_bundle": "CA bundle",
        "credential_prefix": "Credential variable prefix",
        "auto_map_interfaces": "Auto map interfaces",
        "ipv4_site_prefix": "IPv4 site prefix",
        "ipv6_site_prefix": "IPv6 site prefix",
        "dhcp_backend": "DHCP server",
    }
    inlines = [MappingInline, FirewallGroupMembershipInline]
    readonly_fields = ["credential_settings", "mapping_overview"]
    fieldsets = [
        ("General settings", {"fields": ["enabled", "name", "notes"]}),
        ("Connection", {"fields": ["base_url", "ca_bundle", "credential_prefix", "credential_settings"]}),
        ("Interfaces", {"fields": ["auto_map_interfaces", "mapping_overview"]}),
        (
            "Addressing and DHCP",
            {"fields": ["ipv4_site_prefix", "ipv6_site_prefix", "dhcp_backend"]},
        ),
    ]
    sections = {"addressing": "Addressing and DHCP"}
    address_fields = {"ipv4_site_prefix": ("prefix", ()), "ipv6_site_prefix": ("prefix", ())}

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        # Plain inputs, as OPNsense shows them (no "Currently/Change" URL widget, no oversized notes box).
        if db_field.name == "base_url":
            kwargs["widget"] = forms.URLInput(attrs={"placeholder": "https://fw.example.net"})
        elif db_field.name == "notes":
            kwargs["widget"] = forms.Textarea(attrs={"rows": 3})
        return super().formfield_for_dbfield(db_field, request, **kwargs)

    def get_deleted_objects(self, objs, request):
        deleted, counts, permissions, protected = super().get_deleted_objects(objs, request)
        # Snapshots belong to their firewall. Permit their cascade here without
        # opening standalone snapshot deletion or weakening other permissions.
        if self.has_delete_permission(request):
            permissions.discard(Snapshot._meta.verbose_name)
        return deleted, counts, permissions, protected

    @admin.display(description="Interface mappings")
    def mapping_overview(self, obj):
        if not obj or not obj.pk:
            return "Save this firewall first, then map its interfaces below."
        return format_html(
            "{} of {} logical interfaces mapped. Edit them below, or compare every firewall side by side on "
            '<a href="{}?firewalls={}">Fleet: Logical Interfaces</a>.',
            obj.interface_mappings.count(),
            LogicalInterface.objects.count(),
            reverse("logical_matrix"),
            obj.pk,
        )

    @admin.display(description="API credentials")
    def credential_settings(self, obj):
        if not obj or not obj.pk:
            return "Save this firewall first to configure its API credentials."
        return format_html(
            '<a href="{}">Manage write-only API key and secret</a>', reverse("credentials", args=[obj.pk])
        )


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    from .forms import RuleForm

    form = RuleForm
    change_form_template = "admin/fleet/rule/change_form.html"
    # Sections and field order follow OPNsense's Firewall: Rules dialog. Deployment is
    # manager-only, and sits under Organisation so a rule's reach is visible up front.
    fieldsets = [
        ("Organisation", {"fields": ("enabled", "sequence", "categories", "name")}),
        ("Deployment", {"fields": ("targets",)}),
        ("Interface", {"fields": ("interface_not", "bindings", "origin_not", "origin_bindings")}),
        (
            "Filter",
            {
                "fields": (
                    "quick",
                    "action",
                    "direction",
                    "ip_version",
                    "protocol",
                    "icmp_types",
                    "icmp6_types",
                    "source_not",
                    "source",
                    "source_port",
                    "destination_not",
                    "destination",
                    "destination_port",
                    "log",
                )
            },
        ),
        ("Stateful firewall", {"fields": ("state_type",)}),
        ("Source Routing", {"fields": ("gateway",)}),
    ]
    list_display = ["name", "sequence", "rule_bindings", "action", "protocol", "scope", "enabled"]
    list_filter = ["scope", "interfaces", "interface_groups", "categories", "floating", "action", "enabled"]
    search_fields = ["name", "source", "destination"]

    # Bulk toggles offered on Firewall: Rules, like OPNsense's rule grid.
    BULK_ACTIONS = {
        "enable": ("enabled", True),
        "disable": ("enabled", False),
        "log": ("log", True),
        "nolog": ("log", False),
    }

    @admin.display(description="Interfaces / groups")
    def rule_bindings(self, obj):
        return (
            ", ".join([i.name for i in obj.bound_interfaces()] + [g.name for g in obj.interface_groups.all()])
            or "Floating / global"
        )

    def get_urls(self):
        view = self.admin_site.admin_view
        return [
            path("bulk/", view(require_POST(self.bulk_action_view)), name="fleet_rule_bulk"),
            path("bulk-edit/", view(self.bulk_edit_view), name="fleet_rule_bulk_edit"),
        ] + super().get_urls()

    # Firewall: Rules is the rule list; the admin changelist only duplicated it.
    def return_url(self, request):
        target = request.GET.get("_next") or request.POST.get("_next") or ""
        if target and url_has_allowed_host_and_scheme(target, {request.get_host()}, request.is_secure()):
            return target
        return reverse("rules")

    def changelist_view(self, request, extra_context=None):
        if request.GET.get(admin.options.IS_POPUP_VAR):
            return super().changelist_view(request, extra_context)
        return HttpResponseRedirect(reverse("rules"))

    def render_change_form(self, request, context, *args, **kwargs):
        context["rules_return"] = self.return_url(request)
        context["modal"] = self.is_modal(request)
        return super().render_change_form(request, context, *args, **kwargs)

    def response_add(self, request, obj, post_url_continue=None):
        if "_continue" in request.POST or "_addanother" in request.POST or self.is_popup(request):
            return super().response_add(request, obj, post_url_continue)
        if self.is_modal(request):
            return self.modal_done(request, f"Rule “{obj}” added.")
        messages.success(request, f"Rule “{obj}” added.")
        return HttpResponseRedirect(self.return_url(request))

    def response_change(self, request, obj):
        if "_continue" in request.POST or "_addanother" in request.POST or self.is_popup(request):
            return super().response_change(request, obj)
        if self.is_modal(request):
            return self.modal_done(request, f"Rule “{obj}” saved.")
        messages.success(request, f"Rule “{obj}” saved.")
        return HttpResponseRedirect(self.return_url(request))

    def response_delete(self, request, obj_display, obj_id):
        if self.is_popup(request):
            return super().response_delete(request, obj_display, obj_id)
        if self.is_modal(request):
            return self.modal_done(request, f"Rule “{obj_display}” deleted.")
        messages.success(request, f"Rule “{obj_display}” deleted.")
        return HttpResponseRedirect(self.return_url(request))

    # Firewall: Rules opens the rule dialog in a frame with ?_modal=1. Saving answers
    # with a page that tells the rules page to close the dialog and refresh its table.
    MODAL_VAR = "_modal"

    @classmethod
    def is_modal(cls, request):
        return cls.MODAL_VAR in request.GET or cls.MODAL_VAR in request.POST

    def modal_done(self, request, message):
        return TemplateResponse(request, "admin/fleet/rule/modal_done.html", {"result": {"message": message}})

    def framed(self, request, response):
        # Only the rules page, on this origin, may frame the dialog; everything else stays DENY.
        if self.is_modal(request):
            response["X-Frame-Options"] = "SAMEORIGIN"
        return response

    def changeform_view(self, request, *args, **kwargs):
        return self.framed(request, super().changeform_view(request, *args, **kwargs))

    def delete_view(self, request, object_id, extra_context=None):
        extra_context = {**(extra_context or {}), "modal": self.is_modal(request)}
        return self.framed(request, super().delete_view(request, object_id, extra_context))

    @staticmethod
    def is_popup(request):
        return admin.options.IS_POPUP_VAR in request.POST or admin.options.IS_POPUP_VAR in request.GET

    def get_changeform_initial_data(self, request):
        """Clone: open the add dialog filled in from another rule, as OPNsense does."""
        initial = super().get_changeform_initial_data(request)
        source = Rule.objects.filter(pk=request.GET.get("clone")).first() if request.GET.get("clone") else None
        if source is None:
            return initial
        from .forms import RuleForm, rule_form_data, rule_form_initial

        initial.update(rule_form_initial(rule_form_data(source), RuleForm.base_fields))
        # Keep the clone next to its source without taking the source's sequence.
        taken = set(Rule.objects.values_list("sequence", flat=True))
        sequence = source.sequence + 1
        while sequence in taken and sequence < 999999:
            sequence += 1
        initial["sequence"] = sequence
        return initial

    def selected_rules(self, request):
        ids = request.POST.getlist("ids") or request.GET.getlist("ids")
        try:
            return list(Rule.objects.filter(pk__in=ids).order_by("sequence", "name"))
        except ValidationError:  # malformed UUIDs
            return []

    def bulk_action_view(self, request):
        action = request.POST.get("action")
        rules = self.selected_rules(request)
        wants_json = "application/json" in request.headers.get("Accept", "")

        def back(level, text):
            # Firewall: Rules posts with fetch and refreshes its table; forms get a redirect.
            if wants_json:
                return JsonResponse(
                    {"ok": level == "success", "message": text}, status=200 if level == "success" else 400
                )
            getattr(messages, level)(request, text)
            return HttpResponseRedirect(self.return_url(request))

        if not rules:
            return back("warning", "Select one or more rules first.")
        if action == "delete":
            if not self.has_delete_permission(request):
                raise PermissionDenied
            queryset = Rule.objects.filter(pk__in=[r.pk for r in rules])
            self.log_deletions(request, queryset)
            self.delete_queryset(request, queryset)
            return back("success", f"Deleted {len(rules)} rule{'s' if len(rules) != 1 else ''}.")
        if action not in self.BULK_ACTIONS:
            return back("error", "Unknown rule action.")
        if not self.has_change_permission(request):
            raise PermissionDenied
        field, value = self.BULK_ACTIONS[action]
        changed = [rule for rule in rules if getattr(rule, field) != value]
        with transaction.atomic():
            for rule in changed:
                setattr(rule, field, value)
                rule.save(update_fields=[field])
                self.log_change(request, rule, [{"changed": {"fields": [Rule._meta.get_field(field).verbose_name]}}])
        label = {
            "enable": "Enabled",
            "disable": "Disabled",
            "log": "Turned on logging for",
            "nolog": "Turned off logging for",
        }
        return back("success", f"{label[action]} {len(changed)} rule{'s' if len(changed) != 1 else ''}.")

    def bulk_edit_view(self, request):
        """Edit several rules at once. Fields that differ start greyed out; only changed fields are saved."""
        if not self.has_change_permission(request):
            raise PermissionDenied
        return self.framed(request, self._bulk_edit(request))

    def _bulk_edit(self, request):
        from .forms import RuleForm, bulk_rule_forms, comparable, rule_form_data, rule_form_initial

        rules = self.selected_rules(request)
        if len(rules) < 2:
            if rules:
                url = reverse("admin:fleet_rule_change", args=[rules[0].pk])
                return HttpResponseRedirect(url + ("?_modal=1" if self.is_modal(request) else ""))
            messages.warning(request, "Select two or more rules to edit them together.")
            return HttpResponseRedirect(self.return_url(request))
        datas = [rule_form_data(rule) for rule in rules]
        names = [name for fieldset in self.fieldsets for name in fieldset[1]["fields"]]
        mixed = {name for name in names if len({comparable(data, name) for data in datas}) > 1}
        changed = [name for name in request.POST.getlist("_changed") if name in names]
        bulk_errors = []
        if request.method == "POST":
            if not changed:
                if self.is_modal(request):
                    return self.modal_done(request, "Nothing was changed.")
                messages.info(request, "Nothing was changed.")
                return HttpResponseRedirect(self.return_url(request))
            edits = bulk_rule_forms(rules, request.POST, changed)
            for rule, form in zip(rules, edits, strict=True):
                for field, errors in form.errors.items():
                    label = form.fields[field].label if field in form.fields else ""
                    bulk_errors += [f"{rule.name}: {label + ': ' if label else ''}{error}" for error in errors]
            if not bulk_errors:
                labels = [str(edits[0].fields[name].label) for name in changed]
                with transaction.atomic():
                    for rule, form in zip(rules, edits, strict=True):
                        form.save()
                        self.log_change(request, rule, [{"changed": {"fields": labels}}])
                if self.is_modal(request):
                    return self.modal_done(request, f"Updated {', '.join(labels)} on {len(rules)} rules.")
                messages.success(request, f"Updated {', '.join(labels)} on {len(rules)} rules.")
                return HttpResponseRedirect(self.return_url(request))
        # The dialog shows shared values; differing fields start empty and greyed out.
        initial = rule_form_initial(datas[0], set(RuleForm.base_fields) - mixed)
        # Keep what was entered when the save is refused.
        initial.update(rule_form_initial(request.POST, changed))
        form = RuleForm(initial=initial)
        adminform = helpers.AdminForm(form, list(self.get_fieldsets(request)), {}, model_admin=self)
        context = {
            **self.admin_site.each_context(request),
            "title": f"Edit {len(rules)} rules",
            "subtitle": None,
            "adminform": adminform,
            "object_id": None,
            "original": None,
            "is_popup": False,
            "to_field": None,
            "media": self.media + adminform.media,
            "inline_admin_formsets": [],
            "errors": helpers.AdminErrorList(form, []),
            "preserved_filters": "",
            "bulk_rules": rules,
            "bulk_mixed": sorted(mixed),
            "bulk_changed": changed,
            "bulk_errors": bulk_errors,
        }
        return self.render_change_form(
            request, context, add=False, change=True, obj=None, form_url=request.get_full_path()
        )


@admin.register(Alias)
class AliasAdmin(admin.ModelAdmin):
    from .forms import AliasForm

    form = AliasForm
    list_display = ["name", "type", "scope", "enabled"]


admin.site.register(LogicalInterface)
admin.site.register(InterfaceMapping)


@admin.register(Snapshot, AuditEvent)
class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


admin.site.site_header = "OPNmanager · Configuration"
admin.site.site_title = "OPNmanager"


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    from .forms import CategoryForm

    form = CategoryForm
    list_display = ["name", "color", "scope"]


@admin.register(InterfaceGroup)
class InterfaceGroupAdmin(admin.ModelAdmin):
    from .forms import InterfaceGroupForm

    form = InterfaceGroupForm
    list_display = ["name", "description", "scope", "sequence", "no_gui_group"]


@admin.register(FirewallGroup)
class FirewallGroupAdmin(admin.ModelAdmin):
    from .forms import FirewallGroupForm

    form = FirewallGroupForm
    list_display = ["name", "description"]
    search_fields = ["name"]


class DesiredProfileAdmin(admin.ModelAdmin):
    def changeform_view(self, request, *args, **kwargs):
        from django.contrib import messages

        messages.info(
            request,
            "Desired configuration only: the inspected OPNsense core does not expose a supported write API for ordered system search domains. Saving here does not change device DNS.",
        )
        return super().changeform_view(request, *args, **kwargs)


@admin.register(DNSProfile)
class DNSProfileAdmin(DesiredProfileAdmin):
    form = DNSProfileForm
    list_display = ["name", "scope"]


@admin.register(VirtualIP)
class VirtualIPAdmin(OpnDialogAdmin):
    address_fields = {"network": ("interface", ())}
    form = VirtualIPForm
    list_display = ["name", "interface", "network", "mode", "scope"]


@admin.register(InterfaceAddressing)
class InterfaceAddressingAdmin(OpnDialogAdmin):
    return_view = "ipam_plan"
    labels = {"ipv4_address": "Firewall IPv4 address", "ipv6_address": "Firewall IPv6 address"}
    address_fields = {
        "ipv4_address": ("template", ("logical_interface",)),
        "ipv6_address": ("template", ("logical_interface",)),
    }

    def get_form(self, request, obj=None, change=False, **kwargs):
        form = super().get_form(request, obj, change, **kwargs)
        # One plan per interface: offer only interfaces that don't have one yet.
        field = form.base_fields.get("logical_interface")
        if field is not None:
            taken = InterfaceAddressing.objects.exclude(pk=obj.pk if obj else None).values("logical_interface")
            field.queryset = LogicalInterface.objects.exclude(pk__in=taken)
        return form

    list_display = ["logical_interface", "ipv4_address", "ipv6_address", "notes"]
    fields = ["logical_interface", "ipv4_address", "ipv6_address", "notes"]


@admin.register(AddressRange)
class AddressRangeAdmin(OpnDialogAdmin):
    return_view = "ipam_ranges"
    address_fields = {"addresses": ("range", ("logical_interface",))}
    list_display = ["logical_interface", "name", "addresses", "description"]
    list_filter = ["logical_interface"]
    fields = ["logical_interface", "name", "addresses", "description"]


class DhcpOptionInline(admin.TabularInline):
    model = DhcpOption
    extra = 0
    fields = ["code", "kind", "value", "description"]


@admin.register(DhcpScope)
class DhcpScopeAdmin(OpnDialogAdmin):
    return_view = "ipam_dhcp"
    address_fields = {"dynamic_range": ("pool", ("logical_interface",))}
    form = DhcpScopeForm
    inlines = [DhcpOptionInline]
    list_display = ["name", "logical_interface", "dynamic_range", "enabled", "scope"]
    fieldsets = [
        (None, {"fields": ["name", "enabled", "logical_interface", "description"]}),
        ("Addresses", {"fields": ["dynamic_range", "lease_time"]}),
        ("Options", {"fields": ["gateway", "dns_servers", "ntp_servers", "domain_name"]}),
        ("Deployment", {"fields": ["targets"]}),
    ]


@admin.register(StaticReservation)
class StaticReservationAdmin(OpnDialogAdmin):
    return_view = "ipam_reservations"
    address_fields = {"ip_address": ("address", ("logical_interface", "firewall"))}
    list_display = ["firewall", "logical_interface", "ip_address", "mac_address", "hostname", "description"]
    list_filter = ["firewall", "logical_interface"]
    search_fields = ["hostname", "mac_address", "ip_address", "description"]
    fields = ["firewall", "logical_interface", "ip_address", "mac_address", "hostname", "description"]


@admin.register(DnsPreference)
class DnsPreferenceAdmin(OpnDialogAdmin):
    from .forms import DnsPreferenceForm

    form = DnsPreferenceForm
    return_view = "ipam_dns"
    list_display = ["name", "dns_servers", "search_domains", "is_default"]
    fieldsets = [
        (None, {"fields": ["name", "is_default", "description"]}),
        ("Order", {"fields": ["dns_servers", "search_domains"]}),
    ]


class DnsBaseValueInline(PlainRelationsMixin, admin.TabularInline):
    model = DnsBaseValue
    extra = 0
    fields = ["firewall", "value"]
    verbose_name = "Site value"
    verbose_name_plural = "Site values (replace the default at that site)"


@admin.register(DnsBase)
class DnsBaseAdmin(OpnDialogAdmin):
    from .forms import DnsBaseForm

    form = DnsBaseForm
    return_view = "ipam_dns"
    inlines = [DnsBaseValueInline]
    list_display = ["name", "kind", "default"]
    fieldsets = [(None, {"fields": ["name", "kind", "default", "description"]})]
