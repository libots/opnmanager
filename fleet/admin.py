from django.contrib import admin, messages
from django.contrib.admin import helpers
from django.core.exceptions import PermissionDenied, ValidationError
from django.db import transaction
from django.http import HttpResponseRedirect
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from .forms import DNSProfileForm, VirtualIPForm
from .models import (
    Alias,
    AuditEvent,
    Category,
    DNSProfile,
    Firewall,
    FirewallGroup,
    InterfaceGroup,
    InterfaceMapping,
    LogicalInterface,
    Rule,
    Snapshot,
    VirtualIP,
)


class MappingInline(admin.TabularInline):
    model = InterfaceMapping
    extra = 0


class FirewallGroupMembershipInline(admin.TabularInline):
    model = FirewallGroup.firewalls.through
    extra = 0
    verbose_name = "Firewall group membership"
    verbose_name_plural = "Firewall group memberships"


@admin.register(Firewall)
class FirewallAdmin(admin.ModelAdmin):
    list_display = ["name", "base_url", "enabled"]
    inlines = [MappingInline, FirewallGroupMembershipInline]
    readonly_fields = ["credential_settings"]

    def get_deleted_objects(self, objs, request):
        deleted, counts, permissions, protected = super().get_deleted_objects(objs, request)
        # Snapshots belong to their firewall. Permit their cascade here without
        # opening standalone snapshot deletion or weakening other permissions.
        if self.has_delete_permission(request):
            permissions.discard(Snapshot._meta.verbose_name)
        return deleted, counts, permissions, protected

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
    # Sections and field order follow OPNsense's Firewall: Rules dialog; Deployment is manager-only.
    fieldsets = [
        ("Organisation", {"fields": ("enabled", "sequence", "categories", "name")}),
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
        ("Deployment", {"fields": ("scope", "firewalls", "firewall_groups")}),
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
        return super().render_change_form(request, context, *args, **kwargs)

    def response_add(self, request, obj, post_url_continue=None):
        if "_continue" in request.POST or "_addanother" in request.POST or self.is_popup(request):
            return super().response_add(request, obj, post_url_continue)
        messages.success(request, f"Rule “{obj}” added.")
        return HttpResponseRedirect(self.return_url(request))

    def response_change(self, request, obj):
        if "_continue" in request.POST or "_addanother" in request.POST or self.is_popup(request):
            return super().response_change(request, obj)
        messages.success(request, f"Rule “{obj}” saved.")
        return HttpResponseRedirect(self.return_url(request))

    def response_delete(self, request, obj_display, obj_id):
        if self.is_popup(request):
            return super().response_delete(request, obj_display, obj_id)
        messages.success(request, f"Rule “{obj_display}” deleted.")
        return HttpResponseRedirect(self.return_url(request))

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
        back = HttpResponseRedirect(self.return_url(request))
        if not rules:
            messages.warning(request, "Select one or more rules first.")
            return back
        if action == "delete":
            if not self.has_delete_permission(request):
                raise PermissionDenied
            queryset = Rule.objects.filter(pk__in=[r.pk for r in rules])
            self.log_deletions(request, queryset)
            self.delete_queryset(request, queryset)
            messages.success(request, f"Deleted {len(rules)} rule{'s' if len(rules) != 1 else ''}.")
            return back
        if action not in self.BULK_ACTIONS:
            messages.error(request, "Unknown rule action.")
            return back
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
        messages.success(request, f"{label[action]} {len(changed)} rule{'s' if len(changed) != 1 else ''}.")
        return back

    def bulk_edit_view(self, request):
        """Edit several rules at once. Fields that differ start greyed out; only changed fields are saved."""
        from .forms import RuleForm, bulk_rule_forms, comparable, rule_form_data, rule_form_initial

        if not self.has_change_permission(request):
            raise PermissionDenied
        rules = self.selected_rules(request)
        if len(rules) < 2:
            if rules:
                return HttpResponseRedirect(reverse("admin:fleet_rule_change", args=[rules[0].pk]))
            messages.warning(request, "Select two or more rules to edit them together.")
            return HttpResponseRedirect(self.return_url(request))
        datas = [rule_form_data(rule) for rule in rules]
        names = [name for fieldset in self.fieldsets for name in fieldset[1]["fields"]]
        mixed = {name for name in names if len({comparable(data, name) for data in datas}) > 1}
        changed = [name for name in request.POST.getlist("_changed") if name in names]
        bulk_errors = []
        if request.method == "POST":
            if not changed:
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
    list_display = ["name", "description", "scope", "sequence"]


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
class VirtualIPAdmin(admin.ModelAdmin):
    form = VirtualIPForm
    list_display = ["name", "interface", "network", "mode", "scope"]
