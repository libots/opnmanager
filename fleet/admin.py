from django.contrib import admin
from django.urls import reverse
from django.utils.html import format_html
from .models import Firewall, LogicalInterface, InterfaceMapping, Alias, Rule, Snapshot, AuditEvent, Category, InterfaceGroup

class MappingInline(admin.TabularInline):
    model = InterfaceMapping
    extra = 0
@admin.register(Firewall)
class FirewallAdmin(admin.ModelAdmin):
    list_display = ["name", "base_url", "enabled"]
    inlines = [MappingInline]
    readonly_fields = ["credential_settings"]
    @admin.display(description="API credentials")
    def credential_settings(self, obj):
        if not obj or not obj.pk: return "Save this firewall first to configure its API credentials."
        return format_html('<a href="{}">Manage write-only API key and secret</a>', reverse("credentials", args=[obj.pk]))
@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    from .forms import RuleForm
    form = RuleForm
    list_display = ["name", "sequence", "bindings", "action", "protocol", "scope", "enabled"]
    list_filter = ["scope", "interfaces", "interface_groups", "categories", "floating", "action", "enabled"]
    search_fields = ["name", "source", "destination"]
    @admin.display(description="Interfaces / groups")
    def bindings(self, obj):
        return ", ".join([i.name for i in obj.bound_interfaces()] + [g.name for g in obj.interface_groups.all()]) or "Floating / global"
@admin.register(Alias)
class AliasAdmin(admin.ModelAdmin):
    from .forms import AliasForm
    form = AliasForm
    list_display = ["name", "type", "scope", "enabled"]
admin.site.register(LogicalInterface)
admin.site.register(InterfaceMapping)
@admin.register(Snapshot, AuditEvent)
class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False
admin.site.site_header = "OPNmanager · Configuration"
admin.site.site_title = "OPNmanager"

@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ["name", "color", "scope"]
    filter_horizontal = ["firewalls"]

@admin.register(InterfaceGroup)
class InterfaceGroupAdmin(admin.ModelAdmin):
    list_display = ["name", "description", "scope", "sequence"]
    filter_horizontal = ["members", "firewalls"]
