from django.contrib import admin
from .models import Firewall, LogicalInterface, InterfaceMapping, Alias, Rule, Snapshot, AuditEvent

class MappingInline(admin.TabularInline):
    model = InterfaceMapping
    extra = 0
@admin.register(Firewall)
class FirewallAdmin(admin.ModelAdmin):
    list_display = ["name", "base_url", "enabled"]
    inlines = [MappingInline]
@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ["name", "sequence", "interface", "action", "protocol", "scope", "enabled"]
    list_filter = ["scope", "interface", "action", "enabled"]
    search_fields = ["name", "source", "destination"]
    filter_horizontal = ["firewalls"]
@admin.register(Alias)
class AliasAdmin(admin.ModelAdmin):
    list_display = ["name", "type", "scope", "enabled"]
    filter_horizontal = ["firewalls"]
admin.site.register(LogicalInterface)
admin.site.register(InterfaceMapping)
@admin.register(Snapshot, AuditEvent)
class ReadOnlyAdmin(admin.ModelAdmin):
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False
admin.site.site_header = "OPNmanager · Configuration"
admin.site.site_title = "OPNmanager"
