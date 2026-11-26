from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from fleet import interface_views, ipam_views, views
from fleet import management_views as management
from fleet.accounts import InitialPasswordChangeView, LocalLoginView

urlpatterns = [
    path("interfaces/virtual-ips/refresh/", management.refresh_vips, name="refresh_vips"),
    path("interfaces/virtual-ips/<int:pk>/adopt/<uuid:uuid>/", management.adopt_vip, name="adopt_vip"),
    path("interfaces/virtual-ips/<int:pk>/delete/<uuid:uuid>/", management.delete_vip, name="delete_vip"),
    path("system/settings/general/", management.dns_general, name="dns_general"),
    path("fleet/deployment/", management.deployment_overview, name="deployment_overview"),
    path("fleet/logical-interfaces/", interface_views.logical_interfaces, name="logical_matrix"),
    path("fleet/logical-interfaces/add/", interface_views.create_logical_interface, name="create_logical_interface"),
    path("interfaces/", management.interfaces, name="interface_overview"),
    path("interfaces/refresh/", management.read_interfaces, name="refresh_interfaces"),
    path("fleet/mappings/save/", interface_views.save_mappings, name="save_mappings"),
    path("interfaces/virtual-ips/", management.virtual_ips, name="virtual_ips"),
    path("interfaces/virtual-ips/<int:pk>/<int:vip_id>/", management.review_vip, name="review_vip"),
    path("system/firmware/status/", management.firmware, name="firmware_status"),
    path(
        "system/firmware/updates/", lambda request: management.firmware(request, updates=True), name="firmware_updates"
    ),
    path("system/firmware/action/", management.firmware_task, name="firmware_task"),
    path("settings/authentication/", management.oidc_options, name="oidc_options"),
    path("ipam/", ipam_views.address_plan, name="ipam_plan"),
    path("ipam/dhcp/", ipam_views.dhcp_scopes, name="ipam_dhcp"),
    path("ipam/dns/", ipam_views.dns_order, name="ipam_dns"),
    path("ipam/ula-vips/", ipam_views.create_ula_vips, name="ipam_ula_vips"),
    path("ipam/<int:pk>/push/", ipam_views.push_addresses, name="ipam_push"),
    path("ipam/subnet-info/", ipam_views.subnet_info, name="ipam_subnet_info"),
    path("ipam/ranges/", ipam_views.address_ranges, name="ipam_ranges"),
    path("ipam/reservations/", ipam_views.reservations, name="ipam_reservations"),
    path("ipam/reservations/<int:pk>/read/", ipam_views.read_dhcp, name="ipam_read_dhcp"),
    path("ipam/reservations/<int:pk>/import/", ipam_views.import_reservations, name="ipam_import"),
    path("ipam/reservations/<int:pk>/sync/", ipam_views.sync_reservations, name="ipam_sync"),
    path("", views.dashboard, name="dashboard"),
    path("firewalls/<int:pk>/", views.firewall_detail, name="firewall"),
    path("firewalls/order/", views.reorder_firewalls, name="reorder_firewalls"),
    path("firewalls/<int:pk>/import/", views.import_snapshot, name="import_snapshot"),
    path("firewalls/<int:pk>/pull/", views.pull_snapshot, name="pull_snapshot"),
    path("firewalls/<int:pk>/plan/", views.download_plan, name="download_plan"),
    path("firewalls/<int:pk>/deploy/", views.deploy_rules, name="deploy_rules"),
    path("fleet/deployment/deploy/", views.deploy_all, name="deploy_all"),
    path("rules/", views.rules_page, name="rules"),
    path("firewalls/<int:pk>/credentials/", views.firewall_credentials, name="credentials"),
    path("firewalls/<int:pk>/sync/", views.sync_definitions, name="sync_definitions"),
    path("firewalls/<int:pk>/mappings/defaults/", views.default_mappings, name="default_mappings"),
    path("firewalls/<int:pk>/rules/import/", views.adopt_rules, name="adopt_rules"),
    path("jobs/<int:pk>/", views.job_detail, name="job"),
    path("settings/", views.settings_page, name="settings"),
    path("accounts/login/", LocalLoginView.as_view(), name="login"),
    path("accounts/password_change/", InitialPasswordChangeView.as_view(), name="password_change"),
    path("accounts/", include("django.contrib.auth.urls")),
    path("admin/", admin.site.urls),
]
if settings.OIDC_ENABLED:
    urlpatterns += [path("oidc/", include("mozilla_django_oidc.urls"))]
