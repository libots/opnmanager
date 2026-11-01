from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from fleet import views
from fleet import management_views as management
from fleet.accounts import LocalLoginView, InitialPasswordChangeView

urlpatterns = [path('interfaces/virtual-ips/refresh/',management.refresh_vips,name='refresh_vips'),
    path('interfaces/virtual-ips/<int:pk>/adopt/<uuid:uuid>/',management.adopt_vip,name='adopt_vip'),
    path('interfaces/virtual-ips/<int:pk>/delete/<uuid:uuid>/',management.delete_vip,name='delete_vip'),path('system/settings/general/',management.dns_general,name='dns_general'),path('fleet/deployment/',management.deployment_overview,name='deployment_overview'),
    path('fleet/logical-interfaces/',lambda request: management.interfaces(request,logical=True),name='logical_matrix'),
    path('interfaces/',management.interfaces,name='interface_overview'),
    path('interfaces/refresh/',management.read_interfaces,name='refresh_interfaces'),
    path('fleet/mappings/save/',management.save_mapping,name='save_mapping'),
    path('interfaces/virtual-ips/',management.virtual_ips,name='virtual_ips'),
    path('interfaces/virtual-ips/<int:pk>/<int:vip_id>/',management.review_vip,name='review_vip'),
    path('system/firmware/status/',management.firmware,name='firmware_status'),
    path('system/firmware/updates/',lambda request: management.firmware(request,updates=True),name='firmware_updates'),
    path('system/firmware/action/',management.firmware_task,name='firmware_task'),
    path('settings/authentication/',management.oidc_options,name='oidc_options'),path("", views.dashboard, name="dashboard"),
    path("firewalls/<int:pk>/", views.firewall_detail, name="firewall"),
    path("firewalls/<int:pk>/import/", views.import_snapshot, name="import_snapshot"),
    path("firewalls/<int:pk>/pull/", views.pull_snapshot, name="pull_snapshot"),
    path("firewalls/<int:pk>/plan/", views.download_plan, name="download_plan"),
    path("firewalls/<int:pk>/deploy/", views.deploy_rules, name="deploy_rules"),
    path("rules/", views.rules_page, name="rules"),
    path("firewalls/<int:pk>/credentials/", views.firewall_credentials, name="credentials"),
    path("firewalls/<int:pk>/sync/", views.sync_definitions, name="sync_definitions"),
    path("firewalls/<int:pk>/mappings/defaults/", views.default_mappings, name="default_mappings"),
    path("firewalls/<int:pk>/rules/import/", views.adopt_rules, name="adopt_rules"),
    path("settings/", views.settings_page, name="settings"),
    path("accounts/login/", LocalLoginView.as_view(), name="login"),
    path("accounts/password_change/", InitialPasswordChangeView.as_view(), name="password_change"),
    path("accounts/", include("django.contrib.auth.urls")), path("admin/", admin.site.urls)]
if settings.OIDC_ENABLED:
    urlpatterns += [path("oidc/", include("mozilla_django_oidc.urls"))]
