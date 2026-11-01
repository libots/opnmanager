from django.conf import settings
from django.contrib import admin
from django.urls import include, path
from fleet import views
from fleet.accounts import LocalLoginView, InitialPasswordChangeView

urlpatterns = [path("", views.dashboard, name="dashboard"),
    path("firewalls/<int:pk>/", views.firewall_detail, name="firewall"),
    path("firewalls/<int:pk>/import/", views.import_snapshot, name="import_snapshot"),
    path("firewalls/<int:pk>/pull/", views.pull_snapshot, name="pull_snapshot"),
    path("firewalls/<int:pk>/plan/", views.download_plan, name="download_plan"),
    path("settings/", views.settings_page, name="settings"),
    path("accounts/login/", LocalLoginView.as_view(), name="login"),
    path("accounts/password_change/", InitialPasswordChangeView.as_view(), name="password_change"),
    path("accounts/", include("django.contrib.auth.urls")), path("admin/", admin.site.urls)]
if settings.OIDC_ENABLED:
    urlpatterns += [path("oidc/", include("mozilla_django_oidc.urls"))]
