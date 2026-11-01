from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin
from .models import LocalAccountState


class InitialPasswordMiddleware(MiddlewareMixin):
    """Apply to dashboard, admin, and all device actions, not just the login landing."""
    def process_view(self, request, view_func, view_args, view_kwargs):
        if not request.user.is_authenticated:
            return None
        if request.resolver_match.url_name in {"password_change", "password_change_done", "logout"}:
            return None
        if LocalAccountState.objects.filter(user=request.user, must_change_password=True).exists():
            return redirect("password_change")
