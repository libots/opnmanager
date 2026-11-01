from django.contrib import messages
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django import forms
from django.contrib.auth.views import LoginView, PasswordChangeView
from django.db import transaction
from django.urls import reverse_lazy
from .models import LocalAccountState


class LocalAuthenticationForm(AuthenticationForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["username"].initial = "admin"


class LocalLoginView(LoginView):
    authentication_form = LocalAuthenticationForm


class NewPasswordForm(PasswordChangeForm):
    def clean_new_password1(self):
        password = self.cleaned_data["new_password1"]
        if self.user.check_password(password):
            raise forms.ValidationError("Choose a different password from your current one.")
        return password


class InitialPasswordChangeView(PasswordChangeView):
    form_class = NewPasswordForm
    template_name = "registration/password_change_form.html"
    success_url = reverse_lazy("dashboard")

    @transaction.atomic
    def form_valid(self, form):
        response = super().form_valid(form)
        LocalAccountState.objects.filter(user=self.request.user).update(must_change_password=False)
        messages.success(self.request, "Password updated. You can now manage your fleet and settings.")
        return response
