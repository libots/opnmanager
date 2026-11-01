import hashlib
import time
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import SuspiciousOperation
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

class SubjectOIDCBackend(OIDCAuthenticationBackend):
    """Bind accounts to issuer + subject, never auto-link by mutable email."""
    def verify_token(self, token, **kwargs):
        payload = super().verify_token(token, **kwargs)
        if payload.get("iss") != settings.OIDC_ISSUER:
            raise SuspiciousOperation("Unexpected OIDC issuer")
        now = time.time()
        audience = payload.get("aud", [])
        if isinstance(audience, str): audience = [audience]
        if not isinstance(audience, list) or settings.OIDC_RP_CLIENT_ID not in audience:
            raise SuspiciousOperation("Unexpected OIDC audience")
        if (len(audience) > 1 or "azp" in payload) and payload.get("azp") != settings.OIDC_RP_CLIENT_ID:
            raise SuspiciousOperation("Unexpected OIDC authorized party")
        for name in ("exp", "iat"):
            if type(payload.get(name)) not in (int, float):
                raise SuspiciousOperation("Missing OIDC token timestamps")
        if payload["exp"] <= now or payload["iat"] > now + 60 or not payload.get("sub"):
            raise SuspiciousOperation("Expired or invalid OIDC token")
        if "nbf" in payload and (type(payload["nbf"]) not in (int, float) or payload["nbf"] > now + 60):
            raise SuspiciousOperation("OIDC token not yet valid")
        return payload

    def get_userinfo(self, access_token, id_token, payload):
        claims = super().get_userinfo(access_token, id_token, payload)
        if claims.get("sub") != payload.get("sub"):
            raise SuspiciousOperation("OIDC subject mismatch")
        return claims

    def verify_claims(self, claims):
        return bool(claims.get("sub")) and claims.get("email_verified") is True and super().verify_claims(claims)

    def get_username(self, claims):
        identity = settings.OIDC_ISSUER + "\0" + claims["sub"]
        return "oidc_" + hashlib.sha256(identity.encode()).hexdigest()

    def filter_users_by_claims(self, claims):
        if not claims.get("sub"):
            return get_user_model().objects.none()
        return get_user_model().objects.filter(username=self.get_username(claims))

    def create_user(self, claims):
        user = get_user_model().objects.create_user(self.get_username(claims), email=claims.get("email", ""))
        user.set_unusable_password()
        user.save()
        return user

    def update_user(self, user, claims):
        user.email = claims.get("email", "")
        user.save(update_fields=["email"])
        return user
