"""Write-only UI credentials encrypted with a key kept outside the database."""
import os
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from .opnsense_errors import DeviceError


def cipher(create=True):
    key = os.getenv("OPNMANAGER_CREDENTIAL_KEY")
    if not key:
        path = settings.DATA_DIR / ".credentials-key"
        if not create and not path.exists():
            raise DeviceError("Credential encryption key is missing. Restore it or replace credentials in Settings.")
        try:
            with open(path, "xb", opener=lambda p, f: os.open(p, f, 0o600)) as file:
                file.write(Fernet.generate_key())
        except FileExistsError:
            pass
        key = path.read_bytes()
    try: return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise DeviceError("The credential encryption key is invalid; check server configuration.") from exc


def encrypt_credentials(firewall, key, secret):
    box = cipher()
    firewall.encrypted_api_key = box.encrypt(key.encode()).decode()
    firewall.encrypted_api_secret = box.encrypt(secret.encode()).decode()


def get_credentials(firewall):
    if firewall.encrypted_api_key or firewall.encrypted_api_secret:
        try:
            box = cipher(create=False)
            return box.decrypt(firewall.encrypted_api_key.encode()).decode(), box.decrypt(firewall.encrypted_api_secret.encode()).decode()
        except (InvalidToken, ValueError) as exc:
            raise DeviceError("Unable to decrypt this firewall's credentials. Restore the encryption key or replace credentials in Settings.") from exc
    prefix = firewall.credential_prefix
    key, secret = os.getenv(prefix + "_API_KEY"), os.getenv(prefix + "_API_SECRET")
    if not key or not secret:
        raise DeviceError("Configure an API key and secret in this firewall's credential settings, or supply its environment variables.")
    return key, secret
