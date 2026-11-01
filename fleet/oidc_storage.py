"""Explicit restart-based UI configuration, read before Django auth initializes."""
import json,os,tempfile
from cryptography.fernet import Fernet, InvalidToken

FIELDS=['OIDC_ISSUER','OIDC_RP_CLIENT_ID','OIDC_OP_AUTHORIZATION_ENDPOINT','OIDC_OP_TOKEN_ENDPOINT','OIDC_OP_USER_ENDPOINT','OIDC_OP_JWKS_ENDPOINT']

def load(data_dir):
    path=data_dir / '.oidc-settings.json'
    if not path.exists():return {}
    data=json.loads(path.read_text())
    if data.get('OIDC_ENABLED') and data.get('encrypted_secret'):
        key=os.getenv('OPNMANAGER_CREDENTIAL_KEY') or (data_dir / '.credentials-key').read_bytes()
        try:data['OIDC_RP_CLIENT_SECRET']=Fernet(key).decrypt(data['encrypted_secret'].encode()).decode()
        except InvalidToken as exc:raise ValueError('Unable to decrypt saved OIDC secret.') from exc
    return data


def save(data_dir,data):
    fd,path=tempfile.mkstemp(prefix='.oidc-write-',dir=data_dir)
    try:
        with os.fdopen(fd,'w') as file:json.dump(data,file)
        os.replace(path,data_dir / '.oidc-settings.json')
    finally:
        if os.path.exists(path):os.unlink(path)
