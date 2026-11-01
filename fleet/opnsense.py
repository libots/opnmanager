"""OPNsense MVC adapter: configuration reads and explicit alias upserts only."""
import os
import requests
from .reconcile import validate_snapshot

class DeviceError(Exception): pass

def flatten(value):
    """OPNsense get endpoints expose OptionFields as selected-value maps."""
    if not isinstance(value, dict): return str(value)
    return ",".join(str(key) for key, item in value.items() if isinstance(item, dict) and str(item.get("selected", "0")) == "1")

class OPNsenseClient:
    def __init__(self, firewall):
        firewall.full_clean()
        self.firewall = firewall
        prefix = firewall.credential_prefix
        key, secret = os.getenv(prefix + "_API_KEY"), os.getenv(prefix + "_API_SECRET")
        if not key or not secret:
            raise DeviceError(f"Set {prefix}_API_KEY and {prefix}_API_SECRET in the server environment.")
        self.session = requests.Session()
        self.session.auth = (key, secret)
        self.session.verify = firewall.ca_bundle or True
    def get(self, path):
        try:
            response = self.session.get(self.firewall.base_url.rstrip("/") + path, timeout=(5, 30), allow_redirects=False)
            if response.status_code != 200:
                raise DeviceError(f"Device API returned HTTP {response.status_code}. Check URL, API access and permissions.")
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            # Don't leak device response bodies, Basic auth, or credentials to users/logs.
            raise DeviceError("Unable to read device API. Check connectivity, TLS trust and API credentials.") from exc
    def snapshot(self):
        raw = self.get("/api/firewall/filter/get")
        try:
            rules = raw["filter"]["rules"]["rule"]
            alias_export = self.get("/api/firewall/alias/export")
            aliases = alias_export["aliases"]["alias"]
            def rows(nodes):
                if nodes == []: return []
                if not isinstance(nodes, dict): raise ValueError()
                return [{**{k: flatten(v) for k, v in fields.items()}, "uuid": uid} for uid, fields in nodes.items()]
            data = {"schema_version": 1, "rules": rows(rules), "aliases": rows(aliases)}
            return validate_snapshot(data)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise DeviceError("Unsupported OPNsense response. This connector requires MVC firewall/filter and alias APIs.") from exc

    def post(self, path, payload):
        try:
            response = self.session.post(self.firewall.base_url.rstrip("/") + path, json=payload,
                timeout=(5, 30), allow_redirects=False)
            if response.status_code != 200:
                raise DeviceError(f"Device write returned HTTP {response.status_code}.")
            return response.json()
        except (requests.RequestException, ValueError) as exc:
            raise DeviceError("Device write failed or timed out; state is uncertain. Pull a fresh snapshot before retrying.") from exc

    def save_alias(self, operation):
        from urllib.parse import quote
        if operation["action"] == "update":
            if not operation.get("remote_uuid"):
                raise DeviceError("Cannot update an alias without its remote UUID.")
            path = "/api/firewall/alias/set_item/" + quote(operation["remote_uuid"], safe="")
        else:
            path = "/api/firewall/alias/add_item"
        result = self.post(path, {"alias": operation["payload"]})
        if result.get("result") != "saved":
            raise DeviceError("OPNsense rejected the alias. Inspect its validation errors in the device UI.")

    def reconfigure_aliases(self):
        if self.post("/api/firewall/alias/reconfigure", {}).get("status") != "ok":
            raise DeviceError("Aliases saved but device reconfiguration failed. Inspect the device before retrying.")
