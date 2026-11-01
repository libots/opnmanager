"""OPNsense MVC adapter: configuration reads and explicit supporting-definition upserts."""
import requests
from .reconcile import validate_snapshot

from .opnsense_errors import DeviceError
from .credentials import get_credentials

def flatten(value):
    """OPNsense get endpoints expose OptionFields as selected-value maps."""
    if not isinstance(value, dict): return str(value)
    return ",".join(str(key) for key, item in value.items() if isinstance(item, dict) and str(item.get("selected", "0")) == "1")

class OPNsenseClient:
    def __init__(self, firewall):
        firewall.full_clean()
        self.firewall = firewall
        key, secret = get_credentials(firewall)
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
            inventory = self.get("/api/firewall/filter/get_interface_list")
            groups = self.get("/api/firewall/group/get")["group"].get("ifgroupentry", {})
            categories = self.get("/api/firewall/category/get")["category"].get("categories", {}).get("category", {})
            interfaces = [{"name": item["value"], "label": item["label"]}
                          for item in inventory["interfaces"]["items"]]
            data = {"schema_version": 1, "rules": rows(rules), "aliases": rows(aliases),
                    "interfaces": interfaces, "groups": rows(groups), "categories": rows(categories)}
            return validate_snapshot(data)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise DeviceError("Unsupported OPNsense response. This connector requires MVC filter, alias, interface inventory, group and category APIs.") from exc

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


    def save_definition(self, operation):
        if operation["kind"] == "alias":
            return self.save_alias(operation)
        from urllib.parse import quote
        kind = operation["kind"]
        controller = {"group": "group", "category": "category"}[kind]
        if operation["action"] == "update":
            if not operation.get("remote_uuid"): raise DeviceError("Missing remote UUID; pull a live snapshot first.")
            endpoint = "set_item/" + quote(operation["remote_uuid"], safe="")
        else:
            endpoint = "add_item"
        result = self.post(f"/api/firewall/{controller}/{endpoint}", {kind: operation["payload"]})
        if result.get("result") != "saved":
            raise DeviceError(f"OPNsense rejected the {kind}. Inspect device validation errors.")

    def reconfigure_definitions(self, kinds):
        if "group" in kinds and self.post("/api/firewall/group/reconfigure", {}).get("status") != "ok":
            raise DeviceError("Groups saved but reconfiguration failed. Inspect device state.")
        if "alias" in kinds: self.reconfigure_aliases()
