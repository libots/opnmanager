"""OPNsense MVC adapter: configuration reads and explicit supporting-definition upserts."""

from urllib.parse import quote

import requests

from .credentials import get_credentials
from .opnsense_errors import DeviceError
from .reconcile import validate_snapshot


def flatten(value):
    """OPNsense get endpoints expose OptionFields as selected-value maps."""
    if not isinstance(value, dict):
        return str(value)
    return ",".join(
        str(key) for key, item in value.items() if isinstance(item, dict) and str(item.get("selected", "0")) == "1"
    )


class OPNsenseClient:
    def __init__(self, firewall):
        firewall.full_clean()
        self.firewall = firewall
        key, secret = get_credentials(firewall)
        self.session = requests.Session()
        self.session.auth = (key, secret)
        self.session.verify = firewall.ca_bundle or True

    # Read timeout matches ROLLBACK_SECONDS headroom: a slow apply must still
    # leave time to confirm or revert before OPNsense's own rollback timer.
    TIMEOUT = (5, 30)
    STATUS_EXPLANATIONS = {
        401: "Authentication rejected. Use an OPNsense API key and secret, not the account login password.",
        403: "Access denied. Check the API user's effective privileges and any source-address restrictions.",
        404: "Endpoint not found. Check the management URL/port and whether this OPNsense version supports this API.",
    }

    def _request(self, method, path, payload=None, *, write=False):
        """Send one API request and translate every failure into an actionable DeviceError.

        Writes append a warning that device state is uncertain, because a timeout or
        error after the request was sent does not prove the change was not made.
        """
        endpoint = f"API endpoint {path}"
        suffix = " Device state is uncertain; pull a fresh snapshot before retrying." if write else ""
        url = self.firewall.base_url.rstrip("/") + path
        try:
            kwargs = {"timeout": self.TIMEOUT, "allow_redirects": False}
            if method == "POST":
                kwargs["json"] = payload
            send = self.session.post if method == "POST" else self.session.get
            response = send(url, **kwargs)
        except requests.exceptions.SSLError as exc:
            raise DeviceError(
                f"{endpoint}: TLS handshake or certificate verification failed. If OPNsense uses a private CA or self-signed certificate, install its trusted PEM certificate on the manager server and set this firewall's CA bundle path. Also use a management hostname matching the certificate.{suffix}"
            ) from exc
        except requests.exceptions.ProxyError as exc:
            raise DeviceError(
                f"{endpoint}: proxy connection failed. Check the manager server's proxy configuration and whether it permits access to the firewall.{suffix}"
            ) from exc
        except requests.exceptions.ConnectTimeout as exc:
            raise DeviceError(
                f"{endpoint}: connection timed out. Check the management address and port, routing from the manager server, and firewall access rules.{suffix}"
            ) from exc
        except requests.exceptions.ReadTimeout as exc:
            raise DeviceError(
                f"{endpoint}: connected but the firewall did not respond within {self.TIMEOUT[1]} seconds. Check device load and API availability.{suffix}"
            ) from exc
        except requests.exceptions.Timeout as exc:
            raise DeviceError(
                f"{endpoint}: API request timed out. Check device reachability and API availability.{suffix}"
            ) from exc
        except requests.exceptions.ConnectionError as exc:
            raise DeviceError(
                f"{endpoint}: connection failed. Check DNS, management address/port, routing from the manager server and firewall access rules.{suffix}"
            ) from exc
        except OSError as exc:
            raise DeviceError(
                f"{endpoint}: unable to read the configured CA bundle. Set a readable PEM file path on the manager server."
            ) from exc
        except requests.RequestException as exc:
            raise DeviceError(
                f"{endpoint}: request failed. Check the management address and server networking.{suffix}"
            ) from exc
        if response.status_code != 200:
            detail = self.STATUS_EXPLANATIONS.get(response.status_code, "Check device/API availability.")
            if 300 <= response.status_code < 400:
                detail = "The device redirected the request. Use the final HTTPS management origin and correct port; API redirects are not followed."
            raise DeviceError(f"{endpoint}: HTTP {response.status_code}. {detail}{suffix}")
        try:
            return response.json()
        except ValueError as exc:
            raise DeviceError(
                f"{endpoint}: the server returned HTTP 200 but not valid JSON. Check that the URL/port reaches the OPNsense API rather than a login page or another web service.{suffix}"
            ) from exc

    def get(self, path):
        return self._request("GET", path)

    def post(self, path, payload, *, write=True):
        """POST to the API. Pass write=False for read-only search/info endpoints."""
        return self._request("POST", path, payload, write=write)

    def snapshot(self):
        raw = self.get("/api/firewall/filter/get")
        try:
            rules = raw["filter"]["rules"]["rule"]
            alias_export = self.get("/api/firewall/alias/export")
            aliases = alias_export["aliases"]["alias"]

            def rows(nodes):
                if nodes == []:
                    return []
                if not isinstance(nodes, dict):
                    raise ValueError()
                return [{**{k: flatten(v) for k, v in fields.items()}, "uuid": uid} for uid, fields in nodes.items()]

            inventory = self.get("/api/firewall/filter/get_interface_list")
            groups = self.get("/api/firewall/group/get")["group"].get("ifgroupentry", {})
            categories = self.get("/api/firewall/category/get")["category"].get("categories", {}).get("category", {})
            interfaces = [{"name": item["value"], "label": item["label"]} for item in inventory["interfaces"]["items"]]
            data = {
                "schema_version": 1,
                "rules": rows(rules),
                "aliases": rows(aliases),
                "interfaces": interfaces,
                "groups": rows(groups),
                "categories": rows(categories),
            }
            return validate_snapshot(data)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise DeviceError(
                "Unsupported OPNsense response. This connector requires MVC filter, alias, interface inventory, group and category APIs."
            ) from exc

    def save_alias(self, operation):
        if operation["action"] == "update":
            if not operation.get("remote_uuid"):
                raise DeviceError("Cannot update an alias without its remote UUID.")
            path = "/api/firewall/alias/set_item/" + quote(operation["remote_uuid"], safe="")
        else:
            path = "/api/firewall/alias/add_item"
        result = self.post(path, {"alias": operation["payload"]})
        if not _saved(result):
            raise DeviceError("OPNsense rejected the alias. Inspect its validation errors in the device UI.")

    def reconfigure_aliases(self):
        if not _status_ok(self.post("/api/firewall/alias/reconfigure", {})):
            raise DeviceError("Aliases saved but device reconfiguration failed. Inspect the device before retrying.")

    def save_definition(self, operation):
        if operation["kind"] == "alias":
            return self.save_alias(operation)
        kind = operation["kind"]
        controller = {"group": "group", "category": "category"}[kind]
        if operation["action"] == "update":
            if not operation.get("remote_uuid"):
                raise DeviceError("Missing remote UUID; pull a live snapshot first.")
            endpoint = "set_item/" + quote(operation["remote_uuid"], safe="")
        else:
            endpoint = "add_item"
        result = self.post(f"/api/firewall/{controller}/{endpoint}", {kind: operation["payload"]})
        if not _saved(result):
            raise DeviceError(f"OPNsense rejected the {kind}. Inspect device validation errors.")

    def reconfigure_definitions(self, kinds):
        if "group" in kinds and not _status_ok(self.post("/api/firewall/group/reconfigure", {})):
            raise DeviceError("Groups saved but reconfiguration failed. Inspect device state.")
        if "alias" in kinds:
            self.reconfigure_aliases()

    def save_rule(self, operation):
        if operation["action"] == "update":
            if not operation.get("remote_uuid"):
                raise DeviceError("Missing remote rule UUID.")
            endpoint = "set_rule/" + quote(operation["remote_uuid"], safe="")
        else:
            endpoint = "add_rule"
        result = self.post("/api/firewall/filter/" + endpoint, {"rule": operation["payload"]})
        if not _saved(result):
            raise DeviceError("OPNsense rejected a rule. Inspect device validation errors; partial changes may remain.")

    # --- Filter rule savepoint / rollback -------------------------------------
    # OPNsense reverts an apply made with a savepoint revision after
    # ROLLBACK_SECONDS unless cancel_rollback is called. Confirming only after a
    # successful readback means a rule that cuts off the manager reverts itself.
    ROLLBACK_SECONDS = 60

    def savepoint(self):
        result = self.post("/api/firewall/filter/savepoint", {})
        revision = str(result.get("revision", "")).strip() if isinstance(result, dict) else ""
        if not revision:
            raise DeviceError(
                "The firewall did not return a filter savepoint revision. No rule writes were made; "
                "this OPNsense version may not support protected rule apply."
            )
        return revision

    def apply_rules(self, revision=None):
        """Apply saved filter rules. With a savepoint revision, OPNsense arms automatic rollback."""
        path = "/api/firewall/filter/apply" + ("/" + quote(revision, safe="") if revision else "")
        if not _status_ok(self.post(path, {})):
            raise DeviceError(
                "Rule apply failed. Inspect the device; saved configuration may differ from active rules."
            )

    def cancel_rollback(self, revision):
        """Confirm an applied savepoint so OPNsense keeps the new rules."""
        result = self.post("/api/firewall/filter/cancel_rollback/" + quote(revision, safe=""), {})
        if not _status_ok(result):
            raise DeviceError(
                f"Rules were applied but could not be confirmed. OPNsense will revert them automatically "
                f"within {self.ROLLBACK_SECONDS} seconds of the apply; pull a fresh snapshot to verify."
            )

    def revert(self, revision):
        """Restore the filter configuration saved at the revision and reload it immediately."""
        if not _status_ok(self.post("/api/firewall/filter/revert/" + quote(revision, safe=""), {})):
            raise DeviceError("Revert request was not accepted.")


def _status_ok(result):
    return isinstance(result, dict) and str(result.get("status", "")).strip().lower() == "ok"


def _saved(result):
    return isinstance(result, dict) and result.get("result") == "saved"
