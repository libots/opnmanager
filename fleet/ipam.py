"""IP address management: site prefixes, per-interface address templates, ranges and DHCP settings.

Pure functions only (no device access, no database writes). One address plan is written once
for the whole fleet and resolved per firewall ("site"):

* Each firewall has a site prefix per family, e.g. ``10.20.0.0/16`` and ``2001:db8:0:1400::/56``.
* A template is an address in which ``x`` stands for "whatever the site prefix says", e.g.
  ``10.x.40.1/21`` or ``x:x:x:40::1/64``. Resolving merges the site's network bits with the
  template's remaining bits, so ``10.x.40.1/21`` at site ``10.20.0.0/16`` is ``10.20.40.1/21``
  and ``x:x:x:40::1/64`` at ``2001:db8:0:1400::/56`` is ``2001:db8:0:1440::1/64``.
  Explicit components inside the site prefix must agree with the site (or be zero).
* Addresses inside a subnet may also be written relative to it: ``+10`` is the 10th address
  after the network address, ``-2`` the second-to-last before the broadcast address.
* A range is ``start-end``; a bare number as the end replaces the start's last component, so
  ``10.x.10.10-29`` is ``10.x.10.10`` to ``10.x.10.29``.
"""

import ipaddress
import re

ROUTER = "0.0.0.0"  # In DHCP settings: "this firewall's own address on the interface".

# DHCP option value types. Values are stored as text and encoded per backend.
OPTION_TYPES = [
    ("ip", "IP addresses"),
    ("text", "Text"),
    ("uint8", "Integer (8-bit)"),
    ("uint16", "Integer (16-bit)"),
    ("uint32", "Integer (32-bit)"),
    ("bool", "Boolean"),
    ("hex", "Hex bytes"),
    ("unifi", "UniFi controller (option 43)"),
]

# Common DHCPv4 option names, for labels and Kea's named options.
OPTION_NAMES = {
    2: "time-offset",
    3: "routers",
    4: "time-servers",
    6: "domain-name-servers",
    12: "host-name",
    15: "domain-name",
    26: "interface-mtu",
    42: "ntp-servers",
    43: "vendor-encapsulated-options",
    44: "netbios-name-servers",
    51: "dhcp-lease-time",
    66: "tftp-server-name",
    67: "boot-file-name",
    119: "domain-search",
    121: "classless-static-route",
    150: "tftp-server-address",
    252: "wpad",
}


# Short labels for the DHCP overview.
OPTION_LABELS = {3: "Gateway", 6: "DNS", 15: "Domain", 42: "NTP", 43: "Vendor (43)", 66: "TFTP server", 67: "Boot file"}


class TemplateError(ValueError):
    pass


def _family_of(text):
    return 6 if ":" in text else 4


def _components(text, family):
    """Split an address into components, expanding IPv6 "::"; returns a list of strings."""
    if family == 4:
        parts = text.split(".")
        if len(parts) != 4:
            raise TemplateError(f"{text} is not a complete IPv4 address (four parts, x for the site part).")
        return parts
    if text.count("::") > 1:
        raise TemplateError(f"{text} uses :: more than once.")
    if "::" in text:
        head, tail = text.split("::")
        head = head.split(":") if head else []
        tail = tail.split(":") if tail else []
        missing = 8 - len(head) - len(tail)
        if missing < 1:
            raise TemplateError(f"{text} has too many parts.")
        return head + ["0"] * missing + tail
    parts = text.split(":")
    if len(parts) != 8:
        raise TemplateError(f"{text} is not a complete IPv6 address (use :: or x for the site part).")
    return parts


def _parse_template(text):
    """(family, integer value with x as 0, wildcard mask of the x components)."""
    text = text.strip().lower()
    family = _family_of(text)
    parts = _components(text, family)
    bits = 8 if family == 4 else 16
    value = wildcard = 0
    for part in parts:
        value <<= bits
        wildcard <<= bits
        if part == "x":
            wildcard |= (1 << bits) - 1
            continue
        try:
            number = int(part, 10 if family == 4 else 16)
        except ValueError:
            raise TemplateError(f"{text}: {part!r} is not a valid address part.") from None
        if not 0 <= number < (1 << bits):
            raise TemplateError(f"{text}: {part} is out of range.")
        value |= number
    return family, value, wildcard


def parse_site_prefix(text, family=None):
    """A site prefix such as 10.20.0.0/16; host bits are not allowed."""
    try:
        network = ipaddress.ip_network(text.strip(), strict=True)
    except ValueError:
        raise TemplateError(f"{text} is not a network prefix such as 10.20.0.0/16 (no host bits).") from None
    if family and network.version != family:
        raise TemplateError(f"{text} is not an IPv{family} prefix.")
    return network


def resolve_address(template, site):
    """Merge a template address (no prefix length) into a site network; returns an ip_address."""
    family, value, wildcard = _parse_template(template)
    if family != site.version:
        raise TemplateError(f"{template} is IPv{family}, the site prefix is IPv{site.version}.")
    width = 32 if family == 4 else 128
    site_mask = int(site.netmask)
    explicit = site_mask & ~wildcard & ((1 << width) - 1)
    given = value & explicit
    if given and given != int(site.network_address) & explicit:
        raise TemplateError(
            f"{template} doesn't fit site {site}: write the site's part as x (or as the site's own value)."
        )
    merged = (int(site.network_address) & site_mask) | (value & ~site_mask & ((1 << width) - 1))
    return ipaddress.ip_address(merged)


def resolve_interface(template, site):
    """A template with prefix length (10.x.40.1/21) → ip_interface at this site."""
    if "/" not in template:
        raise TemplateError(f"{template} needs a prefix length, e.g. 10.x.40.1/21.")
    address, length = template.strip().rsplit("/", 1)
    if not length.isdigit():
        raise TemplateError(f"{template}: the prefix length must be a number.")
    length = int(length)
    if length < site.prefixlen:
        raise TemplateError(
            f"{template} is larger than the site prefix /{site.prefixlen}; it would overlap other sites."
        )
    resolved = resolve_address(address, site)
    try:
        return ipaddress.ip_interface(f"{resolved}/{length}")
    except ValueError:
        raise TemplateError(f"{template}: /{length} is not a valid prefix length.") from None


def check_template(template, prefixed=False):
    """Validate a template's syntax without a site (used by forms). Returns the family."""
    text = template.strip()
    if prefixed:
        if "/" not in text:
            raise TemplateError(f"{text} needs a prefix length, e.g. 10.x.40.1/21.")
        text, length = text.rsplit("/", 1)
        family = _family_of(text)
        if not length.isdigit() or not 0 < int(length) <= (32 if family == 4 else 128):
            raise TemplateError(f"{template}: invalid prefix length.")
    family, _, _ = _parse_template(text)
    return family


RELATIVE = re.compile(r"^([+-])(\d+)$")


def resolve_in_subnet(value, subnet, site):
    """An address written as a template or relative to a subnet (+10, -2) → ip_address."""
    value = value.strip()
    relative = RELATIVE.match(value)
    if relative:
        offset = int(relative.group(2))
        if relative.group(1) == "+":
            address = subnet.network_address + offset
        else:
            address = subnet.broadcast_address - offset
        if address not in subnet:
            raise TemplateError(f"{value} is outside {subnet}.")
        return address
    if site is None:
        raise TemplateError(f"{value} needs a site prefix to resolve.")
    return resolve_address(value, site)


def split_range(text):
    """'10.x.10.10-29' → ('10.x.10.10', '10.x.10.29'); '+100-+199' and full ends work too."""
    text = text.strip()
    if text.startswith(("+", "-")):
        match = re.match(r"^([+-]\d+)\s*-\s*([+-]?\d+)$", text)
        if not match:
            raise TemplateError(f"{text} is not a range such as +100-+199.")
        start, end = match.groups()
        return start, end if end[0] in "+-" else "+" + end
    if "-" not in text:
        raise TemplateError(f"{text} is not a range: write start-end, e.g. 10.x.10.10-29.")
    start, end = (part.strip() for part in text.split("-", 1))
    if not start or not end:
        raise TemplateError(f"{text} is not a range: write start-end, e.g. 10.x.10.10-29.")
    family = _family_of(start)
    if re.fullmatch(r"[0-9a-fA-F]+", end) and ("." not in end and ":" not in end):
        separator = "." if family == 4 else ":"
        if family == 6 and "::" in start and start.endswith("::"):
            end = start + end
        else:
            end = start.rsplit(separator, 1)[0] + separator + end
    return start, end


def check_range(text):
    start, end = split_range(text)
    for part in (start, end):
        if not RELATIVE.match(part):
            _parse_template(part)
    return start, end


def resolve_range(text, subnet, site):
    """(first, last) ip_addresses of a range inside a subnet at a site."""
    start, end = split_range(text)
    first = resolve_in_subnet(start, subnet, site)
    last = resolve_in_subnet(end, subnet, site)
    for address in (first, last):
        if address not in subnet:
            raise TemplateError(f"{address} is outside the interface subnet {subnet}.")
    if int(last) < int(first):
        raise TemplateError(f"{text} ends before it starts ({first} to {last}).")
    return first, last


def range_size(first, last):
    return int(last) - int(first) + 1


def site_prefix(firewall, family):
    text = firewall.ipv4_site_prefix if family == 4 else firewall.ipv6_site_prefix
    return parse_site_prefix(text, family) if text else None


def interface_plan(addressing, firewall):
    """Both families of one logical interface at one site: {4: {...}, 6: {...}}.

    Each family is None (no template), or {"interface", "subnet", "router"} or {"error"}.
    """
    result = {}
    for family, template in ((4, addressing.ipv4_address), (6, addressing.ipv6_address)):
        if not template:
            result[family] = None
            continue
        try:
            site = site_prefix(firewall, family)
            if site is None:
                raise TemplateError(f"{firewall.name} has no IPv{family} site prefix.")
            interface = resolve_interface(template, site)
            result[family] = {"interface": interface, "subnet": interface.network, "router": interface.ip}
        except TemplateError as exc:
            result[family] = {"error": str(exc)}
    return result


def observed_addresses(inventory_row):
    """ip_interfaces (or bare addresses) a device reports for an interface in the inventory."""
    found = []
    for family in ("ipv4", "ipv6"):
        for value in str(inventory_row.get(family, "") or "").replace(";", ",").split(","):
            value = value.strip()
            if not value:
                continue
            try:
                found.append(ipaddress.ip_interface(value) if "/" in value else ipaddress.ip_address(value))
            except ValueError:
                continue
    return found


def compare_observed(planned, observed):
    """'match', 'mismatch' or 'absent' for a planned family against observed addresses."""
    if not planned or "error" in planned:
        return None
    wanted = planned["interface"]
    same_family = [a for a in observed if a.version == wanted.version]
    if not same_family:
        return "absent"
    for address in same_family:
        if isinstance(address, ipaddress.IPv4Interface | ipaddress.IPv6Interface):
            if address == wanted:
                return "match"
        elif address == wanted.ip:
            return "match"
    return "mismatch"


# --- DHCP ----------------------------------------------------------------------------------------


def _resolve_servers(text, subnet, site, router, aliases):
    """DNS/NTP-style lists: 0.0.0.0 (router), templates, +N offsets, IPs or host alias names."""
    servers, problems = [], []
    for token in [t.strip() for t in re.split(r"[,\s]+", text or "") if t.strip()]:
        if token == ROUTER:
            servers.append(str(router))
            continue
        if token in aliases:
            members = [m.strip() for m in aliases[token].splitlines() if m.strip()]
            addresses = []
            for member in members:
                try:
                    address = ipaddress.ip_address(member)
                except ValueError:
                    problems.append(f"alias {token} member {member} is not a single address")
                    continue
                if address.version == subnet.version:
                    addresses.append(str(address))
            servers.extend(addresses)
            continue
        try:
            servers.append(str(resolve_in_subnet(token, subnet, site)))
        except TemplateError as exc:
            problems.append(str(exc))
    unique = []
    for server in servers:
        if server not in unique:
            unique.append(server)
    return unique, problems


def encode_option(kind, values):
    """Hex bytes (aa:bb:...) of an option value, for backends that take raw data."""
    if kind == "ip":
        data = b"".join(ipaddress.ip_address(v).packed for v in values)
    elif kind == "unifi":
        # UniFi adoption: sub-option 1, length 4, the controller's IPv4 address.
        data = b"".join(b"\x01\x04" + ipaddress.IPv4Address(v).packed for v in values)
    elif kind == "text":
        data = values[0].encode()
    elif kind in ("uint8", "uint16", "uint32"):
        data = int(values[0]).to_bytes({"uint8": 1, "uint16": 2, "uint32": 4}[kind], "big")
    elif kind == "bool":
        data = b"\x01" if values[0] in ("1", "true", "yes", "on") else b"\x00"
    else:
        data = bytes.fromhex(values[0].replace(":", "").replace(" ", ""))
    return ":".join(f"{byte:02x}" for byte in data)


def check_option_value(kind, value):
    """Validate an option value that doesn't depend on the site (forms)."""
    value = (value or "").strip()
    if not value:
        raise TemplateError("Enter a value.")
    if kind in ("uint8", "uint16", "uint32"):
        limit = {"uint8": 255, "uint16": 65535, "uint32": 4294967295}[kind]
        if not value.isdigit() or int(value) > limit:
            raise TemplateError(f"Enter a whole number from 0 to {limit}.")
    elif kind == "bool":
        if value.lower() not in ("0", "1", "true", "false", "yes", "no", "on", "off"):
            raise TemplateError("Enter true or false.")
    elif kind == "hex":
        cleaned = value.replace(":", "").replace(" ", "")
        if not cleaned or len(cleaned) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", cleaned):
            raise TemplateError("Enter hex bytes such as 01:04:0a:14:0a:05.")
    elif kind == "text" and len(value) > 255:
        raise TemplateError("Text options hold at most 255 characters.")


def scope_settings(scope, subnet, site, router, aliases):
    """Resolve a DHCP scope at one site → backend-neutral settings dict (or raise TemplateError)."""
    problems = []
    settings = {"subnet": str(subnet), "interface_address": str(router), "range": None, "options": []}
    if scope.dynamic_range:
        first, last = resolve_range(scope.dynamic_range, subnet, site)
        if first <= router <= last:
            problems.append(f"the dynamic range {first}-{last} includes the router address {router}")
        settings["range"] = {"start": str(first), "end": str(last), "size": range_size(first, last)}
    if scope.gateway:
        gateways, issues = _resolve_servers(scope.gateway, subnet, site, router, aliases)
        problems += issues
        settings["options"].append({"code": 3, "name": "routers", "kind": "ip", "values": gateways})
    for code, text in ((6, scope.dns_servers), (42, scope.ntp_servers)):
        if text:
            servers, issues = _resolve_servers(text, subnet, site, router, aliases)
            problems += issues
            settings["options"].append({"code": code, "name": OPTION_NAMES[code], "kind": "ip", "values": servers})
    if scope.domain_name:
        settings["options"].append({"code": 15, "name": "domain-name", "kind": "text", "values": [scope.domain_name]})
    settings["lease_time"] = scope.lease_time
    for option in scope.options.all():
        if option.kind in ("ip", "unifi"):
            values, issues = _resolve_servers(option.value, subnet, site, router, aliases)
            problems += issues
        else:
            values = [option.value.strip()]
        entry = {
            "code": option.code,
            "name": OPTION_NAMES.get(option.code, f"option-{option.code}"),
            "kind": option.kind,
            "values": values,
        }
        try:
            entry["hex"] = encode_option(option.kind, values) if values else ""
        except (ValueError, ipaddress.AddressValueError) as exc:
            problems.append(f"option {option.code}: {exc}")
        settings["options"] = [o for o in settings["options"] if o["code"] != option.code] + [entry]
    settings["options"].sort(key=lambda o: o["code"])
    for option in settings["options"]:
        option["label"] = OPTION_LABELS.get(option["code"], f"Option {option['code']}")
    for option in settings["options"]:
        if option["kind"] in ("ip", "unifi") and not option["values"]:
            problems.append(f"option {option['code']} ({option['name']}) resolves to no addresses here")
    if problems:
        raise TemplateError("; ".join(problems))
    return settings


def render_dnsmasq(settings, device_interface):
    """dnsmasq-style lines for a scope (what Services: Dnsmasq: DHCP ranges/options express)."""
    lines = []
    if settings["range"]:
        lease = f",{settings['lease_time']}" if settings.get("lease_time") else ""
        lines.append(f"dhcp-range={device_interface},{settings['range']['start']},{settings['range']['end']}{lease}")
    for option in settings["options"]:
        if option["kind"] in ("ip",):
            value = ",".join(option["values"])
        elif option["kind"] in ("unifi", "hex"):
            value = option.get("hex", "")
        else:
            value = option["values"][0] if option["values"] else ""
            if option["kind"] == "text":
                value = '"' + value.replace('"', '\\"') + '"'
        lines.append(f"dhcp-option={device_interface},{option['code']},{value}")
    return lines


def render_kea(settings, device_interface):
    """Kea DHCPv4 subnet (as JSON-ready dict) for the same settings."""
    subnet = {"subnet": settings["subnet"], "interface": device_interface, "option-data": []}
    if settings["range"]:
        subnet["pools"] = [{"pool": f"{settings['range']['start']} - {settings['range']['end']}"}]
    if settings.get("lease_time"):
        subnet["valid-lifetime"] = settings["lease_time"]
    for option in settings["options"]:
        if option["kind"] == "ip":
            entry = {"code": option["code"], "data": ", ".join(option["values"])}
        elif option["kind"] in ("unifi", "hex"):
            entry = {"code": option["code"], "csv-format": False, "data": option.get("hex", "").replace(":", "")}
        else:
            entry = {"code": option["code"], "data": option["values"][0] if option["values"] else ""}
        if option["code"] in OPTION_NAMES and option["kind"] not in ("unifi", "hex"):
            entry["name"] = OPTION_NAMES[option["code"]]
        subnet["option-data"].append(entry)
    return subnet


# --- Reservations --------------------------------------------------------------------------------

MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")


def normalize_mac(value):
    """aa:bb:cc:dd:ee:ff from common notations (dashes, dots, no separators); '' if invalid."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value or "").lower()
    if len(cleaned) != 12:
        return ""
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))


HOSTNAME = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


def next_free(first, last, taken):
    """First address in [first, last] not in taken (a set of strings); None when full."""
    address = first
    while int(address) <= int(last):
        if str(address) not in taken:
            return address
        address += 1
    return None
