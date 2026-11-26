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
OPTION_LABELS = {
    3: "Gateway",
    6: "DNS",
    15: "Domain",
    42: "NTP",
    43: "Vendor (43)",
    66: "TFTP server",
    67: "Boot file",
    119: "Search",
}


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


ULA_NETWORK = ipaddress.ip_network("fc00::/7")


def ipv6_scope(address):
    """'ula', 'link-local' or 'global' for an IPv6 address or interface."""
    ip = getattr(address, "ip", address)
    if ip.is_link_local:
        return "link-local"
    if ip in ULA_NETWORK:
        return "ula"
    return "global"


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


# --- DNS options: bases and preference lists ----------------------------------------------------
#
# A DNS base is a named per-site value: DNS servers (kind "servers") or domains (kind "domains"),
# with an optional fleet-wide default (templates such as 10.x.10.5 resolve at each site) and a
# value per site that replaces it ("none" for no value there). Preference lists order them:
#   this.<base>         this site's value
#   others.<base>       every other enabled site's, in the fleet order, skipping sites named
#                       elsewhere in the list for that base
#   <base>              this.<base> then others.<base>
#   <firewall>.<base>   a named site's value
#   router / 0.0.0.0    the firewall's own address on the interface (DNS servers only)
# plus literal addresses, templates or host aliases (servers) and literal domains (search).
#
# Bases are passed as {lower name: {"name", "kind", "default", "values": {firewall pk: text}}}.

DOMAIN = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)
BASE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")
RESERVED_BASES = ("this", "others", "router")
LIST_KINDS = {"servers": "servers", "search": "domains"}


def preference_tokens(text):
    return [t.strip() for t in re.split(r"[,\s]+", text or "") if t.strip()]


def check_base_value(text, kind, aliases):
    """Problems with a base's default or per-site value; [] when it is valid."""
    problems = []
    tokens = preference_tokens(text)
    if [t.lower() for t in tokens] == ["none"]:
        return []
    for token in tokens:
        if kind == "servers":
            if token in aliases:
                continue
            try:
                if check_template(token) != 4:
                    problems.append(f"{token}: DHCP hands out IPv4 DNS servers only")
            except TemplateError:
                problems.append(f"{token} isn't an IPv4 address, template or host alias")
        elif not DOMAIN.match(token.rstrip(".")):
            problems.append(f"{token} isn't a domain name")
    return problems


def _base_reference(token, bases, firewall_names):
    """(scope, site name or None, base) for a base token, else None. scope: this|others|both|site."""
    lower = token.lower()
    if lower in bases:
        return "both", None, bases[lower]
    head, dot, tail = token.rpartition(".")
    if not dot or tail.lower() not in bases:
        return None
    base = bases[tail.lower()]
    if head.lower() in ("this", "others"):
        return head.lower(), None, base
    if head in firewall_names:
        return "site", head, base
    named = {name.lower(): name for name in firewall_names}
    if head.lower() in named:
        return "site", named[head.lower()], base
    return None


def check_preference(text, kind, firewall_names, aliases, bases):
    """Problems with a preference list (kind "servers" or "search"); [] when it is valid."""
    problems = []
    wanted = LIST_KINDS[kind]
    for token in preference_tokens(text):
        reference = _base_reference(token, bases, firewall_names)
        if reference:
            base = reference[2]
            if base["kind"] != wanted:
                other = "DNS servers" if base["kind"] == "servers" else "domains"
                problems.append(f"{token}: base {base['name']} holds {other}")
            continue
        head, dot, tail = token.rpartition(".")
        if dot and head.lower() in ("this", "others"):
            problems.append(f"{token}: there is no DNS base named {tail}")
            continue
        if kind == "servers":
            if token.lower() == "router" or token == ROUTER or token in aliases:
                continue
            try:
                if check_template(token) != 4:
                    problems.append(f"{token}: DHCP hands out IPv4 DNS servers only")
            except TemplateError:
                problems.append(f"{token} isn't a DNS base, address, template, host alias or router")
        elif not DOMAIN.match(token.rstrip(".")):
            problems.append(f"{token} isn't a DNS base or a domain name")
    return problems


def base_values(base, firewall, aliases):
    """A base's values at one site (its own value, else the default), resolved; and problems."""
    text = base["values"].get(firewall.pk)
    if text is None:
        text = base["default"]
    tokens = preference_tokens(text)
    if [t.lower() for t in tokens] == ["none"]:
        return [], []
    values, problems = [], []
    for token in tokens:
        if base["kind"] == "domains":
            values.append(token.rstrip("."))
            continue
        if token in aliases:
            for member in (m.strip() for m in aliases[token].splitlines() if m.strip()):
                try:
                    if ipaddress.ip_address(member).version == 4:
                        values.append(member)
                except ValueError:
                    problems.append(f"alias {token} member {member} is not a single address")
            continue
        try:
            if "x" in token.lower():
                site = site_prefix(firewall, 4)
                if site is None:
                    raise TemplateError(f"{firewall.name} has no IPv4 site prefix for {token} ({base['name']})")
                values.append(str(resolve_address(token, site)))
            else:
                values.append(str(ipaddress.ip_address(token)))
        except TemplateError as exc:
            problems.append(str(exc))
        except ValueError:
            problems.append(f"{token} isn't an IPv4 address ({base['name']})")
    return values, problems


def resolve_preference(text, kind, firewall, firewalls, aliases, bases, router=None):
    """An ordered, de-duplicated list for one site: [{"value", "source"}], and problems.

    `firewalls` is the fleet in display order (for others.<base> and <firewall>.<base>); `router` is
    the interface address that `router` / 0.0.0.0 stands for (None outside an interface context).
    """
    entries, problems, seen = [], [], set()
    named = {fw.name: fw for fw in firewalls}

    def add(value, source):
        if value and value.lower() not in seen:
            seen.add(value.lower())
            entries.append({"value": value, "source": source})

    def add_base(base, fw, source):
        values, issues = base_values(base, fw, aliases)
        problems.extend(issues)
        for value in values:
            add(value, source)

    tokens = preference_tokens(text)
    references = [(_base_reference(t, bases, named), t) for t in tokens]
    # Sites a list names for a base (this.ad, Cloud.ad) are left out of others.ad.
    claimed = {}
    for reference, _ in references:
        if reference and reference[0] in ("this", "both", "site"):
            site = firewall if reference[0] != "site" else named[reference[1]]
            claimed.setdefault(reference[2]["name"].lower(), set()).add(site.pk)
    for reference, token in references:
        lower = token.lower()
        if reference:
            scope, site_name, base = reference
            label = base["name"]
            if base["kind"] != LIST_KINDS[kind]:
                problems.append(f"{token}: base {label} holds other values")
                continue
            if scope in ("this", "both"):
                add_base(base, firewall, f"{label} · {firewall.name} (this site)")
            if scope == "site":
                add_base(base, named[site_name], f"{label} · {site_name}")
            if scope in ("others", "both"):
                for other in firewalls:
                    if other.enabled and other.pk != firewall.pk and other.pk not in claimed.get(label.lower(), set()):
                        add_base(base, other, f"{label} · {other.name}")
        elif kind == "servers" and (lower == "router" or token == ROUTER):
            if router is None:
                add("router", "the firewall on each interface")
            else:
                add(str(router), "the firewall on this interface")
        elif kind == "servers" and token in aliases:
            for member in (m.strip() for m in aliases[token].splitlines() if m.strip()):
                try:
                    if ipaddress.ip_address(member).version == 4:
                        add(member, f"alias {token}")
                except ValueError:
                    problems.append(f"alias {token} member {member} is not a single address")
        elif kind == "servers":
            try:
                site = site_prefix(firewall, 4) if "x" in lower else None
                address = resolve_address(token, site) if site else ipaddress.ip_address(token)
                add(str(address), "listed")
            except (TemplateError, ValueError):
                problems.append(f"{token} doesn't resolve to an IPv4 address at {firewall.name}")
        else:
            add(token.rstrip("."), "listed")
    return entries, problems


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


def scope_settings(scope, subnet, site, router, aliases, dns_context=None):
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
    preference = getattr(scope, "dns_preference", None)
    if preference is not None and dns_context is not None:
        firewall, firewalls, bases = dns_context
        servers, issues = resolve_preference(
            preference.dns_servers, "servers", firewall, firewalls, aliases, bases, router
        )
        problems += issues
        if preference.dns_servers:
            values = [entry["value"] for entry in servers]
            settings["options"].append({"code": 6, "name": OPTION_NAMES[6], "kind": "ip", "values": values})
        search, issues = resolve_preference(preference.search_domains, "search", firewall, firewalls, aliases, bases)
        problems += issues
        if search:
            domains = [entry["value"] for entry in search]
            settings["options"].append({"code": 119, "name": OPTION_NAMES[119], "kind": "domains", "values": domains})
            if not scope.domain_name:
                settings["options"].append({"code": 15, "name": "domain-name", "kind": "text", "values": domains[:1]})
    for code, text in ((6, scope.dns_servers if preference is None else ""), (42, scope.ntp_servers)):
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
        if option["kind"] in ("ip", "domains"):
            # dnsmasq encodes option 119 (domain-search) as RFC 3397 names itself.
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
        if option["kind"] in ("ip", "domains"):
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


def _format(components, family):
    if family == 4:
        return ".".join(components)
    # Compress the longest run of two or more zero hextets, as ipaddress does.
    best_start, best_length, start = -1, 1, None
    for index, value in enumerate([*components, "end"]):
        if value == "0":
            start = index if start is None else start
            continue
        if start is not None and index - start > best_length:
            best_start, best_length = start, index - start
        start = None
    if best_start < 0:
        return ":".join(components)
    head = ":".join(components[:best_start])
    tail = ":".join(components[best_start + best_length :])
    return f"{head}::{tail}"


def suggest_template(samples):
    """A template that reproduces every observed (site prefix, ip_interface) pair, or '' if none does.

    Parts entirely inside the site prefix become x (or stay literal for IPv4 when every site agrees);
    parts outside it must agree across sites. Used to prefill "Add plan" from current addresses.
    """
    if not samples:
        return ""
    family = samples[0][1].version
    if any(o.version != family or s.version != family or o.ip not in s for s, o in samples):
        return ""
    lengths = {o.network.prefixlen for _, o in samples}
    if len(lengths) != 1 or min(lengths) < max(s.prefixlen for s, _ in samples):
        return ""
    bits, count = (8, 4) if family == 4 else (16, 8)
    full = (1 << bits) - 1
    components = []
    for index in range(count):
        shift = (count - 1 - index) * bits
        values = [(int(o.ip) >> shift) & full for _, o in samples]
        site_masks = {(int(s.netmask) >> shift) & full for s, _ in samples}
        if len(site_masks) != 1:
            return ""
        site_mask = site_masks.pop()
        if site_mask == full:
            same = len(set(values)) == 1 and len(samples) > 1 and family == 4
            components.append(str(values[0]) if same else "x")
            continue
        rest = {value & ~site_mask & full for value in values}
        if len(rest) != 1:
            return ""
        value = rest.pop()
        components.append(str(value) if family == 4 else f"{value:x}")
    return f"{_format(components, family)}/{lengths.pop()}"


def _count(number):
    return f"{number:,}"


def describe_network(network, short=False):
    """One line about a subnet: usable range and size, as a subnet calculator shows it."""
    if short:
        if network.version == 6:
            return f"{network}" + (
                f" · {_count(2 ** (64 - network.prefixlen))} /64 networks" if network.prefixlen < 64 else ""
            )
        if network.prefixlen >= 31:
            return describe_network(network)
        return (
            f"usable {network.network_address + 1} – {network.broadcast_address - 1} "
            f"({_count(network.num_addresses - 2)} hosts)"
        )
    if network.version == 4:
        if network.prefixlen == 32:
            return f"Single address {network.network_address}"
        if network.prefixlen == 31:
            return f"Point-to-point: {network.network_address} – {network.broadcast_address} (2 addresses)"
        first, last = network.network_address + 1, network.broadcast_address - 1
        return (
            f"Usable {first} – {last} · {_count(network.num_addresses - 2)} hosts · "
            f"mask {network.netmask} · broadcast {network.broadcast_address}"
        )
    size = (
        f"{_count(network.num_addresses)} addresses"
        if network.prefixlen >= 96
        else f"2^{128 - network.prefixlen} addresses"
    )
    if network.prefixlen < 64:
        size += f" · {_count(2 ** (64 - network.prefixlen))} /64 networks"
    return f"Range {network.network_address} – {network.broadcast_address} · {size}"


def hint_lines(kind, value, firewalls=(), subnets=None, site_of=None):
    """Hint lines for a field value. kind: prefix, interface, template, range, pool or address.

    firewalls / subnets / site_of give the per-site context: subnets maps a firewall pk to that
    site's interface subnet (for ranges and addresses) and site_of(firewall, family) its prefix.
    Returns a list of {"label", "text", "error"} dicts.
    """
    value = (value or "").strip()
    if not value:
        return []
    if kind == "prefix":
        network = parse_site_prefix(value)
        return [{"label": "", "text": describe_network(network)}]
    if kind == "interface":
        try:
            interface = ipaddress.ip_interface(value)
        except ValueError:
            raise TemplateError(f"{value} is not an address with prefix length, e.g. 192.0.2.5/24.") from None
        return [{"label": "", "text": f"Network {interface.network} · " + describe_network(interface.network)}]
    lines = []
    if kind == "template":
        family = check_template(value, prefixed=True)
        for fw in firewalls:
            try:
                site = site_of(fw, family)
                if site is None:
                    lines.append({"label": fw.name, "text": f"no IPv{family} site prefix", "error": True})
                    continue
                interface = resolve_interface(value, site)
                lines.append(
                    {
                        "label": fw.name,
                        "text": f"{interface.network}, firewall {interface.ip}"
                        + (f" · {describe_network(interface.network, short=True)}" if family == 4 else ""),
                    }
                )
            except TemplateError as exc:
                lines.append({"label": fw.name, "text": str(exc), "error": True})
        return lines
    if kind in ("range", "pool"):
        check_range(value)
    for fw in firewalls:
        subnet = (subnets or {}).get(fw.pk)
        if subnet is None:
            continue
        if isinstance(subnet, str):
            lines.append({"label": fw.name, "text": subnet, "error": True})
            continue
        try:
            if kind in ("range", "pool"):
                first, last = resolve_range(value, subnet, site_of(fw, 4))
                lines.append(
                    {"label": fw.name, "text": f"{first} – {last} ({_count(range_size(first, last))} addresses)"}
                )
            else:
                address = ipaddress.ip_address(value)
                where = "inside" if address in subnet else "outside"
                lines.append({"label": fw.name, "text": f"{address} is {where} {subnet}", "error": where == "outside"})
        except (TemplateError, ValueError) as exc:
            lines.append({"label": fw.name, "text": str(exc), "error": True})
    return lines
