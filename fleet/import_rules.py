"""Promote snapshot rules into manager policy without writing the source firewall."""

import ipaddress

from django.core.exceptions import ValidationError
from django.db import transaction

from .alias_patterns import compile_content
from .choices import ICMP6_TYPES, ICMP_TYPES, PORTS, protocol_choices
from .models import RULE_NAME_MAX, Alias, Category, InterfaceGroup, Rule, RuleOrigin
from .reconcile import RULE_DEFAULTS, canonical
from .rule_identity import is_managed, untagged

# Non-default behavior we cannot represent must never be silently discarded.
SUPPORTED = set(RULE_DEFAULTS) | {"uuid", "description", "interface", "sequence", "icmptype", "icmp6type"}
IGNORED = {"sort_order", "prio_group", "audit", "created", "updated", "category", "category_colors"}
SAFE_DEFAULTS = {
    "state-policy": "",
    "allowopts": "0",
    "tcpflags_any": "0",
    "max": "",
    "max-src-nodes": "",
    "max-src-conn": "",
    "max-src-states": "",
}

# OPNsense's labels for settings the manager can't represent, so errors say what to change.
UNSUPPORTED_LABELS = {
    "sched": "Schedule",
    "shaper1": "Traffic shaper",
    "shaper2": "Traffic shaper (reverse)",
    "tag": "Set local tag",
    "tagged": "Match local tag",
    "divert-to": "Divert to",
    "replyto": "Reply-to",
    "disablereplyto": "Disable reply-to",
    "nosync": "No XMLRPC sync",
    "nopfsync": "No pfsync",
    "state-policy": "State policy",
    "statetimeout": "State timeout",
    "udp-first": "UDP first timeout",
    "udp-multiple": "UDP multiple timeout",
    "udp-single": "UDP single timeout",
    "max": "Max states",
    "max-src-nodes": "Max source nodes",
    "max-src-states": "Max established states per host",
    "max-src-conn": "Max connections per host",
    "max-src-conn-rate": "Max new connections",
    "max-src-conn-rates": "Max new connections (seconds)",
    "max-pkt-rate-number": "Max packet rate",
    "max-pkt-rate-seconds": "Max packet rate (seconds)",
    "overload": "Overload table",
    "adaptivestart": "Adaptive timeouts start",
    "adaptiveend": "Adaptive timeouts end",
    "prio": "Match priority",
    "set-prio": "Set priority",
    "set-prio-low": "Set priority (low delay)",
    "tcpflags1": "TCP flags",
    "tcpflags2": "TCP flags out of",
    "tcpflags_any": "Any TCP flags",
    "tos": "Match TOS / DSCP",
    "allowopts": "Allow IP options",
    "scrub_no_df": "Normalization: clear DF",
    "scrub_random_id": "Normalization: random IP ID",
    "scrub_max_mss": "Normalization: max MSS",
    "scrub_min_ttl": "Normalization: min TTL",
    "scrub_set_tos": "Normalization: set TOS",
}
# Network values that exist on every OPNsense firewall.
BUILTIN_NETWORKS = {"any", "(self)", "bogons", "bogonsv6"}


def is_address(token):
    """An IP, CIDR or from-to range, as OPNsense's network field accepts."""
    for part in token.split("-", 1):
        try:
            ipaddress.ip_network(part, strict=False)
        except ValueError:
            return False
    return True


def tokens(value):
    return [v.strip() for v in value.split(",") if v.strip()]


@transaction.atomic
def import_rules(snapshot, indices, scope, targets, firewall_groups=()):
    firewall = snapshot.firewall
    if firewall.snapshots.first().pk != snapshot.pk:
        raise ValidationError("A newer snapshot exists. Refresh the rules page before importing.")
    mappings = {
        m.device_interface: m.logical_interface for m in firewall.interface_mappings.select_related("logical_interface")
    }
    source_groups = {r["ifname"]: r for r in snapshot.data.get("groups", [])}
    source_categories = {r["uuid"]: r for r in snapshot.data.get("categories", []) if r.get("uuid")}
    source_aliases = {r["name"]: r for r in snapshot.data["aliases"]}

    def apply_scope(obj):
        obj.scope = scope
        obj.save()
        obj.firewalls.set(targets)
        obj.firewall_groups.set(firewall_groups)

    def import_alias(name, stack=()):
        if name not in source_aliases:
            return
        if name in stack:
            raise ValidationError(f"Alias cycle at {name}.")
        row = source_aliases[name]
        if row["type"] not in {"host", "network", "port"}:
            raise ValidationError(f"Alias {name} has an unsupported type.")
        for member in row["content"].splitlines():
            import_alias(member.strip(), stack + (name,))
        existing = Alias.objects.filter(name=name).first()
        if existing:
            row = source_aliases[name]
            fields = {
                "type": existing.type,
                "content": compile_content(
                    existing.content, existing.type, Alias.objects.values_list("name", flat=True)
                ),
                "enabled": str(int(existing.enabled)),
            }
            if canonical(fields, fields, "alias") != canonical(row, fields, "alias"):
                raise ValidationError(
                    f"Alias {name} conflicts with an existing manager definition. Reconcile it before importing."
                )
            return
        alias = Alias(
            name=name,
            type=row["type"],
            content=row["content"],
            description=untagged(row.get("description", "")),
            enabled=row.get("enabled", "1") == "1",
        )
        alias.full_clean()
        apply_scope(alias)

    def ensure_group(local):
        source = source_groups[local]
        if source.get("nogroup", "0") not in ("", "0"):
            raise ValidationError("Import of groups with nogroup behavior is unsupported.")
        members = tokens(source["members"])
        if any(m not in mappings for m in members):
            raise ValidationError(f"Map every member of group {local} before importing.")
        group = InterfaceGroup.objects.filter(name=local).first()
        member_ids = {mappings[m].pk for m in members}
        if group:
            if set(group.members.values_list("pk", flat=True)) != member_ids:
                raise ValidationError(
                    f"Group {local} conflicts with an existing manager definition. Reconcile it before importing."
                )
            return group
        group = InterfaceGroup(
            name=local, description=source.get("descr", ""), sequence=int(source.get("sequence") or 0), scope=scope
        )
        group.full_clean()
        group.save()
        group.members.set(member_ids)
        group.firewalls.set(targets)
        group.firewall_groups.set(firewall_groups)
        return group

    interface_labels = {r["name"]: r.get("label") or r["name"] for r in snapshot.data.get("interfaces", [])}
    protocols = {value.lower(): value for value, _ in protocol_choices()}
    port_names = {name for name, _ in PORTS}

    def unmapped(local):
        label = interface_labels.get(local)
        named = f"{local} ({label})" if label and label != local else local
        return ValidationError(
            f"interface {named} isn't mapped on {firewall.name}. Map it under Interfaces: Overview first."
        )

    def import_rule(row):
        uid = row.get("uuid")
        if not uid:
            raise ValidationError("it has no UUID. Pull a live snapshot from the firewall and try again.")
        origin = RuleOrigin.objects.filter(firewall=firewall, remote_uuid=uid).first()
        if origin:
            return origin.rule
        if is_managed(row.get("description", "")):
            raise ValidationError("it already carries a manager tag; edit the existing manager rule instead.")
        # Keys starting with "%" are OPNsense's display labels (e.g. "%source_net": "LAN net"), not settings.
        unsupported = sorted(
            {
                UNSUPPORTED_LABELS.get(k, k)
                for k, v in row.items()
                if not k.startswith(("%", "alias_meta_"))
                and k not in SUPPORTED | IGNORED
                and v not in ("", "0", SAFE_DEFAULTS.get(k, ""))
            }
        )
        if unsupported:
            raise ValidationError(
                "it uses settings the manager can't keep: " + ", ".join(unsupported) + ". Remove them on the "
                "firewall and pull again, or leave this rule device-local."
            )
        description = row.get("description") or "Imported rule"
        if len(description) > RULE_NAME_MAX:
            raise ValidationError(
                f"its description is {len(description)} characters. The manager adds an 18-character tag, "
                f"so shorten it to {RULE_NAME_MAX} on the firewall and pull again."
            )
        interfaces, groups = [], []
        for local in tokens(row.get("interface", "")):
            if local in mappings:
                interfaces.append(mappings[local])
            elif local in source_groups:
                groups.append(ensure_group(local))
            else:
                raise unmapped(local)

        def address(value):
            result = []
            for token in tokens(value):
                if token in mappings:
                    token = "@" + mappings[token].name + ":net"
                elif token.endswith("ip") and token[:-2] in mappings:
                    token = "@" + mappings[token[:-2]].name + ":ip"
                elif token in source_groups:
                    ensure_group(token)
                elif token in source_aliases:
                    import_alias(token)
                elif token in interface_labels or (token.endswith("ip") and token[:-2] in interface_labels):
                    raise unmapped(token if token in interface_labels else token[:-2])
                elif not (token in BUILTIN_NETWORKS or is_address(token) or Alias.objects.filter(name=token).exists()):
                    raise ValidationError(
                        f"it refers to {token}, which isn't an alias, interface or address in the snapshot. "
                        "Pull a fresh snapshot and try again."
                    )
                result.append(token)
            return ",".join(result)

        protocol_values = []
        for value in tokens(row.get("protocol", "any")):
            if value.lower() not in protocols:
                raise ValidationError(
                    f"its protocol {value} isn't in the manager's protocol list. Refresh the firewall on "
                    "Interfaces: Overview to load its protocols, then import again."
                )
            protocol_values.append(protocols[value.lower()])
        values = {
            "name": description,
            "sequence": int(row["sequence"]),
            "protocol": ",".join(protocol_values),
            "scope": scope,
            "floating": len(interfaces) + len(groups) != 1,
            "ip_version": row.get("ipprotocol", "inet"),
            "source": address(row.get("source_net", "any")),
            "destination": address(row.get("destination_net", "any")),
            "icmp_types": row.get("icmptype", ""),
            "icmp6_types": row.get("icmp6type", ""),
            "state_type": row.get("statetype") or "keep",
            "gateway": row.get("gateway", ""),
        }
        if any(v not in dict(ICMP_TYPES) for v in tokens(values["icmp_types"])) or any(
            v not in dict(ICMP6_TYPES) for v in tokens(values["icmp6_types"])
        ):
            raise ValidationError("it uses an ICMP type the manager doesn't know.")
        for key in ("action", "direction", "source_port", "destination_port"):
            values[key] = row.get(key, RULE_DEFAULTS[key])
            if key in ("source_port", "destination_port") and values[key] == "any":
                values[key] = ""
        for field in ("source_port", "destination_port"):
            port = values[field]
            if port in source_aliases:
                import_alias(port)
            elif port and not (port in port_names or Alias.objects.filter(name=port, type="port").exists()):
                low, _, high = port.partition("-")
                if not all(part.isdigit() for part in (low, high or low)):
                    raise ValidationError(f"its port {port} isn't a port, range or port alias in the snapshot.")
        for key, source_key in [
            ("enabled", "enabled"),
            ("quick", "quick"),
            ("log", "log"),
            ("source_not", "source_not"),
            ("destination_not", "destination_not"),
            ("interface_not", "interfacenot"),
            ("origin_not", "received-on-not"),
        ]:
            values[key] = row.get(source_key, RULE_DEFAULTS[source_key]) == "1"
        origin_interfaces, origin_groups = [], []
        for local in tokens(row.get("received-on", "")):
            if local in mappings:
                origin_interfaces.append(mappings[local])
            elif local in source_groups:
                origin_groups.append(ensure_group(local))
            else:
                raise unmapped(local)
        categories = []
        for category_id in tokens(row.get("categories", "")):
            if category_id not in source_categories:
                raise ValidationError("its categories aren't in the snapshot. Pull a fresh snapshot.")
            category_row = source_categories[category_id]
            category, created = Category.objects.get_or_create(
                name=category_row["name"], defaults={"color": category_row.get("color") or "137b66", "scope": scope}
            )
            if created:
                category.full_clean()
                category.firewalls.set(targets)
                category.firewall_groups.set(firewall_groups)
            categories.append(category)
        rule = Rule(**values)
        rule.full_clean()
        rule.save()
        rule.interfaces.set(interfaces)
        rule.interface_groups.set(groups)
        rule.origin_interfaces.set(origin_interfaces)
        rule.origin_interface_groups.set(origin_groups)
        rule.categories.set(categories)
        rule.firewalls.set(targets)
        rule.firewall_groups.set(firewall_groups)
        RuleOrigin.objects.create(firewall=firewall, rule=rule, remote_uuid=uid)
        return rule

    # Check every selected rule and report all problems at once; save nothing unless all import.
    imported, problems = [], []
    for index in indices:
        row = snapshot.data["rules"][int(index)]
        label = row.get("description") or row.get("uuid") or f"rule {int(index) + 1}"
        try:
            with transaction.atomic():
                imported.append(import_rule(row))
        except ValidationError as exc:
            problems += [f"“{label}”: {message}" for message in exc.messages]
        except (KeyError, ValueError):
            problems.append(f"“{label}”: its snapshot data is incomplete. Pull a fresh snapshot.")
    if problems:
        raise ValidationError(problems)
    return imported
