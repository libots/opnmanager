"""Promote snapshot rules into manager policy without writing the source firewall."""
from django.core.exceptions import ValidationError
from django.db import transaction
from .models import Rule, RuleOrigin, Alias, Category, InterfaceGroup
from .reconcile import RULE_DEFAULTS, PREFIX, canonical
from .choices import ICMP_TYPES, ICMP6_TYPES
from .alias_patterns import compile_content

# Non-default behavior we cannot represent must never be silently discarded.
SUPPORTED = set(RULE_DEFAULTS) | {"uuid", "description", "interface", "sequence", "icmptype", "icmp6type"}
IGNORED = {"sort_order", "prio_group", "audit", "created", "updated", "category", "category_colors"}
SAFE_DEFAULTS = {"statetype": "keep", "state-policy": "", "allowopts": "0", "tcpflags_any": "0", "max": "", "max-src-nodes": "", "max-src-conn": "", "max-src-states": ""}


def tokens(value): return [v.strip() for v in value.split(",") if v.strip()]


@transaction.atomic
def import_rules(snapshot, indices, scope, targets, firewall_groups=()):
    firewall = snapshot.firewall
    if firewall.snapshots.first().pk != snapshot.pk:
        raise ValidationError("A newer snapshot exists. Refresh the rules page before importing.")
    mappings = {m.device_interface: m.logical_interface for m in firewall.interface_mappings.select_related("logical_interface")}
    source_groups = {r["ifname"]: r for r in snapshot.data.get("groups", [])}
    source_categories = {r["uuid"]: r for r in snapshot.data.get("categories", []) if r.get("uuid")}
    source_aliases = {r["name"]: r for r in snapshot.data["aliases"]}
    def apply_scope(obj):
        obj.scope = scope; obj.save(); obj.firewalls.set(targets); obj.firewall_groups.set(firewall_groups)
    def import_alias(name, stack=()):
        if name not in source_aliases: return
        if name in stack: raise ValidationError(f"Alias cycle at {name}.")
        row = source_aliases[name]
        if row["type"] not in {"host", "network", "port"}: raise ValidationError(f"Alias {name} has an unsupported type.")
        for member in row["content"].splitlines(): import_alias(member.strip(), stack + (name,))
        existing = Alias.objects.filter(name=name).first()
        if existing:
            row = source_aliases[name]
            fields = {"type": existing.type, "content": compile_content(existing.content, existing.type, Alias.objects.values_list("name", flat=True)), "enabled": str(int(existing.enabled))}
            if canonical(fields, fields, "alias") != canonical(row, fields, "alias"):
                raise ValidationError(f"Alias {name} conflicts with an existing manager definition. Reconcile it before importing.")
            return
        alias = Alias(name=name, type=row["type"], content=row["content"], description=row.get("description", ""), enabled=row.get("enabled", "1") == "1")
        alias.full_clean(); apply_scope(alias)
    def ensure_group(local):
        source = source_groups[local]
        if source.get("nogroup", "0") not in ("", "0"): raise ValidationError("Import of groups with nogroup behavior is unsupported.")
        members = tokens(source["members"])
        if any(m not in mappings for m in members): raise ValidationError(f"Map every member of group {local} before importing.")
        group = InterfaceGroup.objects.filter(name=local).first()
        member_ids = {mappings[m].pk for m in members}
        if group:
            if set(group.members.values_list("pk", flat=True)) != member_ids:
                raise ValidationError(f"Group {local} conflicts with an existing manager definition. Reconcile it before importing.")
            return group
        group = InterfaceGroup(name=local, description=source.get("descr", ""), sequence=int(source.get("sequence") or 0), scope=scope)
        group.full_clean(); group.save(); group.members.set(member_ids); group.firewalls.set(targets); group.firewall_groups.set(firewall_groups)
        return group
    imported = []
    for index in indices:
        row = snapshot.data["rules"][int(index)]
        uid = row.get("uuid")
        if not uid: raise ValidationError("Import requires rule UUIDs. Pull a live snapshot or include UUIDs in the import.")
        origin = RuleOrigin.objects.filter(firewall=firewall, remote_uuid=uid).first()
        if origin:
            imported.append(origin.rule)
            continue
        if row.get("description", "").startswith(PREFIX):
            raise ValidationError("This rule already carries a manager identity; edit the existing manager rule instead.")
        unsupported = [k for k, v in row.items() if k not in SUPPORTED | IGNORED and not k.startswith("alias_meta_") and v not in ("", "0", SAFE_DEFAULTS.get(k, ""))]
        if unsupported: raise ValidationError("Cannot import without losing behavior: " + ", ".join(sorted(unsupported)))
        interfaces, groups = [], []
        for local in tokens(row["interface"]):
            if local in mappings: interfaces.append(mappings[local]); continue
            if local not in source_groups: raise ValidationError(f"Map interface {local} before importing this rule.")
            groups.append(ensure_group(local))
        def address(value):
            result = []
            for token in tokens(value):
                if token in mappings: token = "@" + mappings[token].name + ":net"
                elif token.endswith("ip") and token[:-2] in mappings: token = "@" + mappings[token[:-2]].name + ":ip"
                elif token in source_groups: ensure_group(token)
                else: import_alias(token)
                result.append(token)
            return ",".join(result)
        protocol = row.get("protocol", "any")
        protocol_names = {"tcp": "TCP", "udp": "UDP", "tcp/udp": "TCP/UDP", "icmp": "ICMP", "ipv6-icmp": "IPv6-ICMP", "icmp6": "IPv6-ICMP"}
        protocol = ",".join(protocol_names.get(value.lower(), value) for value in tokens(protocol))
        values = {"name": (row.get("description") or "Imported rule")[:150], "sequence": int(row["sequence"]),
            "protocol": protocol, "scope": scope, "floating": len(interfaces) + len(groups) != 1,
            "ip_version": row.get("ipprotocol", "inet"), "source": address(row.get("source_net", "any")),
            "destination": address(row.get("destination_net", "any")), "icmp_types": row.get("icmptype", ""), "icmp6_types": row.get("icmp6type", "")}
        if any(v not in dict(ICMP_TYPES) for v in tokens(values["icmp_types"])) or any(v not in dict(ICMP6_TYPES) for v in tokens(values["icmp6_types"])):
            raise ValidationError("This rule contains an unsupported ICMP type.")
        for key in ("action", "direction", "source_port", "destination_port"):
            values[key] = row.get(key, RULE_DEFAULTS[key])
            if key in ("source_port", "destination_port") and values[key] == "any": values[key] = ""
        for key, source_key in [("enabled", "enabled"), ("quick", "quick"), ("log", "log"), ("source_not", "source_not"), ("destination_not", "destination_not"), ("interface_not", "interfacenot")]:
            values[key] = row.get(source_key, RULE_DEFAULTS[source_key]) == "1"
        for field in ("source_port", "destination_port"): import_alias(values[field])
        rule = Rule(**values); rule.full_clean(); rule.save()
        rule.interfaces.set(interfaces); rule.interface_groups.set(groups); rule.firewalls.set(targets); rule.firewall_groups.set(firewall_groups)
        for category_id in tokens(row.get("categories", "")):
            if category_id not in source_categories: raise ValidationError("Category inventory is missing. Pull a fresh snapshot.")
            category_row = source_categories[category_id]
            category, created = Category.objects.get_or_create(name=category_row["name"], defaults={"color": category_row.get("color") or "137b66", "scope": scope})
            if created:
                category.full_clean(); category.firewalls.set(targets); category.firewall_groups.set(firewall_groups)
            rule.categories.add(category)
        for local in tokens(row.get('received-on','')):
            if local in mappings: rule.origin_interfaces.add(mappings[local])
            elif local in source_groups: rule.origin_interface_groups.add(ensure_group(local))
            else: raise ValidationError(f'Map origin interface {local} before importing.')
        if row.get('received-on-not','0') not in ('','0'): raise ValidationError('Inverted origin interfaces are not supported.')
        RuleOrigin.objects.create(firewall=firewall, rule=rule, remote_uuid=uid)
        imported.append(rule)
    return imported
