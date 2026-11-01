"""Deterministic, read-only reconciliation. Never contacts or changes a device."""
import ipaddress
import re
from .models import Alias, Rule, InterfaceGroup, Category

PREFIX = "[opnmanager:"
RULE_DEFAULTS = {"enabled": "1", "action": "pass", "direction": "in", "ipprotocol": "inet",
    "protocol": "any", "source_net": "any", "destination_net": "any", "source_port": "", "destination_port": "",
    "icmptype": "", "icmp6type": "", "categories": "", "log": "0", "quick": "1", "interfacenot": "0", "source_not": "0", "destination_not": "0"}

def validate_snapshot(data):
    if not isinstance(data, dict) or (type(data.get("schema_version")) is not int or data.get("schema_version") != 1):
        raise ValueError("Expected snapshot schema_version 1.")
    kinds = ["rules", "aliases"] + [k for k in ("interfaces", "groups", "categories") if k in data]
    for kind in kinds:
        if not isinstance(data.get(kind), list):
            raise ValueError(f"{kind} must be a list.")
        for row in data[kind]:
            if not isinstance(row, dict) or not all(isinstance(v, (str, int, bool)) for v in row.values()):
                raise ValueError(f"{kind} entries must contain scalar fields only.")
            required = {"rules": ("description", "interface", "sequence"), "aliases": ("name", "type", "content"), "interfaces": ("name", "label"), "groups": ("ifname", "members"), "categories": ("name",)}[kind]
            if any(key not in row for key in required):
                raise ValueError(f"{kind} entry missing required fields: {', '.join(required)}.")
    return {"schema_version": 1, **{kind: [{key: scalar(value) for key, value in row.items()} for row in data[kind]] for kind in kinds}}

def scalar(value):
    if isinstance(value, bool): return "1" if value else "0"
    return str(value).strip()

def canonical(row, fields, kind):
    defaults = RULE_DEFAULTS if kind == "rule" else {"enabled": "1", "description": ""}
    result = {key: scalar(row.get(key, defaults.get(key, ""))) for key in fields}
    if "color" in result: result["color"] = result["color"].lower()
    if kind == "alias" and "content" in result:
        result["content"] = "\n".join(sorted(set(filter(None, (s.strip() for s in result["content"].splitlines())))))
    for key in ("interface", "members", "categories", "icmptype", "icmp6type", "source_net", "destination_net"):
        if key in result: result[key] = ",".join(sorted(set(v.strip() for v in result[key].split(",") if v.strip())))
    if kind == "rule":
        if "protocol" in result: result["protocol"] = ",".join(sorted(set(p.strip().lower() for p in result["protocol"].split(","))))
        for port in ("source_port", "destination_port"):
            if result.get(port) == "any": result[port] = ""
    return result

def resolve_address(value, mappings):
    if "," in value: return ",".join(resolve_address(token.strip(), mappings) for token in value.split(","))
    if not value.startswith("@"): return value
    match = re.fullmatch(r"@([A-Za-z_][A-Za-z0-9_]*):(net|ip)", value)
    if not match or match[1] not in mappings:
        raise ValueError(f"Unmapped or invalid logical address {value}.")
    return mappings[match[1]] + ("ip" if match[2] == "ip" else "")

def plan_for(firewall, snapshot=None):
    snapshot = snapshot or firewall.snapshots.first()
    plan = {"firewall": firewall.name, "snapshot_id": snapshot.pk if snapshot else None,
            "observed_at": snapshot.created_at.isoformat() if snapshot else None,
            "errors": [], "items": [], "operations": [], "read_only": True}
    if not firewall.enabled:
        plan["errors"].append("Firewall is disabled; no synchronization planned.")
        return plan
    if not snapshot:
        plan["errors"].append("No snapshot. Import or pull current configuration first.")
        return plan
    data = validate_snapshot(snapshot.data)
    mappings = {m.logical_interface.name: m.device_interface for m in firewall.interface_mappings.select_related("logical_interface")}
    aliases = list(Alias.objects.all())
    alias_names = {a.name for a in aliases}
    desired_aliases = [a for a in aliases if a.applies_to(firewall)]
    available = {a.name for a in desired_aliases} | {a["name"] for a in data["aliases"] if a["name"] not in alias_names}
    expected = []
    for alias in desired_aliases:
        expected.append(("alias", alias.name, alias.name, {"name": alias.name, "type": alias.type,
            "content": alias.content, "description": alias.description, "enabled": str(int(alias.enabled))}))
        for member in alias.content.splitlines():
            member = member.strip()
            if not member: continue
            try:
                if alias.type == "port":
                    if member.isidentifier():
                        if member not in available: raise ValueError()
                    else:
                        ports = [int(p) for p in member.split(":")]
                        if not 1 <= len(ports) <= 2 or any(p < 1 or p > 65535 for p in ports) or ports[0] > ports[-1]: raise ValueError()
                elif member not in available:
                    ipaddress.ip_network(member, strict=False)
            except ValueError:
                plan["errors"].append(f"Alias {alias.name}: unresolved or invalid member {member} on this firewall.")
    # Alias cycles would produce invalid nested tables.
    graph = {a.name: [v.strip() for v in a.content.splitlines() if v.strip() in alias_names] for a in desired_aliases}
    def visit(name, path):
        if name in path:
            return True
        return any(visit(child, path | {name}) for child in graph.get(name, []))
    if any(visit(name, set()) for name in graph):
        plan["errors"].append("Alias dependency cycle detected.")
    for category in Category.objects.all():
        if not category.applies_to(firewall): continue
        if "categories" not in data:
            plan["errors"].append("Snapshot lacks categories. Pull a new snapshot before synchronization.")
        expected.append(("category", category.name, category.name, {"name": category.name, "color": category.color.lower()}))
    groups = {group.name: group for group in InterfaceGroup.objects.prefetch_related("members").all()}
    for group in groups.values():
        if not group.applies_to(firewall): continue
        if "groups" not in data: plan["errors"].append("Snapshot lacks interface groups. Pull a new snapshot before synchronization.")
        members = list(group.members.all())
        missing = [i.name for i in members if i.name not in mappings]
        if missing or not members:
            plan["errors"].append(f"Group {group.name}: missing members or mappings: {', '.join(missing)}.")
            continue
        if group.name in mappings.values():
            plan["errors"].append(f"Group {group.name} conflicts with a device interface name.")
        expected.append(("group", group.name, group.name, {"ifname": group.name,
            "members": ",".join(mappings[i.name] for i in members), "descr": group.description,
            "sequence": str(group.sequence), "nogroup": "0"}))
    category_ids = {row["name"]: row.get("uuid", "") for row in data.get("categories", [])}
    seen_sequences = set()
    for rule in Rule.objects.select_related("interface").prefetch_related("interfaces", "interface_groups", "categories", "origins").all():
        if not rule.applies_to(firewall): continue
        identity = str(rule.pk)
        marker = f"{PREFIX}{identity}]"
        try:
            bound = rule.bound_interfaces()
            missing = [i.name for i in bound if i.name not in mappings]
            if missing: raise ValueError(f"Rule {rule.name}: missing interface mapping for {', '.join(missing)}.")
            selected_groups = list(rule.interface_groups.all())
            for group in selected_groups:
                if not group.applies_to(firewall): raise ValueError(f"Rule {rule.name}: group {group.name} is excluded from this firewall.")
            bindings = sorted({mappings[i.name] for i in bound} | {g.name for g in selected_groups})
            if not bindings and not rule.floating: raise ValueError(f"Rule {rule.name}: choose interfaces, groups or floating placement.")
            for binding in bindings or ["__floating"]:
                key = (binding, rule.sequence)
                if key in seen_sequences: raise ValueError(f"Ambiguous sequence {rule.sequence} on {binding}.")
                seen_sequences.add(key)
            selected_categories = list(rule.categories.all())
            if any(not c.applies_to(firewall) for c in selected_categories):
                raise ValueError(f"Rule {rule.name}: a category is excluded from this firewall.")
            fields = {**RULE_DEFAULTS, "description": marker + " " + rule.name,
                "sequence": str(rule.sequence), "interface": ",".join(bindings),
                "enabled": str(int(rule.enabled)), "action": rule.action, "direction": rule.direction,
                "ipprotocol": rule.ip_version, "protocol": rule.protocol,
                "source_net": resolve_address(rule.source, mappings), "source_port": rule.source_port,
                "destination_net": resolve_address(rule.destination, mappings), "destination_port": rule.destination_port,
                "log": str(int(rule.log)), "quick": str(int(rule.quick)),
                "interfacenot": str(int(rule.interface_not)), "source_not": str(int(rule.source_not)), "destination_not": str(int(rule.destination_not)),
                "icmptype": rule.icmp_types, "icmp6type": rule.icmp6_types,
                "categories": ",".join(category_ids.get(c.name) or "@category:" + c.name for c in selected_categories)}
            for field in ("source_net", "destination_net", "source_port", "destination_port"):
                for value in fields[field].split(","):
                    if value in groups and not groups[value].applies_to(firewall):
                        raise ValueError(f"Rule {rule.name}: group {value} is excluded from this firewall.")
                    if value in alias_names and value not in available:
                        raise ValueError(f"Rule {rule.name}: alias {value} is excluded from this firewall.")
            expected.append(("rule", marker, rule.name, fields))
        except ValueError as exc:
            plan["errors"].append(str(exc))
    origin_uuids = {str(origin.rule_id): origin.remote_uuid for origin in firewall.ruleorigin_set.all()}
    matched = {"alias": set(), "rule": set(), "group": set(), "category": set()}
    collection = {"alias": "aliases", "rule": "rules", "group": "groups", "category": "categories"}
    for kind, identity, label, desired in expected:
        rows = data.get(collection[kind], [])
        def matches_identity(row):
            if kind != "rule": return row.get("ifname" if kind == "group" else "name") == identity
            description = row.get("description", "")
            rule_id = identity[len(PREFIX):-1]
            return description == identity or description.startswith(identity + " ") or (bool(row.get("uuid")) and row["uuid"] == origin_uuids.get(rule_id))
        matches = [(i, row) for i, row in enumerate(rows) if matches_identity(row)]
        item = {"kind": kind, "name": label, "status": "missing", "changes": [], "desired": desired, "actual": None}
        actual = None
        if len(matches) > 1:
            item["status"] = "conflict"
            plan["errors"].append(f"Duplicate {kind} identity: {label}.")
            matched[kind].update(i for i, r in matches)
        elif matches:
            index, actual = matches[0]
            matched[kind].add(index)
            item["actual"] = actual
            before = canonical(actual, desired, kind)
            after = canonical(desired, desired, kind)
            item["changes"] = [{"field": key, "actual": before[key], "desired": after[key]} for key in after if before[key] != after[key]]
            item["status"] = "changed" if item["changes"] else "in_sync"
        if item["status"] in ("missing", "changed"):
            plan["operations"].append({"kind": kind, "action": "create" if actual is None else "update",
                "remote_uuid": actual.get("uuid") if actual else None, "payload": desired})
        plan["items"].append(item)
    for kind, list_name in collection.items():
        rows = data.get(list_name, [])
        for index, row in enumerate(rows):
            if index in matched[kind]: continue
            managed = kind == "rule" and row.get("description", "").startswith(PREFIX)
            plan["items"].append({"kind": kind, "name": row.get("name", row.get("ifname", row.get("description", "Unnamed"))),
                "status": "out_of_scope" if managed else "local_only", "changes": [], "actual": row, "desired": None})
    # Never offer a partial plan when prerequisites fail.
    if plan["errors"]: plan["operations"] = []
    return plan
