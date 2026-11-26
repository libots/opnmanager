"""Deterministic, read-only reconciliation. Never contacts or changes a device."""

import re
from collections import Counter

from .alias_patterns import compile_content
from .models import Alias, Category, InterfaceGroup, Rule, ScopedPolicy
from .rule_identity import is_managed, marker_of, short_marker, tagged
from .rule_identity import matches as matches_rule

RULE_DEFAULTS = {
    "enabled": "1",
    "action": "pass",
    "direction": "in",
    "ipprotocol": "inet",
    "protocol": "any",
    "source_net": "any",
    "destination_net": "any",
    "source_port": "",
    "destination_port": "",
    "received-on": "",
    "received-on-not": "0",
    "icmptype": "",
    "icmp6type": "",
    "categories": "",
    "log": "0",
    "quick": "1",
    "interfacenot": "0",
    "source_not": "0",
    "destination_not": "0",
    "statetype": "keep",
    "gateway": "",
}


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
            required = {
                "rules": ("description", "interface", "sequence"),
                "aliases": ("name", "type", "content"),
                "interfaces": ("name", "label"),
                "groups": ("ifname", "members"),
                "categories": ("name",),
            }[kind]
            if any(key not in row for key in required):
                raise ValueError(f"{kind} entry missing required fields: {', '.join(required)}.")
    return {
        "schema_version": 1,
        **{kind: [{key: scalar(value) for key, value in row.items()} for row in data[kind]] for kind in kinds},
    }


def scalar(value):
    if isinstance(value, bool):
        return "1" if value else "0"
    return str(value).strip()


def canonical(row, fields, kind):
    defaults = RULE_DEFAULTS if kind == "rule" else {"enabled": "1", "description": ""}
    result = {key: scalar(row.get(key, defaults.get(key, ""))) for key in fields}
    if "color" in result:
        result["color"] = result["color"].lower()
    if kind == "alias" and "content" in result:
        result["content"] = "\n".join(sorted(set(filter(None, (s.strip() for s in result["content"].splitlines())))))
    for key in ("interface", "members", "categories", "icmptype", "icmp6type", "source_net", "destination_net"):
        if key in result:
            result[key] = ",".join(sorted(set(v.strip() for v in result[key].split(",") if v.strip())))
    if kind == "rule":
        if "protocol" in result:
            result["protocol"] = ",".join(sorted(set(p.strip().lower() for p in result["protocol"].split(","))))
        for port in ("source_port", "destination_port"):
            if result.get(port) == "any":
                result[port] = ""
    return result


# Fields always listed when reviewing a new rule, so its placement and match are visible.
REVIEW_FIELDS = {"description", "interface", "sequence", "action", "protocol", "source_net", "destination_net"}


def field_changes(actual, desired, kind):
    """Fields a push writes, as {field, actual, desired}, for a compact review.

    For an update only the fields that differ are listed. For a create every field
    with a meaningful value is listed (defaults and empty values are left out).
    """
    after = canonical(desired, desired, kind)
    if actual is None:
        defaults = RULE_DEFAULTS if kind == "rule" else {"enabled": "1"}
        return [
            {"field": key, "actual": "", "desired": value}
            for key, value in sorted(after.items())
            if key in REVIEW_FIELDS or (value and value != defaults.get(key))
        ]
    before = canonical(actual, desired, kind)
    return [
        {"field": key, "actual": before[key], "desired": after[key]}
        for key in sorted(after)
        if before[key] != after[key]
    ]


ADDRESS_TOKEN = re.compile(r"@([A-Za-z_][A-Za-z0-9_]*):(net|ip)")


def resolve_addresses(*values, mappings):
    """Resolve logical @Interface:net/ip tokens in each value.

    Tokens for interfaces that aren't mapped on this firewall are left out, the
    same way unmapped rule interfaces are: that network doesn't exist here.
    Returns (resolved values, left-out tokens, emptied) where emptied is True when
    some value lost every token, so pushing it would widen the rule to "any".
    Malformed tokens still raise ValueError.
    """
    resolved, missing, emptied = [], [], False
    for value in values:
        kept = []
        tokens = [t.strip() for t in value.split(",") if t.strip()]
        for token in tokens:
            if not token.startswith("@"):
                kept.append(token)
                continue
            match = ADDRESS_TOKEN.fullmatch(token)
            if not match:
                raise ValueError(f"Invalid logical address {token}.")
            if match[1] not in mappings:
                missing.append(token)
                continue
            kept.append(mappings[match[1]] + ("ip" if match[2] == "ip" else ""))
        emptied = emptied or bool(tokens and not kept)
        resolved.append(",".join(kept))
    return resolved, list(dict.fromkeys(missing)), emptied


def _tagged_matches(uid, name, rows, owned_markers, name_key="name", description_key="description"):
    """Device rows for one manager alias or group: by its tag, else an untagged (or orphan-tagged) row of that name."""
    by_tag = [(i, row) for i, row in enumerate(rows) if matches_rule(row.get(description_key, ""), uid)]
    if by_tag:
        return by_tag
    claimed = owned_markers - {short_marker(uid)}
    return [
        (i, row)
        for i, row in enumerate(rows)
        if row.get(name_key) == name and marker_of(row.get(description_key, "")) not in claimed
    ]


def _alias_matches(alias_uid, name, rows, owned_markers):
    return _tagged_matches(alias_uid, name, rows, owned_markers)


def _group_matches(group_uid, name, rows, owned_markers):
    return _tagged_matches(group_uid, name, rows, owned_markers, name_key="ifname", description_key="descr")


def _matches_identity(kind, identity, row, origin_uuids):
    if kind != "rule":
        return row.get("ifname" if kind == "group" else "name") == identity
    description = row.get("description", "")
    return matches_rule(description, identity) or (bool(row.get("uuid")) and row["uuid"] == origin_uuids.get(identity))


class Policy:
    """All manager definitions, loaded once with their scopes prefetched.

    Planning used to re-query every alias, group, category and rule (plus two
    scope queries per object) on each call. Build one Policy and pass it to
    every plan_for call that should see the same manager state.
    """

    def __init__(self):
        scope = ScopedPolicy.SCOPE_PREFETCH
        self.aliases = list(Alias.objects.prefetch_related(*scope))
        self.alias_names = {a.name for a in self.aliases}
        self.aliases_by_name = {a.name: a for a in self.aliases}
        self.alias_markers = {short_marker(a.uid) for a in self.aliases}
        self.categories = list(Category.objects.prefetch_related(*scope))
        self.categories_by_pk = {c.pk: c for c in self.categories}
        self.groups = {g.name: g for g in InterfaceGroup.objects.prefetch_related("members", *scope)}
        self.groups_by_pk = {g.pk: g for g in self.groups.values()}
        self.group_markers = {short_marker(g.uid) for g in self.groups.values()}
        self.rules = list(
            Rule.objects.prefetch_related(
                "interfaces",
                "interface_groups",
                "categories",
                "origin_interfaces",
                "origin_interface_groups",
                *scope,
            )
        )
        self.marker_counts = Counter(short_marker(rule.pk) for rule in self.rules)
        self._firewalls = {}

    def firewall_state(self, firewall, snapshot):
        """Validated snapshot data, interface mappings and adopted rule UUIDs for one firewall."""
        key = (firewall.pk, snapshot.pk)
        if key not in self._firewalls:
            self._firewalls[key] = (
                validate_snapshot(snapshot.data),
                {
                    m.logical_interface.name: m.device_interface
                    for m in firewall.interface_mappings.select_related("logical_interface")
                },
                {str(origin.rule_id): origin.remote_uuid for origin in firewall.ruleorigin_set.all()},
            )
        return self._firewalls[key]


def _available_bindings(rule, label, interfaces, groups, mappings, group_problems, warnings):
    """Leave out interfaces and groups that don't exist on this firewall, with a warning.

    Dropping them keeps the rule's meaning on this firewall, since traffic can't
    arrive on an interface it doesn't have. If every binding is missing, the rule
    is skipped here instead: an empty list would widen it to all interfaces.
    group_problems maps each group that doesn't exist here to the reason.
    Returns (interfaces, groups, skipped).
    """
    reasons = [f"interface {i.name} is not mapped on this firewall" for i in interfaces if i.name not in mappings]
    reasons += [f"group {g.name} {group_problems[g.name]}" for g in groups if g.name in group_problems]
    if not reasons:
        return interfaces, groups, False
    kept_interfaces = [i for i in interfaces if i.name in mappings]
    kept_groups = [g for g in groups if g.name not in group_problems]
    because = "; ".join(sorted(reasons))
    if not kept_interfaces and not kept_groups:
        warnings.append(f"Rule {rule.name} is not pushed to this firewall. None of its {label} exist here: {because}.")
        return kept_interfaces, kept_groups, True
    warnings.append(f"Rule {rule.name}: some {label} are left out of the pushed rule: {because}.")
    return kept_interfaces, kept_groups, False


def plan_for(firewall, snapshot=None, *, rule_ids=None, definition_names=None, policy=None):
    snapshot = snapshot or firewall.snapshots.first()
    plan = {
        "firewall": firewall.name,
        "snapshot_id": snapshot.pk if snapshot else None,
        "observed_at": snapshot.created_at.isoformat() if snapshot else None,
        "errors": [],
        # Warnings never block operations; the deploy review asks to acknowledge them.
        "warnings": [],
        "items": [],
        "operations": [],
        "read_only": True,
    }
    if not firewall.enabled:
        plan["errors"].append("Firewall is disabled; no synchronization planned.")
        return plan
    if not snapshot:
        plan["errors"].append("No snapshot. Import or pull current configuration first.")
        return plan
    policy = policy or Policy()
    data, mappings, origin_uuids = policy.firewall_state(firewall, snapshot)
    aliases = policy.aliases
    alias_names = policy.alias_names
    desired_aliases = [
        a
        for a in aliases
        if a.applies_to(firewall) and (definition_names is None or a.name in definition_names["alias"])
    ]
    # Device-local aliases rules may use; tagged ones belong to the manager, current or deleted.
    available = {a.name for a in desired_aliases} | {
        a["name"] for a in data["aliases"] if a["name"] not in alias_names and not is_managed(a.get("description", ""))
    }
    expected = []
    for alias in desired_aliases:
        try:
            excluded = [
                member.strip()
                for member in alias.content.splitlines()
                if member.strip() in alias_names and member.strip() not in available
            ]
            if excluded:
                raise ValueError("Referenced aliases are excluded from this firewall: " + ", ".join(excluded))
            compiled = compile_content(alias.content, alias.type, available)
            expected.append(
                (
                    "alias",
                    str(alias.uid),
                    alias.name,
                    {
                        "name": alias.name,
                        "type": alias.type,
                        "content": compiled,
                        "description": tagged(alias.description, alias.uid),
                        "enabled": str(int(alias.enabled)),
                    },
                )
            )
        except ValueError as exc:
            plan["errors"].append(f"Alias {alias.name}: {exc}")
    # Alias cycles would produce invalid nested tables.
    graph = {a.name: [v.strip() for v in a.content.splitlines() if v.strip() in alias_names] for a in desired_aliases}

    def visit(name, path):
        if name in path:
            return True
        return any(visit(child, path | {name}) for child in graph.get(name, []))

    if any(visit(name, set()) for name in graph):
        plan["errors"].append("Alias dependency cycle detected.")
    for category in policy.categories:
        if definition_names is not None and category.name not in definition_names["category"]:
            continue
        if not category.applies_to(firewall):
            continue
        if "categories" not in data:
            plan["errors"].append("Snapshot lacks categories. Pull a new snapshot before synchronization.")
        expected.append(
            ("category", category.name, category.name, {"name": category.name, "color": category.color.lower()})
        )
    groups = policy.groups
    # Interfaces can exist on only some firewalls. A group that doesn't target this
    # firewall, or has no member mapped here, doesn't exist here: it isn't created,
    # and rules bound to it leave it out.
    group_problems = {}
    for g in groups.values():
        if not g.applies_to(firewall):
            group_problems[g.name] = f"is not deployed to {firewall.name}: its targets don't include this firewall"
        elif not any(i.name in mappings for i in g.members.all()):
            group_problems[g.name] = "has no members mapped on this firewall"
    for group in groups.values():
        if definition_names is not None and group.name not in definition_names["group"]:
            continue
        if not group.applies_to(firewall):
            continue
        if "groups" not in data:
            plan["errors"].append("Snapshot lacks interface groups. Pull a new snapshot before synchronization.")
        members = [i for i in group.members.all() if i.name in mappings]
        if not members:
            plan["warnings"].append(
                f"Group {group.name} has no members mapped on this firewall, so it is not created here."
            )
            continue
        if group.name in mappings.values():
            plan["errors"].append(f"Group {group.name} conflicts with a device interface name.")
        expected.append(
            (
                "group",
                str(group.uid),
                group.name,
                {
                    "ifname": group.name,
                    "members": ",".join(mappings[i.name] for i in members),
                    "descr": tagged(group.description, group.uid),
                    "sequence": str(group.sequence),
                    "nogroup": str(int(group.no_gui_group)),
                },
            )
        )
    category_ids = {row["name"]: row.get("uuid", "") for row in data.get("categories", [])}
    marker_counts = policy.marker_counts
    seen_sequences = set()
    for rule in policy.rules:
        if rule_ids is not None and str(rule.pk) not in rule_ids:
            continue
        if not rule.applies_to(firewall):
            continue
        identity = str(rule.pk)
        marker = short_marker(rule.pk)
        try:
            if marker_counts[marker] > 1:
                raise ValueError(
                    f"Short rule identity collision for {marker}. Resolve the duplicate UUID prefix before deployment."
                )
            bound = rule.bound_interfaces()
            selected_groups = [policy.groups_by_pk[g.pk] for g in rule.interface_groups.all()]
            bound, selected_groups, skipped = _available_bindings(
                rule, "interfaces", bound, selected_groups, mappings, group_problems, plan["warnings"]
            )
            if skipped:
                continue
            bindings = sorted({mappings[i.name] for i in bound} | {g.name for g in selected_groups})
            if not bindings and not rule.floating:
                raise ValueError(f"Rule {rule.name}: choose interfaces, groups or floating placement.")
            for binding in bindings or ["__floating"]:
                key = (binding, rule.sequence)
                if key in seen_sequences:
                    raise ValueError(f"Ambiguous sequence {rule.sequence} on {binding}.")
                seen_sequences.add(key)
            selected_categories = [policy.categories_by_pk[c.pk] for c in rule.categories.all()]
            if any(not c.applies_to(firewall) for c in selected_categories):
                raise ValueError(f"Rule {rule.name}: a category is excluded from this firewall.")
            origins = list(rule.origin_interfaces.all())
            origin_groups = [policy.groups_by_pk[g.pk] for g in rule.origin_interface_groups.all()]
            origins, origin_groups, skipped = _available_bindings(
                rule, "origin interfaces", origins, origin_groups, mappings, group_problems, plan["warnings"]
            )
            if skipped:
                continue
            (source_net, destination_net), missing, emptied = resolve_addresses(
                rule.source, rule.destination, mappings=mappings
            )
            if missing:
                names = ", ".join(missing)
                if emptied:
                    plan["warnings"].append(
                        f"Rule {rule.name}: addresses {names} are not mapped on this firewall, which leaves its "
                        "source or destination empty, so it is not pushed here."
                    )
                    continue
                plan["warnings"].append(
                    f"Rule {rule.name}: addresses {names} are not mapped on this firewall and are left out of the pushed rule."
                )
            origin_binding = ",".join(sorted([mappings[i.name] for i in origins] + [g.name for g in origin_groups]))
            fields = {
                **RULE_DEFAULTS,
                "received-on": origin_binding,
                "received-on-not": str(int(rule.origin_not)),
                "statetype": rule.state_type,
                "gateway": rule.gateway,
                "description": rule.name + " " + marker,
                "sequence": str(rule.sequence),
                "interface": ",".join(bindings),
                "enabled": str(int(rule.enabled)),
                "action": rule.action,
                "direction": rule.direction,
                "ipprotocol": rule.ip_version,
                "protocol": rule.protocol,
                "source_net": source_net,
                "source_port": rule.source_port,
                "destination_net": destination_net,
                "destination_port": rule.destination_port,
                "log": str(int(rule.log)),
                "quick": str(int(rule.quick)),
                "interfacenot": str(int(rule.interface_not)),
                "source_not": str(int(rule.source_not)),
                "destination_not": str(int(rule.destination_not)),
                "icmptype": rule.icmp_types,
                "icmp6type": rule.icmp6_types,
                "categories": ",".join(category_ids.get(c.name) or "@category:" + c.name for c in selected_categories),
            }
            for field in ("source_net", "destination_net", "source_port", "destination_port"):
                for value in fields[field].split(","):
                    if value in groups and not groups[value].applies_to(firewall):
                        raise ValueError(f"Rule {rule.name}: group {value} is excluded from this firewall.")
                    if value in alias_names and value not in available:
                        raise ValueError(f"Rule {rule.name}: alias {value} is excluded from this firewall.")
            expected.append(("rule", identity, rule.name, fields))
        except ValueError as exc:
            plan["errors"].append(str(exc))
    matched = {"alias": set(), "rule": set(), "group": set(), "category": set()}
    collection = {"alias": "aliases", "rule": "rules", "group": "groups", "category": "categories"}
    for kind, identity, label, desired in expected:
        rows = data.get(collection[kind], [])
        if kind == "alias":
            matches = _alias_matches(identity, label, rows, policy.alias_markers)
            if len(matches) == 1 and matches[0][1].get("name") != label:
                if any(row.get("name") == label for row in rows):
                    plan["errors"].append(
                        f"Alias {label}: renaming {matches[0][1].get('name')} would collide with the firewall's "
                        f"existing alias {label}. Rename or remove that alias first."
                    )
        elif kind == "group":
            matches = _group_matches(identity, label, rows, policy.group_markers)
            if len(matches) == 1 and matches[0][1].get("ifname") != label:
                if any(row.get("ifname") == label for row in rows):
                    plan["errors"].append(
                        f"Group {label}: renaming {matches[0][1].get('ifname')} would collide with the firewall's "
                        f"existing group {label}. Rename or remove that group first."
                    )
        else:
            matches = [(i, row) for i, row in enumerate(rows) if _matches_identity(kind, identity, row, origin_uuids)]
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
            item["changes"] = [
                {"field": key, "actual": before[key], "desired": after[key]}
                for key in after
                if before[key] != after[key]
            ]
            item["status"] = "changed" if item["changes"] else "in_sync"
        if item["status"] in ("missing", "changed"):
            plan["operations"].append(
                {
                    "kind": kind,
                    "action": "create" if actual is None else "update",
                    "remote_uuid": actual.get("uuid") if actual else None,
                    "payload": desired,
                }
            )
        plan["items"].append(item)
    for kind, list_name in collection.items():
        rows = data.get(list_name, [])
        for index, row in enumerate(rows):
            if index in matched[kind]:
                continue
            managed = kind in ("rule", "alias", "group") and is_managed(
                row.get("descr" if kind == "group" else "description", "")
            )
            plan["items"].append(
                {
                    "kind": kind,
                    "name": row.get("name", row.get("ifname", row.get("description", "Unnamed"))),
                    "status": "out_of_scope" if managed else "local_only",
                    "changes": [],
                    "actual": row,
                    "desired": None,
                }
            )
    # Never offer a partial plan when prerequisites fail.
    if plan["errors"]:
        plan["operations"] = []
    return plan
