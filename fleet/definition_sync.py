"""Reviewed synchronization of supporting definitions, never rules.

Creates and updates are planned automatically; removing a manager alias or
interface group that was deleted (or no longer targets the firewall) is offered
per object and only done when selected.
"""

from .alias_sync import digest
from .dependencies import rule_definitions
from .locks import device_write_lock
from .models import AuditEvent, Snapshot
from .opnsense import DeviceError
from .reconcile import Policy, canonical, plan_for
from .rule_identity import marker_of, short_marker
from .snapshot_compare import rows_by_identity

COLLECTIONS = {"alias": "aliases", "group": "groups", "category": "categories"}


def alias_removals(firewall, data, policy):
    """Tagged device aliases whose manager alias was deleted or no longer targets this firewall.

    Identity is the tag, so an alias that merely fails to plan is never offered.
    An alias the device still references is listed but blocked: OPNsense refuses
    to delete it, and the referring rule or alias has to go first.
    """
    current = [a for a in policy.aliases if a.applies_to(firewall)]
    markers = {short_marker(a.uid) for a in current}
    names = {a.name for a in current}
    rows = data.get("aliases", [])
    users = {}
    for rule in data.get("rules", []):
        label = "rule " + (rule.get("description") or rule.get("uuid") or "unnamed")
        for field in ("source_net", "destination_net", "source_port", "destination_port"):
            for token in str(rule.get(field, "")).split(","):
                users.setdefault(token.strip(), []).append(label)
    for alias in rows:
        for member in str(alias.get("content", "")).splitlines():
            users.setdefault(member.strip(), []).append("alias " + alias.get("name", ""))
    candidates = []
    for row in rows:
        marker = marker_of(row.get("description", ""))
        if not marker or marker in markers or row.get("name") in names:
            continue
        errors = []
        if not row.get("uuid"):
            errors.append("Pull a live snapshot with remote alias UUIDs before removing this alias.")
        referrers = sorted(set(users.get(row.get("name", ""), [])))
        if referrers:
            errors.append("Still used by " + ", ".join(referrers) + ". Remove or change those first.")
        candidates.append(
            {
                "kind": "alias",
                "uuid": row.get("uuid", ""),
                "name": row.get("name", ""),
                "content": row.get("content", ""),
                "errors": errors,
            }
        )
    return sorted(candidates, key=lambda c: c["name"])


def group_removals(firewall, data, mappings, policy):
    """Tagged device interface groups whose manager group was deleted or is no longer created here.

    Like aliases, identity is the [om:...] tag in the group description. A group a
    device rule still uses (as its interface, received-on or address) is listed
    but blocked until that rule changes.
    """
    current = [
        g for g in policy.groups.values() if g.applies_to(firewall) and any(i.name in mappings for i in g.members.all())
    ]
    markers = {short_marker(g.uid) for g in current}
    names = {g.name for g in current}
    users = {}
    for rule in data.get("rules", []):
        label = "rule " + (rule.get("description") or rule.get("uuid") or "unnamed")
        for field in ("interface", "received-on", "source_net", "destination_net"):
            for token in str(rule.get(field, "")).split(","):
                users.setdefault(token.strip(), []).append(label)
    candidates = []
    for row in data.get("groups", []):
        marker = marker_of(row.get("descr", ""))
        if not marker or marker in markers or row.get("ifname") in names:
            continue
        errors = []
        if not row.get("uuid"):
            errors.append("Pull a live snapshot with remote group UUIDs before removing this group.")
        referrers = sorted(set(users.get(row.get("ifname", ""), [])))
        if referrers:
            errors.append("Still used by " + ", ".join(referrers) + ". Remove or change those first.")
        candidates.append(
            {
                "kind": "group",
                "uuid": row.get("uuid", ""),
                "name": row.get("ifname", ""),
                "content": row.get("members", "").replace(",", "\n"),
                "errors": errors,
            }
        )
    return sorted(candidates, key=lambda c: c["name"])


def definition_plan(firewall, rule=None):
    policy = Policy()
    all_objects = plan_for(
        firewall,
        # Rule problems don't block definitions; they're reported on the rules themselves.
        rule_ids={str(rule.pk)} if rule else set(),
        definition_names=rule_definitions(rule, policy) if rule else None,
        policy=policy,
    )
    pending = {op["payload"]["name"]: op for op in all_objects["operations"] if op["kind"] == "alias"}
    aliases = []
    while pending:
        ready = [
            name for name, op in pending.items() if not (set(op["payload"]["content"].splitlines()) & set(pending))
        ]
        if not ready:
            all_objects["errors"].append("Alias dependency cycle; synchronization blocked.")
            aliases = []
            break
        for name in sorted(ready):
            aliases.append(pending.pop(name))
    operations = [
        op for kind in ("group", "category") for op in all_objects["operations"] if op["kind"] == kind
    ] + aliases
    result = {
        "firewall": firewall.name,
        "snapshot_id": all_objects["snapshot_id"],
        "rule_id": str(rule.pk) if rule else None,
        "errors": all_objects["errors"],
        "warnings": all_objects["warnings"],
        "operations": operations,
        "removals": [],
    }
    snapshot = firewall.snapshots.first()
    if rule is None and snapshot and firewall.enabled:
        data, mappings, _ = policy.firewall_state(firewall, snapshot)
        result["removals"] = group_removals(firewall, data, mappings, policy) + alias_removals(firewall, data, policy)
    result["approval_sha256"] = digest(result)
    return result


def fingerprint(data):
    return digest({kind: rows_by_identity(data, collection) for kind, collection in COLLECTIONS.items()})


def execute_definition_plan(firewall, approved_sha, client, actor, rule=None, remove=()):
    with device_write_lock(firewall.pk, "A definition synchronization"):
        return _execute_definition_plan(firewall, approved_sha, client, actor, rule, remove)


def _execute_definition_plan(firewall, approved_sha, client, actor, rule=None, remove=()):
    plan = definition_plan(firewall, rule=rule)
    if plan["errors"] or plan["approval_sha256"] != approved_sha:
        raise DeviceError("Plan changed or is blocked. Review a fresh synchronization plan.")
    removable = {c["uuid"]: c for c in plan["removals"] if not c["errors"]}
    remove = set(remove)
    if not remove <= removable.keys():
        raise DeviceError("Select only unblocked aliases and groups from the current plan for removal.")
    baseline = firewall.snapshots.get(pk=plan["snapshot_id"])
    current = client.snapshot()
    if fingerprint(current) != fingerprint(baseline.data):
        raise DeviceError("Device definitions changed since this snapshot. Pull again and review a new plan.")
    if definition_plan(firewall, rule=rule)["approval_sha256"] != approved_sha:
        raise DeviceError("Manager policy changed during preflight. Review a new plan.")
    operations = plan["operations"]
    if any(op["action"] == "update" and not op.get("remote_uuid") for op in operations):
        raise DeviceError("Updates require remote UUIDs. Pull a live snapshot first.")
    if not operations and not remove:
        return 0
    AuditEvent.objects.create(actor=actor, action="definitions.sync.started", detail=firewall.name + " " + approved_sha)
    try:
        for operation in operations:
            client.save_definition(operation)
        removed_kinds = {removable[uuid]["kind"] for uuid in remove}
        for uuid in sorted(remove, key=lambda u: (removable[u]["kind"], removable[u]["name"])):
            kind = removable[uuid]["kind"]
            client.delete_definition(kind, uuid)
            AuditEvent.objects.create(
                actor=actor, action=f"{kind}.removed", detail=f"{firewall.name}: {removable[uuid]['name']} ({uuid})"
            )
        client.reconfigure_definitions({op["kind"] for op in operations} | removed_kinds)
        observed = client.snapshot()
        remaining = {row.get("uuid") for kind in removed_kinds for row in observed.get(COLLECTIONS[kind], [])}
        if remove & remaining:
            raise DeviceError("Device readback still lists a definition selected for removal.")
        for op in operations:
            key = "ifname" if op["kind"] == "group" else "name"
            desired = op["payload"]
            matches = [row for row in observed.get(COLLECTIONS[op["kind"]], []) if row.get(key) == desired[key]]
            if len(matches) != 1 or canonical(matches[0], desired, op["kind"]) != canonical(
                desired, desired, op["kind"]
            ):
                raise DeviceError("Device readback did not match the approved definitions.")
        Snapshot.objects.create(firewall=firewall, data=observed, source="api")
        AuditEvent.objects.create(actor=actor, action="definitions.sync.completed", detail=firewall.name)
    except DeviceError:
        AuditEvent.objects.create(
            actor=actor, action="definitions.sync.failed", detail=firewall.name + "; partial changes may remain"
        )
        raise
    return len(operations) + len(remove)
