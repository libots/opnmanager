"""Reviewed synchronization of supporting definitions, never rules.

Creates and updates are planned automatically; removing a manager alias that was
deleted (or no longer targets the firewall) is offered per alias and only done
when selected.
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
                "uuid": row.get("uuid", ""),
                "name": row.get("name", ""),
                "content": row.get("content", ""),
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
        result["removals"] = alias_removals(firewall, policy.firewall_state(firewall, snapshot)[0], policy)
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
        raise DeviceError("Select only unblocked aliases from the current plan for removal.")
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
        for uuid in sorted(remove, key=lambda u: removable[u]["name"]):
            client.delete_alias(uuid)
            AuditEvent.objects.create(
                actor=actor, action="alias.removed", detail=f"{firewall.name}: {removable[uuid]['name']} ({uuid})"
            )
        client.reconfigure_definitions({op["kind"] for op in operations} | ({"alias"} if remove else set()))
        observed = client.snapshot()
        if remove & {row.get("uuid") for row in observed.get("aliases", [])}:
            raise DeviceError("Device readback still lists an alias selected for removal.")
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
