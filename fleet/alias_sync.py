"""Explicit single-firewall alias upsert workflow; never deletes objects or writes rules."""
import hashlib
import json
from .models import Snapshot, AuditEvent
from .opnsense import DeviceError
from .reconcile import plan_for, canonical


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def alias_fingerprint(rows):
    return digest(sorted(rows, key=lambda row: (row.get("name", ""), row.get("uuid", ""))))


def alias_plan(firewall):
    plan = plan_for(firewall)
    operations = [op for op in plan["operations"] if op["kind"] == "alias"]
    # Dependencies must exist before referring aliases are created.
    pending = {op["payload"]["name"]: op for op in operations}
    ordered = []
    while pending:
        ready = [name for name, op in pending.items() if not
                 (set(op["payload"]["content"].splitlines()) & set(pending))]
        if not ready:
            plan["errors"].append("Alias dependency cycle; no synchronization allowed.")
            ordered = []
            break
        for name in sorted(ready): ordered.append(pending.pop(name))
    result = {"firewall": firewall.name, "snapshot_id": plan["snapshot_id"],
              "errors": plan["errors"], "operations": ordered}
    result["approval_sha256"] = digest(result)
    return result


def execute_alias_plan(firewall, approved_sha, client, actor):
    plan = alias_plan(firewall)
    if plan["errors"] or plan["approval_sha256"] != approved_sha:
        raise DeviceError("Plan changed or is blocked. Review a new dry-run plan.")
    baseline = firewall.snapshots.get(pk=plan["snapshot_id"])
    current = client.snapshot()
    if alias_fingerprint(current["aliases"]) != alias_fingerprint(baseline.data["aliases"]):
        raise DeviceError("Device aliases changed since the snapshot. Pull a fresh snapshot and review a new plan.")
    # Reject policy edits made while the API read was in flight.
    if alias_plan(firewall)["approval_sha256"] != approved_sha:
        raise DeviceError("Desired policy changed during preflight. Review a new plan.")
    operations = plan["operations"]
    for op in operations:
        if op["action"] == "update" and not op.get("remote_uuid"):
            raise DeviceError("Snapshot lacks alias UUIDs. Pull a live snapshot before synchronization.")
    if not operations: return 0
    AuditEvent.objects.create(actor=actor, action="alias.sync.started", detail=firewall.name + " " + approved_sha)
    try:
        for op in operations: client.save_alias(op)
        client.reconfigure_aliases()
        observed = client.snapshot()
        for op in operations:
            desired = op["payload"]
            matches = [row for row in observed["aliases"] if row["name"] == desired["name"]]
            if len(matches) != 1 or canonical(matches[0], desired, "alias") != canonical(desired, desired, "alias"):
                raise DeviceError("Device did not retain the desired aliases after synchronization.")
        Snapshot.objects.create(firewall=firewall, data=observed, source="api")
        AuditEvent.objects.create(actor=actor, action="alias.sync.completed", detail=firewall.name)
    except DeviceError:
        AuditEvent.objects.create(actor=actor, action="alias.sync.failed", detail=firewall.name + "; partial configuration may remain")
        raise
    return len(operations)
