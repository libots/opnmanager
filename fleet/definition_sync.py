"""Reviewed, additive synchronization of supporting definitions, never rules."""
from .alias_sync import digest
from .models import AuditEvent, Snapshot
from .reconcile import plan_for, canonical
from .dependencies import rule_definitions
from .snapshot_compare import rows_by_identity
from .opnsense import DeviceError

COLLECTIONS = {"alias": "aliases", "group": "groups", "category": "categories"}


def definition_plan(firewall,rule=None):
    all_objects = plan_for(firewall,rule_ids={str(rule.pk)} if rule else None,
                           definition_names=rule_definitions(rule) if rule else None)
    pending={op['payload']['name']:op for op in all_objects['operations'] if op['kind']=='alias'}
    aliases=[]
    while pending:
        ready=[name for name,op in pending.items() if not (set(op['payload']['content'].splitlines()) & set(pending))]
        if not ready:
            all_objects['errors'].append('Alias dependency cycle; synchronization blocked.');aliases=[];break
        for name in sorted(ready):aliases.append(pending.pop(name))
    operations = [op for kind in ('group','category') for op in all_objects['operations'] if op['kind']==kind]+aliases
    result = {'firewall':firewall.name,'snapshot_id':all_objects['snapshot_id'],
              'rule_id':str(rule.pk) if rule else None,'errors':all_objects['errors'],'operations':operations}
    result['approval_sha256']=digest(result)
    return result


def fingerprint(data):
    return digest({kind: rows_by_identity(data,collection) for kind, collection in COLLECTIONS.items()})


def execute_definition_plan(firewall, approved_sha, client, actor, rule=None):
    plan = definition_plan(firewall,rule=rule)
    if plan["errors"] or plan["approval_sha256"] != approved_sha:
        raise DeviceError("Plan changed or is blocked. Review a fresh synchronization plan.")
    baseline = firewall.snapshots.get(pk=plan["snapshot_id"])
    current = client.snapshot()
    if fingerprint(current) != fingerprint(baseline.data):
        raise DeviceError("Device definitions changed since this snapshot. Pull again and review a new plan.")
    if definition_plan(firewall,rule=rule)["approval_sha256"] != approved_sha:
        raise DeviceError("Manager policy changed during preflight. Review a new plan.")
    operations = plan["operations"]
    if any(op["action"] == "update" and not op.get("remote_uuid") for op in operations):
        raise DeviceError("Updates require remote UUIDs. Pull a live snapshot first.")
    if not operations: return 0
    AuditEvent.objects.create(actor=actor, action="definitions.sync.started", detail=firewall.name + " " + approved_sha)
    try:
        for operation in operations: client.save_definition(operation)
        client.reconfigure_definitions({op["kind"] for op in operations})
        observed = client.snapshot()
        for op in operations:
            key = "ifname" if op["kind"] == "group" else "name"
            desired = op["payload"]
            matches = [row for row in observed.get(COLLECTIONS[op["kind"]], []) if row.get(key) == desired[key]]
            if len(matches) != 1 or canonical(matches[0], desired, op["kind"]) != canonical(desired, desired, op["kind"]):
                raise DeviceError("Device readback did not match the approved definitions.")
        Snapshot.objects.create(firewall=firewall, data=observed, source="api")
        AuditEvent.objects.create(actor=actor, action="definitions.sync.completed", detail=firewall.name)
    except DeviceError:
        AuditEvent.objects.create(actor=actor, action="definitions.sync.failed", detail=firewall.name + "; partial changes may remain")
        raise
    return len(operations)
