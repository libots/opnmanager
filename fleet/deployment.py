"""Explicit selected-rule upsert/apply, protected by an OPNsense savepoint with automatic rollback."""

import difflib
import json

from .alias_sync import digest
from .dependencies import rule_definitions
from .locks import device_write_lock
from .models import AuditEvent, Snapshot
from .opnsense import DeviceError
from .reconcile import Policy, canonical, plan_for
from .snapshot_compare import configuration_changes


def fingerprint(data):
    return digest(
        {
            key: sorted(value, key=lambda row: json.dumps(row, sort_keys=True)) if isinstance(value, list) else value
            for key, value in data.items()
        }
    )


def rule_positions(rule_row):
    """(binding, sequence) slots a rule occupies; OPNsense orders rules by sequence within a binding."""
    sequence = str(rule_row.get("sequence", "")).strip()
    sequence = str(int(sequence)) if sequence.isdigit() else sequence
    bindings = [b.strip() for b in str(rule_row.get("interface", "")).split(",") if b.strip()]
    return {(binding, sequence) for binding in bindings or ["(floating)"]}


def _check_positions(placed, device_rules):
    """Block rules whose position is shared with another manager rule or a device-local rule.

    Equal sequences on one binding leave the evaluation order up to the device. A
    single-rule plan can't see this, so it is checked across every targeted rule.
    Device rows that a manager rule already matches are represented by that rule's
    desired position instead of their current one.
    """
    owners = {}
    for row, desired, _ in placed:
        for position in rule_positions(desired):
            owners.setdefault(position, []).append(row["name"])
    matched = {id(actual) for _, _, actual in placed if actual}
    local = {}
    for device_rule in device_rules:
        if id(device_rule) not in matched:
            label = device_rule.get("description") or device_rule.get("uuid") or "unnamed rule"
            for position in rule_positions(device_rule):
                local.setdefault(position, []).append(label)
    for row, desired, _ in placed:
        for binding, sequence in sorted(rule_positions(desired)):
            others = [name for name in owners[(binding, sequence)] if name != row["name"]]
            if others:
                row["errors"].append(
                    f"Sequence {sequence} on {binding} is also used by manager rule {', '.join(others)}. "
                    "Give each rule a distinct sequence."
                )
            if (binding, sequence) in local:
                row["errors"].append(
                    f"Sequence {sequence} on {binding} is also used by device rule {', '.join(local[(binding, sequence)])}. "
                    "Change one sequence so evaluation order is explicit."
                )


def deployment_plan(firewall):
    snapshot = firewall.snapshots.first()
    result = {"firewall": firewall.name, "snapshot_id": snapshot.pk if snapshot else None, "rows": []}
    policy = Policy()
    placed = []  # (row, desired payload, matched device row) for the position check below
    for rule in policy.rules:
        if not rule.applies_to(firewall):
            continue
        plan = plan_for(
            firewall,
            snapshot,
            rule_ids={str(rule.pk)},
            definition_names=rule_definitions(rule, policy),
            policy=policy,
        )
        errors = list(plan["errors"])
        dependencies = [op for op in plan["operations"] if op["kind"] != "rule"]
        if dependencies:
            names = ", ".join(
                op["kind"] + " " + op["payload"].get("name", op["payload"].get("ifname", "")) for op in dependencies
            )
            errors.append(
                "Required definitions need synchronization: "
                + names
                + ". Review them using the link below, then return to this rule plan."
            )
        item = next((i for i in plan["items"] if i["kind"] == "rule" and i.get("desired")), None)
        operation = next((op for op in plan["operations"] if op["kind"] == "rule"), None)
        if (
            operation
            and not dependencies
            and any(value.startswith("@category:") for value in operation["payload"].get("categories", "").split(","))
        ):
            errors.append("Required category UUIDs are missing. Pull a live snapshot before pushing this rule.")
        if operation and operation["action"] == "update" and not operation.get("remote_uuid"):
            errors.append("Pull a live snapshot with remote rule UUIDs before updating.")
        before = canonical(item["actual"] or {}, item["desired"], "rule") if item and item["actual"] else {}
        after = canonical(item["desired"], item["desired"], "rule") if item else {}
        lines = (
            list(
                difflib.unified_diff(
                    json.dumps(before, indent=2, sort_keys=True).splitlines(),
                    json.dumps(after, indent=2, sort_keys=True).splitlines(),
                    fromfile="firewall/current",
                    tofile="manager/desired",
                    lineterm="",
                )
            )
            if operation
            else []
        )
        row = {
            "id": str(rule.pk),
            "name": rule.name,
            "operation": operation,
            "errors": errors,
            "dependencies": dependencies,
            "diff": [
                {
                    "text": line,
                    "kind": "added" if line.startswith("+") else "removed" if line.startswith("-") else "",
                }
                for line in lines
            ],
        }
        result["rows"].append(row)
        if item:
            placed.append((row, item["desired"], item["actual"]))
    if snapshot:
        _check_positions(placed, policy.firewall_state(firewall, snapshot)[0]["rules"])
    result["approval_sha256"] = digest(result)
    return result


def verify_rule_readback(observed, rows):
    for row in rows:
        payload = row["operation"]["payload"]
        matches = [r for r in observed["rules"] if r.get("description") == payload["description"]]
        if len(matches) != 1 or canonical(matches[0], payload, "rule") != canonical(payload, payload, "rule"):
            raise DeviceError("Rule readback did not match the selected changes.")


def _revert(client, revision):
    """Best-effort immediate revert; OPNsense's rollback timer is the backstop."""
    try:
        client.revert(revision)
    except DeviceError:
        return (
            f"Immediate revert failed; OPNsense will restore the previous rules automatically within "
            f"{client.ROLLBACK_SECONDS} seconds unless the apply never started. Pull a fresh snapshot to verify."
        )
    return "The previous rule configuration was restored."


def _execute_deployment(firewall, approved, selected, client, actor):
    plan = deployment_plan(firewall)
    if approved != plan["approval_sha256"]:
        raise DeviceError("Rule plan changed. Review again before applying.")
    selected = set(selected)
    eligible = {row["id"]: row for row in plan["rows"] if row["operation"] and not row["errors"]}
    if not selected or not selected <= eligible.keys():
        raise DeviceError("Select one or more unblocked rule changes from the current plan.")
    occupied = set()
    for key in selected:
        payload = eligible[key]["operation"]["payload"]
        for binding in payload["interface"].split(","):
            position = (binding, payload["sequence"])
            if position in occupied:
                raise DeviceError("Selected rules have conflicting sequence positions. Resolve ordering first.")
            occupied.add(position)
    baseline = firewall.snapshots.get(pk=plan["snapshot_id"])
    current = client.snapshot()
    changes = configuration_changes(baseline.data, current)
    if changes:
        summary = "; ".join(changes[:5])
        if len(changes) > 5:
            summary += f"; and {len(changes) - 5} more changes"
        raise DeviceError(
            "Device configuration changed: "
            + summary
            + ". Pull a new snapshot and review again. No rule writes were made."
        )
    if deployment_plan(firewall)["approval_sha256"] != approved:
        raise DeviceError("Manager policy changed during preflight. Review again.")
    AuditEvent.objects.create(
        actor=actor,
        action="rules.deploy.started",
        detail=firewall.name + " " + approved + " " + ",".join(sorted(selected)),
    )
    rows = [row for row in plan["rows"] if row["id"] in selected]
    # Savepoint before any write: if anything below fails, or the new rules cut
    # the manager off so it can never confirm, OPNsense restores this revision.
    revision = client.savepoint()
    try:
        for row in rows:
            client.save_rule(row["operation"])
        client.apply_rules(revision)
        observed = client.snapshot()
        verify_rule_readback(observed, rows)
    except DeviceError as exc:
        outcome = _revert(client, revision)
        AuditEvent.objects.create(
            actor=actor, action="rules.deploy.failed", detail=f"{firewall.name} revision {revision}; {outcome}"
        )
        raise DeviceError(f"{exc} {outcome}") from exc
    try:
        client.cancel_rollback(revision)
    except DeviceError:
        AuditEvent.objects.create(
            actor=actor,
            action="rules.deploy.unconfirmed",
            detail=f"{firewall.name} revision {revision}; OPNsense will roll back automatically",
        )
        raise
    Snapshot.objects.create(firewall=firewall, data=observed, source="api")
    AuditEvent.objects.create(
        actor=actor, action="rules.deploy.completed", detail=f"{firewall.name} revision {revision}"
    )
    return len(selected)


def execute_deployment(firewall, approved, selected, client, actor):
    with device_write_lock(firewall.pk, "A rule deployment"):
        return _execute_deployment(firewall, approved, selected, client, actor)
