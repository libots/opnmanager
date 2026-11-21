"""Explicit selected-rule upsert/apply, protected by an OPNsense savepoint with automatic rollback."""

import difflib
import json

from .alias_sync import digest
from .dependencies import rule_definitions
from .locks import device_write_lock
from .models import AuditEvent, DeviceInventory, Snapshot
from .opnsense import DeviceError
from .opnsense_errors import SavepointUnsupported
from .reconcile import Policy, canonical, plan_for
from .rule_identity import is_managed
from .rule_identity import matches as matches_rule
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


def retire_candidates(device_rules, targeted_rule_ids):
    """Managed device rules whose manager rule was deleted or no longer targets this firewall.

    Identity is decided by the description tag, not by plan success: a targeted rule
    that merely fails to plan (say, a missing mapping) is never offered for retirement.
    """
    candidates = []
    for device_rule in device_rules:
        description = device_rule.get("description", "")
        uuid = device_rule.get("uuid", "")
        if not is_managed(description) or any(matches_rule(description, pk) for pk in targeted_rule_ids):
            continue
        options = [] if not uuid else [("delete", "Delete")]
        if uuid and device_rule.get("enabled", "1") != "0":
            options.insert(0, ("disable", "Disable"))
        candidates.append(
            {
                "uuid": uuid,
                "name": description,
                "interface": device_rule.get("interface", ""),
                "sequence": device_rule.get("sequence", ""),
                "errors": [] if uuid else ["Pull a live snapshot with remote rule UUIDs before retiring this rule."],
                "options": [
                    {
                        "id": f"{action}:{uuid}",
                        "label": label,
                        "operation": {"kind": "rule", "action": action, "remote_uuid": uuid, "payload": {}},
                    }
                    for action, label in options
                ],
            }
        )
    return candidates


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
            "warnings": list(plan.get("warnings", [])),
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
    result["retire"] = []
    if snapshot:
        device_rules = policy.firewall_state(firewall, snapshot)[0]["rules"]
        _check_positions(placed, device_rules)
        targeted = [rule.pk for rule in policy.rules if rule.applies_to(firewall)]
        result["retire"] = retire_candidates(device_rules, targeted)
    result["has_warnings"] = any(row["warnings"] for row in result["rows"])
    result["rollback"] = rollback_mode(firewall)
    result["approval_sha256"] = digest(result)
    return result


def verify_rule_readback(observed, operations):
    by_uuid = {r.get("uuid"): r for r in observed["rules"] if r.get("uuid")}
    for operation in operations:
        if operation["action"] == "delete":
            ok = operation["remote_uuid"] not in by_uuid
        elif operation["action"] == "disable":
            ok = by_uuid.get(operation["remote_uuid"], {}).get("enabled") == "0"
        else:
            payload = operation["payload"]
            matches = [r for r in observed["rules"] if r.get("description") == payload["description"]]
            ok = len(matches) == 1 and canonical(matches[0], payload, "rule") == canonical(payload, payload, "rule")
        if not ok:
            raise DeviceError("Rule readback did not match the selected changes.")


def _revert(client, revision, history_backup=None):
    """Best-effort immediate revert. With a savepoint, OPNsense's rollback timer is the backstop."""
    try:
        if revision:
            client.revert(revision)
        else:
            client.revert_config(history_backup)
    except DeviceError:
        if revision:
            return (
                f"Immediate revert failed; OPNsense will restore the previous rules automatically within "
                f"{client.ROLLBACK_SECONDS} seconds unless the apply never started. Pull a fresh snapshot to verify."
            )
        return (
            "Reverting from configuration history also failed, and this firewall has no automatic rollback. "
            f"Restore entry {history_backup} under System: Configuration: History, then pull a fresh snapshot."
        )
    if revision:
        return "The previous rule configuration was restored."
    return f"The firewall configuration was restored from configuration history ({history_backup})."


def rollback_mode(firewall):
    """How rule pushes to this firewall can be undone: savepoint, config_history or unknown (not tried yet)."""
    inventory = DeviceInventory.objects.filter(firewall=firewall).first()
    return (inventory.data.get("rule_rollback") if inventory else None) or "unknown"


def _remember_rollback(firewall, mode):
    inventory, _ = DeviceInventory.objects.get_or_create(firewall=firewall)
    if inventory.data.get("rule_rollback") != mode:
        inventory.data = {**inventory.data, "rule_rollback": mode}
        inventory.save()


def _execute_deployment(firewall, approved, selected, client, actor, accept_warnings=False, allow_unprotected=False):
    plan = deployment_plan(firewall)
    if approved != plan["approval_sha256"]:
        raise DeviceError("Rule plan changed. Review again before applying.")
    selected = set(selected)
    eligible = {row["id"]: row["operation"] for row in plan["rows"] if row["operation"] and not row["errors"]}
    for candidate in plan["retire"]:
        if not candidate["errors"]:
            eligible.update({option["id"]: option["operation"] for option in candidate["options"]})
    if not selected or not selected <= eligible.keys():
        raise DeviceError("Select one or more unblocked rule changes from the current plan.")
    retiring = [eligible[key]["remote_uuid"] for key in selected if eligible[key]["action"] in ("disable", "delete")]
    if len(retiring) != len(set(retiring)):
        raise DeviceError("Choose either Disable or Delete for each retired rule, not both.")
    warned = [row["name"] for row in plan["rows"] if row["id"] in selected and row["warnings"]]
    if warned and not accept_warnings:
        raise DeviceError(
            "Confirm the interface warnings for " + ", ".join(warned) + " before pushing. No rule writes were made."
        )
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
    operations = [eligible[key] for key in sorted(selected)]
    # Savepoint before any write: if anything below fails, or the new rules cut
    # the manager off so it can never confirm, OPNsense restores this revision.
    history_backup = None
    try:
        revision = client.savepoint()
        _remember_rollback(firewall, "savepoint")
    except SavepointUnsupported as exc:
        # OPNsense 26.7+: the manager can still undo a failed push from the firewall's
        # configuration history, but nothing on the firewall undoes a push that cuts
        # the manager off. That needs the person's explicit agreement.
        _remember_rollback(firewall, "config_history")
        if not allow_unprotected:
            raise DeviceError(
                f'{exc} Review the rules again and tick "Push without automatic rollback" to continue.'
            ) from exc
        revision = None
        history_backup = client.latest_config_backup()
    protection = f"revision {revision}" if revision else f"config history {history_backup}, no automatic rollback"
    AuditEvent.objects.create(
        actor=actor,
        action="rules.deploy.started",
        detail=f"{firewall.name} {approved} {','.join(sorted(selected))}; {protection}",
    )
    try:
        for operation in operations:
            if operation["action"] == "delete":
                client.delete_rule(operation["remote_uuid"])
            elif operation["action"] == "disable":
                client.disable_rule(operation["remote_uuid"])
            else:
                client.save_rule(operation)
        client.apply_rules(revision)
        observed = client.snapshot()
        verify_rule_readback(observed, operations)
    except DeviceError as exc:
        outcome = _revert(client, revision, history_backup)
        AuditEvent.objects.create(
            actor=actor, action="rules.deploy.failed", detail=f"{firewall.name} {protection}; {outcome}"
        )
        raise DeviceError(f"{exc} {outcome}") from exc
    if revision:
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
    AuditEvent.objects.create(actor=actor, action="rules.deploy.completed", detail=f"{firewall.name} {protection}")
    return len(selected)


def execute_deployment(firewall, approved, selected, client, actor, accept_warnings=False, allow_unprotected=False):
    with device_write_lock(firewall.pk, "A rule deployment"):
        return _execute_deployment(firewall, approved, selected, client, actor, accept_warnings, allow_unprotected)
