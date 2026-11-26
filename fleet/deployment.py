"""Explicit selected-rule upsert/apply, protected by an OPNsense savepoint with automatic rollback."""

import json

from .alias_sync import digest
from .definition_sync import _execute_definition_plan, definition_plan
from .dependencies import rule_definitions
from .locks import device_write_lock
from .models import AuditEvent, DeviceInventory, Snapshot
from .opnsense import DeviceError
from .opnsense_errors import SavepointUnsupported
from .reconcile import Policy, canonical, field_changes, plan_for
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


def definition_key(operation):
    """(kind, name) of a definition operation; groups are named by ifname."""
    payload = operation["payload"]
    return operation["kind"], payload.get("name") or payload.get("ifname", "")


def rule_intent(operation, category_names):
    """What a rule push writes, independent of whether its categories exist on the device yet.

    A category the device lacks is planned as "@category:Name" and becomes a UUID once
    synchronized, so categories compare by name. Used to confirm that a rule approved
    alongside pending definitions still writes the same thing after they are applied.
    """
    if not operation:
        return None
    payload = dict(operation["payload"])
    payload["categories"] = ",".join(
        sorted(
            category_names.get(value, value.removeprefix("@category:"))
            for value in payload.get("categories", "").split(",")
            if value
        )
    )
    return digest(payload)


def deployment_plan(firewall, pending_definitions=None):
    """Per-rule push plan. pending_definitions: (kind, name) keys that a combined
    deployment synchronizes first; rules waiting only on those are not blocked."""
    snapshot = firewall.snapshots.first()
    result = {"firewall": firewall.name, "snapshot_id": snapshot.pk if snapshot else None, "rows": []}
    policy = Policy()
    category_names = {}
    if snapshot and firewall.enabled:
        category_names = {
            row["uuid"]: row["name"]
            for row in policy.firewall_state(firewall, snapshot)[0].get("categories", [])
            if row.get("uuid")
        }
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
        names = ", ".join(" ".join(definition_key(op)) for op in dependencies)
        after_definitions = bool(
            dependencies
            and pending_definitions is not None
            and all(definition_key(op) in pending_definitions for op in dependencies)
        )
        if dependencies and not after_definitions:
            if pending_definitions is None:
                errors.append(
                    "Required definitions need synchronization: "
                    + names
                    + ". Review them using the link below, then return to this rule plan."
                )
            else:
                errors.append(
                    "Required definitions need synchronization: "
                    + names
                    + ". They can't be synchronized in this deployment; resolve the definition problems above."
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
        changes = field_changes(item["actual"], item["desired"], "rule") if item and operation else []
        row = {
            "id": str(rule.pk),
            "name": rule.name,
            "operation": operation,
            "errors": errors,
            "warnings": list(plan.get("warnings", [])),
            "dependencies": dependencies,
            "after_definitions": names if after_definitions else "",
            "intent": rule_intent(operation, category_names),
            "changes": changes,
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


def eligible_operations(plan):
    """Selectable keys of a rule plan (rule ids and retire options) and their operations."""
    eligible = {row["id"]: row["operation"] for row in plan["rows"] if row["operation"] and not row["errors"]}
    for candidate in plan["retire"]:
        if not candidate["errors"]:
            eligible.update({option["id"]: option["operation"] for option in candidate["options"]})
    return eligible


def _check_selection(plan, selected, accept_warnings):
    eligible = eligible_operations(plan)
    if not selected or not selected <= eligible.keys():
        raise DeviceError("Select one or more unblocked rule changes from the current plan.")
    retiring = [eligible[key]["remote_uuid"] for key in selected if eligible[key]["action"] in ("disable", "delete")]
    if len(retiring) != len(set(retiring)):
        raise DeviceError("Choose either Disable or Delete for each retired rule, not both.")
    warned = [row["name"] for row in plan["rows"] if row["id"] in selected and row["warnings"]]
    if warned and not accept_warnings:
        raise DeviceError(
            "Confirm the warnings for " + ", ".join(warned) + " before pushing. No rule writes were made."
        )
    return eligible


def _execute_deployment(firewall, approved, selected, client, actor, accept_warnings=False, allow_unprotected=False):
    plan = deployment_plan(firewall)
    if approved != plan["approval_sha256"]:
        raise DeviceError("Rule plan changed. Review again before applying.")
    selected = set(selected)
    eligible = _check_selection(plan, selected, accept_warnings)
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


def combined_plan(firewall, include_definitions=True):
    """Everything one deployment applies: supporting definitions first, then selected rules.

    Rules that only wait on definitions this plan synchronizes are selectable. Without
    include_definitions (a person who may not synchronize definitions), the rule plan is
    the standalone one and such rules stay blocked.
    """
    definitions = definition_plan(firewall) if include_definitions else None
    pending = None
    if definitions is not None:
        pending = set() if definitions["errors"] else {definition_key(op) for op in definitions["operations"]}
    rules = deployment_plan(firewall, pending_definitions=pending)
    return {
        "firewall": firewall.name,
        "definitions": definitions,
        "rules": rules,
        "approval_sha256": digest(
            {
                "definitions": definitions["approval_sha256"] if definitions else None,
                "rules": rules["approval_sha256"],
            }
        ),
    }


def definitions_to_apply(plan, remove=()):
    definitions = plan["definitions"]
    return bool(definitions and not definitions["errors"] and (definitions["operations"] or remove))


def execute_combined(
    firewall,
    approved,
    selected,
    client,
    actor,
    remove=(),
    include_definitions=True,
    accept_warnings=False,
    allow_unprotected=False,
):
    """Synchronize definitions, then push the selected rules, under one write lock.

    Every selection is validated before the first write. If the definitions apply but a
    rule can no longer be pushed as reviewed, the job stops there and says so: the
    definitions stay (they are referenced by nothing new yet) and no rule is written.
    Returns (definition changes, rule changes).
    """
    with device_write_lock(firewall.pk, "A deployment"):
        plan = combined_plan(firewall, include_definitions)
        if approved != plan["approval_sha256"]:
            raise DeviceError("Deployment plan changed. Review again before applying.")
        rules, definitions = plan["rules"], plan["definitions"]
        selected, remove = {key for key in selected if key}, {uuid for uuid in remove if uuid}
        if remove:
            removable = {c["uuid"] for c in (definitions or {}).get("removals", []) if not c["errors"]}
            if not include_definitions or not remove <= removable:
                raise DeviceError("Select only unblocked aliases and groups from the current plan for removal.")
        sync = definitions_to_apply(plan, remove)
        if not selected and not sync:
            raise DeviceError("Nothing selected to deploy.")
        if selected:
            _check_selection(rules, selected, accept_warnings)
            if rules["rollback"] == "config_history" and not allow_unprotected:
                raise DeviceError(
                    f"{firewall.name} has no automatic rollback. Review again and tick "
                    '"Push without automatic rollback" to continue. Nothing was written.'
                )
        synced = 0
        if sync:
            synced = _execute_definition_plan(firewall, definitions["approval_sha256"], client, actor, remove=remove)
        if not selected:
            return synced, 0
        prefix = f"Applied {synced} definition changes, then stopped before writing rules: " if synced else ""
        fresh = deployment_plan(firewall)
        current = {row["id"]: row for row in fresh["rows"]}
        final = set()
        for row in rules["rows"]:
            if row["id"] not in selected:
                continue
            now = current.get(row["id"])
            if now is None or now["errors"]:
                problems = " ".join(now["errors"]) if now else "it no longer targets this firewall."
                raise DeviceError(f"{prefix}rule {row['name']} is blocked: {problems} Review again.")
            if not now["operation"]:
                continue  # Already matches the device after the definitions were applied.
            if now["intent"] != row["intent"]:
                raise DeviceError(f"{prefix}rule {row['name']} changed since review. Review again.")
            final.add(row["id"])
        final |= selected - {row["id"] for row in rules["rows"]}  # retire options
        if not final:
            return synced, 0
        pushed = _execute_deployment(
            firewall, fresh["approval_sha256"], final, client, actor, accept_warnings, allow_unprotected
        )
        return synced, pushed
