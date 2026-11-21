"""Resolve the manager definitions actually referenced by one rule."""

from .models import Alias, InterfaceGroup


def rule_definitions(rule, policy=None):
    """Names of aliases (with nested members), groups and categories one rule needs.

    Pass a reconcile.Policy to resolve from memory; the rule should then be one of policy.rules.
    """
    if policy is None:
        aliases = {alias.name: alias for alias in Alias.objects.all()}
        groups = set(InterfaceGroup.objects.values_list("name", flat=True))
    else:
        aliases, groups = policy.aliases_by_name, set(policy.groups)
    address_tokens = {value.strip() for text in (rule.source, rule.destination) for value in text.split(",")}
    alias_tokens = address_tokens | {rule.source_port, rule.destination_port}
    required_aliases = set()
    pending = list(alias_tokens & aliases.keys())
    while pending:
        name = pending.pop()
        if name in required_aliases:
            continue
        required_aliases.add(name)
        pending.extend(value.strip() for value in aliases[name].content.splitlines() if value.strip() in aliases)
    required_groups = {g.name for g in rule.interface_groups.all()}
    required_groups.update(g.name for g in rule.origin_interface_groups.all())
    required_groups.update(address_tokens & groups)
    return {"alias": required_aliases, "group": required_groups, "category": {c.name for c in rule.categories.all()}}
