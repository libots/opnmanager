"""Resolve the manager definitions actually referenced by one rule."""
from .models import Alias, InterfaceGroup


def rule_definitions(rule):
    aliases={alias.name:alias for alias in Alias.objects.all()}
    groups=set(InterfaceGroup.objects.values_list('name',flat=True))
    address_tokens={value.strip() for text in (rule.source,rule.destination) for value in text.split(',')}
    alias_tokens=address_tokens | {rule.source_port,rule.destination_port}
    required_aliases=set()
    pending=list(alias_tokens & aliases.keys())
    while pending:
        name=pending.pop()
        if name in required_aliases:continue
        required_aliases.add(name)
        pending.extend(value.strip() for value in aliases[name].content.splitlines() if value.strip() in aliases)
    required_groups=set(rule.interface_groups.values_list('name',flat=True))
    required_groups.update(rule.origin_interface_groups.values_list('name',flat=True))
    required_groups.update(address_tokens & groups)
    return {'alias':required_aliases,'group':required_groups,'category':set(rule.categories.values_list('name',flat=True))}
