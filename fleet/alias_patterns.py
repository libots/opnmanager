"""Bounded component-pattern expansion. No wildcard syntax is sent to OPNsense."""
import ipaddress
import itertools
import math
import re

MAX_ALIAS_ENTRIES = 4096


def _interval(token, base, maximum):
    if token.lower() == 'x' or token == '*': return 0, maximum
    parts = token.split('-')
    pattern = r'[0-9]+' if base == 10 else r'[0-9a-fA-F]{1,4}'
    if not 1 <= len(parts) <= 2 or any(not re.fullmatch(pattern, p) for p in parts):
        raise ValueError(f"Invalid IP component {token!r}; use a value, x, *, or an inclusive range.")
    values = [int(p, base) for p in parts]
    if not 0 <= values[0] <= values[-1] <= maximum: raise ValueError(f"IP component out of range: {token}.")
    return values[0], values[-1]


def _format_network(network):
    return str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)


def _expand_basic(entry, alias_type, limit=MAX_ALIAS_ENTRIES):
    """Return addresses for host patterns; compact CIDRs for network patterns."""
    try:
        ipaddress.ip_network(entry, strict=False)
        return [entry]  # Preserve conventional addresses/CIDRs, including their existing formatting.
    except ValueError:
        pass
    # Full address ranges are also accepted, e.g. 192.0.2.1-192.0.2.20.
    parts = entry.split('-')
    if len(parts) == 2:
        try: start, end = (ipaddress.ip_address(p) for p in parts)
        except ValueError: pass
        else:
            if start.version != end.version or int(start) > int(end): raise ValueError("Invalid IP address range.")
            if alias_type == 'host':
                if int(end) - int(start) + 1 > limit: raise ValueError(f"Host expansion exceeds {limit} entries; use a network alias for compact CIDRs.")
                return [str(type(start)(value)) for value in range(int(start), int(end) + 1)]
            return [_format_network(n) for n in ipaddress.summarize_address_range(start, end)]
    if '/' in entry: raise ValueError("Use a literal CIDR, or a component pattern without a /prefix.")
    if ':' in entry:
        width, count, base, maximum, address = 16, 8, 16, 65535, ipaddress.IPv6Address
        if '.' in entry: raise ValueError("Mixed IPv4/IPv6 patterns are unsupported; use explicit addresses.")
        if '::' in entry:
            if entry.count('::') != 1: raise ValueError("IPv6 patterns may contain only one ::.")
            left, right = entry.split('::')
            left, right = left.split(':') if left else [], right.split(':') if right else []
            missing = count - len(left) - len(right)
            if missing < 1: raise ValueError("Invalid IPv6 compression.")
            components = left + ['0'] * missing + right
        else: components = entry.split(':')
    else:
        width, count, base, maximum, address = 8, 4, 10, 255, ipaddress.IPv4Address
        components = entry.split('.')
    if len(components) != count: raise ValueError("Expected four IPv4 octets or eight IPv6 hextets (with optional ::).")
    intervals = [_interval(component, base, maximum) for component in components]
    sizes = [end - start + 1 for start, end in intervals]
    if alias_type == 'host':
        if math.prod(sizes) > limit: raise ValueError(f"Host expansion exceeds {limit} entries; use a network alias for compact CIDRs.")
        output = []
        for values in itertools.product(*(range(start, end + 1) for start, end in intervals)):
            number = 0
            for value in values: number = (number << width) | value
            output.append(str(address(number)))
        return output
    # Full trailing components form contiguous address blocks: summarize them
    # without ever enumerating their addresses, even for a full IPv6 /0.
    last = next((i for i in range(count - 1, -1, -1) if intervals[i] != (0, maximum)), -1)
    if last == -1: return [str(ipaddress.ip_network('0.0.0.0/0' if count == 4 else '::/0'))]
    if math.prod(sizes[:last]) > limit: raise ValueError(f"Pattern requires more than {limit} CIDR entries; narrow its non-trailing wildcards.")
    output = []
    trailing_bits = width * (count - last - 1)
    for values in itertools.product(*(range(start, end + 1) for start, end in intervals[:last])):
        prefix = 0
        for value in values: prefix = (prefix << width) | value
        low = ((prefix << width) | intervals[last][0]) << trailing_bits
        high = (((prefix << width) | intervals[last][1]) << trailing_bits) | ((1 << trailing_bits) - 1)
        for network in ipaddress.summarize_address_range(address(low), address(high)):
            output.append(_format_network(network))
            if len(output) > limit: raise ValueError(f"Pattern expansion exceeds {limit} CIDR entries.")
    return output


def _component_values(component, base, maximum):
    if '[' not in component and not ('x' in component.lower() and component.lower() != 'x'):
        low, high = _interval(component, base, maximum)
        return range(low, high + 1)
    if base != 16: raise ValueError("Bracketed digit ranges are supported inside IPv6 hextets only.")
    atoms = re.findall(r"\[[0-9a-fA-F]+-[0-9a-fA-F]+\]|[0-9a-fA-F]+|[xX*]", component)
    if ''.join(atoms) != component: raise ValueError("Invalid bracketed IPv6 component.")
    width = sum(max(map(len, atom[1:-1].split('-'))) if atom.startswith('[') else 1 if atom in ('x','X','*') else len(atom) for atom in atoms)
    if width > 4: raise ValueError('An expanded IPv6 hextet cannot exceed four digits.')
    choices = []
    for atom in atoms:
        if atom in ('x', 'X', '*'): choices.append('0123456789abcdef')
        elif atom.startswith('['):
            start, end = atom[1:-1].split('-'); width = max(len(start), len(end))
            low, high = int(start, 16), int(end, 16)
            if width > 4 or low > high: raise ValueError("Invalid hexadecimal digit range.")
            choices.append([format(value, f'0{width}x') for value in range(low, high + 1)])
        else: choices.append([atom])
    if sum(len(values[0]) for values in choices) > 4: raise ValueError("An expanded IPv6 hextet cannot exceed four digits.")
    return sorted({int(''.join(parts), 16) for parts in itertools.product(*choices)})


def expand_entry(entry, alias_type, limit=MAX_ALIAS_ENTRIES):
    try:
        ipaddress.ip_network(entry, strict=False)
        return [entry]
    except ValueError: pass
    partial = ':' in entry and any('x' in c.lower() and c.lower() != 'x' for c in entry.split(':'))
    if '[' not in entry and '/' not in entry and not partial:
        return _expand_basic(entry, alias_type, limit)
    body, separator, prefix_text = entry.partition('/')
    version = 6 if ':' in body else 4
    bits, count, base, maximum = (16, 8, 16, 65535) if version == 6 else (8, 4, 10, 255)
    prefix = bits * count
    if separator:
        if not prefix_text.isdigit() or not 0 <= int(prefix_text) <= prefix: raise ValueError("Invalid CIDR prefix.")
        prefix = int(prefix_text)
        if alias_type == 'host' and prefix != bits * count: raise ValueError("Pattern CIDRs require a network alias.")
    if version == 6 and '::' in body:
        if body.count('::') != 1: raise ValueError("Invalid IPv6 compression.")
        left, right = body.split('::'); left = left.split(':') if left else []; right = right.split(':') if right else []
        missing = count - len(left) - len(right)
        if missing < 1: raise ValueError("Invalid IPv6 compression.")
        components = left + ['0'] * missing + right
    else: components = body.split(':' if version == 6 else '.')
    if len(components) != count: raise ValueError("Invalid IP component count.")
    options = []
    for index, component in enumerate(components):
        values = _component_values(component, base, maximum)
        keep = max(0, min(bits, prefix - index * bits))
        mask = ((1 << keep) - 1) << (bits - keep)
        options.append(sorted({value & mask for value in values}))
    if math.prod(len(values) for values in options) > limit: raise ValueError(f"Pattern expansion exceeds {limit} entries; narrow the pattern.")
    address = ipaddress.IPv6Address if version == 6 else ipaddress.IPv4Address
    output = []
    for parts in itertools.product(*options):
        value = 0
        for part in parts: value = (value << bits) | part
        network = ipaddress.ip_network(f"{address(value)}/{prefix}")
        output.append(_format_network(network))
    return output


def compile_content(content, alias_type, known_aliases=(), limit=MAX_ALIAS_ENTRIES):
    output = dict()
    known_aliases = set(known_aliases)
    for entry in (line.strip() for line in content.splitlines()):
        if not entry: continue
        if entry in known_aliases:
            entries = [entry]
        elif alias_type == 'port':
            try:
                ports = [int(p) for p in entry.split(':')]
                if not 1 <= len(ports) <= 2 or not 1 <= ports[0] <= ports[-1] <= 65535: raise ValueError()
            except ValueError as exc: raise ValueError(f"Invalid port or unknown port alias: {entry}.") from exc
            entries = [entry]
        else:
            entries = expand_entry(entry, alias_type, limit)
        for value in entries:
            output[value] = None
            if len(output) > limit: raise ValueError(f"Alias expansion exceeds {limit} total entries.")
    return '\n'.join(output)
