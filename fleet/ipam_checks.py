"""Overlap checks for the address plan: warnings, never errors.

`Overlaps` resolves the whole plan once (site prefixes, interface subnets per site, what each
firewall reports on its interfaces, named ranges, DHCP dynamic ranges, reservations) and answers:

* site prefixes of two firewalls that overlap;
* planned interface subnets that overlap each other at one site, or overlap an address a firewall
  already uses on a different interface;
* named ranges that overlap each other or a DHCP dynamic range on the same interface;
* reservations inside a DHCP dynamic range.

The same `check_*` methods back the live hints in the editors (with the edited object excluded) and
the warnings on the Addressing pages, so both always agree.
"""

import ipaddress

from .ipam import TemplateError, interface_plan, resolve_range, site_prefix
from .models import AddressRange, DhcpScope, Firewall, InterfaceAddressing, ScopedPolicy, StaticReservation


def _span(first, last):
    return f"{first} – {last}" if first != last else str(first)


def _meets(a_first, a_last, b_first, b_last):
    return int(a_first) <= int(b_last) and int(b_first) <= int(a_last)


class Overlaps:
    def __init__(self, firewalls=None):
        queryset = Firewall.objects.select_related("inventory").prefetch_related("interface_mappings")
        self.firewalls = list(firewalls) if firewalls is not None else list(queryset.filter(enabled=True))
        self.addressing = list(InterfaceAddressing.objects.select_related("logical_interface"))
        self.ranges = list(AddressRange.objects.select_related("logical_interface"))
        self.scopes = [
            s
            for s in DhcpScope.objects.select_related("logical_interface").prefetch_related(
                *ScopedPolicy.SCOPE_PREFETCH
            )
            if s.enabled and s.dynamic_range
        ]
        self.reservations = {}
        for reservation in StaticReservation.objects.select_related("logical_interface"):
            self.reservations.setdefault(reservation.firewall_id, []).append(reservation)
        self.sites = {}  # fw pk -> {family: network}
        self.subnets = {}  # (fw pk, li pk) -> {family: network}
        self.observed = {}  # fw pk -> [(device, logical name or "", ip_interface)]
        self.spans = {}  # ("range"|"pool", fw pk, pk) -> (first, last)
        for fw in self.firewalls:
            self.sites[fw.pk] = {}
            for family in (4, 6):
                try:
                    prefix = site_prefix(fw, family)
                except TemplateError:
                    prefix = None
                if prefix:
                    self.sites[fw.pk][family] = prefix
            for addressing in self.addressing:
                plan = interface_plan(addressing, fw)
                self.subnets[(fw.pk, addressing.logical_interface_id)] = {
                    family: plan[family]["subnet"] for family in (4, 6) if plan[family] and "subnet" in plan[family]
                }
            names = {m.device_interface: m.logical_interface.name for m in fw.interface_mappings.all()}
            inventory = getattr(getattr(fw, "inventory", None), "data", None) or {}
            found = []
            for row in inventory.get("interfaces", []):
                for family in ("ipv4", "ipv6"):
                    for value in str(row.get(family, "") or "").replace(";", ",").split(","):
                        try:
                            address = ipaddress.ip_interface(value.strip())
                        except ValueError:
                            continue
                        if "/" in value and not address.is_link_local:
                            found.append((row.get("name", ""), names.get(row.get("name", ""), ""), address))
            self.observed[fw.pk] = found
            for item in self.ranges:
                subnet = self.subnets.get((fw.pk, item.logical_interface_id), {}).get(4)
                if subnet:
                    try:
                        self.spans[("range", fw.pk, item.pk)] = resolve_range(
                            item.addresses, subnet, self.sites[fw.pk].get(4)
                        )
                    except TemplateError:
                        pass
            for scope in self.scopes:
                subnet = self.subnets.get((fw.pk, scope.logical_interface_id), {}).get(4)
                if subnet and scope.applies_to(fw):
                    try:
                        self.spans[("pool", fw.pk, scope.pk)] = resolve_range(
                            scope.dynamic_range, subnet, self.sites[fw.pk].get(4)
                        )
                    except TemplateError:
                        pass
        self._names = {a.logical_interface_id: a.logical_interface.name for a in self.addressing}
        self._report = None

    # --- checks for one candidate (also used by the live hints) ---

    def check_site_prefix(self, network, exclude=None):
        problems = []
        for fw in self.firewalls:
            other = self.sites.get(fw.pk, {}).get(network.version)
            if fw.pk != exclude and other and network.overlaps(other):
                problems.append(f"overlaps {fw.name}'s site prefix {other}")
        return problems

    def check_subnet(self, fw, logical_pk, network):
        return [text for text, _ in self._subnet_conflicts(fw, logical_pk, network)]

    def _subnet_conflicts(self, fw, logical_pk, network):
        problems = []
        for (fw_pk, other_pk), families in sorted(
            self.subnets.items(), key=lambda item: self._names.get(item[0][1], "")
        ):
            other = families.get(network.version)
            if fw_pk == fw.pk and other_pk != logical_pk and other and network.overlaps(other):
                problems.append(
                    (f"overlaps {self._names.get(other_pk, 'another interface')} ({other})", ("li", other_pk))
                )
        logical_name = self._names.get(logical_pk)
        mapped_device = next(
            (m.device_interface for m in fw.interface_mappings.all() if m.logical_interface_id == logical_pk), None
        )
        planned_names = {
            name
            for (fw_pk, pk), families in self.subnets.items()
            if fw_pk == fw.pk and families
            for name in [self._names.get(pk)]
        }
        for device, name, address in self.observed.get(fw.pk, []):
            # An interface with a plan is compared through its planned subnet (and its own
            # "differs" state), so only addresses on interfaces without a plan are checked here.
            if device == mapped_device or (name and (name == logical_name or name in planned_names)):
                continue
            if address.version == network.version and network.overlaps(address.network):
                where = f"{device} ({name})" if name else device
                problems.append((f"overlaps {address} in use on {where}", ("device", device, str(address))))
        return problems

    def check_range(self, fw, logical_pk, first, last, exclude_range=None, exclude_pool=None, label="range"):
        return [
            text for text, _ in self._range_conflicts(fw, logical_pk, first, last, exclude_range, exclude_pool, label)
        ]

    def _range_conflicts(self, fw, logical_pk, first, last, exclude_range=None, exclude_pool=None, label="range"):
        problems = []
        for item in self.ranges:
            span = self.spans.get(("range", fw.pk, item.pk))
            if (
                item.logical_interface_id == logical_pk
                and item.pk != exclude_range
                and span
                and _meets(first, last, *span)
            ):
                problems.append((f"overlaps range {item.name} ({_span(*span)})", ("range", item.pk)))
        for scope in self.scopes:
            span = self.spans.get(("pool", fw.pk, scope.pk))
            if (
                scope.logical_interface_id == logical_pk
                and scope.pk != exclude_pool
                and span
                and _meets(first, last, *span)
            ):
                problems.append(
                    (f"overlaps the dynamic DHCP range of {scope.name} ({_span(*span)})", ("pool", scope.pk))
                )
        if label == "pool":
            inside = [
                r
                for r in self.reservations.get(fw.pk, [])
                if r.logical_interface_id == logical_pk
                and int(first) <= int(ipaddress.ip_address(r.ip_address)) <= int(last)
            ]
            if inside:
                names = ", ".join(f"{r.ip_address}{' ' + r.hostname if r.hostname else ''}" for r in inside[:5])
                more = f" and {len(inside) - 5} more" if len(inside) > 5 else ""
                problems.append((f"contains reservation{'s' if len(inside) > 1 else ''} {names}{more}", ("contains",)))
        return problems

    def check_reservation(self, fw, logical_pk, address):
        problems = []
        for scope in self.scopes:
            span = self.spans.get(("pool", fw.pk, scope.pk))
            if scope.logical_interface_id == logical_pk and span and int(span[0]) <= int(address) <= int(span[1]):
                problems.append(f"is inside the dynamic DHCP range of {scope.name} ({_span(*span)})")
        return problems

    # --- everything at once, for the Addressing pages ---

    def report(self):
        """{subject key: [messages]} plus a flat, de-duplicated list for summaries.

        Subject keys: ("site", fw), ("subnet", fw, li), ("range", fw, range), ("pool", fw, scope),
        ("reservation", reservation pk).
        """
        if self._report is not None:
            return self._report
        by_subject, summary, seen = {}, [], set()

        def add(subjects, message, pair, short=None):
            # Cells already name the firewall and the object, so they get the short form.
            for subject in subjects:
                by_subject.setdefault(subject, []).append(short or message)
            if pair not in seen:
                seen.add(pair)
                summary.append(message)

        for fw in self.firewalls:
            for family, network in sorted(self.sites[fw.pk].items()):
                for other in self.firewalls:
                    prefix = self.sites[other.pk].get(family)
                    if other.pk != fw.pk and prefix and network.overlaps(prefix):
                        add(
                            [("site", fw.pk)],
                            f"Site prefix {network} of {fw.name} overlaps {other.name}'s {prefix}.",
                            ("site", family, frozenset({fw.pk, other.pk})),
                            short=f"{network} overlaps {other.name}'s {prefix}.",
                        )
            for addressing in self.addressing:
                li = addressing.logical_interface
                for family, network in sorted(self.subnets.get((fw.pk, li.pk), {}).items()):
                    for problem, other in self._subnet_conflicts(fw, li.pk, network):
                        pair = frozenset({("li", li.pk), other}) if other[0] == "li" else (li.pk, other)
                        add(
                            [("subnet", fw.pk, li.pk)],
                            f"{fw.name}: {li.name} {network} {problem}.",
                            (fw.pk, family, pair),
                            short=f"{network} {problem}.",
                        )
            for item in self.ranges:
                span = self.spans.get(("range", fw.pk, item.pk))
                if span:
                    for problem, other in self._range_conflicts(
                        fw, item.logical_interface_id, *span, exclude_range=item.pk
                    ):
                        add(
                            [("range", fw.pk, item.pk)],
                            f"{fw.name}: {item.logical_interface} range {item.name} ({_span(*span)}) {problem}.",
                            (fw.pk, frozenset({("range", item.pk), other})),
                            short=f"{problem[0].upper()}{problem[1:]}.",
                        )
            for scope in self.scopes:
                span = self.spans.get(("pool", fw.pk, scope.pk))
                if span:
                    conflicts = self._range_conflicts(
                        fw, scope.logical_interface_id, *span, exclude_pool=scope.pk, label="pool"
                    )
                    for problem, other in conflicts:
                        add(
                            [("pool", fw.pk, scope.pk)],
                            f"{fw.name}: dynamic DHCP range of {scope.name} ({_span(*span)}) {problem}.",
                            (fw.pk, frozenset({("pool", scope.pk), other})),
                            short=f"Dynamic range {problem}.",
                        )
            for reservation in self.reservations.get(fw.pk, []):
                address = ipaddress.ip_address(reservation.ip_address)
                for problem in self.check_reservation(fw, reservation.logical_interface_id, address):
                    add(
                        [("reservation", reservation.pk)],
                        f"{fw.name}: reservation {reservation.ip_address} {problem}.",
                        ("reservation", reservation.pk, problem),
                        short=f"{problem[0].upper()}{problem[1:]}.",
                    )
        unique = summary
        self._report = {"by_subject": by_subject, "summary": unique}
        return self._report

    def for_subject(self, *key):
        return self.report()["by_subject"].get(key, [])
