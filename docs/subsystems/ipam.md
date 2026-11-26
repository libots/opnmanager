# Addressing (IPAM): address plan, DHCP scopes, ranges, reservations

Files: `fleet/ipam.py` (pure template engine and DHCP rendering), `fleet/dhcp.py` (device reads,
reservation plan, sync execution, import), `fleet/ipam_views.py` (pages), models at the end of
`fleet/models.py`, admin editors at the end of `fleet/admin.py`, `forms.DhcpScopeForm`.
Templates `templates/fleet/ipam_*.html`. Tests: `fleet/test_ipam.py`.

## Address templates (`ipam.py`)

- Site prefixes live on `Firewall.ipv4_site_prefix` / `ipv6_site_prefix` (normalized in
  `Firewall.clean`, no host bits).
- A template is an address with `x` components (`10.x.40.1/21`, `x:x:x:40::1/64`).
  `resolve_address` merges: site network bits under the site mask, template bits elsewhere.
  Explicit components inside the site mask must be zero or equal the site's (else `TemplateError`).
  `resolve_interface` also rejects prefix lengths shorter than the site's.
- Inside a subnet, `+N` / `-N` are offsets from the network / broadcast address
  (`resolve_in_subnet`). Ranges are `start-end`; a bare number as end replaces the last component
  (`split_range`).
- `interface_plan(addressing, firewall)` → `{4: ..., 6: ...}`, each `None`, `{interface, subnet,
  router}` or `{error}`. `compare_observed` checks it against `DeviceInventory.data["interfaces"]`.
- Templates are the firewall's own address on the interface (`interface`), from which the subnet
  follows. `interface_push.py` writes them on OPNsense 26.7+ (below).
- Identity association: `refresh_inventory` stores `ipv4_mode` / `ipv6_mode` per interface
  (`system_management.address_modes`: `static`, `none`, or the keyword: `idassoc6` = Identity
  association, `track6` = legacy Track Interface, `dhcp6`, `slaac`, ...). For `idassoc6`/`track6`
  interfaces with a ULA plan (`ipam.ipv6_scope`), `ipam_views._ula_vip` reports whether an IP alias
  `VirtualIP` with that address exists for the firewall and whether it is on the device (inventory
  `vips` or observed). `ipam_views.create_ula_vips` defines missing ones (selected scope, one
  firewall) and hands over to `review_vip`; applying is the normal VIP job.
- The Address Plan page lists every logical interface; those without a plan are rows hidden until
  "Show interfaces without a plan" is ticked (`static/ipam.js`, localStorage). Their **Add plan**
  opens the editor prefilled by `suggest_template()` from the addresses currently observed at each
  site (only when every observed site agrees). Site prefixes are edited in a small dialog: the
  firewall editor with `?_section=addressing`. All Addressing editors open as dialogs (ui.md).

Address fields in the editors show live hints from `ipam.hint_lines` (`describe_network` for a
subnet's usable range) via `/ipam/subnet-info/`, plus a client-side subnet calculator; see ui.md.

## Pushing interface addresses (`interface_push.py`)

OPNsense 26.7 added `/api/interfaces/assignment/` (controller `AssignmentController`, model
`NetworkInterface`): `get_item/<if>` (body `interface`: `type4`/`ipaddr`, `type6`/`ipaddrv6`, address
with prefix length), `set_item/<if>`, `reconfigure` (applies only interfaces with pending edits),
`pending` (`ok` / `pending`). A 404 means an older firewall: the review says 26.7 is needed.
`review()` reads each mapped planned interface, plans per family and returns a digest of
(observed, rows); the view signs it (`signing`, salt `interface-addresses`, 10 minutes). Job
`interfaces.addresses` (`execute`): lock → `pending` must be `ok` → re-read and digest must match →
`set_item` per device → `reconfigure` → readback with `get_item` → best-effort inventory refresh →
audit (`interfaces.addresses.started/completed/failed`). Only `staticv4`/`staticv6` interfaces are
changed; the management address (an IP literal in `base_url`) is blocked. No rollback.

## Ranges page (`ipam_views.range_layout`)

One group per interface with an IPv4 plan: header (subnet, router, usable count per site), then
items — the router (`Firewall address`), `AddressRange`s and enabled scopes' dynamic ranges (only at
sites the scope applies to) — sorted by their offset at the first site where the interface resolves.
`_gap_row` puts an unused row before each item and after the last; at a site it spans from the end
of everything before it to the next item, and is empty where the next item doesn't exist there (that
space shows once, further down). When every site's gap has the same offsets it gets a template label
(`_range_template`, via `suggest_template`) used to prefill "Add range here".

## Overlap warnings (`ipam_checks.py`)

`Overlaps()` resolves the plan once for the enabled firewalls and reports, as warnings only:
site prefixes overlapping between firewalls; planned interface subnets overlapping each other at a
site, or overlapping an address observed on an interface *without* a plan (interfaces with a plan
are compared by their planned subnet and their own "differs" state, so nothing is reported twice);
named ranges overlapping each other or a DHCP dynamic range on the same interface; and
reservations inside a dynamic range. `report()` gives `by_subject` (short messages keyed
`("site", fw)`, `("subnet", fw, li)`, `("range", fw, range)`, `("pool", fw, scope)`,
`("reservation", pk)`) for the page cells and `summary` (one full line per overlapping pair) for the
Address Plan panel. The editors' hints call the same `check_*` methods via `/ipam/subnet-info/`,
leaving out the object being edited (`self`, set by `OpnDialogAdmin.get_form` as `data-hint-self`);
the DHCP dynamic range uses hint kind `pool`.

## DHCP scopes

`DhcpScope` (a `ScopedPolicy`) + `DhcpOption` rows. `scope_settings()` resolves a scope at one site
into a backend-neutral dict (`subnet`, `range`, `options` with `code`/`kind`/`values`/`hex`/`label`);
`0.0.0.0` = the interface's router address; host alias names expand to their addresses of the
family. `render_dnsmasq` / `render_kea` are previews only — **scopes are not deployed**. The DHCP page
(`ipam_views.dhcp_scopes`) lists every logical interface: one row per scope (grouped, first row
carries the interface) and, for interfaces without one, a row hidden until "Show interfaces without a
scope" (`static/ipam.js`, generic `data-toggle-*` toggle) with an Add scope prefilled from the widest
consistent unused span in `range_layout`. The DHCP
page flags several enabled scopes reaching one interface on one firewall.

## Reservations (`dhcp.py`)

- `StaticReservation` (firewall, logical interface, IPv4, MAC, hostname, description, `uid`,
  `remote_uuid`). `clean()` normalizes the MAC and checks the address is inside that site's subnet
  and isn't the network/broadcast/router address (`models.reservation_subnet_problem`).
- `read_state(firewall, client)` uses `ENDPOINTS[firewall.dhcp_backend]` (search endpoints are
  POSTed with `write=False`, `rowCount: -1`) and normalizes rows: reservations `{uuid, ip, mac,
  hostname, description, complex, managed[, subnet]}`, IPv4 leases `{address, mac, hostname, expire,
  interface, reserved}`, Kea `subnets`. `refresh_dhcp` stores it in `DeviceInventory.data["dhcp"]`
  with `read_at`.
- Identity: description ends with `short_marker(uid)`, or the device UUID equals `remote_uuid`
  (set by `import_reservations`). Untagged device entries with the same IP or MAC block the row.
- `reservation_plan(firewall)` is computed from the **stored** observation (like a snapshot) and is
  hashed (`approval_sha256`). It includes `fingerprint(state)` (reservations + Kea subnets, not
  leases). Kea payloads reference the containing Kea subnet's UUID.
- `execute_reservation_sync` (job kind `dhcp.reservations.sync`, `fleet.sync_dhcp`): lock → re-plan
  & digest → validate selection → preflight `read_state` fingerprint compare → re-plan → add/set,
  selected deletes → `service/reconfigure` → readback `_verify` → store observation → audit
  (`dhcp.reservations.started/completed/failed`, `dhcp.reservation.removed`). Removals happen only
  for tagged entries explicitly selected.

Endpoints and field names were checked against OPNsense core (`Dnsmasq/Api/SettingsController`,
`LeasesController`, `Dnsmasq.xml`; `Kea/Api/Dhcpv4Controller`, `Leases4Controller`,
`KeaDhcpv4.xml`). Dnsmasq hosts: body key `host`, fields `host`, `ip`, `hwaddr`, `descr` (`ip` and
`hwaddr` are lists; entries with several are shown as `complex` and not managed). Kea reservations:
body key `reservation`, fields `subnet` (UUID), `ip_address`, `hw_address`, `hostname`, `description`.
