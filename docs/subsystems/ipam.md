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
- Interface addresses are never written to devices (no OPNsense API).
- The Address Plan page lists every logical interface; those without a plan are rows hidden until
  "Show interfaces without a plan" is ticked (`static/ipam.js`, localStorage). Their **Add plan**
  opens the editor prefilled by `suggest_template()` from the addresses currently observed at each
  site (only when every observed site agrees). Site prefixes are edited in a small dialog: the
  firewall editor with `?_section=addressing`. All Addressing editors open as dialogs (ui.md).

## DHCP scopes

`DhcpScope` (a `ScopedPolicy`) + `DhcpOption` rows. `scope_settings()` resolves a scope at one site
into a backend-neutral dict (`subnet`, `range`, `options` with `code`/`kind`/`values`/`hex`/`label`);
`0.0.0.0` = the interface's router address; host alias names expand to their addresses of the
family. `render_dnsmasq` / `render_kea` are previews only — **scopes are not deployed**. The DHCP
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
