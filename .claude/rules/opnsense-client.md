---
paths:
  - "fleet/opnsense.py"
  - "fleet/opnsense_errors.py"
  - "fleet/system_management.py"
  - "fleet/management_views.py"
  - "fleet/credentials.py"
---
# OPNsense API rules

Full reference: `docs/subsystems/opnsense-client.md`, `docs/subsystems/system-management.md`.

- All device HTTP goes through `OPNsenseClient._request`. Keep TLS verification on, redirects off,
  timeouts set. Never add a "skip verify" option.
- Raise `DeviceError` with an actionable message; never include raw exception text, response bodies
  or credential values. Read-only POSTs pass `write=False`.
- Quote path parameters from device data with `quote(value, safe="")`.
- Device writes (VIP, firmware too) take `locks.device_write_lock(firewall.pk, "<operation>")`.
  Multi-step writes (save → reconfigure → readback) belong in a `DeviceJob`, not a view.
- Only use endpoints that exist in OPNsense core; never guess endpoints or rewrite XML. When adding
  one, update the API privilege list in the root `README.md`.
- Tests mock the client (`Mock`) or patch `requests`; no test may reach a real host.
