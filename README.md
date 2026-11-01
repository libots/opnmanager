# OPNmanager

Manage the intended firewall policy for a fleet of OPNsense devices. This initial application provides an inventory, logical interface mappings, shared aliases, scoped rules, snapshot imports, drift reports, and explicit alias synchronization.

The GUI supports searchable multiselects, interface groups, rule categories, adoption of existing MVC rules, and UI-managed API credentials.

Built on **Django** for users, groups, sessions, CSRF protection, administration and database migrations; **Mozilla django-oidc** handles the OIDC authorization flow. See [THIRD_PARTY.md](THIRD_PARTY.md) for upstream projects and licenses. We depend on maintained packages rather than copying their authentication code.

## Run on a local server

Python 3.12 is the tested runtime. Run these commands from the checkout:

```sh
./scripts/setup-local.sh
./scripts/run-local.sh
```

Setup installs the pinned dependencies, migrates the database, collects static assets, and creates the default local **admin** account. It prints a randomly generated temporary password **once in your terminal**. Sign in at `/accounts/login/` on port 8000 using username `admin` and that password. You must choose a new password before accessing the dashboard, device actions or administration. There is no shared factory password. Do not redirect the initial setup output into shared logs.

The server binds to `127.0.0.1:8000` by default. The GUI includes:

- `/`: fleet dashboard and per-firewall drift reviews.
- `/settings/`: links to inventory, interface mappings, shared rules, aliases and user/group settings.
- `/admin/`: Django's configuration editor, including user permissions.
- `/accounts/password_change/`: local account password changes.

Both scripts are safe to repeat: they never reset existing users or passwords, and an existing active administrator is preserved. If an ordinary user already owns the name `admin`, setup stops instead of promoting that account. If you lose your password, recover it on the server with:

```sh
OPNMANAGER_LOCAL=1 .venv/bin/python manage.py changepassword admin
```

Local server mode uses **Gunicorn and WhiteNoise with Django debug mode disabled**, and generates/persists the application's signing key. You do not need an OIDC provider, a container runtime, Node, or an external database to start using the application.

### Listen on your LAN

Set your server's actual IP or DNS name before starting, for example:

```sh
export DJANGO_ALLOWED_HOSTS=firewall-manager.lan,192.168.10.20,localhost,127.0.0.1
export OPNMANAGER_BIND=0.0.0.0:8000
./scripts/run-local.sh
```

Local mode serves HTTP by default. Use it on your own host or trusted management network. For ongoing LAN use, put it behind an HTTPS reverse proxy. Set `OPNMANAGER_HTTPS=1` for HTTPS-only redirects and secure cookies; set `DJANGO_TRUST_PROXY=1` only when the trusted reverse proxy strips client-supplied forwarding headers and sends `X-Forwarded-Proto: https`. Do not expose the bootstrap login over an untrusted network. Application HTTPS settings never disable TLS verification for connections to firewalls.

### Persistent data and future containers

By default the SQLite database (`db.sqlite3`) and generated signing key (`.local-secret`) stay in the checkout for compatibility with the initial version. Both are ignored by Git. To separate application data from the source code, set this consistently for **setup, startup, backups and management commands**:

```sh
export OPNMANAGER_DATA_DIR=/var/lib/opnmanager
# Ensure this directory is writable by your service account, then:
./scripts/setup-local.sh
./scripts/run-local.sh
```

The directory is created with owner-only permissions by the scripts' umask when it does not exist. An existing directory's permissions are left unchanged. Changing the data directory selects a different database; it does not move or erase the old one. To relocate existing data, stop the server, back up and copy both the database and signing key to the new directory with appropriate ownership, then restart with the new path. Keep credentials and backups private.

A future container can use the same Gunicorn application and environment variables, with `OPNMANAGER_DATA_DIR=/data` backed by a persistent volume. Static assets can be baked into the image or collected to `OPNMANAGER_STATIC_ROOT`. No Docker image/Compose deployment is included or tested yet. SQLite is appropriate for this initial single-server setup; multiple replicas need a shared database and separate deployment work.

### Development and offline demo

```sh
# Use this after setup when you want the development server instead of Gunicorn.
DJANGO_DEBUG=1 .venv/bin/python manage.py runserver 127.0.0.1:8000
# Optional, only for an empty fleet; never contacts a device:
OPNMANAGER_LOCAL=1 .venv/bin/python manage.py seed_demo
```

The demo uses `.invalid` hostnames and invented snapshots, not real device observations. `seed_demo` is repeatable and leaves a nonempty fleet unchanged. Normal local setup does not seed demo devices. Production deployments that do not use local mode must supply `DJANGO_SECRET_KEY` explicitly.

## Define the ideal policy

1. Add firewalls with HTTPS management origins and environment-variable credential prefixes.
2. Create logical interfaces such as `VL10` and `VL20`. Map `VL10` to `opt2` on one firewall and `opt4` on another. Mappings are explicit: matching display labels alone does not prove two interfaces represent the same network.
3. Define shared aliases. Hosts, networks and port aliases are supported, including nested aliases. Alias names identify managed aliases: defining a name that already exists brings that alias into the comparison and can propose an update. Review these collisions before synchronization.
4. Create ideal rules against logical interfaces. Scope defaults to **all enabled firewalls**. Select **Selected firewalls** and choose devices for exceptions. An empty selected set targets none. The selections are ignored when scope is All.
5. Use `@VL10:net` or `@VL10:ip` in source/destination to resolve an interface network or address on each firewall. Ordinary network/alias values pass through unchanged.
6. Pull current configuration or import a normalized snapshot, then review field differences and export a plan.

Rule sequence is significant. Duplicate sequence values on the same logical interface block planning. Stable `[opnmanager:<UUID>]` description prefixes identify managed rules across devices; a local rule with the same name is **not** silently adopted. Existing rules can be reviewed as local-only, then modeled explicitly in the ideal set. Rules whose markers are no longer targeted are reported as out-of-scope for manual review, never deleted automatically.

Statuses distinguish missing, changed, in-sync managed fields, local-only objects, out-of-scope rules, and conflicting identities. Missing mappings, alias cycles, excluded alias references and duplicate managed identities block exportable operations. Reports use the last captured snapshot and show its timestamp; they are not live compliance guarantees.

## Rule import, interface groups and richer rule editing

Use **Settings → Interface groups** to create groups of logical interfaces. Group members resolve separately on each firewall (`VL10` can be `opt2` on one and `opt4` on another). Categories are managed under **Settings → Rule categories**, with a name, color and firewall scope. Both support All or Selected firewall targeting.

In the rule editor, interfaces, groups, categories and protocols support searchable multiple selections. Source and destination allow multiple addresses, networks, aliases and mapped interface references; type a literal address and press Enter to add it. Port fields accept one port, range or port alias, as OPNsense does; put multiple ports in a port alias. Alias content also supports searchable nested aliases and multiple typed entries. ICMP and ICMPv6 have separate type selectors, each supporting multiple types. Empty ICMP type selections mean any type.

Rules with no bindings are floating/global and require the Floating checkbox. In the current OPNsense MVC API, multiple bindings also use floating placement, while a single binding is an interface/group rule. A single-bound rule cannot be forced into floating placement by a separate API flag. The manager derives filters using this same rule.

### Adopt existing OPNsense rules

1. Open a firewall's page and **Pull from firewall**. The enriched snapshot reads MVC rules, aliases, interface inventory, groups and categories.
2. Unique interface display names (such as `VL10`) create missing default mappings automatically. This is controlled by **Auto map interfaces** in the firewall editor. Existing/manual mappings are never overwritten. Duplicate labels, invalid logical names and conflicting mappings are skipped; review the mapping table before sharing rules. The **Add defaults from interface names** button can also apply them explicitly to an existing enriched snapshot.
3. Click **Browse & import rules**. Filter by interface/group, floating placement, category, enabled state or text.
4. Select rules, choose All or Selected target firewalls, and click **Import into manager**. The initial selection targets the source firewall only. Imported rules can then be edited and assigned to any enabled firewalls.

Imports do not write to the source device. They translate local interface-network/address references to logical references, retain ICMP and supported rule flags, and bring in missing alias dependencies, groups and categories. A source firewall/UUID association prevents duplicate imports and identifies the original source rule in drift comparisons before it has a manager marker. Re-importing an adopted UUID preserves the existing manager policy; edit its targets in the manager instead of importing it again. Existing shared definitions are preserved; conflicting alias content or group membership blocks import until reconciled. When expanding a rule to more firewalls later, give its referenced aliases/groups/categories a compatible scope too; the planner flags excluded dependencies.

Imports are atomic: a rule using unsupported active behavior (such as a device-specific gateway or schedule), an unknown protocol/ICMP type, a missing mapping, or a missing category inventory causes the whole selection to fail. This avoids silently changing rule behavior. Only the **MVC** rule inventory is supported; classic XML rules, automatic rules and NAT are not adopted by this connector. Device snapshots are immutable historical observations; stale selections are rejected after a newer pull.

**Ideal rules** in the sidebar now opens the filterable manager policy view. Choose a firewall in its Source dropdown to browse that device's snapshot instead. Interface filters also include global floating rules and rules attached to groups containing that interface; inverted bindings are respected. Filters change the view, not policy targeting.

### Synchronize supporting definitions from the GUI

On a firewall page, choose **Review definition sync**. This previews alias, category and interface-group upserts. Apply only after reviewing the exact fields shown. The server checks the approval digest and re-reads the device before writing, rejecting stale snapshots or changed manager policy. Groups/categories are saved before aliases; nested aliases follow dependency order. It then reconfigures groups/aliases, reads back all changes, saves a fresh snapshot and records the attempt/result in the audit log. Existing unrelated definitions are preserved, and nothing is automatically deleted.

Categories are matched by name and translated to each device's category UUID in desired rule payloads. If a category must first be created, the rule review shows `@category:Name` as an unresolved dependency; sync definitions and refresh before using its device payload. Category assignments are part of the rule comparison; rule deployment uses its own explicit review and apply screen.

Group and alias reconfiguration can reload the filter and activate other pending device edits. These operations are not transactional and have no automatic rollback. Inspect a device after failure and pull a new snapshot before retrying. The permissions `fleet.sync_definitions`, `fleet.manage_credentials`, and existing model permissions allow administrators to delegate individual actions; new permissions are available to superusers automatically.

## Read an OPNsense device

Configure a least-privilege API account on each device. The initial connector targets the **MVC firewall/filter and firewall/alias APIs**. Legacy XML rules, automatic rules, NAT and plugins are outside its snapshot. Older versions without these APIs are unsupported. We inspected upstream core controllers during development; a real device/version compatibility check is still needed.

The preferred setup is **firewall detail → API credentials**. Enter an API key and secret previously generated in OPNsense. This UI stores/replaces/removes connection credentials; it does not create or revoke keys on the firewall. Fields are write-only, empty fields retain saved values, and explicit removal switches back to environment credentials. The credential page requires `fleet.manage_credentials`, `fleet.change_firewall` and `fleet.view_firewall`.

Credentials are encrypted with Fernet before they reach the database. The server creates a separate owner-readable `.credentials-key` in `OPNMANAGER_DATA_DIR`, or uses `OPNMANAGER_CREDENTIAL_KEY` if configured. **Back up this key separately from the database** and keep it stable across restarts/containers. Losing it makes saved credentials unreadable; restore it or re-enter credentials. Encryption protects a database-only backup, not a compromised server with access to both files. Credential values never appear in saved snapshots, plans, admin change messages or audit details. Use HTTPS for the manager when entering credentials over a network.

Environment credentials remain supported. For a firewall with prefix `BRANCH1`, provide `BRANCH1_API_KEY` and `BRANCH1_API_SECRET` to the server. UI credentials take precedence. Local values must be usable by Requests' HTTPS Basic authentication; use your platform's supported credential route for proxy-injected authentication. Grant read access to all five inventory endpoints below, plus edit/reconfigure privileges only when synchronizing definitions.

TLS verification is always enabled. For a private CA, set the firewall's **CA bundle** to a readable PEM file path. API redirects are rejected. Network access to device hostnames must be configured separately in your hosting environment. Never expose firewall APIs directly to the public Internet just for this app.

Pulls use:

- `GET /api/firewall/filter/get`
- `GET /api/firewall/alias/export`
- `GET /api/firewall/filter/get_interface_list`
- `GET /api/firewall/group/get`
- `GET /api/firewall/category/get`

The UI's pull/import controls require `fleet.refresh_firewall` plus `fleet.view_firewall`. Pulls and imports preserve historical snapshots and create audit events. There is no automatic polling yet. [examples/snapshot.json](examples/snapshot.json) shows the normalized import format; an OPNsense XML backup is not accepted as that format. Option-field maps returned by live APIs are normalized into their selected raw identifiers.

## Synchronize aliases explicitly

First pull a current snapshot in the UI. Review the alias-only dry run:

```sh
DJANGO_DEBUG=1 .venv/bin/python manage.py sync_aliases Amsterdam
```

The result includes operations and `approval_sha256`. To perform those exact reviewed operations, use:

```sh
DJANGO_DEBUG=1 .venv/bin/python manage.py sync_aliases Amsterdam --execute --approve <approval_sha256>
```

**This command changes a real firewall.** A dry run never contacts or writes the device. Execution re-reads device aliases, rejects changes since the snapshot or changes to the approved policy, upserts aliases in dependency order, reconfigures once, reads back the result and verifies managed fields. It never deletes aliases or writes ideal rules. An update requires a remote UUID, so imported snapshots without UUIDs require a live pull first.

OPNsense's alias reconfigure endpoint reloads the filter as well as refreshing aliases: unrelated pending changes on the device may become active. Use a maintenance window and review pending device changes first. Operations are sequential and **not transactional**, within or across devices. Concurrent device edits after preflight can race with writes. A timeout or failure may leave partial changes; audit records identify attempts, completion and failure. Inspect the device and pull a new snapshot before retrying. There is no automatic rollback or unattended fleet-wide apply in this version.

Rules can be compared, exported and explicitly deployed using **Review & push rules** on a firewall’s page. The rule model covers basic interface rules, address family, direction, protocol, addresses, ports, logging and enablement. Advanced settings such as gateways, schedules and state tuning are not fully compared: an in-sync status means the displayed managed fields match, not complete behavioral equivalence of the firewall.

## Authentication and permissions

Django local accounts support initial bootstrap and break-glass access. Local setup creates the default `admin` user with a generated temporary password and enforces a first-login password change. You can also create additional administrators with `createsuperuser`. Use Django admin to create users/groups and assign permissions. All logged-in accounts require `fleet.view_firewall` to see inventory and policy reports. These reports contain network topology and addresses. Permissions currently apply to the entire fleet; this is a single-organization application, not a multi-tenant service. Configuration editors use Django's staff/admin permissions. Audit records are read-only in admin; Django also records admin edits.

Enable OIDC with these server-side environment variables (also see `.env.example`; the app reads process variables and does not automatically load dotenv files):

```text
OIDC_ENABLED=1
OIDC_ISSUER=https://identity.example.org/realms/network
OIDC_RP_CLIENT_ID=opnmanager
OIDC_RP_CLIENT_SECRET=<enter securely in environment settings>
OIDC_OP_AUTHORIZATION_ENDPOINT=https://identity.example.org/realms/network/protocol/openid-connect/auth
OIDC_OP_TOKEN_ENDPOINT=https://identity.example.org/realms/network/protocol/openid-connect/token
OIDC_OP_USER_ENDPOINT=https://identity.example.org/realms/network/protocol/openid-connect/userinfo
OIDC_OP_JWKS_ENDPOINT=https://identity.example.org/realms/network/protocol/openid-connect/certs
```

Register `https://<application-host>/oidc/callback/` with your identity provider. Require RS256 signed tokens and `openid email profile` scopes. The backend validates issuer, audience, authorized party, expiry, issue time, nonce and matching userinfo subject. The provider must supply `sub`, `email` and boolean `email_verified=true` in userinfo. PKCE is enabled. Accounts bind to issuer + subject and never auto-link to a privileged local account by email. New OIDC accounts have unusable local passwords and no fleet/staff privileges until an administrator grants access. Provider group claims do not automatically grant administrator rights. Logout ends the local session; IdP logout and ongoing provider-side revocation/session checks are not yet implemented.

OIDC has unit coverage but has not been tested against your identity provider. Configure and test your provider before relying on it for production access. The application currently requires a locally usable client secret for the library's token exchange; if your platform only supports proxy substitution in HTTP headers, use a compatible credential injection method rather than a placeholder in the request body.

## Checks and deployment notes

```sh
DJANGO_DEBUG=1 .venv/bin/python manage.py test
DJANGO_DEBUG=1 .venv/bin/python manage.py check
DJANGO_DEBUG=1 .venv/bin/python manage.py makemigrations --check --dry-run
DJANGO_DEBUG=1 .venv/bin/python manage.py plan Amsterdam
```

The tests exercise interface resolution, all/selected targeting, drift, conflicts, alias ordering, stale-plan rejection, synchronization/readback/failure, permissions, import validation, API request behavior and OIDC identity boundaries. API operations are mocked in tests; this does not establish live OPNsense compatibility.

For deployment set `DJANGO_DEBUG=0`, a strong `DJANGO_SECRET_KEY`, and explicit `DJANGO_ALLOWED_HOSTS`. HTTPS redirects and secure cookies are enabled by default. The local launcher already runs Gunicorn and serves collected static files with WhiteNoise. For production, use an HTTPS ingress, protect API credentials and CA files, and back up the database, signing key and credential encryption key. Production database configuration, rate limiting, task scheduling, high availability and container packaging remain deployment work; Django's development server is not a production server. Don't enable forwarded-host/proto trust unless your ingress strips untrusted forwarding headers.

## Upgrade an existing local installation

Stop the server with Ctrl+C, keep your existing data-directory and host environment settings, then run:

```sh
git pull --ff-only
./scripts/setup-local.sh
./scripts/run-local.sh
```

Setup applies additive schema/data migrations, refreshes static assets and preserves existing administrators, passwords, mappings and rules. The migration copies existing single-interface bindings into the multiselect field. Pull fresh snapshots for the new interface/group/category inventory; old normalized snapshots still load but cannot safely plan group/category synchronization until that inventory is known. Do not delete the database or key files when upgrading.

### Troubleshooting firewall pulls

Pull errors identify the failing endpoint and distinguish TLS failures, proxy/connectivity failures, timeouts, API authentication (401), authorization (403), unsupported endpoints (404), redirects and non-JSON responses. Raw exception messages and response bodies are not shown because they can contain credentials or device details.

A self-signed or private-CA certificate requires trust configuration on the **manager server**. Export the trusted CA certificate (or the self-signed server certificate) as PEM, copy it to a file readable by the manager process, and set the firewall's **CA bundle** field to that absolute file path. The management hostname must match the certificate. Browser acceptance of a certificate does not configure Python's certificate trust. Do not disable certificate verification.

Check reachability from the Ubuntu container running OPNmanager, not just from your workstation. For example, `curl --connect-timeout 5 https://FIREWALL-HOST:PORT/api/firewall/filter/get` tests network and certificate trust without sending credentials; an HTTP 401 is expected when a reachable API requires authentication. Use the actual management hostname/port. Provide `--cacert /path/to/trusted-ca.pem` when checking a private CA. Do not include keys or secrets in shared command output. A working read on one endpoint does not establish permission to read the others.

Deleting a firewall in administration also deletes its owned snapshots and source-rule associations after confirmation. Shared manager rules, logical interfaces and audit records are retained. Standalone snapshot/audit deletion remains disabled; the firewall deletion workflow still requires the normal firewall and other related-object permissions.

## Firewall groups and automatic policy targeting

**Settings → Firewall groups & memberships** manages groups of firewall devices (for example, Branches or Datacenters). These are distinct from interface groups inside OPNsense. Choose member devices in the group editor, or use the membership section in a firewall's editor. Membership selectors also support bulk text editing.

Every rule, alias, category and interface-group definition has a Scope:

- **All enabled firewalls** (the default) includes existing and future enabled firewalls. Device/group selection lists are ignored in this mode.
- **Selected firewalls / firewall groups** targets the union of directly selected devices and members of the selected firewall groups. An empty combined selection targets no devices. Overlapping groups do not create duplicate policies.

Assignments are evaluated dynamically. Adding a new firewall to a targeted group makes the existing policy appear in its desired state without copying policy records. Removing a membership removes that group's coverage, unless another group/direct assignment still targets it. Disabled firewalls are excluded. New devices still require the necessary interface mappings and a snapshot before a synchronization plan can be generated.

This automatically assigns **desired state**, not unattended device changes. Definition synchronization still requires an explicit reviewed apply; rule deployment requires the explicit Review & push rules workflow. Existing device entries that fall out of scope are never automatically deleted. Give dependent aliases/categories/interface groups compatible targets too; importing new supporting definitions with a rule automatically gives them the same scope and selected firewall groups. Imports still reuse matching existing definitions and reject conflicts without overwriting shared policy.

## Alias IP wildcard and range patterns

Host and network aliases accept patterns as well as ordinary addresses, CIDRs and nested alias references. Save patterns in the manager; only compiled addresses/CIDRs are sent to OPNsense. The saved alias form shows a preview, and the definition-sync review shows the exact payload to apply.

| Input | Meaning |
| --- | --- |
| `192.168.x.10` or `192.168.*.10` | 256 addresses: `192.168.0.10` through `192.168.255.10` |
| `192.168.0-3.10` | Four addresses, varying the third octet |
| `192.168.0-3.*` | A network alias compiles this to `192.168.0.0/22` |
| `2001:db8::0-af` | 176 IPv6 addresses, with the final hextet from hexadecimal 0 through af |
| `2001:db8:0-af:*:*:*:*:*` | A network alias compiles this to exact CIDRs, without enumerating every address |
| `192.0.2.1-192.0.2.20` | An inclusive full-address range; same-family IPv6 endpoints also work |

`x`/`X` or `*` replaces a **whole IPv4 octet or IPv6 hextet**. IPv4 component ranges are decimal (0–255); IPv6 component ranges are hexadecimal (0–ffff). Ranges are inclusive. Standard IPv6 `::` compression is supported and means zero hextets, not wildcard hextets. IPv6 digit globs and bracketed ranges are supported as described below. CIDR suffixes are also supported on network-alias patterns (see the examples below). Port aliases retain OPNsense's `100:200` range syntax; IP globs are not port syntax.

**Host aliases** expand patterns to individual addresses. **Network aliases** produce exact CIDR coverage where possible; sparse patterns produce multiple entries without including extra addresses. For example, `192.168.x.10` never includes `192.168.1.11`. Contiguous IPv6 wildcard suffixes can represent huge networks compactly. Each alias is limited to **4096 compiled entries**, with early rejection of patterns whose expansion would exceed that limit. Use a network alias for compact CIDRs or narrow the pattern. An invalid/oversized expansion blocks the entire synchronization plan. Existing known alias names take precedence over wildcard parsing (an alias named `x` is a reference, not an IP pattern).

## Edit selection lists as text

Searchable multi-option controls now offer **Edit as text**. Paste or type one item per line, then choose **Apply list**. This replaces the selection, removes duplicate selections and leaves the rest of the form untouched; an empty applied list clears that field. Cancel preserves the original selection. Apply or cancel all open text editors before saving the form.

For fixed option/relation fields (interfaces, groups, firewalls, categories, protocols, ICMP types), enter existing option names or values. Unknown or ambiguous lines are shown as errors and do not partially modify the selection. For fields that allow custom entries (alias content and rule addresses/ports), new values can be entered; normal server-side validation still applies. Free-text entry does not bypass OPNsense restrictions: port fields still take a single port/range/port alias, and unknown categories/interfaces must be created using their normal editors first.

## Unified interface, pattern CIDRs, and selected rule deployment

The configuration editors at `/admin/` now use the same sidebar, colors and page layout as the fleet interface. Django still supplies their permissions and form behavior. Bulk text editors occupy a full-width row beneath the selector, rather than sharing a narrow side column. Checkbox lists for imports and deployments include an All/none toggle; Django administration retains its native select-all action checkbox.

IPv6 patterns now support ranges inside a hextet: `fd5b:47d4:9272:[20-22]35::/64` compiles to exactly `fd5b:47d4:9272:2035::/64`, `fd5b:47d4:9272:2135::/64`, and `fd5b:47d4:9272:2235::/64`. Bracket values are hexadecimal and padded to the width of the longer endpoint. Nibble wildcards also work, e.g. `20x5`. IPv4 patterns with CIDRs work too, such as `10.20-22.35.0/24`. Pattern CIDRs require a network alias. Bits outside the CIDR prefix are masked and duplicate networks removed. The same 4096-entry limit applies; broad patterns that cannot fit that limit must be narrowed. Literal CIDRs and previous whole-component patterns remain supported.

**Review & push rules** presents per-rule unified diffs with selectable create/update operations. Uncheck rules you do not want to push. A dedicated `fleet.deploy_rules` permission is required (superusers receive it automatically). Supporting definitions must be synchronized first. Updates require a live snapshot with remote UUIDs. The server rejects changed manager plans or changed device configuration, writes only selected eligible operations, calls the filter apply endpoint, reads back managed fields, stores a new snapshot and records success/failure in the audit log. Unchecked rules and unmanaged local rules are retained; this workflow does not automatically delete rules.

The API account needs privileges for `/api/firewall/filter/add_rule`, `/set_rule/<uuid>` and `/apply`, as well as the inventory endpoints. Applying reloads the device filter and can activate unrelated pending device edits. It can interrupt management access. Writes are sequential and not transactional; there is **no automatic rollback**. A write/apply timeout may leave partially saved or active rules; inspect the device and pull a fresh snapshot before retrying. Keep independent management access and review in a maintenance window. The deployment workflow has automated mocked API coverage; a real-device acceptance test with your OPNsense version remains necessary before production use.

## Navigation and fleet system management

The shared sidebar now groups pages under **Fleet Overview**, **Firewall System**, **Interfaces**, **Firewall** and **Settings**. User name, password change and sign out remain at the top. Firewall groups and authentication permission groups remain separate concepts.

### Interface comparison and rule catalogs

**Fleet Overview → Logical Interfaces** renders logical names vertically and selected firewalls as columns. It supports creating logical interfaces, editing per-cell mappings and reviewing observed addresses. **Interfaces → Overview** compares device interface identifiers in the same layout, including IPv4/IPv6 addresses, link status, device name, MTU, VLAN and observation time. Choose devices using All/none or individual checkboxes, then compare or refresh. Refresh uses `POST /api/interfaces/overview/interfaces_info` with `rowCount=-1` so the UI does not silently show only the first page.

The refresh also reads `/api/firewall/filter/get_rule` for the complete protocol catalog available on those devices. The manager retains its basic catalog until the first successful device refresh; a missing catalog privilege is reported and does not discard interface observations. Protocol choices are not inferred from the manager's Linux installation. The full IPv4/IPv6 ICMP choices and OPNsense's predefined service-port list are included. ICMP fields are shown only for selected ICMP/ICMPv6 protocols. Searchable action, direction and address-family selectors are also available. `any`, `(self)`, `bogons` and `bogonsv6` do not need shared alias definitions. Blank/Any ports mean no port restriction.

The rule editor is organized into **Organization**, **Interface**, and **Filter**. Rule and origin bindings independently support logical interfaces and interface groups; origin bindings compile to OPNsense's `received-on` field. Importing a supported rule preserves these bindings. Inverted origin-interface rules remain unsupported and are rejected rather than imported with changed behavior. Categories have a native color picker, storing the six-digit color expected by OPNsense.

### Firmware

**Firewall System → Firmware → Status** can queue update checks on selected enabled devices and refresh their results. **Updates** can request stable package updates after the device reports an available `update`, with explicit confirmation and a separate `fleet.install_firmware` permission. Normal refresh/check also requires `fleet.refresh_firewall`. Use All/none carefully when selecting maintenance targets.

The connector uses the actual core firmware `running`, `check`, `status`, `update` and `upgradestatus` APIs. `running=ready` is required before queueing; remote `busy` or unknown states are rejected. Requests to queue firmware work are serialized locally. Accepted tasks are recorded as running, not successful. Refresh monitors completion, reboot requirements or uncertain outcomes. A finished remote log is not proof that every package installed successfully; verify device version and status. No major upgrade, poweroff or explicit reboot action is exposed. Package updates may still disrupt access or require a reboot, and there is no automatic rollback, HA rollout coordination or automatic retry. Unsupported endpoints or missing device privileges are shown as errors. Existing actions are recorded in the deployment overview.

### Virtual IPs

**Interfaces → Virtual IPs** reads observed VIPs without retaining CARP passwords, adopts existing IP Alias/Proxy ARP entries into scoped manager definitions, and offers reviewed apply/deletion actions. Logical interface mappings resolve per firewall. A signed review expires after ten minutes and is rejected if the VIP inventory or desired payload changed. Apply/reconfigure is followed by readback. Deletion respects OPNsense's in-use validation and verifies absence. Removing a live VIP does not silently remove a manager desired definition; remove/retarget that separately. CARP entries can be viewed but secrets and mutation remain on-device because their HA dependencies need separate handling. Writes can interrupt access and have no automatic rollback.

### Authentication servers and ordered search-domain profiles — desired configuration only

**Firewall System → Access → Servers** centrally stores LDAP/RADIUS server definitions, scope and encrypted bind/shared secrets. **Settings → Administration** associates those servers with firewall authentication profiles. **Settings → General** manages DNS search-domain profiles with one domain per line in explicit lookup order; the per-firewall overview flags conflicting overlapping profiles.

**These profile editors do not deploy LDAP/RADIUS or DNS search-domain settings.** The inspected upstream core provides no supported API for writing these legacy configuration sections. No guessed endpoint, hidden XML rewrite or unverified remote command is used. Profiles are central desired configuration until a version-compatible firewall-side adapter/extension is supplied and tested. They do not change OPNmanager's own login. Other authentication server types also require such an adapter.

### OPNmanager OIDC settings from the UI

**Settings → Authentication Options** is restricted to local superusers and configures OPNmanager's OIDC provider. Secret fields are write-only. Configuration is saved atomically in owner-only `.oidc-settings.json` in `OPNMANAGER_DATA_DIR`; its client secret is encrypted with the existing separate credential key. A manager restart activates saved settings, including login routes. UI settings take precedence over environment settings. Keep local administrators available and test the provider before relying on it; existing sessions are not revoked automatically.

Back up this configuration and the credential encryption key privately. If the saved file/key is corrupt and prevents startup, stop the manager, restore the configuration/key backup or move `.oidc-settings.json` aside to return to environment/local login configuration, then restart. Never put secret values in Git or support messages. LDAP/RADIUS profiles under Firewall System are independent of these manager OIDC settings.

All new live-device operations have mocked API tests but still need acceptance testing against your OPNsense version. Upgrade using the usual `git pull --ff-only`, `./scripts/setup-local.sh`, then `./scripts/run-local.sh`; migrations preserve existing accounts and policy.
