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
# In a second terminal: the worker that runs rule deploys, definition syncs and virtual IP changes.
DJANGO_DEBUG=1 .venv/bin/python manage.py run_jobs
# Optional, only for an empty fleet; never contacts a device:
OPNMANAGER_LOCAL=1 .venv/bin/python manage.py seed_demo
```

The demo uses `.invalid` hostnames and invented snapshots, not real device observations. `seed_demo` is repeatable and leaves a nonempty fleet unchanged. Normal local setup does not seed demo devices. Production deployments that do not use local mode must supply `DJANGO_SECRET_KEY` explicitly.

## Define the ideal policy

1. Add firewalls with HTTPS management origins and environment-variable credential prefixes.
2. Create logical interfaces such as `VL10` and `VL20`. Map `VL10` to `opt2` on one firewall and `opt4` on another. Mappings are explicit: matching display labels alone does not prove two interfaces represent the same network.
3. Define shared aliases. Hosts, networks and port aliases are supported, including nested aliases. Alias names identify managed aliases: defining a name that already exists brings that alias into the comparison and can propose an update. Review these collisions before synchronization.
4. Create ideal rules against logical interfaces. **Deploy to** defaults to **All enabled firewalls**. For exceptions, pick firewall groups and single firewalls in the same list instead. Nothing selected targets none.
5. Use `@VL10:net` or `@VL10:ip` in source/destination to resolve an interface network or address on each firewall. Ordinary network/alias values pass through unchanged.
6. Pull current configuration or import a normalized snapshot, then review field differences and export a plan.

Rule sequence is significant. Duplicate sequence values on the same logical interface block planning. On **Review & deploy**, each rule is also checked against every other manager rule targeting that firewall and against the device's own local rules: a rule that shares a sequence with either on the same interface (or among floating rules) is blocked until one sequence changes, even when only one of the two rules is selected. Compact stable `[om:<12 hexadecimal digits>]` description suffixes identify managed rules across devices; a local rule with the same name is **not** silently adopted. Existing rules can be reviewed as local-only, then modeled explicitly in the ideal set. Rules whose markers are no longer targeted are reported as out-of-scope for manual review, never deleted automatically.

**Interfaces that exist on only some firewalls.** A rule or interface group can include logical interfaces that aren't mapped on every firewall. On a firewall without a mapping, the missing interfaces (and groups with no mapped members) are left out of what gets pushed, and the plan shows a warning instead of blocking. That keeps the rule's meaning, because traffic can't arrive on an interface the firewall doesn't have. If none of a rule's interfaces, or none of its origin interfaces, exist on a firewall, the rule isn't pushed there at all, because an empty list would widen it to every interface. On **Review & deploy**, rules with warnings start unchecked, and pushing them requires ticking the warning confirmation. Logical addresses such as `@DMZ:net` still need a mapping, because leaving out an address would change what the rule matches.

Statuses distinguish missing, changed, in-sync managed fields, local-only objects, out-of-scope rules, and conflicting identities. Unmapped logical addresses, alias cycles, excluded alias references and duplicate managed identities block exportable operations. Reports use the last captured snapshot and show its timestamp; they are not live compliance guarantees.

## Rule import, interface groups and richer rule editing

Use **Settings → Interface groups** to create groups of logical interfaces. Group members resolve separately on each firewall (`VL10` can be `opt2` on one and `opt4` on another). Shared interface groups use only members with mappings on that firewall; unmapped members remain in the manager group for other devices. A group with no mapped members blocks synchronization instead of sending an empty group. Explicit rule interfaces and source/origin interface references still require their mappings. Categories are managed under **Settings → Rule categories**, with a name, color and firewall scope. Both support All or Selected firewall targeting.

In the rule editor, categories, rule interfaces, origin interfaces and ICMP types take several values, as in OPNsense. Version, protocol, ports, state type and gateway take one. Source and destination are OPNsense's network selector: pick any number of aliases and networks, or choose **Single host or Network** and type an address or CIDR in the box that appears. Port fields work like OPNsense's port selector: pick **any**, a port alias or a well-known service, or choose **Single port or range** and type a port (`443`) or a range (`5060-5070`). Put several ports in a port alias. Alias content keeps its free-form chips. ICMP and ICMPv6 type lists only appear when that protocol is selected; empty means any type.

Floating placement is automatic in the rule editor; there is no Floating checkbox. In the current OPNsense MVC API, one rule-interface or group binding is an interface/group rule, multiple bindings are floating, and no bindings means floating on all interfaces. A live **Placement** preview shows the result. Origin bindings do not determine placement. A single-bound rule cannot be forced into floating placement by a separate API flag. The manager derives filters using this same rule.

### Working with the rule list

**Firewall: Rules** is the place to manage rules; the old admin rule list now redirects there, and saving, cloning or deleting a rule returns you to the list with your filters intact. As in OPNsense, each row has a checkbox, a clickable enabled checkbox, and **log**, **edit**, **clone** and **delete** buttons. **Clone** opens the add dialog filled in from that rule, with the next free sequence number after it. Select rules with the checkboxes (the header checkbox selects every matching rule, including collapsed sections) and use the buttons under the table to enable, disable, turn logging on or off, delete, or **Edit** them together.

**Editing several rules at once** isn't something OPNsense offers. The dialog shows each field's value when every selected rule has the same one. Fields that differ are greyed out with **Multiple values**: click one to set a new value for all the selected rules. Only fields you change are saved; everything else keeps each rule's own value. Every rule is checked before anything is saved, so if the change is invalid for one rule (for example a port on a rule whose protocol is *any*), none of them change and the errors name the rules. Like any rule edit, this changes manager policy only; push it from **Review & deploy**.

### Adopt existing OPNsense rules

1. Open a firewall's page and **Pull from firewall**. The enriched snapshot reads MVC rules, aliases, interface inventory, groups and categories.
2. Unique interface display names (such as `VL10`) create missing default mappings automatically. This is controlled by **Auto map interfaces** in the firewall editor. Existing/manual mappings are never overwritten. Duplicate labels, invalid logical names and conflicting mappings are skipped; review the mapping table before sharing rules. The **Add defaults from interface names** button can also apply them explicitly to an existing enriched snapshot.
3. Click **Browse & import rules**. Filter by interface/group, floating placement, category, enabled state or text.
4. Select rules, choose All or Selected target firewalls, and click **Import into manager**. The initial selection targets the source firewall only. Imported rules can then be edited and assigned to any enabled firewalls.

Imports do not write to the source device. They translate local interface-network/address references to logical references, retain ICMP and supported rule flags, and bring in missing alias dependencies, groups and categories. A source firewall/UUID association prevents duplicate imports and identifies the original source rule in drift comparisons before it has a manager marker. Re-importing an adopted UUID preserves the existing manager policy; edit its targets in the manager instead of importing it again. Existing shared definitions are preserved; conflicting alias content or group membership blocks import until reconciled. When expanding a rule to more firewalls later, give its referenced aliases/groups/categories a compatible scope too; the planner flags excluded dependencies. The exception is interface groups a rule is bound to: like an interface that isn't mapped, an excluded group is left out on that firewall with a warning, and the rule is skipped there if none of its bindings remain.

Imports are atomic: if any selected rule can't be imported exactly, nothing is imported, and every problem in the selection is listed with the rule it belongs to, so you can fix them in one pass. A rule can't be imported when it uses a setting the manager can't represent (such as a schedule, traffic shaper, local tag, state limits or TCP flags; the message names them), refers to an interface that isn't mapped on that firewall, uses a protocol missing from the manager's list (refresh the firewall on **Interfaces: Overview** to load its protocols), or has a description longer than 237 characters (the manager appends an 18-character tag, and OPNsense allows 255). Fields OPNsense returns with a `%` prefix are display labels, not settings, and are ignored. This avoids silently changing rule behavior. Only the **MVC** rule inventory is supported; classic XML rules, automatic rules and NAT are not adopted by this connector. Device snapshots are immutable historical observations; stale selections are rejected after a newer pull.

**Ideal rules** in the sidebar now opens the filterable manager policy view. Choose a firewall in its Source dropdown to browse that device's snapshot instead. Interface filters also include global floating rules and rules attached to groups containing that interface; inverted bindings are respected. Filters change the view, not policy targeting. The compact rules table separates source/destination ports, origin, version, protocol and command columns, with collapsible floating, group and interface sections.

The toolbar follows OPNsense's: source, interface (All rules, Floating rules, or one interface or group) and category filters; **Inspect** (eye) lists every rule that applies in evaluation order (floating, then group, then interface rules, by sequence); **Tree** (tag) groups rules by category; then expand/collapse, search, refresh, rules per page, columns, CSV export of the matching rules, and full screen. The columns menu shows or hides any rule setting, including sequence, action, quick, direction, log, ICMP type, state type, placement and (for manager policy) deployment targets; drag a column heading, or use the arrows in that menu, to change the order. Layout, page size and the Inspect/Tree toggles are remembered per browser; **Reset columns** restores the default columns.

Adding, editing, cloning, deleting and editing several rules together open the rule dialog over the grid instead of leaving the page. Saving closes it and refreshes the table in place; so do the enable, disable, logging and delete commands. Search and filter selections update immediately without reloading the page. Changing Source loads that source’s saved rules; it does not pull fresh device data. Import selections survive filtering and collapsing sections. The header All/none checkbox affects all matching rules, including collapsed sections; the selected count includes hidden selections, and **Clear all selections** clears them across filters.

### Deploy definitions and rules together

On **Fleet → Deployment** (or a firewall page), choose **Review & deploy**. One page shows what would change: **Definitions** (alias, category and interface-group creates and updates, plus opt-in removal of aliases and groups deleted from the manager), **Rules** (new or changed rules, checked to push) and **Retire managed rules**. Each change lists only the fields that differ, side by side with the firewall's current value (a new rule lists its placement, match and other non-default fields). Rules that already match, warnings about rules that are not pushed to this firewall, and definition notes are folded into an **unchanged** section that starts collapsed; rules that can't be pushed are folded into a **blocked** section with the reason. One **Deploy** runs both as a single background job under the firewall's write lock: definitions are written and verified first, then the checked rules are pushed. A rule that only waits on definitions written first is selectable and says which ones it uses; you no longer sync definitions on a separate page first. Every selection is validated before the first write. After the definitions are applied, each selected rule is re-planned against the new snapshot and must write exactly what you reviewed (categories created in step 1 resolve to their new UUIDs); otherwise the job stops before writing rules and says why. People with `fleet.deploy_rules` but not `fleet.sync_definitions` see the rule part only, with dependent rules blocked.

**Deploy to all firewalls at once.** **Fleet → Deployment → Review & deploy all firewalls** reviews every enabled firewall on one page, in the same layout. Firewalls with changes are listed first and checked; firewalls with nothing to deploy are folded away. Uncheck a firewall to leave it out, or uncheck single rules within it. One confirmation queues a separate deployment job per checked firewall, each with its own approval digest, preflight, write lock, savepoint (or the **Push without automatic rollback** checkbox on OPNsense 26.7+), readback and audit trail. The firewalls are deployed one after another by the worker; a failure on one doesn't stop or roll back the others. Recent jobs and their results are listed on **Fleet → Deployment**.

The definition part works as the standalone review did (still available to people who can only synchronize definitions). Apply only after reviewing the exact fields shown. Problems with individual rules no longer block definitions. The server checks the approval digest and re-reads the device before writing, rejecting stale snapshots or changed manager policy. Groups/categories are saved before aliases; nested aliases follow dependency order. It then reconfigures groups/aliases, reads back all changes, saves a fresh snapshot and records the attempt/result in the audit log. Existing unrelated definitions are preserved, and nothing is automatically deleted.

Categories are matched by name and translated to each device's category UUID in desired rule payloads. If a category must first be created, the rule diff shows `@category:Name`; the deployment creates the category first and pushes the rule with its new UUID. Category assignments are part of the rule comparison.

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

Rules can be compared, exported and explicitly deployed using **Review & deploy** on a firewall’s page. The rule model covers basic interface rules, address family, direction, protocol, addresses, ports, logging and enablement. Advanced settings such as gateways, schedules and state tuning are not fully compared: an in-sync status means the displayed managed fields match, not complete behavioral equivalence of the firewall.

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
# Style and lint (CI runs both):
ruff format --check .
ruff check .
```

**Which rules are visible.** The connector reads and writes rules through OPNsense's MVC filter API (**Firewall › Automation › Filter**, or the new rules UI in newer releases). Rules created in the legacy **Firewall › Rules** pages live in a different part of the configuration. The API doesn't return them, so they never appear in snapshots, drift reports or sequence-collision checks. Move rules you want managed to the MVC rules, or adopt them from another firewall's MVC rules.

**Snapshot history.** Every pull or import stores the firewall's full configuration as JSON. Only the newest 50 snapshots per firewall are kept, and older ones are deleted automatically. Set `OPNMANAGER_SNAPSHOT_RETENTION` to change the limit, or to `0` to keep everything. Planning and deploys only ever use the newest snapshot.

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

**Settings → Firewall groups & memberships** manages groups of firewall devices (for example, Branches or Datacenters). These are distinct from interface groups inside OPNsense. Choose member devices in the group editor, or use the membership section in a firewall's editor.

Every rule, alias, category, interface-group, DNS and VIP definition has one **Deploy to** list, which works like a rule's Source:

- **All enabled firewalls** (the default) includes existing and future enabled firewalls. It stands alone: choosing it clears other selections, and choosing a group or firewall clears it.
- Otherwise, pick any mix of **firewall groups** and single **firewalls**. The definition targets the union of the chosen firewalls and the groups' members. Nothing selected targets no devices. Overlapping groups do not create duplicate policies.

Forms and scripts that still post the former `scope`, `firewalls` and `firewall_groups` fields keep working.

Assignments are evaluated dynamically. Adding a new firewall to a targeted group makes the existing policy appear in its desired state without copying policy records. Removing a membership removes that group's coverage, unless another group/direct assignment still targets it. Disabled firewalls are excluded. New devices still require the necessary interface mappings and a snapshot before a synchronization plan can be generated.

This automatically assigns **desired state**, not unattended device changes. Definitions and rules are only written by an explicit reviewed **Review & deploy**. Existing device entries that fall out of scope are never automatically deleted. Give dependent aliases/categories/interface groups compatible targets too; importing new supporting definitions with a rule automatically gives them the same scope and selected firewall groups. Imports still reuse matching existing definitions and reject conflicts without overwriting shared policy.

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

## Selection lists

Multi-select pickers stay open while you pick: click as many entries as you like, scrolling as you go, and each toggles its checkmark. Click outside the list or press Escape to close it.

**Alias content** works like OPNsense's tokenizer. Each entry is a chip with a ×. Type to get suggestions from existing aliases; Enter, a comma or a space adds what you typed, and pasting several lines adds them all. Backspace in an empty box removes the last chip. Below the box, **Clear All**, **Copy**, **Paste** and **Text** match OPNsense. **Text** swaps the chips for a one-item-per-line box in the same place; choose **Done** to go back to chips, or just save the form: whatever is in the text box is what gets saved. Normal server-side validation still applies.

## Unified interface, pattern CIDRs, and selected rule deployment

The configuration editors at `/admin/` now use the same sidebar, colors and page layout as the fleet interface. Django still supplies their permissions and form behavior. Checkbox lists for imports and deployments include an All/none toggle; Django administration retains its native select-all action checkbox.

IPv6 patterns now support ranges inside a hextet: `fd5b:47d4:9272:[20-22]35::/64` compiles to exactly `fd5b:47d4:9272:2035::/64`, `fd5b:47d4:9272:2135::/64`, and `fd5b:47d4:9272:2235::/64`. Bracket values are hexadecimal and padded to the width of the longer endpoint. Nibble wildcards also work, e.g. `20x5`. IPv4 patterns with CIDRs work too, such as `10.20-22.35.0/24`. Pattern CIDRs require a network alias. Bits outside the CIDR prefix are masked and duplicate networks removed. The same 4096-entry limit applies; broad patterns that cannot fit that limit must be narrowed. Literal CIDRs and previous whole-component patterns remain supported.

**Review & deploy** presents per-rule field changes with selectable create/update operations. Uncheck rules you do not want to push. A dedicated `fleet.deploy_rules` permission is required (superusers receive it automatically). Supporting definitions the selected rules need are synchronized first in the same deployment. Updates require a live snapshot with remote UUIDs. The server rejects changed manager plans or changed device configuration, writes only selected eligible operations, calls the filter apply endpoint, reads back managed fields, stores a new snapshot and records success/failure in the audit log. Unchecked rules and unmanaged local rules are retained; nothing is deleted automatically.

**Retiring rules.** When a manager rule is deleted, or its scope no longer includes a firewall, its tagged copy stays on that device. **Review & deploy** lists these under **Retire managed rules**, and you choose Keep (the default), Disable or Delete for each one. Retirements go through the same approval, preflight, savepoint, readback and rollback as rule pushes. A rule is only offered when its tag matches no manager rule that still targets the firewall, so a rule that just fails to plan (for example, because of a missing mapping) is never offered. This needs API privileges for `/api/firewall/filter/toggle_rule/<uuid>/0` and `/del_rule/<uuid>`.

The API account needs privileges for `/api/firewall/filter/add_rule`, `/set_rule/<uuid>`, `/savepoint`, `/apply/<revision>`, `/cancel_rollback/<revision>` and `/revert/<revision>`, as well as the inventory endpoints.

**Protected apply.** Every rule deployment first creates an OPNsense filter savepoint, then applies with that revision. OPNsense arms a 60-second rollback timer. The manager reads the rules back and calls `cancel_rollback` only if the readback matches. If a write, the apply or the readback fails, the manager asks the firewall to revert immediately. If the firewall can no longer be reached (for example because a pushed rule blocked the manager), OPNsense restores the previous rules on its own when the timer expires. The audit log records the revision as `rules.deploy.completed`, `rules.deploy.failed` or `rules.deploy.unconfirmed`. Applying still reloads the device filter and can activate unrelated pending device edits, and a revert restores the whole filter configuration as of the savepoint. Keep independent management access and review in a maintenance window. The deployment workflow has automated mocked API coverage; a real-device acceptance test with your OPNsense version remains necessary before production use.

**OPNsense 26.7 and later.** OPNsense 26.7 removed the filter savepoint and rollback API ([opnsense/core#10411](https://github.com/opnsense/core/pull/10411)), so on those firewalls nothing on the firewall can undo a push by itself. The first push to such a firewall stops before writing anything and explains this. From then on, **Review & deploy** shows a red notice and a **Push without automatic rollback** checkbox. With it ticked, the manager records the newest entry in the firewall's configuration history before writing. If a write, the apply or the readback fails, it restores that entry (`/api/core/backup/revert_backup`) and reloads the filter. That restores the whole configuration, not just the rules. If a pushed rule cuts off the manager's access, nothing reverts it automatically: restore the entry the audit log names under **System: Configuration: History** from the console or another management path. The API user then also needs access to the configuration history (`/api/core/backup/`).

**One write at a time per firewall.** Rule deploys, alias and definition syncs, virtual IP changes and firmware requests share a single per-firewall lock (`.device-write-<id>.lock` in the data directory). A second write to the same firewall is refused with the name of the operation already running, so one workflow's "device unchanged" preflight can't be invalidated by another's writes. Different firewalls never block each other. The lock covers one host sharing `OPNMANAGER_DATA_DIR`.

**Background jobs.** Pushing rules, applying a definition sync, and applying or deleting a virtual IP don't run inside the web request. The request checks the form and queues a job, and the browser goes to a job page that refreshes until the job finishes. A separate worker (`manage.py run_jobs`) runs the jobs one at a time. `scripts/run-local.sh` starts it next to Gunicorn and stops it on exit. If you run the app another way, run exactly one worker per data directory, for example as a second systemd service. A reverse-proxy timeout or a closed tab doesn't stop a running job. If the worker itself stops mid-job, the next worker start marks the job **Interrupted**: rules that were applied but not confirmed roll back automatically, and you should pull a fresh snapshot before trying again.

## Navigation and fleet system management

The shared sidebar now groups pages under **Fleet Overview**, **Firewall System**, **Interfaces**, **Firewall** and **Settings**. User name, password change and sign out remain at the top. Firewall groups and authentication permission groups remain separate concepts.

### Interface comparison and rule catalogs

**Fleet → Logical Interfaces** lists logical interfaces as rows and firewalls as columns. Logical and device interfaces are listed in natural order, as OPNsense does (VL49 before VL100_Parents). Firewall names stay pinned at the top and interface names on the left while you scroll. Each cell is a dropdown of that firewall's interfaces (from **Refresh from firewalls** or, until then, the newest snapshot), with the address, VLAN and link status underneath. Edits are collected and saved together with **Save changes**, so you can swap two interfaces in one go. Picking **not mapped** removes a mapping after a confirmation, and picking an interface that another logical interface already uses on that firewall is highlighted and blocks saving. **Fill in matches by name** (or **Fill matches** for one firewall) picks the interface whose identifier or OPNsense description matches each unmapped logical interface; review the picks, then save. Each row shows how many rules, interface groups and virtual IPs use it. The **Not mapped yet** row lists each firewall's interfaces that nothing uses, with a button that creates a logical interface from the interface's description and maps it. **Add** creates a logical interface by name; rename or delete one from its name. Renaming updates every rule source and destination that uses its network or address (`@OLD:net` becomes `@NEW:net`). A firewall's own page (**Fleet → Overview**, then the firewall's settings) has the same dropdowns for that firewall alone. **Interfaces → Overview** compares device interface identifiers in the same layout, including IPv4/IPv6 addresses, link status, device name, MTU, VLAN and observation time. Refresh uses `POST /api/interfaces/overview/interfaces_info` with `rowCount=-1` so the UI does not silently show only the first page.

The refresh also reads `/api/firewall/filter/get_rule` for the complete protocol catalog available on those devices. The manager retains its basic catalog until the first successful device refresh; a missing catalog privilege is reported and does not discard interface observations. Protocol choices are not inferred from the manager's Linux installation. The full IPv4/IPv6 ICMP choices and OPNsense's predefined service-port list are included. ICMP fields are shown only for selected ICMP/ICMPv6 protocols. Searchable action, direction and address-family selectors are also available. `any`, `(self)`, `bogons` and `bogonsv6` do not need shared alias definitions. Blank/Any ports mean no port restriction.

The rule editor follows OPNsense's **Edit rule** dialog field for field: **Organisation**, **Interface**, **Filter**, **Stateful firewall** and **Source Routing** sections, then a manager-only **Deployment** section with the **Deploy to** list. The layout, labels and help texts come from OPNsense's `dialogFilterRule.xml`. **Interface (rule)** and **Interface (origin)** list interface groups and logical interfaces together, as on the firewall. The **advanced mode** switch reveals the inverted-interface options, and the editor opens in advanced mode when one of them is set. The **full help** switch and the per-field info icons show OPNsense's help texts; grey icons mark fields OPNsense documents without help. Both switches are remembered. Choosing Match turns Quick off, and choosing anything but Pass sets the state type to "no state" and clears the gateway, as in OPNsense. The gateway list offers gateway names already in use on your firewalls; the name must exist on every firewall the rule is pushed to. Inverted origin interfaces, state type and gateway are now imported and pushed. Saving still changes only manager policy. Categories have a native color picker, storing the six-digit color expected by OPNsense.

**Look and navigation.** The interface uses OPNsense's default theme: Source Sans, the #C03E14 accent, a white top bar and menu, and grey content areas. Menu sections can be folded, and the ☰ button collapses the menu to an icon rail with hover flyouts. Both are remembered in the browser across pages, including the Django admin pages. On phones the menu opens as an overlay.

### Firmware

**Firewall System → Firmware → Status** can queue update checks on selected enabled devices and refresh their results. **Updates** can request stable package updates after the device reports an available `update`, with explicit confirmation and a separate `fleet.install_firmware` permission. Normal refresh/check also requires `fleet.refresh_firewall`. Use All/none carefully when selecting maintenance targets.

**Update status on the fleet overview.** **Fleet → Overview** shows each firewall's OPNsense version, its update status (up to date, packages and plugins to update, a pending major upgrade, reboot required, or not checked yet), its policy drift, how many interfaces are mapped and the result of its latest deployment. **Check for updates** asks every enabled firewall to download its package catalog (the same as **Check for updates** on the firewall, which covers core and plugin packages alike); it runs in the background on the device, so use **Refresh update status** a minute later to read the result. Pending updates are split into plugins (`os-*` packages) and base/core packages, with old and new versions; the refresh also reads the installed plugins (`GET /api/core/firmware/info`) and flags plugins OPNsense reports as needing configuration. **System → Firmware → Status** shows the same details. If the API user may read the status but not the package list, the installed-plugin list from the previous refresh is kept and marked as such.

The connector uses the actual core firmware `running`, `check`, `status`, `update` and `upgradestatus` APIs. The status refresh also calls `GET /api/core/firmware/info` for installed plugins. `running=ready` is required before queueing; remote `busy` or unknown states are rejected. Requests to queue firmware work are serialized locally. Accepted tasks are recorded as running, not successful. Refresh monitors completion, reboot requirements or uncertain outcomes. A finished remote log is not proof that every package installed successfully; verify device version and status. No major upgrade, poweroff or explicit reboot action is exposed. Package updates may still disrupt access or require a reboot, and there is no automatic rollback, HA rollout coordination or automatic retry. Unsupported endpoints or missing device privileges are shown as errors. Existing actions are recorded in the deployment overview.

### Virtual IPs

**Interfaces → Virtual IPs** reads observed VIPs without retaining CARP passwords, adopts existing IP Alias/Proxy ARP entries into scoped manager definitions, and offers reviewed apply/deletion actions. Logical interface mappings resolve per firewall. A signed review expires after ten minutes. Applying or deleting runs as a background job: the worker re-reads the device and rejects the change if the VIP inventory or desired payload changed since the review. Apply/reconfigure is followed by readback. Deletion respects OPNsense's in-use validation and verifies absence. Removing a live VIP does not silently remove a manager desired definition; remove/retarget that separately. CARP entries can be viewed but secrets and mutation remain on-device because their HA dependencies need separate handling. Writes can interrupt access and have no automatic rollback.

### Ordered search-domain profiles — desired configuration only

**System → Settings → General** manages DNS search-domain profiles with one domain per line in explicit lookup order; the per-firewall overview flags conflicting overlapping profiles.

**These profiles do not deploy DNS search-domain settings.** The inspected upstream core provides no supported API for writing this legacy configuration section. No guessed endpoint, hidden XML rewrite or unverified remote command is used.

**Authentication servers (LDAP/RADIUS) aren't managed.** OPNsense still edits them only on its legacy **System › Access › Servers** page, with no API, so configure them on each firewall. Earlier versions of OPNmanager stored server and administration profiles it could never deploy; upgrading deletes them.

### OPNmanager OIDC settings from the UI

**Settings → Authentication Options** is restricted to local superusers and configures OPNmanager's OIDC provider. Secret fields are write-only. Configuration is saved atomically in owner-only `.oidc-settings.json` in `OPNMANAGER_DATA_DIR`; its client secret is encrypted with the existing separate credential key. A manager restart activates saved settings, including login routes. UI settings take precedence over environment settings. Keep local administrators available and test the provider before relying on it; existing sessions are not revoked automatically.

Back up this configuration and the credential encryption key privately. If the saved file/key is corrupt and prevents startup, stop the manager, restore the configuration/key backup or move `.oidc-settings.json` aside to return to environment/local login configuration, then restart. Never put secret values in Git or support messages.

All new live-device operations have mocked API tests but still need acceptance testing against your OPNsense version. Upgrade using the usual `git pull --ff-only`, `./scripts/setup-local.sh`, then `./scripts/run-local.sh`; migrations preserve existing accounts and policy.


Rule deployment resolves supporting definitions **per rule**, including nested aliases, port aliases, category memberships and rule/origin interface groups. Unrelated alias/category/group drift or invalid unrelated definitions does not block an otherwise valid selected rule. A rule that needs definitions the device lacks names them; when step 1 of the same deployment synchronizes them, the rule stays selectable and is pushed after their verified readback. Out-of-scope dependencies, invalid patterns, missing interface mappings, and missing category UUIDs still block deployment until corrected.


Deployment preflight compares semantic configuration rather than raw API JSON. Known audit/UI annotations, collection order, multi-value selection order, alias line order and equivalent default-field representations do not count as edits. Unknown nonempty fields—including advanced rule settings—remain protected. Real additions/removals or configuration changes still stop the operation before rule writes; the error now names affected collections, identities and fields without exposing field values. Pull a fresh snapshot and review those actual changes rather than bypassing the guard. Alias/definition preflight uses the same normalization.


Alias preflight also excludes known PF runtime counters (`eval_match`, `eval_nomatch`, and the incoming/outgoing pass/block packet/byte counters). Normal traffic must not look like a configuration edit. This exclusion applies only to alias records; actual alias content, type, enablement and unknown settings remain protected. Counter changes do not require repulling a snapshot before applying a reviewed rule plan.


Rule descriptions now use a short stable marker such as `Allow DNS [om:6dd1349ef6bd]` instead of the full UUID prefix. The human rule name stays unchanged. The token comes from the immutable manager rule UUID, and collisions are checked against all manager rules before deployment (a collision blocks writes rather than guessing ownership). Legacy `[opnmanager:<UUID>]` prefixes and the earlier short `[om:...]` prefixes remain recognized. New descriptions place the compact marker at the end. Existing deployed rules appear as description-only updates and can be shortened through the normal reviewed push; they are updated by their existing remote UUID, not recreated. All marker formats remain protected from duplicate import and are recognized for out-of-scope reporting. Preserve the marker when editing a managed rule on-device; changing only the human description does not change its identity. This change applies to rules, not VIP markers.

The fleet overview and deployment firewall tables provide **Pull** for each enabled device and **Pull all enabled firewalls** above the table. Bulk pull reads two devices at a time, updates timestamps (and overview drift status) in place, and continues after individual failures. Disabled devices are skipped. These controls require refresh permission and read saved configuration from devices; they do not deploy rules or definitions.
