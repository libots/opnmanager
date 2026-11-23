# Developer documentation

Internal docs for working on OPNmanager. The root [README.md](../README.md) is the
**user/operator** guide (setup, features, OPNsense API privileges); these pages explain
how the code works. Read only the page for the area you are changing.

| Page | Read it when you are… |
| --- | --- |
| [architecture.md](architecture.md) | New to the codebase; need the module map, process model or request flow |
| [data-model.md](data-model.md) | Touching `fleet/models.py`, migrations, snapshot JSON or `DeviceInventory.data` |
| [subsystems/planning.md](subsystems/planning.md) | Changing drift/plan logic: `reconcile.py`, identity tags, `canonical`, dependencies |
| [subsystems/device-writes.md](subsystems/device-writes.md) | Changing deploys, definition/alias syncs, rollback, jobs or locks |
| [subsystems/opnsense-client.md](subsystems/opnsense-client.md) | Calling a new OPNsense endpoint or changing error handling / snapshot reads |
| [subsystems/import-and-mappings.md](subsystems/import-and-mappings.md) | Rule adoption from a snapshot, interface mappings, the Logical Interfaces page |
| [subsystems/ui.md](subsystems/ui.md) | Views, URLs, Django admin editors, the rule dialog, rules grid, JS/CSS/templates |
| [subsystems/system-management.md](subsystems/system-management.md) | Firmware, virtual IPs, DNS profiles |
| [subsystems/auth-and-secrets.md](subsystems/auth-and-secrets.md) | Settings, login/OIDC, permissions, credential encryption, data-dir files |
| [testing.md](testing.md) | Writing or running tests; how the device is mocked |
| [decisions.md](decisions.md) | You want to know *why* something is designed the way it is before changing it |
| [pitfalls.md](pitfalls.md) | Before any non-trivial change — short list of traps that have bitten before |

Keep these pages true: when a change alters behavior described here, update the page in
the same commit. Prefer linking to code (`fleet/module.py`, function names) over copying it.
