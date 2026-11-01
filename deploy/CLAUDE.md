# deploy

## Systemd units

- **A new unit beside an existing one starts as a copy, then every path directive is diffed against the sibling and each difference is justified.** `fleet-tool-install@.service` made `/var/lib/fleet/jobs/.cache` writable by copying the agent unit's `ReadWritePaths=`, while the agent unit makes that mirror read-only on purpose (TOOL-5, gate FAIL).
- **A path directive for a directory created at runtime takes the `-` prefix.** Without it systemd fails the unit when the path is absent, and the install unit has no data dir of its own for mise.
