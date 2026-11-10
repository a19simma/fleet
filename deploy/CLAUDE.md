# deploy

## Systemd units

- **A new unit beside an existing one starts as a copy, then every path directive is diffed against the sibling and each difference is justified.** `fleet-tool-install@.service` made `/var/lib/fleet/jobs/.cache` writable by copying the agent unit's `ReadWritePaths=`, while the agent unit makes that mirror read-only on purpose (TOOL-5, gate FAIL).
- **A path directive for a directory created at runtime takes the `-` prefix.** Without it systemd fails the unit when the path is absent, and the install unit has no data dir of its own for mise.

## Probe scripts

- **A snippet a live-host probe runs gets a case in `crates/fleetd/tests/env_probe_script.rs` before the first live run.** The `net-lo-only` snippet shipped untested, failed on the box with Errno 97, and cost a live round trip (ENV-6f).
- **Check the mode of an edited script with `git diff --summary` before committing.** A temp-file replace dropped the exec bit on `probe-env-setup.sh` and the gate missed it (ENV-6f, fixed in e128070).
