# fleetd self-update

Status: Proposed 2026-11-01. Built and wired in fleetd (`crates/fleetd/src/update/`, the release workflow signs the manifest, the server relays it in the heartbeat). No live run on a real Box yet. Amends ADR-0017. The trust root is amended by ADR-0050.

ADR-0017 makes a fleetd upgrade a Template rebuild: the Template pins a version and boxes reach GitHub at build time only. This ADR adds an in-place update so a running Box can move to a new fleetd without a rebuild. The design fixes who signs, where the trust root lives, how the binary is laid out on disk, and how a bad update is undone.

## Decision

### Signing and trust root

- Releases are signed with minisign. The signing key is held outside the server, offline or in a CI-protected environment. The server never holds it.
- The server only relays a signed manifest: `{version, min_protocol, seq, per-target sha256, size}`. A compromised server can withhold or replay a manifest. It cannot forge one.
- The trust root is a minisign public key. fleetd embeds a default key at build time (`crates/fleetd/trust/update.pub`). If `/etc/fleetd/update.pub` exists it replaces the default and must be root-owned with no group or other write bit. If it exists and fails any check, updating is disabled. fleetd never falls back to the embedded key. `update_trust_root` set in config makes that path required.

### Release assets

ADR-0017 fixes the cargo-dist assets as `fleetd-<target>.tar.gz` plus a `.sha256` file per archive. This ADR adds two assets to each release: a `.minisig` signature per archive and a `manifest.json` signed by the same key. The three targets stay as in ADR-0017.

### On-disk layout

- `/var/lib/fleet/bin` is a new 0755 directory owned by fleetd. It is not under `/var/lib/fleetd`: the unit sets `StateDirectory=fleetd` with `StateDirectoryMode=0700` (`deploy/fleetd-systemd.service:19-20`), so the job uid `fleet-job` could not read a binary placed there.
- fleetd downloads the archive, checks the sha256 and the minisign signature against the trust root, then stages the binary at `/var/lib/fleet/bin/<ver>/fleetd`.
- A `current` symlink points at the active version. fleetd swaps it by creating a new link and `rename(2)` over `current`, so a reader sees the old target or the new one, never a gap.
- A `previous` symlink keeps the last good version.
- The unit's `ExecStart` points at the symlink. It is `/var/lib/fleet/bin/current/fleetd serve` (`deploy/fleetd-systemd.service:14`). The baked binary stays at `/usr/local/bin/fleetd`, root-owned, as the fallback and the source of the rollback guard.

### Drain and restart

- Idle-only drain: fleetd stops claiming jobs, then waits until no lease is held.
- A 30 minute cap on the wait aborts the update. It never aborts a job. The update retries on a later manifest poll.
- Restart is an exit. The unit sets `Restart=always` (`deploy/fleetd-systemd.service:15`), so systemd starts the new binary. No polkit rule is needed.

### Rollback guard

- An `ExecStartPre` runs the guard from the root-owned baked binary, not from the staged one, so a broken update cannot disable its own rollback.
- A health marker is written once the new fleetd registers with the server. When the marker is missing after N starts, the guard flips `current` back to `previous`.
- The guard only ever moves `current` to `previous`. It never picks a version by any other rule.

### Never a downgrade

fleetd accepts a manifest only when its version is strictly newer than the running version, `version` is at or above the configured minimum, and `seq` is strictly greater than the highest `seq` fleetd has accepted. The accepted `seq` is stored in fleetd state. A replayed older manifest fails the `seq` check. The rollback guard is the one exception, and it restores a version that already ran as `current`.

### Protocol skew

The server rolls first. Protocol changes are additive only, so a new server serves an old fleetd. `min_protocol` in the manifest tells fleetd the protocol the server speaks, and fleetd refuses an update whose `min_protocol` exceeds what it can serve.

## Consequences

- A signing key compromise is the one failure that ships a bad binary to every Box. The key custody rule limits it to the CI environment or the offline holder.
- ADR-0017 said Boxes need GitHub only at Template build time. With self-update a Box reaches the release hosts at runtime, or the server proxies the assets. This ADR does not choose between them.
- Disk holds up to three binaries: `current`, `previous` and a staged one.
- A Template rebuild still works and resets the Box to the baked version. The guard and `seq` state keep a stale baked binary from undoing a newer update only if the new baked version is newer than `current`.

## Unverified

- Whether the Box egress policy (ADR-0038) admits the GitHub release hosts at runtime.
- The value of N for the guard, and where the health marker lives.
- Whether `rename(2)` over a symlink behaves the same on the macOS target. The Box target is Linux.

## Considered and rejected

- **Server-held signing key.** A server compromise would sign arbitrary binaries.
- **Checksum only, no signature.** The `.sha256` file travels with the archive, so an attacker who swaps one swaps both.
- **Stage under `/var/lib/fleetd`.** The 0700 mode hides it from `fleet-job`.
- **Restart through systemctl and polkit.** `Restart=always` already restarts on exit and needs no privilege rule.
- **Guard run from the staged binary.** A broken binary would not roll itself back.
