# Profile tools and bundled mise

Status: Proposed 2026-11-01, not built. Amends ADR-0034 (closed Profile field list) and ADR-0035 (hash covers tools). Builds on ADR-0038 and ADR-0031.

A Job sometimes needs a toolchain the Box image lacks. This ADR adds a `tools` field to the Profile and has fleetd install the tools with a bundled mise, without opening new egress or giving a repo control of the install.

## Decision

### Profile field

ADR-0034 fixes the Profile field list and sets `deny_unknown_fields`. The list gains one field:

- `tools`: a list of `{name, version}`.

Rules:

- `version` is an exact pinned version. Ranges, `latest` and aliases are rejected.
- `name` comes from a closed registry kept by the Box operator. A name outside the registry is rejected by the shared validator in `fleet-core`.
- Profile input for `tools` is TOML only. JSON profile input does not accept the field.
- Server-stored profiles only. A profile read from a repo carries no `tools`.

### Hash

ADR-0035 hashes `sha256("fleet-profile-v1\0" + canonical bytes)`. A profile with no `tools` keeps the `fleet-profile-v1` prefix, so every existing hash stays valid. A profile that uses `tools` hashes with the prefix `fleet-profile-v2\0`. The hash therefore covers the tool list.

### Bundled mise

- fleetd bundles one pinned mise build for linux x64 musl.
- Before the first run fleetd verifies the binary by sha256 and by minisign. A failed check blocks the install and fails the Job with a fixed error.
- mise is MIT licensed. Redistribution is allowed with the licence notice, which ships beside the binary.

### Install

- fleetd runs `mise install --locked` as the fleet-job uid in a sandboxed template unit.
- The unit sets `MISE_SAFE=1`.
- fleetd writes the mise config from the Profile `tools` list. A repo `mise.toml` is never read.
- Backends are limited to `aqua`, `github`, `http` and core tools. The lockfile pins no artifact for `cargo`, `npm`, `pypi`, `go` and `ubi`, so `--locked` cannot hold them.

### Egress

Egress stays Box-only under ADR-0038. A profile cannot add hosts. The Box allowlist must cover the hosts the install needs (see Researched facts).

### Cache and PATH

- The cache is keyed by tool name and version.
- The agent unit mounts the cache read-only.
- fleetd builds `PATH` for the agent. Neither the profile nor the repo sets it.

### Server gate

The server has only box and client scopes (`crates/fleet-server/src/auth.rs`), so no per-user permission can gate `tools`. The operator enables the field with a server config switch. With the switch off, `CreateProfile` rejects a profile that has `tools`.

## Researched facts

Marked unverified until a live run confirms them:

- `MISE_SAFE=1` takes effect with `mise install`. Unverified.
- Egress hosts for the install: `api.github.com`, `github.com`, the GitHub asset hosts and the mise-versions host. Unverified.
- The attestation verify command for the bundled binary. Unverified.

## Consequences

- Existing profile hashes do not change.
- A profile with `tools` needs a server that has the switch on and a fleetd that bundles mise.
- The registry is an operator change, not a profile change.
- The unverified facts gate the build.

## Considered and rejected

- **Per-user permission for tools.** The server has no such scope. The config switch replaces it.
- **Repo `mise.toml`.** The repo would control what runs at install.
- **Backends `cargo`, `npm`, `pypi`, `go`, `ubi`.** The lockfile pins no artifact for them.
- **Profile-added egress hosts.** It breaks the Box-only policy of ADR-0038.
- **One `v2` prefix for every profile.** It would change every stored hash.
