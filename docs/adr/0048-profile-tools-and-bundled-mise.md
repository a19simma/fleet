# Profile tools and bundled mise

Status: Proposed 2026-11-01. Built: the Profile `tools` field and v2 hash, the `FLEET_ALLOW_PROFILE_TOOLS` server gate (built then replaced by ADR-0054), the `fleet-tool-install@.service` unit and the fleetd tool cache. No live run. Amends ADR-0034 (closed Profile field list) and ADR-0035 (hash covers tools). Builds on ADR-0038 and ADR-0031. Amended by ADR-0054 (the `FLEET_ALLOW_PROFILE_TOOLS` server gate becomes the per-user capability `profile:tools`).

A Job sometimes needs a toolchain the Box image lacks. This ADR adds a `tools` field to the Profile and has fleetd install the tools with a bundled mise, without opening new egress or giving a repo control of the install.

## Decision

### Profile field

ADR-0034 fixes the Profile field list and sets `deny_unknown_fields`. The list gains one field:

- `tools`: a list of `{name, version}`.

Rules:

- `version` is an exact pinned version. Ranges, `latest` and aliases are rejected.
- `name` comes from a closed registry kept by the Box operator. A name outside the registry is rejected by the shared validator in `fleet-core`.
- Profile input for `tools` is TOML only. JSON profile input does not accept the field.
- Server-stored profiles only. A profile read from a repo carries no `tools`: `Profile::from_json` in `fleet-core` is the entry for untrusted input and returns `ProfileError::ToolsNotAllowed` for a non-empty `tools`. Only `Profile::from_stored_json` accepts the field, and only a caller that re-validates the profile and checks its hash against a trusted reference may use it.

### Hash

ADR-0035 hashes `sha256("fleet-profile-v1\0" + canonical bytes)`. A profile with no `tools` keeps the `fleet-profile-v1` prefix, so every existing hash stays valid. A profile that uses `tools` hashes with the prefix `fleet-profile-v2\0`. The hash therefore covers the tool list.

### Bundled mise

- fleetd bundles one pinned mise build for linux x64 musl. No other OS or architecture has a build: a Box of another kind cannot run a profile with `tools`, and the design names no fallback for it.
- Before the first run fleetd verifies the binary by sha256 and by minisign. A failed check blocks the install and fails the Job with a fixed error.
- mise is MIT licensed. Redistribution is allowed with the licence notice, which ships beside the binary.

### Install

- fleetd runs `mise install --locked` as the fleet-job uid in a sandboxed template unit.
- The unit sets `MISE_SAFE=1`.
- fleetd writes the mise config from the Profile `tools` list. A repo `mise.toml` is never read.
- Backends are limited to `aqua`, `github`, `http` and core tools. The lockfile pins no artifact for `cargo`, `npm`, `pypi`, `go` and `ubi`, so `--locked` cannot hold them.

### Egress

Egress stays Box-only under ADR-0038. A profile cannot add hosts. The Box allowlist must cover the hosts the install needs (see Researched facts). The install unit runs with `PrivateNetwork=yes` and reaches the network through the four proxy variables fleetd writes to `tool-env`, which name the loopback proxy of ADR-0031. The allowlist therefore binds only once that proxy enforces it; with the proxy not enforcing, the install has no egress filter.

### Cache and PATH

- The cache is keyed by tool name and version.
- Only the install unit writes the cache. It runs as the install uid, which owns the cache directory under `/var/lib/fleet/tools`, and the agent unit has no write access. A tool lands in the cache only through `mise install --locked` from a registry name and an exact version. What the cache holds is as trusted as the artifacts mise fetched, and the design adds no check of the cache contents at read time.
- The agent unit mounts the cache read-only.
- fleetd builds `PATH` for the agent. Neither the profile nor the repo sets it.

### Server gate

The server has only box and client scopes (`crates/fleet-server/src/auth.rs`), so no per-user permission can gate `tools`. The operator enables the field with a server config switch. With the switch off, `CreateProfile` rejects a profile that has `tools`.

## Researched facts

Marked unverified until a live run confirms them:

- `MISE_SAFE=1` takes effect with `mise install`. Unverified.
- Egress hosts for the install: `api.github.com`, `github.com`, the GitHub asset hosts and the mise-versions host. Unverified.
- The attestation verify command for the bundled binary. Unverified.
- The lockfile pins no artifact for `cargo`, `npm`, `pypi`, `go` and `ubi`, so `--locked` cannot hold them. Unverified: it is a claim about mise lockfile behaviour that no run has checked. The backend limit in Install does not depend on it.
- The install unit reaches the loopback proxy through its `PrivateNetwork=yes` namespace. Unverified.

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
