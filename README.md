# Fleet

Fleet shows what every agent box is doing and whether anything died. It has three parts:

- `fleetd`: a per-box daemon. It listens on loopback for agent hooks and reports to the server.
- `fleet-server`: the hosted service that stores box state.
- `fleet`: the command line client.

Status: pre-alpha. `fleetd` accepts Claude Code hooks on loopback and local events on a unix socket, normalizes and redacts them, and queues them in SQLite. It does not forward them yet. `fleet list` is a stub. `fleet-server` prints its version.

## Install

Releases are on GitHub. The release holds two tools in separate archives (`fleetd-<target>.tar.gz` and `fleet-cli-<target>.tar.gz`), so a single `github:` entry cannot pick both. Declare each one in `mise.toml` with an `asset_pattern`:

```toml
[tool_alias]
fleetd = "github:a19simma/fleet"
fleet = "github:a19simma/fleet"

[tools.fleetd]
version = "0.1.0"
asset_pattern = "fleetd-x86_64-unknown-linux-musl.tar.gz"

[tools.fleet]
version = "0.1.0"
asset_pattern = "fleet-cli-x86_64-unknown-linux-musl.tar.gz"
```

The `fleet-cli` archive installs the `fleet` binary. Use the `aarch64-unknown-linux-musl` names on ARM. A wildcard pattern such as `fleetd-*` ignores the platform, so name the target.

To build from source instead, see below.

## Build from source

Needs Rust 1.88 or newer.

```sh
cargo build --release --workspace
```

Binaries land in `target/release/`.

## Run

```sh
FLEETD_PORT=7071 FLEETD_DB=./fleetd.db FLEETD_SOCKET=./fleetd.sock target/release/fleetd
curl http://127.0.0.1:7071/healthz
curl -X POST http://127.0.0.1:7071/hook/Stop -d '{"session_id":"s-1","last_assistant_message":"ok"}'
target/release/fleetd dump
```

fleetd binds 127.0.0.1 only and listens on the unix socket for `POST /event`. Settings, the systemd unit and the Claude Code hook config are in `deploy/README.md`.

## Licence

Apache-2.0. See `LICENSE`.
