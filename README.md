# Fleet

Fleet shows what every agent box is doing and whether anything died. It has three parts:

- `fleetd`: a per-box daemon. It listens on loopback for agent hooks and reports to the server.
- `fleet-server`: the hosted service that stores box state.
- `fleet`: the command line client.

Status: pre-alpha. `fleetd` serves `GET /healthz` and nothing else. `fleet list` is a stub. `fleet-server` prints its version.

## Install

Releases are not published yet. Once the first tag exists, install with mise:

```sh
mise use -g "github:a19simma/fleet"
```

The release holds two tools in separate archives (`fleetd-<target>.tar.gz` and `fleet-cli-<target>.tar.gz`), so a single `github:` entry cannot pick both. Pin each one with an `asset_pattern`:

```toml
[tools."github:a19simma/fleet[tool_alias=fleetd]"]
version = "0.1.0"
asset_pattern = "fleetd-*"

[tools."github:a19simma/fleet[tool_alias=fleet]"]
version = "0.1.0"
asset_pattern = "fleet-cli-*"
```

Until then, build from source.

## Build from source

Needs Rust 1.88 or newer.

```sh
cargo build --release --workspace
```

Binaries land in `target/release/`.

## Run

```sh
FLEETD_PORT=7071 target/release/fleetd
curl http://127.0.0.1:7071/healthz
```

`FLEETD_PORT` defaults to 7071. fleetd binds 127.0.0.1 only.

## Licence

Apache-2.0. See `LICENSE`.
