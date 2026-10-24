# Fleet

Fleet shows what every agent box is doing and whether anything died. It has three parts:

- `fleetd`: a per-box daemon. It listens on loopback for agent hooks and reports to the server.
- `fleet-server`: the hosted service that stores box state.
- `fleet`: the command line client.

Status: pre-alpha. `fleetd` accepts Claude Code hooks on loopback and local events on a unix socket, normalizes and redacts them, and queues them in SQLite. A forwarder module (batched send, ack through the reply) is built but fleetd does not run it yet, so nothing leaves the queue. `fleet list` is a stub. `fleet-server` serves `FleetIngest` (`PushEvents`, `Heartbeat`) and `FleetQuery.ListFleet` over gRPC on Postgres, with a bearer token, and `GET /healthz`. `FLEET_DATABASE_URL` and `FLEET_TOKEN` are required. `FLEET_LISTEN` defaults to `127.0.0.1:7070` and `FLEET_HEALTH_LISTEN` to `0.0.0.0:7072`. The server warns at startup when either address is not loopback.

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

## Test

The `fleet-server` store tests need a Postgres superuser URL in `DATABASE_URL`. `#[sqlx::test]` creates one database per test from it, and a test fails when the variable is missing. `compose.test.yaml` starts a matching `postgres:17`:

```sh
docker compose -f compose.test.yaml up -d --wait
export DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres
cargo test --workspace
docker compose -f compose.test.yaml down
```

The `docker compose` plugin may be missing. This `docker run` starts the same database, published on loopback only:

```sh
docker run -d --rm --name fleet-test-pg -e POSTGRES_PASSWORD=postgres -p 127.0.0.1:5432:5432 --tmpfs /var/lib/postgresql/data postgres:17
docker exec fleet-test-pg pg_isready
docker rm -fv fleet-test-pg
```

## Run

```sh
FLEETD_PORT=7071 FLEETD_DB=./fleetd.db FLEETD_SOCKET=./fleetd.sock target/release/fleetd
curl http://127.0.0.1:7071/healthz
curl -X POST http://127.0.0.1:7071/hook/Stop -d '{"session_id":"s-1","last_assistant_message":"ok"}'
target/release/fleetd dump
```

`fleet-server` serves plaintext h2c gRPC and does no TLS itself. Run it behind a TLS-terminating Gateway or ingress. It binds loopback by default and logs a warning at start when `FLEET_LISTEN` is any non-loopback address. The container image sets `FLEET_LISTEN=0.0.0.0:7070` so it stays reachable. `FLEET_TOKEN` must be at least 32 characters with no surrounding whitespace. One shared token covers every box and every call, so a leaked token reads and writes the whole fleet. That is a known limit; per-box tokens are planned.

fleetd binds 127.0.0.1 only and listens on the unix socket for `POST /event`. The four http hooks send no job header. The `SessionStart` command hook, `fleetd hook SessionStart`, sends `X-Fleet-Job` from `FLEET_JOB_ID` when set. Settings, the systemd unit and the Claude Code hook config are in `deploy/README.md`.

## Licence

Apache-2.0. See `LICENSE`.
