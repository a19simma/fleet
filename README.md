# Fleet

Fleet shows what every agent box is doing and whether anything died. It has three parts:

- `fleetd`: a per-box daemon. It listens on loopback for agent hooks and reports to the server.
- `fleet-server`: the hosted service that stores box state.
- `fleet`: the command line client.

Status: pre-alpha. `fleetd` accepts Claude Code hooks on loopback and local events on a unix socket, normalizes and redacts them, and queues them in SQLite. A forwarder module (batched send, ack through the reply) is built and tested, but the daemon does not start it, so queued events do not leave the Box. 

While `FLEET_SERVER_URL` is set it sends a heartbeat to the server every 30 s with `FLEET_TOKEN`. While both are set it also polls `ClaimJob` every 5 s and runs one job at a time: `claude -p` in a git worktree, then it pushes `swarm/<job_id>` and opens the pull request with `gh`, streaming the transcript through `ReportJob`. 

`fleet` lists boxes and jobs, submits, shows (with the job telemetry summary, and `status --tools` lists its tool calls), watches, follows the logs of and cancels jobs. `fleet timing` shows where the time of a job went and `fleet stats` aggregates the fleet. `fleet profile` manages Profiles and their selection, `fleet credential` lists, stores, deletes and verifies credentials (the secret comes from stdin), `fleet repo add`, `list` and `remove` manage the repositories you work on (`add` checks each one with the forge, `list` shows the host in punycode form and whether the repository is runnable), `fleet host add`, `list` and `remove` manage the git hosts, with `approve-private`, `revoke-private` and `requests` for the private-address approval flow (`add` refuses a host that resolves to a private address until an admin approves the addresses `requests` lists). `remove`, `approve-private`, `revoke-private` and `requests` are admin only and print a fixed notice to anyone else. The shared `FLEET_CLIENT_TOKEN` acts as the bootstrap user, which is never an admin, so the admin host commands need a per-user API token created in the web UI. `fleet work` manages Work projects, items, dependencies, claims, attempt verdicts, notes and Defers on the server, and `fleet catalog` and `fleet user cap` are the admin commands for the Catalog and the capabilities. 

`fleet-server` serves `FleetIngest`, `FleetQuery`, `FleetWorker` (including `ReportTiming` and `ReportShellLog`), `FleetJobs` (including `GetJobTiming` and `StreamShellLog`), `FleetProfiles`, `FleetCatalog`, `FleetJudge`, `FleetBatches`, `FleetCredentials`, `FleetRepos` and `FleetHosts` over gRPC on Postgres, with two scoped bearer tokens and per-user API tokens. The `FleetCatalogAdmin` and `FleetCapabilityAdmin` services accept only the API token of an admin user. A web UI on the same port shows jobs, job timing, profiles, the Catalog and the capability toggle, and has the Credentials, Tokens and Repositories pages. `GET /healthz` answers on the health listener. See `crates/fleet-server/README.md`. 

`FLEET_DATABASE_URL` and `FLEET_TOKEN` are required. `FLEET_CLIENT_TOKEN` is optional (an empty value counts as unset): without it the static client token is off, and the client-scope services accept only per-user API tokens. `FLEET_MAX_CI_RETRIES` (0 to 5, default 0) caps the automatic CI retry chain and 0 turns it off. `FLEET_MODEL_ALLOWLIST` is an optional comma-separated list of exact model ids a Profile may name, and the matching fleetd key is `model_allowlist`. `FLEET_LISTEN` defaults to `127.0.0.1:7070` and `FLEET_HEALTH_LISTEN` to `0.0.0.0:7072`. The server warns at startup when either address is not loopback.

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

Each test opens up to five pooled connections plus one setup connection, and a Postgres default `max_connections` of 100 runs out at about 16 parallel tests, which fails with `sorry, too many clients already` or a 30 s `PoolTimedOut`. `.cargo/config.toml` caps `RUST_TEST_THREADS` at 8 for `cargo test`. `.config/nextest.toml` sets the same 8 threads and puts the Postgres and child-spawning tests in groups that cap their parallelism. nextest is pinned in `mise.toml` and is required for the in-container `linux_uid` run (`cargo nextest run -p fleetd --test linux_uid --run-ignored only`). CI runs `cargo nextest run --workspace --no-fail-fast` then `cargo test --workspace --doc`, and also the css, update-key, linux-it, infra and scan jobs. Passing `--test-threads` or running the test binaries directly bypasses that cap, so start Postgres with `-c max_connections=300` when you do. Only one process per test binary may use a Postgres at a time, because `sqlx::test` derives database names from the test path.

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

`fleet-server` serves plaintext h2c gRPC and does no TLS itself. Run it behind a TLS-terminating Gateway or ingress. fleetd and the `fleet` CLI both accept an `https://` server URL, with the same crypto provider (rustls with ring) and the bundled webpki roots, so the token is sent encrypted to the gateway. The gateway-to-pod hop depends on the cluster: it is plaintext h2c unless a `BackendTLSPolicy` or a service mesh encrypts it. A certificate the roots do not vouch for fails the call, and `http://` URLs still work. It binds loopback by default and logs a warning at start when `FLEET_LISTEN` is any non-loopback address. The container image sets `FLEET_LISTEN=0.0.0.0:7070` so it stays reachable. `FLEET_TOKEN` (box token: `FleetIngest`, `FleetWorker`) and `FLEET_CLIENT_TOKEN` (client token: `FleetQuery`, `FleetJobs`, `FleetJudge`, `FleetProfiles`, `FleetBatches`, `FleetCredentials`, `FleetRepos`, `FleetHosts`, `FleetCatalog`) must each be at least 32 characters with no surrounding whitespace, and, when the client token is set, the two must differ from each other. `FLEET_CLIENT_TOKEN` is optional. A valid token on a service outside its scope, or on an unknown path, gets `PERMISSION_DENIED`; a missing or unknown token gets `UNAUTHENTICATED`. One box token is shared by every box, so a leaked box token can ingest events and claim Jobs as any box, but cannot read the fleet or submit Jobs. Per-box tokens are planned.

Telemetry retention: `fleet-server` deletes job events 90 days and job summaries 365 days after the job finished (`finished_at`, else `created_at`), and only for jobs in `SUCCEEDED`, `FAILED`, `CANCELLED` or `LOST`. `QUEUED` and `RUNNING` jobs are never pruned. Job rows and transcripts are kept. `GetJob` still returns a pruned job without its summary, and `ReadJobEvents` returns an empty page. `FLEET_EVENTS_RETENTION_DAYS` (default 90) and `FLEET_SUMMARIES_RETENTION_DAYS` (default 365) accept 1 to 3650, and the summaries value must not be below the events value. `FLEET_RETENTION_INTERVAL_SECS` (default 3600, minimum 60) sets the pause between sweeps. Each sweep deletes in statements of 5000 rows, at most 20 statements per table, so a backlog drains over several sweeps. An invalid value stops startup with an error that names the variable. The log shows counts only.

fleetd binds 127.0.0.1 only and listens on the unix socket for `POST /event`. With `agent_launcher = "systemd"` on a host network namespace it also runs a per-job OTLP receiver for Claude jobs and reports the job timing to the server (`crates/fleetd/CLAUDE.md`). All seven managed hooks are command hooks that run `fleetd hook <Event>`. Each one sends `X-Fleet-Job` from `FLEET_JOB_ID` when set. Settings, the systemd unit and the Claude Code hook config are in `deploy/README.md`.

## Licence

Apache-2.0. See `LICENSE`.
