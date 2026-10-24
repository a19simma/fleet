# Fleet server stack

Status: Accepted. The monthly partitioning of `events` and its partition-drop retention are superseded by ADR-0019.

Fleet state must outlive the laptop's sleep and any single Box. The deployment stack is Rust with tonic, Kubernetes and Argo CD.

## Decision

The Fleet server is a long-running service in Rust, with gRPC through tonic and Postgres through sqlx.

- **Services.** `FleetIngest` for Boxes (events, heartbeat, job claim and lease). `FleetQuery` for the laptop (fleet view, preview, events, watch stream; v1 has no watch stream). `FleetJobs` for submit, cancel, queue depth and drain (ADR-0016). One proto package, `fleet.v1`, shared with fleetd and the CLI as a crate.
- **Storage.** Postgres. `events` partitioned monthly on `received_at`. Projections (`boxes`, `sessions`, `jobs`) update in the same transaction as the event insert. `LISTEN/NOTIFY` drives the `Watch` stream so replicas stay possible.
- **Retention.** `events` 30 days, tool events 7 days, by dropping partitions. `jobs` and `job_attempts` 1 year.
- **Location.** A hosted service reachable over a VPN. Any VPN works, for example Tailscale or netbird. The server address is plain config, `FLEET_SERVER_URL` in `/etc/swarm/box.env`, transport-agnostic: any routable network path, TLS optional by deployment. The server and proto read no VPN state, so a VPN switch is a config change plus a note here. Box auth is a bearer token (ADR-0014). The deploy target is not fixed by this ADR.
- **No transcripts.** The server stores prompts and last messages, never transcripts or raw pueue logs.

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- v1 serves `FleetIngest` and `FleetQuery.ListFleet`. `fleet watch` polls `ListFleet` from the client, so the `Watch` rpc and its `LISTEN/NOTIFY` feed wait until after v1.
- Tailscale is not a hard dependency.

## Consequences

- One language and one proto crate across fleetd, server and CLI.
- A database to back up. Losing it loses fleet history. Results still live on git remotes.
- The server is a new availability dependency. Boxes queue events while it is away (ADR-0012).
- Tailscale is not a dependency. Any VPN or routable path works, and an existing VPN carries only ssh access and Template provisioning, outside fleet traffic.
- Prompts are sensitive data at rest. The database follows the same care as Box credentials.

## Considered and rejected

- **HTTP and JSON only.** No streaming for `Watch` and `PushEvents`, and no generated clients.
- **A message broker (NATS, Kafka) in front of Postgres.** A second stateful service for tens of events per second.
- **SQLite on the server.** One writer and no replica path, and the deployment stack already runs Postgres.
- **Another language.** Splits the toolchain from the deployment stack.
