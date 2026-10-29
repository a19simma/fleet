# Fleet server stack

Status: Accepted. Service layout and the "No transcripts" bullet amended by ADR-0021 and ADR-0022 (built in the server). The monthly partitioning of `events` and its partition-drop retention are superseded by ADR-0019. "The deploy target is not fixed" amended by ADR-0025: the manifests live in `infra/`.

Fleet state must outlive the laptop's sleep and any single Box. The deployment stack is Rust with tonic, Kubernetes and Argo CD.

## Decision

The Fleet server is a long-running service in Rust, with gRPC through tonic and Postgres through sqlx.

- **Services.** `FleetIngest` for Boxes (events, heartbeat). `FleetWorker` for Boxes (job claim and report). `FleetQuery` for the laptop (fleet view via `ListFleet`; v1 has no preview, events or watch stream rpc). `FleetJobs` for the laptop (submit, get, list, cancel and transcript reads, ADR-0016). One proto package, `fleet.v1`, shared with fleetd and the CLI as a crate.
- **Storage.** Postgres. `events` partitioned monthly on `received_at`. Projections (`boxes`, `sessions`, `jobs`) update in the same transaction as the event insert. `LISTEN/NOTIFY` drives the `Watch` stream so replicas stay possible.
- **Retention.** `events` 30 days, tool events 7 days, by dropping partitions. `jobs` and `job_attempts` 1 year.
- **Location.** A hosted service reachable over a VPN. Any VPN works, for example Tailscale or netbird. The server address is plain config, `FLEET_SERVER_URL` in `/etc/swarm/box.env`, transport-agnostic: any routable network path, TLS optional by deployment: fleetd accepts `https://` URLs (ADR-0014, amended 2026-10-25). The server and proto read no VPN state, so a VPN switch is a config change plus a note here. Box auth is a bearer token, and the laptop has its own client token (ADR-0014, amended 2026-10-24). The deploy target is not fixed by this ADR.
- **No transcripts.** The server stores prompts and last messages, never transcripts or raw pueue logs.

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- The server serves `FleetIngest`, `FleetQuery.ListFleet`, `FleetWorker` and `FleetJobs`. `fleet watch` polls `GetJob` from the client to follow one job, so the `Watch` rpc and its `LISTEN/NOTIFY` feed wait until after v1.
- Tailscale is not a hard dependency.

## Consequences

- One language and one proto crate across fleetd, server and CLI.
- A database to back up. Losing it loses fleet history. Results still live on git remotes.
- The server is a new availability dependency. Boxes queue events while it is away (ADR-0012).
- Tailscale is not a dependency. Any VPN or routable path works, and an existing VPN carries only ssh access and Template provisioning, outside fleet traffic.
- Prompts are sensitive data at rest. The database follows the same care as Box credentials.

## Amendments

- **Services (ADR-0021), built.** Claim and lease move off `FleetIngest` to a new box-scope service, `FleetWorker` (`ClaimJob`, `ReportJob`). `FleetIngest` keeps events and heartbeat. `FleetJobs` gains `GetJob`, `ListJobs` and `ReadTranscript`. `QueueDepth` and drain are not part of the first job system.
- **Transcripts (ADR-0022), built.** "No transcripts" now holds only for the session transcripts fleetd reads for previews. The server stores the stream-json output of Jobs in `job_transcript`, capped at 4 MiB per Job.
- **Credentials (ADR-0040), not built.** Postgres also holds `credentials` and `credential_use`, sealed with XChaCha20-Poly1305 under a master key file. It protects DB backups and read-only SQL, not a compromised server pod.
- **Retention.** `job_attempts` is not created in the first job system, so only `jobs` and `job_transcript` exist. The one year retention of `jobs` stands. No transcript retention job is designed.

## Considered and rejected

- **HTTP and JSON only.** No streaming for `Watch` and `PushEvents`, and no generated clients.
- **A message broker (NATS, Kafka) in front of Postgres.** A second stateful service for tens of events per second.
- **SQLite on the server.** One writer and no replica path, and the deployment stack already runs Postgres.
- **Another language.** Splits the toolchain from the deployment stack.
