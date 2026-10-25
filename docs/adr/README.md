# Architecture decision records

ADRs for fleetd, the Fleet server and the `fleet` CLI. The plan is in `../plan.md`. Numbers continue from a private earlier series, so this index starts at 0011.

| ADR | Title | Status |
|---|---|---|
| [0011](0011-fleetd-box-daemon.md) | fleetd box daemon | Accepted, "No git" rule superseded in part by 0020 and 0024 (built, run by the daemon) |
| [0012](0012-event-model-and-delivery.md) | Event model and delivery | Accepted, stream and ack parts superseded by 0018 |
| [0013](0013-fleet-server-stack.md) | Fleet server stack | Accepted, service layout and "No transcripts" amended by 0021 and 0022 (built in the server), monthly partitions superseded by 0019 |
| [0014](0014-box-to-server-bearer-token.md) | Box to server bearer token | Accepted, single token superseded by 0023 (built in the server) |
| [0015](0015-fleet-reads-from-the-server.md) | Fleet reads from the server | Accepted |
| [0016](0016-job-queue-claim-and-lease.md) | Job queue, claim and lease | Accepted, pueue runner, `CLAIMED` state, heartbeat lease and `retry_on_lost` superseded by 0020 and 0021 (both built, run by the daemon and the server) |
| [0017](0017-public-repo-and-mise-distribution.md) | Public repo and mise distribution | Accepted |
| [0018](0018-ingest-protocol.md) | Ingest protocol | Accepted |
| [0019](0019-events-storage.md) | Events storage | Accepted |
| [0020](0020-job-runner-in-fleetd.md) | Job runner in fleetd | Accepted, workspace, runner, push and pull request step, poller and gRPC reporter built and run by the daemon, supersedes the pueue and `fleet-job` parts of 0016 and the "No git" rule of 0011 |
| [0021](0021-job-protocol.md) | Job protocol | Accepted, built in the server and the daemon, supersedes the claim and lease sketch of 0016 where they differ |
| [0022](0022-job-transcripts-on-the-server.md) | Job transcripts on the server | Accepted, built in the server, amends 0013 |
| [0023](0023-two-bearer-token-scopes.md) | Two bearer token scopes | Accepted, built in the server, amends 0014 |
| [0024](0024-job-git-credentials-and-permissions.md) | Job git credentials and permission policy | Accepted, runner, push and pull request step and reporter built and run by the daemon, repo host allowlist, cleared workspace git, token host, hardened mirror and scoped fetch credential added, amends 0011 |

Each ADR has a "Decisions (2026-10-24)" section with the choices made when the docs moved into this repo: Apache-2.0 licence, repo github.com/a19simma/fleet, `fleet watch` as a client poll in v1, job cost deferred, Tailscale not a hard dependency.
