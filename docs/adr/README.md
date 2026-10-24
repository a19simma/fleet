# Architecture decision records

ADRs for fleetd, the Fleet server and the `fleet` CLI. The plan is in `../plan.md`. Numbers continue from a private earlier series, so this index starts at 0011.

| ADR | Title | Status |
|---|---|---|
| [0011](0011-fleetd-box-daemon.md) | fleetd box daemon | Accepted |
| [0012](0012-event-model-and-delivery.md) | Event model and delivery | Accepted |
| [0013](0013-fleet-server-stack.md) | Fleet server stack | Accepted |
| [0014](0014-box-to-server-bearer-token.md) | Box to server bearer token | Accepted |
| [0015](0015-fleet-reads-from-the-server.md) | Fleet reads from the server | Accepted |
| [0016](0016-job-queue-claim-and-lease.md) | Job queue, claim and lease | Accepted |
| [0017](0017-public-repo-and-mise-distribution.md) | Public repo and mise distribution | Accepted |

Each ADR has a "Decisions (2026-10-24)" section with the choices made when the docs moved into this repo: Apache-2.0 licence, repo github.com/a19simma/fleet, `fleet watch` as a client poll in v1, job cost deferred, Tailscale not a hard dependency.
