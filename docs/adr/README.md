# Architecture decision records

ADRs for fleetd, the Fleet server and the `fleet` CLI. The plan is in `../plan.md`. Numbers continue from a private earlier series, so this index starts at 0011.

| ADR | Title | Status |
|---|---|---|
| [0011](0011-fleetd-box-daemon.md) | fleetd box daemon | Accepted, "No git" rule superseded in part by 0020 and 0024 (built, run by the daemon) |
| [0012](0012-event-model-and-delivery.md) | Event model and delivery | Accepted, stream and ack parts superseded by 0018 |
| [0013](0013-fleet-server-stack.md) | Fleet server stack | Accepted, service layout and "No transcripts" amended by 0021 and 0022 (built in the server), monthly partitions superseded by 0019, deploy target amended by 0025 |
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
| [0024](0024-job-git-credentials-and-permissions.md) | Job git credentials and permission policy | Accepted, runner, push and pull request step and reporter built and run by the daemon, repo host allowlist, cleared workspace git, token host, hardened mirror and scoped fetch credential added, amends 0011, Known limit superseded by 0031 |
| [0025](0025-fleet-infra-directory-and-scoped-deploy.md) | Fleet infra directory and scoped deploy | Accepted, built, amends 0013 |
| [0028](0028-eval-judge-and-ci-follow-up.md) | Eval, judge and CI follow-up | Accepted 2026-10-27, CI retry built, rest not built, builds on 0029 and 0030, amends 0021 and 0023 |
| [0029](0029-job-telemetry.md) | Job telemetry | Accepted, built in the daemon and the server, amends 0021, beside 0022 |
| [0030](0030-metrics-and-improvement-loop.md) | Metrics and the improvement loop | Accepted, `GetStats`, caps and shadow stuck detector built, enforcement not built, builds on 0029 |
| [0031](0031-agent-isolation.md) | Agent isolation | Accepted 2026-10-26, P1 built behind `agent_launcher = "systemd"` and cut over on the first Box, P2 not built, P3 clone and publish built, supersedes the Known limit paragraph of 0024 and amends its credential and mirror-hardening sections |
| [0033](0033-credential-delivery.md) | Credential delivery | Proposed 2026-10-29, not built, builds on 0035, 0040 and 0043, amends 0014, 0021, 0023, 0024, 0031 and 0037 |
| [0034](0034-profiles-and-batches.md) | Profiles and batches | Accepted 2026-10-27, storage, profile and batch RPCs and `fleet batch show` and `fleet batch submit` built, fleetd profile apply and clone by commit id built, live probe not run, amends 0021, 0023, 0029 and 0030 |
| [0035](0035-profile-blob-distribution.md) | Profile blob distribution | Accepted 2026-10-27, server side and fleetd materialisation built, amends 0021 and 0023, implements 0034 |
| [0036](0036-per-job-unix-socket.md) | Per-job unix socket | Proposed 2026-10-28, not built, systemd launcher only, amends 0031 |
| [0037](0037-credential-broker.md) | Credential broker | Proposed 2026-10-28, built as library code and not wired, push op built on 0031 P3, builds on 0028 and 0036, amends 0024 and 0031 |
| [0038](0038-fetch-tool-and-box-egress-policy.md) | Fetch tool and Box egress policy | Proposed 2026-10-28, fetch core, fetch event and fetch service built and wired under the systemd launcher, amends 0029, 0031 and 0034 |
| [0039](0039-job-socket-service-registration.md) | Job socket service registration | Proposed 2026-10-28, `PerJob` registry built, not wired, supersedes the unspecified service registration in 0036, 0037 and 0038 |
| [0040](0040-credential-store-and-key-custody.md) | Credential store and key custody | Proposed 2026-10-29, not built, amends 0013, builds on 0043 |
| [0043](0043-agent-credential-kinds-and-shapes.md) | Agent credential kinds and shapes | Proposed 2026-10-29, not built, builds on 0040, supersedes the box PAT decision for user Jobs |
| [0041](0041-web-ui.md) | Web UI | Proposed 2026-10-29, not built, spike passed with workarounds, amends 0013 |
| [0042](0042-users-and-auth.md) | Users and auth | Proposed 2026-10-29, not built, amends 0013 and 0014, builds on 0041 and 0040 |
| [0044](0044-agent-runners.md) | Agent runners | Proposed 2026-10-29, not built, builds on 0033 and 0043, amends 0021, 0029, 0034 and 0038 |
| [0045](0045-forge-trait.md) | Forge trait | Proposed 2026-10-29, not built, builds on 0033 and 0043, amends 0024 and 0037 |
| [0046](0046-mirror-key.md) | Mirror key | Proposed 2026-10-29, not built, amends 0024 and 0031 |

Each ADR has a "Decisions (2026-10-24)" section with the choices made when the docs moved into this repo: Apache-2.0 licence, repo github.com/a19simma/fleet, `fleet watch` as a client poll in v1, job cost deferred, Tailscale not a hard dependency.
