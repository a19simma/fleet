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
| [0023](0023-two-bearer-token-scopes.md) | Two bearer token scopes | Accepted, built in the server, amends 0014, identity gates the admin services per 0056 |
| [0024](0024-job-git-credentials-and-permissions.md) | Job git credentials and permission policy | Accepted, runner, push and pull request step and reporter built and run by the daemon, repo host allowlist, cleared workspace git, token host, hardened mirror and scoped fetch credential added, amends 0011, Known limit superseded by 0031, amended by 0058 |
| [0025](0025-fleet-infra-directory-and-scoped-deploy.md) | Fleet infra directory and scoped deploy | Accepted, built, amends 0013 |
| [0028](0028-eval-judge-and-ci-follow-up.md) | Eval, judge and CI follow-up | Accepted 2026-10-27, judge Job, CI status and CI retry built, builds on 0029 and 0030, amends 0021 and 0023 |
| [0029](0029-job-telemetry.md) | Job telemetry | Accepted, built in the daemon and the server, amends 0021, beside 0022, superseded in part by 0055 |
| [0030](0030-metrics-and-improvement-loop.md) | Metrics and the improvement loop | Accepted, `GetStats`, caps and shadow stuck detector built, enforcement not built, builds on 0029 |
| [0031](0031-agent-isolation.md) | Agent isolation | Accepted 2026-10-26, P1 built behind `agent_launcher = "systemd"` and cut over on the first Box, P2 built, P3 clone and publish built, supersedes the Known limit paragraph of 0024 and amends its credential and mirror-hardening sections |
| [0033](0033-credential-delivery.md) | Credential delivery | Proposed 2026-10-29, built, builds on 0035, 0040 and 0043, amends 0014, 0021, 0023, 0024, 0031 and 0037, amended by 0058 |
| [0034](0034-profiles-and-batches.md) | Profiles and batches | Accepted 2026-10-27, storage, profile and batch RPCs, `fleet profile item` and `prompt`, `fleet batch show` and `fleet batch submit` built, fleetd profile apply and clone by commit id built, live probe not run, amends 0021, 0023, 0029 and 0030 |
| [0035](0035-profile-blob-distribution.md) | Profile blob distribution | Accepted 2026-10-27, server side and fleetd materialisation built, amends 0021 and 0023, implements 0034, amended by 0057 |
| [0036](0036-per-job-unix-socket.md) | Per-job unix socket | Proposed 2026-10-28, socket, fetch, egress proxy and broker wired under the systemd launcher, mount isolation unverified, amends 0031 |
| [0037](0037-credential-broker.md) | Credential broker | Proposed 2026-10-28, built and wired under the systemd launcher, push op built on 0031 P3, builds on 0028 and 0036, amends 0024 and 0031 |
| [0038](0038-fetch-tool-and-box-egress-policy.md) | Fetch tool and Box egress policy | Proposed 2026-10-28, fetch core, fetch event and fetch service built and wired under the systemd launcher, amends 0029, 0031 and 0034 |
| [0039](0039-job-socket-service-registration.md) | Job socket service registration | Proposed 2026-10-28, `PerJob` registry built and used for fetch, egress proxy and broker, supersedes the unspecified service registration in 0036, 0037 and 0038 |
| [0040](0040-credential-store-and-key-custody.md) | Credential store and key custody | Proposed 2026-10-29, built except the re-seal pass and live key reload, amends 0013, builds on 0043, amended by 0058 |
| [0041](0041-web-ui.md) | Web UI | Proposed 2026-10-29, built, spike passed with workarounds, amends 0013 |
| [0042](0042-users-and-auth.md) | Users and auth | Proposed 2026-10-29, built except login rate limiting, includes the `fleet-server admin` recovery commands, amends 0013 and 0014, builds on 0041 and 0040, amended by 0056 |
| [0043](0043-agent-credential-kinds-and-shapes.md) | Agent credential kinds and shapes | Proposed 2026-10-29, built, builds on 0040, supersedes the box PAT decision for user Jobs, amended by 0058 and 0059 |
| [0044](0044-agent-runners.md) | Agent runners | Proposed 2026-10-29, Codex and Kimi wired, not built: runner-owned command lines and the Codex and Kimi parsers, builds on 0033 and 0043, amends 0021, 0029, 0034 and 0038 |
| [0045](0045-forge-trait.md) | Forge trait | Proposed 2026-10-29, built, builds on 0033 and 0043, amends 0024 and 0037, amended by 0058 and 0059 |
| [0046](0046-mirror-key.md) | Mirror key | Proposed 2026-10-29, wired to the Job owner, amends 0024 and 0031 |
| [0047](0047-fleetd-self-update.md) | fleetd self-update | Proposed 2026-11-01, built and wired, no live run, amends 0017, trust root amended by 0050, amended by 0060 |
| [0048](0048-profile-tools-and-bundled-mise.md) | Profile tools and bundled mise | Proposed 2026-11-01, built, no live run, amends 0034 and 0035, builds on 0038 and 0031, amended by 0054 |
| [0049](0049-job-docker-and-build-egress.md) | Job docker and build-chain egress | Proposed 2026-11-01, spike pending, amends 0031 and 0038 |
| [0050](0050-baked-default-update-trust-root.md) | Baked default update trust root | Proposed 2026-11-01, built, no live run, amends 0047 |
| [0051](0051-web-ui-styling-tailwind-daisyui.md) | Web UI styling: Tailwind and daisyUI, generated CSS committed | Accepted 2026-11-01, built, extends 0041 |
| [0052](0052-profile-ownership-and-visibility.md) | Profile ownership and visibility | Proposed 2026-11-02, built, amends 0034, 0035 and 0048, builds on 0042 |
| [0053](0053-global-catalog-and-profile-selection.md) | Global catalog and profile selection | Proposed 2026-11-02, save-time selection validation, a re-save equal to an older version moves latest, `fleet profile item` and `prompt`, Kimi dropped-subagent job notes, the web selection editor, the Catalog store and pages, `resolve` and the submit snapshot built, Profile preview and job note display not built, amends 0034 and 0035, builds on 0044, 0048 and 0054 |
| [0054](0054-user-capabilities-and-model-allowlist.md) | User capabilities and model allowlist | Proposed 2026-11-02, built, amends 0048, builds on 0035, 0042 and 0044, amended by 0056 and 0058 |
| [0055](0055-job-timing-breakdown.md) | Job timing breakdown and loopback OTLP receiver | Proposed 2026-11-02, built in fleetd and the server except pushing pueue logs, live end-to-end run unverified, supersedes in part and amends 0029, amends 0031 |
| [0056](0056-admin-is-a-user-flag.md) | Admin is a user flag | Proposed 2026-11-04, built, amends 0023, 0042 and 0054, builds on 0042 |
| [0057](0057-profile-version-streams-keyed-by-profile-id.md) | Profile version streams are keyed by profile id | Proposed 2026-11-04, migration written, store not built, amends 0035, builds on 0052 |
| [0058](0058-github-app-lane.md) | GitHub App lane | Proposed 2026-11-06, partly built (CLI credential commands, kind, installation id parser, key loading and JWT signing, token mint with validation and revoke, App id and key file config, mint audit schema, tombstone, forge:github_app capability with its CHECK, admin page and credential gate; save and verify; release path mints at `GetJobCredentials` with expiry and identity; fleetd consumes the token and identity; fleetd refresh and revoke, per-Job mint cap, per-User rate limit and mint audit rows built; delete tombstone, verify under the release gate and startup key checks built; installation and repository allowlists (operator ceiling only) and owner binding built; runbook and end-to-end test built; not built: per-credential repository list, the audit of revokes inside the mint client, a revoke on a cancel during the mint call itself, and a fleetd revoke that survives a daemon exit; operator chose the widened permission set, App settings still to widen), amends 0024, 0033, 0040, 0043, 0045 and 0054, amended by 0059 |
| [0059](0059-user-repo-registry.md) | User repository registry | Proposed 2026-11-07, partly built (repository reference parser in fleet-core, `FLEET_REPO_HOSTS` config, `FleetRepos` proto, migration 0036, repo reasons and notices; also built: https helper, SSRF-safe connector, repo verifier trait, GitHub verifier and registry, `REPO_CHECK_BUDGET`, `FakeVerifier`; `FleetRepos` handlers, `repo_store` with the per-User cap and credential re-check, check limiter; CLI and web page built; not built: Forgejo verifier, credential host column, `forgejo_pat` kind), builds on 0043, 0045 and 0058, amends 0043, 0045 and 0058 (SEC-009 note), amended by 0061 |
| [0060](0060-server-fetches-release-manifest.md) | The server fetches the release manifest | Proposed 2026-11-07, not built (tasks FEED-2 to FEED-7), amends 0047 (relay description only), builds on 0050 |
| [0061](0061-release-download-redirects.md) | Redirects for release downloads over the no-redirect transport | Proposed 2026-11-07, partly built (ForgeGet optional authorization, accept and ForgeReply location; ReleaseFetcher and later tasks not built, FEED-4 to FEED-7), amends 0059 (redirect scope), builds on 0060 |

Each ADR has a "Decisions (2026-10-24)" section with the choices made when the docs moved into this repo: Apache-2.0 licence, repo github.com/a19simma/fleet, `fleet watch` as a client poll in v1, job cost deferred, Tailscale not a hard dependency.
