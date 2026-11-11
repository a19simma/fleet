# fleet-server

The hosted Fleet service. It stores box state, jobs, transcripts, job timing and profiles in Postgres, serves gRPC and a web UI on one port, and leases jobs to `fleetd`.

## Services

| Service | RPCs | Token |
|---|---|---|
| `FleetIngest` | `PushEvents`, `Heartbeat` | box |
| `FleetWorker` | `ClaimJob`, `ReportJob`, `GetProfileBlob`, `GetJobTranscript`, `GetJobCredentials`, `ReportTiming`, `ReportShellLog` | box |
| `FleetQuery` | `ListFleet` | client |
| `FleetJobs` | `SubmitJob`, `GetJob`, `ListJobs`, `CancelJob`, `ReadTranscript`, `ReadJobEvents`, `GetStats`, `GetJobTiming`, `StreamShellLog` | client |
| `FleetProfiles` | `CreateProfile`, `GetProfile`, `ListProfiles`, `ShareProfile`, `UnshareProfile` | client |
| `FleetCatalog` | `ListCatalog` | client scope, admin user only |
| `FleetRepos` | `AddRepo`, `ListRepos`, `RemoveRepo` (ADR-0059): verify before insert, per-User rows, at most 100 repositories per User, 10 checks per User per 60 s, 8 concurrent checks | client scope, interactive user only |
| `FleetHosts` | `AddHost`, `ListHosts`, `RemoveHost`, `ApproveHostPrivate`, `RevokeHostPrivate`, `ListHostRequests` (ADR-0068): vet, identify and insert in one transaction, at most 20 hosts per User and 500 in total, the per-User check limiter, one `host_audit` row per add and remove. `RemoveHost`, `ApproveHostPrivate`, `RevokeHostPrivate` and `ListHostRequests` are admin only, and `RemoveHost` refuses a host with credentials or repositories. `GetJobCredentials` (`FleetWorker`) reads the Job repository host from `git_hosts` live under `FOR SHARE`; a Job on a host with no row, a `github` row off `github.com`, a Forgejo host without `allow_private` whose registered repository has the epoch `verified_at` that a revoke writes, or a repository that does not parse, is refused with `PRECONDITION_HOST_NO_CREDENTIAL` before any credential is opened or App token minted. The reply holds one `hosts` entry: `github.com` repeats the forge credential, a Forgejo host carries only its `forgejo_pat` | client scope, any user adds and lists |
| `FleetJudge`, `FleetBatches`, `FleetCredentials` | see `crates/fleet-proto/proto/fleet/v1/fleet.proto` | client |
| `FleetCatalogAdmin` | `UpsertCatalogItem`, `SetCatalogItemEnabled` | admin user API token |
| `FleetCapabilityAdmin` | `GrantCapability`, `RevokeCapability`, `ListCapabilities` | admin user API token |

`GET /healthz` answers on the health listener. The box and client tokens are the two static bearer tokens. A per-user API token carries a user, and the two admin services accept only a token whose user has `users.is_admin` set (ADR-0056). Every other request goes to the web UI.

## Modules

- `catalog`: the global Catalog of skill, subagent, tool and context items (ADR-0053). An admin creates and enables items through `FleetCatalogAdmin` or the `/catalog` pages. A Profile switches items off and the effective set is resolved at submit.
- `cred::capability`: per-user capability grants. `profile:tools` (ADR-0054) lets a user save a Profile with tools. `forge:github_app` (ADR-0058) gates the `github_app` credential kind at put, release and verify through `cred::store::required_capability`, which maps the `github_app` kind. Migrations 0034 and 0039 widen the table CHECK to three names, adding `env:scripts` (ADR-0067), and the admin capability page lists, grants and revokes each one.
- `cred::https`, `cred::pinned`: the shared https client plumbing and the SSRF-safe forge connector (ADR-0059). The connector:
  - resolves a host once and vets every address with `is_vetted`;
  - admits global unicast only: metadata addresses, loopback, link-local, CGNAT `100.64/10`, documentation and 6to4 ranges are always refused;
  - `allow_private` admits only RFC 1918 and ULA;
  - dials the vetted IP with SNI and certificate checks by host name;
  - follows no redirect and caps the body at 256 KiB.
- `hosts`: the `git_hosts` store and the `FleetHosts` add, list, remove, approve, revoke and list-requests handlers. A refused add is `NOT_ALLOWED_HOST` for any grammar, private-address or unresolvable cause, so the answer does not map a private network.
- `cred::repo_api`, `cred::repo_store`, `cred::repo_limit`: the `FleetRepos` handlers, the per-User registry table and the per-User check limiter (ADR-0059). Until migration 0037 adds `credentials.host`, `add` binds an unhosted GitHub credential to `github.com`: another github-kind host answers `NO_CREDENTIAL`.
- `cred::repo_verify`, `cred::repo_fake`: the `RepoVerifier` trait, the GitHub verifier and the `RepoVerifiers` registry. A check runs under `REPO_CHECK_BUDGET` (7 s, below `CALL_BUDGET`) and refuses with one of five `RepoRefusal` values, one per `PRECONDITION_REPO_*` reason. The transport is an injected seam. `FakeVerifier` models every state for handler tests. Callers parse a repository with `RepoRef::parse_as` using the kind the registry reports.
- `web::repos`: the repositories page, `GET /repos`, `POST /repos/add` and `POST /repos/remove` (ADR-0059). It needs a session, and every POST the session CSRF token. It answers 404 when the server runs without a repository registry. Outcomes redirect to `/repos?notice=<code>` with a fixed `CredentialNotice` code, the same text `fleet repo` prints. Hosts and paths show through `fleet_core::repo::ascii_form` (punycode host), and the remove form carries a row as lowercase hex. Topcoat already escapes attribute values, so the hex key is defence in depth: no stored host or path reaches an attribute as text. The verified time is the UTC stamp of `fleet_core::stamp::utc_stamp`, the same text `fleet repo list` prints. Form bodies are capped at `MAX_BODY_BYTES` (64 KiB) by the app-wide `BodyLimit` layer.
- `update_feed`: the release feed cache, seq gate and poller (ADR-0060). `FeedCache` holds the last good manifest and signature pair in memory. Its gate stores a first or higher `seq`, heals a torn pair when only the signature differs, and rejects a lower `seq`, an equal `seq` with different manifest bytes, a non-JSON manifest, a bad `seq` and an over-cap body. It never verifies the signature: fleetd does. `FeedPoller` polls a `FeedSource` (the real one is `ReleaseFeed`) in a spawned task with plus or minus 10 percent jitter, doubles the wait on each failure, up to the larger of 1 hour and the poll interval, resets it only after an accepted pair, and stops on its `stop_rx`. `UpdateRelay::from_feed(cache)` serves the cached pair in `HeartbeatReply`: no fields while the cache is empty, then the pair after the first accepted fetch. `main.rs` spawns the poller only when `FLEET_UPDATE_REPO` is set and stops it on the shutdown signal, and a slow first fetch never delays readiness. An empty `FLEET_UPDATE_REPO` means no feed, silently.
- `timing`: stores the `ReportTiming` breakdown and the shell command logs a box reports, and serves `GetJobTiming` and `StreamShellLog` (ADR-0055). The pages are `/jobs/{job_id}/timing` and `/jobs/{job_id}/shell/{command_id}/log`.
- `profiles`: owner-scoped Profiles with `private` and `shared` visibility (ADR-0052).
- `retention`: the telemetry retention sweep. See the root `README.md` for the variables.
- `reaper`: marks jobs `LOST` when a lease expires.

## Configuration

| Variable | Meaning |
|---|---|
| `FLEET_DATABASE_URL` | Postgres URL. Required. |
| `FLEET_TOKEN` | Box token. Required. |
| `FLEET_CLIENT_TOKEN` | Client token. Optional. Acts as the `bootstrap` user: never admin, no capabilities. |
| `FLEET_MODEL_ALLOWLIST` | Comma-separated exact model ids a Profile may name. Unset allows every model. A bad list stops startup. Checked at Profile create, update, submit, batch pin and blob serve. |
| `FLEET_GITHUB_APP_ID`, `FLEET_GITHUB_APP_KEY_FILE` | GitHub App id and private key path. Set both or neither (ADR-0058). |
| `FLEET_GITHUB_APP_BOT_NAME`, `FLEET_GITHUB_APP_BOT_EMAIL` | Git author name and email for App Jobs. Required when the App is set, checked by the identity grammar (ADR-0058 SEC-006). |
| `FLEET_GITHUB_APP_ACCOUNT` | Operator GitHub login that owns the installation. Required when the App is set (ADR-0058 SEC-014). |
| `FLEET_GITHUB_APP_INSTALLATIONS`, `FLEET_GITHUB_APP_REPOS` | Comma separated installation ids and `owner/name` or `owner/*` repository entries. Unset allows nothing (ADR-0058 SEC-001, SEC-002). |
| `FLEET_REPO_HOSTS` | Repository hosts a User may add: `host=H,forge=github\|forgejo,api=URL[,allow_private=true\|false]` entries joined by `;`. Unset allows `github.com`. Empty refuses every add. The last host label must start with a letter, an `api` path segment is at most 64 bytes, and `.` and `..` segments are refused. A bad value stops startup without echoing it. Full rules in `infra/README.md`. |
| `FLEET_MAX_CI_RETRIES` | Automatic CI retry cap, 0 to 5. |
| `FLEET_LISTEN`, `FLEET_HEALTH_LISTEN` | Listen addresses. |
| `FLEET_EVENTS_RETENTION_DAYS`, `FLEET_SUMMARIES_RETENTION_DAYS`, `FLEET_RETENTION_INTERVAL_SECS` | Retention sweep. |

`fleet-server admin` creates users, resets passkeys and grants or revokes admin by direct database access, and writes an `admin_audit` row for each action.

## Test

The store tests need `DATABASE_URL` set to a Postgres superuser URL. See the root `README.md`.
