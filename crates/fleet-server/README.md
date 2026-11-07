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
| `FleetJudge`, `FleetBatches`, `FleetCredentials` | see `crates/fleet-proto/proto/fleet/v1/fleet.proto` | client |
| `FleetCatalogAdmin` | `UpsertCatalogItem`, `SetCatalogItemEnabled` | admin user API token |
| `FleetCapabilityAdmin` | `GrantCapability`, `RevokeCapability`, `ListCapabilities` | admin user API token |

`GET /healthz` answers on the health listener. The box and client tokens are the two static bearer tokens. A per-user API token carries a user, and the two admin services accept only a token whose user has `users.is_admin` set (ADR-0056). Every other request goes to the web UI.

## Modules

- `catalog`: the global Catalog of skill, subagent, tool and context items (ADR-0053). An admin creates and enables items through `FleetCatalogAdmin` or the `/catalog` pages. A Profile switches items off and the effective set is resolved at submit.
- `cred::capability`: per-user capability grants. `profile:tools` (ADR-0054) lets a user save a Profile with tools. `forge:github_app` (ADR-0058) gates the `github_app` credential kind at put, release and verify through `cred::store::required_capability`, which maps the `github_app` kind. Migration 0034 widens the table CHECK to both names, and the admin capability page lists, grants and revokes each one.
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
