# Users and auth

Status: Proposed 2026-10-29. Built in fleet-server: users, hashed API tokens, passkey login, server-side sessions, the first-admin setup code, the `fleet-server admin` recovery subcommand, `jobs.user_id` and owner-scoped reads. Not built: login rate limiting and a decoy challenge for unknown usernames. Amends ADR-0013 and ADR-0014. Builds on ADR-0041 (web UI) and ADR-0040 (credential store).

Credentials and the web UI make Fleet multi-user. The shared client token cannot say whose a Job or a credential is. This ADR adds users, browser login, per-user API tokens and Job ownership.

## Decision

### Users and login

- A **User** has a username and one or more passkeys. Login is local username plus passkey through webauthn-rs 0.5.5 (ADR-0041). No passwords. No external identity provider in v1.
- A browser session is a server-side row. The cookie holds an opaque random id only. The `web_sessions` table came with the `jobs.user_id` migration (0018).
- The cookie uses the `__Host-` prefix: `Secure`, `Path=/`, no `Domain`, plus `HttpOnly` and `SameSite=Strict`.
- A session expires after 12 hours absolute or 30 minutes without use, whichever comes first. The idle window slides: each request that resolves the session renews `last_seen`, so a session in steady use lives until the 12 hour limit. The id rotates at login only: a login deletes the session the browser presented and creates a new one in the same transaction as the counter update. Only `login_finish` rotates the id, so a session keeps its id between logins. Logout deletes the row.
- Every state-changing route behind a session carries a CSRF token tied to the session, checked on the server. The Origin check on every POST route, including the pre-session passkey routes that have no token yet, stays on as a second guard and answers 403 for a foreign Origin.

### Bootstrap admin

On first start with no users, the server logs a one-time setup URL containing a random token and holds it in memory until used. Opening it lets the visitor pick a username and register a passkey, which creates the admin. The token dies on use or on restart: a URL logged before a restart stops working, and a restart with still no users logs a new one. The server logs the URL at `warn`, so it sits in shipped logs until someone redeems it. No startup secret in config. The cost: whoever reads the pod log first can claim the admin, so the log is the trust boundary.

### Admin recovery

`fleet-server admin create-user <username>` and `fleet-server admin reset-passkeys <username>` run against the database named by `FLEET_DATABASE_URL`. No web route does this. Each command runs in one transaction that writes an `admin_audit` row and issues a setup code (table `setup_codes`, migration 0020). The server stores the code as a SHA-256 hash. The code works once, expires after 24 hours and prints once to standard output, so it lands in the operator's terminal scrollback.

`reset-passkeys` deletes the user's passkeys and sessions, revokes their API tokens and replaces any open setup code. The reserved `bootstrap` user cannot be targeted. The audit `operator` is the `$USER` of the caller, which is advisory. A failed command rolls back and leaves no audit row. `admin_audit` has no append-only trigger. Database access is the trust boundary: anyone who can write the database can already do all of this. Lookalike usernames are allowed.

### API tokens

- A User creates API tokens in the UI for the CLI. The server stores only the SHA-256 hash (32 bytes) in `api_tokens` (migration 0017). The plaintext shows once at creation.
- Tokens are 256-bit random values, so a plain hash is enough and no slow hash is needed.
- Tokens can be revoked in the UI.

### Ownership

- `jobs.user_id` records the owner. Jobs are owner-only for now: a User lists, reads and cancels only their own. Sharing comes later.
- `credentials.user_id` (ADR-0040) follows the same rule.

### Read scope

Every read and cancel on jobs is scoped to the caller: `GetJob`, `ListJobs`, `CancelJob`, `ReadTranscript`, `ReadJobEvents`, `GetBatch`, the judge target and `GetStats`. Another user's job, batch or transcript answers `NOT_FOUND` with the same message as an unknown id, and a cancel by a non-owner leaves the job untouched. `GetStats` counts only the caller's jobs in every group and under every repo or box filter. `GetBatch` shows the batch row to the owner of any member job and lists only the jobs that user owns. The box token carries no user and reads everything, because the box services need to.

Boxes and sessions have no user owner. `ListFleet` therefore returns every box to every client caller. The bootstrap user and a caller with no user (the box token, the legacy path) see each session in full. Any other user token gets each session with `last_prompt`, `last_message` and `workdir` blanked, because those fields carry other people's prompts and paths. A real owner for boxes and sessions would replace this rule.

### Transition

`FLEET_CLIENT_TOKEN` stays accepted for the existing CLI during transition. A Job submitted with it is stamped to the bootstrap user, the same user the `bootstrap_user_id()` migration function names, because `Job.user_id` cannot express no owner. The shared token is removed in a later ADR once the CLI uses API tokens. `FLEET_TOKEN` (box scope, ADR-0023) is unchanged.

## Consequences

- A lost passkey locks a User out. A second passkey per User is advised. Admin recovery is the `fleet-server admin reset-passkeys` command above.
- The server holds session state, so a session survives a restart and can be revoked.
- Accepted risk (SEC-002): `login/start` answers 400 for an unknown username and a challenge for a known one, so an attacker can enumerate usernames. A decoy challenge needs a fake passkey credential per name and is not built. Usernames are not secret in a small private deployment, and a guess still needs a passkey to proceed.
- Login rate limiting is not part of this ADR. It is later work, and passkeys reduce but do not remove the need.
- The SEC-002 acceptance has no expiry. Revisit it together with login rate limiting.

## Considered and rejected

- **Passwords.** Adds hashing, reset and breach handling that passkeys avoid.
- **An external IdP (OIDC) in v1.** A hard dependency for a tool that runs on a private network.
- **Signed stateless cookies.** No revocation and no server-side logout.
- **A startup secret for the admin.** A secret in config or the environment outlives setup. A one-time URL does not.

## Unverified

- That Topcoat's origin policy and cookie helpers meet the `__Host-` and CSRF rules without extra code.
- Passkey behaviour behind a TLS-terminating ingress: the webauthn-rs origin and relying party id must match the public host.

## Amendment to ADR-0013 and ADR-0014 (auth)

Postgres also holds users, passkeys, sessions and API tokens. Auth on `FleetQuery` and `FleetJobs` gains per-user API tokens beside `FLEET_CLIENT_TOKEN`, as set above.
