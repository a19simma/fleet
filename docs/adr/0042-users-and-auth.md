# Users and auth

Status: Proposed 2026-10-29. Partly built: users, hashed API tokens, the setup code and the user-aware auth layer exist in fleet-server; the web UI, passkeys and job ownership are not wired. Amends ADR-0013 and ADR-0014. Builds on ADR-0041 (web UI) and ADR-0040 (credential store).

Credentials and the web UI make Fleet multi-user. The shared client token cannot say whose a Job or a credential is. This ADR adds users, browser login, per-user API tokens and Job ownership.

## Decision

### Users and login

- A **User** has a username and one or more passkeys. Login is local username plus passkey through webauthn-rs 0.5.5 (ADR-0041). No passwords. No external identity provider in v1.
- A browser session is a server-side row. The cookie holds an opaque random id only. The session table arrives with the `jobs.user_id` migration (CRED-11).
- The cookie uses the `__Host-` prefix: `Secure`, `Path=/`, no `Domain`, plus `HttpOnly` and `SameSite=Strict`.
- A session expires after 12 hours absolute or 30 minutes without use, whichever comes first. A login deletes the session the browser presented and creates a new one in the same transaction as the counter update, so the id rotates on every login. Logout deletes the row.
- Every state-changing route behind a session carries a CSRF token tied to the session, checked on the server. The Origin check on every POST route, including the pre-session passkey routes that have no token yet, stays on as a second guard and answers 403 for a foreign Origin.

### Bootstrap admin

On first start with no users, the server logs a one-time setup URL containing a random token and holds it in memory until used. Opening it lets the visitor pick a username and register a passkey, which creates the admin. The token dies on use or on restart, and a restart with still no users prints a new one. No startup secret in config. The cost: whoever reads the pod log first can claim the admin, so the log is the trust boundary.

### API tokens

- A User creates API tokens in the UI for the CLI. The server stores only the SHA-256 hash (32 bytes) in the table from migration 0017. The plaintext shows once at creation.
- Tokens are 256-bit random values, so a plain hash is enough and no slow hash is needed.
- Tokens can be revoked in the UI.

### Ownership

- `jobs.user_id` records the owner. Jobs are owner-only for now: a User lists, reads and cancels only their own. Sharing comes later.
- `credentials.user_id` (ADR-0040) follows the same rule.

### Transition

`FLEET_CLIENT_TOKEN` stays accepted for the existing CLI during transition. A Job submitted with it has no owner and is visible only to the admin. The shared token is removed in a later ADR once the CLI uses API tokens. `FLEET_TOKEN` (box scope, ADR-0023) is unchanged.

## Consequences

- A lost passkey locks a User out. A second passkey per User is advised. Admin recovery is a later feature.
- The server holds session state, so a session survives a restart and can be revoked.
- Accepted risk (SEC-002): `login/start` answers 400 for an unknown username and a challenge for a known one, so an attacker can enumerate usernames. A decoy challenge needs a fake passkey credential per name and is not built. Usernames are not secret in a small private deployment, and a guess still needs a passkey to proceed.
- Login rate limiting is not part of this ADR. It is later work, and passkeys reduce but do not remove the need.

## Considered and rejected

- **Passwords.** Adds hashing, reset and breach handling that passkeys avoid.
- **An external IdP (OIDC) in v1.** A hard dependency for a tool that runs on a private network.
- **Signed stateless cookies.** No revocation and no server-side logout.
- **A startup secret for the admin.** A secret in config or the environment outlives setup. A one-time URL does not.

## Unverified

- The exact name and columns of the session and API token tables. Migration 0017 and the CRED-11 migration are not in this tree, so the hash shape above follows the task brief.
- That Topcoat's origin policy and cookie helpers meet the `__Host-` and CSRF rules without extra code.
- Passkey behaviour behind a TLS-terminating ingress: the webauthn-rs origin and relying party id must match the public host.

## Amendment to ADR-0013 and ADR-0014 (auth)

Postgres also holds users, passkeys, sessions and API tokens. Auth on `FleetQuery` and `FleetJobs` gains per-user API tokens beside `FLEET_CLIENT_TOKEN`, as set above.
