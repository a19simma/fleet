# Admin is a user flag

Status: Proposed 2026-11-04. Built: migration 0028 adds `users.is_admin`, `auth.rs` gates the two admin services on it, and the catalog, capability and `fleet-server admin` paths read it. Amends ADR-0023, ADR-0042 and ADR-0054.

ADR-0042 creates "the admin" at setup but stores no admin concept: the first user is a user like any other, and recovery runs as a database operator. ADR-0054 needs admin grants and the catalog and capability RPC services need a caller they can trust. The static client token carries no identity, and the capability table cannot hold an admin role. This ADR stores admin as one flag on the user and fixes who can set it.

## Decision

### Storage

- `users.is_admin boolean NOT NULL DEFAULT false` is the only admin concept.
- The user created by setup redemption is the first admin, through either first-admin path: `begin_redeem_setup` and `begin_redeem_password`. `create-user` inserts a non-admin.
- The reserved `bootstrap` user can never be admin. A migration CHECK enforces it.
- The migration lands as 0028. Migration 0027 is taken by the profile-id migration (ADR-0057).

### Promotion

- `fleet-server admin grant-admin <username>` and `fleet-server admin revoke-admin <username>` run with direct database access like `create-user`, in one transaction, with an `admin_audit` row. The actions are `admin_grant` and `admin_revoke`.
- Grant and revoke refuse `bootstrap` and unknown users with the same `no such user` error. Granting an admin or revoking a non-admin succeeds and writes an audit row.
- Revoke refuses the last admin with exit code 7. In one transaction it locks every admin row `FOR UPDATE` in id order, locks the target row, then counts admins, so two concurrent revokes serialise and the second sees the first's result.
- No RPC and no web route promotes anyone, so a stolen admin token cannot mint admins.

### RPC

- The `FleetCatalogAdmin` and `FleetCapabilityAdmin` services are open only to a Client-scope per-user API token whose user is admin. The server reads `is_admin` live on every request from one joined token query. There is no cache.
- The box token, `FLEET_CLIENT_TOKEN` (the bootstrap user) and non-admin tokens get `PERMISSION_DENIED` with the fixed reason `admin required`.
- Handlers re-check with `Caller::require_admin`. Write transactions run `SELECT is_admin FROM users WHERE id=$1 FOR SHARE` on the actor row.
- `granted_by` and the audit actor come from the `Caller`, never from the request body.

### Web

- Admin routes share one `admin_gate` helper. It reads `is_admin` from the database on every request and never from the session row.
- No session returns 303 to `/login`. A non-admin gets 403. POST routes carry the CSRF check.

### Lifecycle

- Revocation takes effect on the next request.
- `reset-passkeys` keeps `is_admin`.
- There is no backfill. After the upgrade an operator runs `fleet-server admin grant-admin <username>` once. This is a deploy note.

### CLI

- The CLI has no admin mode. The admin puts a per-user API token from `/account` in the CLI config.
- A non-admin gets `PERMISSION_DENIED` with `admin required`, which the CLI maps to its permission exit code.

## Amends

- ADR-0054, "The server now has Users and an admin (ADR-0042)": admin is now the stored `is_admin` flag.
- ADR-0054, "The admin UI and `fleet-server admin` gain grant and revoke for the capability": grant and revoke of the capability go through the admin RPC and the web UI. `fleet-server admin` gains `grant-admin` and `revoke-admin` instead.
- ADR-0042, Bootstrap admin, "which creates the admin": it now sets the stored flag.
- ADR-0042, Admin recovery: two subcommands become four.
- ADR-0042, `admin_audit` actions: the list gains `admin_grant` and `admin_revoke`.
- ADR-0023, "two bearer token scopes": identity gates the admin services. Scope alone no longer opens them.

ADR-0042 and ADR-0054 are Proposed, so their lines are edited in place. ADR-0023 is Accepted and keeps its text. Its README row records the amendment.

## Consequences

- An operator upgrading has no admin until `grant-admin` runs. Admin RPC and routes refuse everyone meanwhile.
- An admin loses access on the next request after revoke. A running Job is unaffected.
- A stolen admin token can use the admin services until revoked or reset, but cannot create another admin.
- Every admin write names its actor, so the audit trail has an identity.

## Considered and rejected

- **A static `FLEET_ADMIN_TOKEN`.** It has no identity for `granted_by` and the audit, adds a second shared secret, needs a redeploy after a leak and has no web use.
- **Making `bootstrap` admin.** The shared client token would become admin.
- **An admin capability in `user_capabilities`.** The grant RPC could mint admins, the table CHECK lists a closed set of resource capabilities.
- **Promotion by RPC or web route.** It is escalation over the network.
