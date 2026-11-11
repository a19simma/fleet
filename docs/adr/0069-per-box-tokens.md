# Per-Box tokens

Status: Accepted 2026-11-11. Built: storage, interceptor, per-RPC binding, ownership, `FleetBoxTokens` and the `fleet box-token` CLI. Not built yet: web page, enroll script and deprecation of the static Box token. The user decided: any signed-in User may issue, a Box is scoped to its User, expiry is mandatory, one active token per Box name, a cap of 20 active tokens per User, and the static `FLEET_TOKEN` keeps working as a shared pool. Amends ADR-0014, ADR-0023, ADR-0033 and ADR-0042.

ADR-0014 gives every Box one shared bearer token. A holder can ingest and claim as any Box, and `GetJobCredentials` releases the stored credentials of any live Job (ADR-0033). The user accepted this for one Box and one User. With several Users and Boxes the shared token is the largest credential in the system.

## Decision

### Token

- A **per-Box token** is `fbx_` followed by 64 lowercase hex characters (256 random bits). API tokens keep `flt_`, so a prefix identifies the class.
- The server stores `sha256` of the value, computed in Postgres as for API tokens. The plaintext is shown once at issue.
- A token binds to a User and to one Box name. It has a label, `created_at`, a mandatory `expires_at`, a `last_used_at` and a `revoked_at`.
- Expiry is mandatory. The default is 90 days and the maximum is 365.
- At most one active (unrevoked, unexpired) token exists per Box name across all Users, enforced by a partial unique index. A second issue for a taken name fails with a reason that does not say who holds it.
- A User holds at most 20 active tokens.
- `last_used_at` is written at most once a minute per token.
- The Box name is a `fleet_core::BoxName` (`box-` and digits). Inferred, not part of the design: the enroll tooling charset (lowercase letters, digits, hyphen) is wider, and the server never accepts a Box name outside `BoxName` on any worker RPC, so a token for another name could not be used.

### Authentication

Lookup order in `auth.rs`: static Box token, static client token, per-Box token (`fbx_`), API token. A per-Box token yields scope Box and a `BoxCaller {token_id, user_id, box}` request extension. It never yields a `Caller`, so no client-scope handler can see it. An unknown, expired or revoked token is `UNAUTHENTICATED` with the same text as any bad token. The static Box token still works as a shared pool and logs a warning on use.

### Enforcement

Each Box-scope RPC checks `BoxCaller::require_box` against the Box name in the request and refuses a mismatch with `PERMISSION_DENIED` and a fixed message. The static token carries no `BoxCaller` and passes unchanged.

`ClaimJob` filters to Jobs whose `jobs.user_id` equals the token's User, so a Box serves only its owner's Jobs. The static token claims with no owner filter. `GetJobCredentials` and `GetJobEnvironment` release only when the Job's owner is the token's User, in addition to the Box and lease checks of ADR-0033 and ADR-0035.

### Issue, list, revoke

A new client-scope service `FleetBoxTokens` has `IssueBoxToken {box, label, ttl_days}`, `ListBoxTokens` and `RevokeBoxToken {id}`. Every call is owner-scoped: a token of another User is `NOT_FOUND`. The static client token is refused with a fixed reason, because it maps to the Bootstrap user and names no person. Issue and revoke write an insert-only `box_token_audit` row in the same transaction. `fleet-server admin reset-passkeys` revokes the User's per-Box tokens with their other credentials.

The redactor masks `fbx_` followed by 64 hex characters.

## Consequences

- A leaked per-Box token exposes one Box name and one User's Jobs until it expires or is revoked. It cannot claim another User's Job or read another User's credentials.
- Exposure of the static token is unchanged until it is retired. Retiring it is a later task.
- Box names are claimed first come, first served among Users. A User cannot learn who holds a name.
