# Per-Box tokens

Status: Accepted 2026-11-11. Built: storage, interceptor, per-RPC binding, ownership (including every lease-bound worker RPC), `FleetBoxTokens`, the `fleet box-token` CLI and the `/box-tokens` web page. Not built yet: enroll script and deprecation of the static Box token. The user decided: any signed-in User may issue, a Box is scoped to its User, expiry is mandatory, one active token per Box name, a cap of 20 active tokens per User, and the static `FLEET_TOKEN` keeps working as a shared pool. Amends ADR-0014, ADR-0023, ADR-0033 and ADR-0042.

ADR-0014 gives every Box one shared bearer token. A holder can ingest and claim as any Box, and `GetJobCredentials` releases the stored credentials of any live Job (ADR-0033). The user accepted this for one Box and one User. With several Users and Boxes the shared token is the largest credential in the system.

## Decision

### Token

- A **per-Box token** is `fbx_` followed by 64 lowercase hex characters (256 random bits). API tokens keep `flt_`, so a prefix identifies the class.
- The server stores `sha256` of the value, computed in Postgres as for API tokens. The plaintext is shown once at issue.
- A token binds to a User and to one Box name. It has a label, `created_at`, a mandatory `expires_at`, a `last_used_at` and a `revoked_at`.
- Expiry is mandatory. The default is 90 days and the maximum is 365. An empty or absent lifetime means the default; 0 is invalid on the web form, the gRPC call and the CLI.
- At most one active (unrevoked, unexpired) token exists per Box name across all Users, enforced by a partial unique index. A second issue for a taken name fails with a reason that does not say who holds it.
- A User holds at most 20 active tokens.
- `last_used_at` is written at most once a minute per token.
- The Box name is a `fleet_core::BoxName` (`box-` and digits). Inferred, not part of the design: the enroll tooling charset (lowercase letters, digits, hyphen) is wider, and the server never accepts a Box name outside `BoxName` on any worker RPC, so a token for another name could not be used.

### Authentication

A header that starts with `fbx_` must match the full token shape before any database lookup; a malformed one is `UNAUTHENTICATED` and runs no query. The scope check runs before the lookup, so a per-Box token on a client-scope path is refused without a query. A failed `last_used_at` write is logged and does not fail authentication.

Lookup order in `auth.rs`: static Box token, static client token, per-Box token (`fbx_`), API token. A per-Box token yields scope Box and a `BoxCaller {token_id, user_id, box}` request extension. It never yields a `Caller`, so no client-scope handler can see it. An unknown, expired or revoked token is `UNAUTHENTICATED` with the same text as any bad token. The static Box token still works as a shared pool and logs a warning on use.

### Enforcement

Each Box-scope RPC checks `BoxCaller::require_box` against the Box name in the request and refuses a mismatch with `PERMISSION_DENIED` and a fixed message. The static token carries no `BoxCaller` and passes unchanged.

`ClaimJob` filters to Jobs whose `jobs.user_id` equals the token's User, so a Box serves only its owner's Jobs. The static token claims with no owner filter. Every lease-bound worker RPC (`GetProfileBlob`, `GetJobTranscript`, `GetJobCredentials`, `GetJobEnvironment`, `ReportJob`, `ReportTiming`, `ReportShellLog`) acts only when the Job's owner is the token's User, in addition to the Box and lease checks of ADR-0033 and ADR-0035. A token revoked and re-issued under the same name to another User therefore cannot touch the first User's leased Job. A refusal is `PERMISSION_DENIED` with the lease-mismatch text, the same as an unknown Job.

### Issue, list, revoke

A new client-scope service `FleetBoxTokens` has `IssueBoxToken {box, label, ttl_days}`, `ListBoxTokens` and `RevokeBoxToken {id}`. Every call is owner-scoped: a token of another User is `NOT_FOUND`. The static client token is refused with a fixed reason, because it maps to the Bootstrap user and names no person. Issue and revoke write an insert-only `box_token_audit` row in the same transaction. Closing an expired token to free its name writes an `expired` audit row. The partial unique index forces that close to set `revoked_at = expires_at`, so a row counts as revoked only when `revoked_at < expires_at`; the list and the web page show every other closed row as expired. `fleet-server admin reset-passkeys` revokes the User's per-Box tokens with their other credentials. `IssueBoxToken` re-checks under the user lock that the API token or session row is still present. A `reset-passkeys` that lands between authentication and the lock is not detected when the caller was a passkey session, because `Caller` carries no credential id; the issued token then outlives the reset until it expires or is revoked. Closing this needs the credential id in `Caller`.

The CLI prints the token alone on stdout. If that write fails after the server committed, it prints the token id and a `fleet box-token revoke <id>` hint on stderr and exits 1.

The redactor masks `fbx_` followed by 64 hex characters.

## Consequences

- A leaked per-Box token exposes one Box name and one User's Jobs until it expires or is revoked. It cannot claim another User's Job or read another User's credentials.
- Exposure of the static token is unchanged until it is retired. Retiring it is a later task.
- Box names are one global namespace claimed first come, first served among Users. A User can squat a name by issuing a token for it. `ALREADY_EXISTS` reveals that a name is taken, though not by whom. An admin revoke-by-Box is a follow-up.
- After a revoke, a request already past authentication finishes. The window is one request, not a lease. Each lease-bound RPC authenticates again on its next call.
- The Postgres log must not record bind parameters (`log_parameter_max_length = 0` and no `log_statement = all`). Lookup binds the plaintext token.
