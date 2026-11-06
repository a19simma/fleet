# Credential delivery

Status: Proposed 2026-10-29. Built: the server `GetJobCredentials`, the fleetd credential holder, and broker, askpass and `gh` use of the held token. Builds on ADR-0035 (lease-authorised worker calls), ADR-0040 (store) and ADR-0043 (kinds). Amends ADR-0014, ADR-0021, ADR-0023, ADR-0024, ADR-0031 and ADR-0037. ADR-0035 reserved this number for delivery. Amended by ADR-0058.

The server stores user credentials (ADR-0040). A Box needs the credentials of one Job, and only for that Job. This ADR fixes the call, its authorisation, who sees the result and what happens when a credential is missing.

## Decision

### Call

A new worker-scope RPC: `FleetWorker.GetJobCredentials{job_id, attempt, box}`. The reply carries the credentials of the Job's owner that the Job's Agent runner and Forge need (ADR-0043, ADR-0044, ADR-0045).

### Authorisation

The job lease authorises the call, exactly as in ADR-0035: the Box proves it holds the claim.

- A wrong box, a wrong attempt, a Job that is not `RUNNING`, an expired lease and a Job that does not exist all return `PERMISSION_DENIED` with one fixed message. A Box learns nothing about other Jobs.
- The server writes one `credential_use` row per credential released (ADR-0040).
- There is no lookup by user, by credential id or by kind.

### Who sees the credentials

- fleetd only. It holds them in broker memory (ADR-0037) for the life of the Job.
- They are never written into the agent's environment or files, and never into events, transcripts or logs. The redactor masks the values.
- The agent must not see them. Where the agent needs to act on a forge, it asks the broker over the per-job socket (ADR-0036).
- The agent's own model credential is the exception ADR-0037 already records: the Claude token stays visible to the agent while the P2 proxy serves the model API.

### Missing GitHub credential

A Job whose owner has no GitHub credential fails with one fixed error, before the clone. fleetd never falls back to the Box PAT. The Box PAT is temporary and will be removed (ADR-0043).

## Accepted risk: shared Box token

Boxes authenticate with the shared `FLEET_TOKEN` (ADR-0023). A holder of that token can call `GetJobCredentials` for any job id, and the lease check passes for a caller that names the right box and attempt. Such a caller can read the credentials of the Job's owner.

Accepted because there is one Box and one user. Per-Box tokens arrive with a later Box enrolment process (ADR-0023, "A token per Box"). The lease check stays required now: it is the check that survives into the per-Box design.

## Consequences

- A leaked `FLEET_TOKEN` exposes every stored credential that a live Job references. This adds to the exposure in ADR-0014.
- A second user or a second Box must wait for per-Box tokens.
- No credential reaches a Box that holds no claim.
- A user with no GitHub credential gets a failed Job. No push happens as the Box identity.

## Considered and rejected

- **Credentials in the claimed `Job`.** They would travel on every claim, including claims that fail after the fact, and sit in the Job row's reply path.
- **Box fetches with the client token.** It would hand a Box the client scope (ADR-0023).
- **Fallback to the Box PAT.** It would push as the Box identity for a user who stored nothing, and keep the PAT alive.
- **Writing credentials to the agent's environment.** The agent could read and exfiltrate them.

## Amendment (ADR-0058)

ADR-0058 (proposed, partly built) adds the `github_app` kind. When a User holds it, release prefers it over `github_pat`, mints an installation token outside the transaction after the capability check, and sends it as the wire kind `github_installation_token` with a `GitIdentity` and `expires_at_ms` (the refresh call, the per-Job cap, the per-User rate limit, the fleetd revoke and the mint audit rows are built; see the Not built list in ADR-0058). Release stays one RPC, called again to refresh before a push or `gh` child when under 10 minutes remain, under a per-Job mint cap and a per-User rate limit. The mirror fetch and the broker token are not refreshed. Mint audit goes into the new insert-only table `github_app_mint` (migration 0033, ADR-0058 SEC-005). The one-row-per-credential-released rule above is unchanged: each refresh release writes one `credential_use` row per credential released, so a refresh adds a row (`crates/fleet-server/src/cred/store.rs` inserts one per released credential). The `github_app_mint` columns include `mint_id` and `attempt_id` (ADR-0058 SEC-015), and its outcomes are `attempt`, `minted`, `failed`, `denied`, `revoked` and `revoke_failed` (ADR-0058 SEC-005, ADR-0058 SEC-022). A mint failure at the first fetch fails the Job; a refresh whose mint fails keeps the last good token until it expires. The server answers `FAILED_PRECONDITION` with `github app token unavailable`; fleetd reports its generic `credentials could not be fetched`. It never falls back to a PAT. The fleetd holder accepts the wire kind `github_installation_token`, holds the token as the Job's GitHub token and re-validates the `GitIdentity`; fleetd calls it again to refresh.
