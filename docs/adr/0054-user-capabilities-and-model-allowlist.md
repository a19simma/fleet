# User capabilities and model allowlist

Status: Proposed 2026-11-02. Built: the `profile:tools` capability (save, Job submit, batch submit, blob serve), the startup refusal of `FLEET_ALLOW_PROFILE_TOOLS`, the server `FLEET_MODEL_ALLOWLIST` check at profile save, Job submit, batch submit and blob serve, and the fleetd `model_allowlist`. Amends ADR-0048 (the server gate for `tools`). Builds on ADR-0035, ADR-0042 and ADR-0044. Amended by ADR-0056 and ADR-0058.

ADR-0048 gates Profile `tools` with one server switch, `FLEET_ALLOW_PROFILE_TOOLS`, because the server then had only box and client scopes. The server now has Users and an admin, a user with `users.is_admin` (ADR-0042, ADR-0056), so a grant can attach to a principal. A global switch lets every client install toolchains once an operator flips it. This ADR replaces it with a per-user capability and adds a model allowlist so a Job cannot select a model the operator never approved.

## Decision

### Capability `profile:tools`

- `profile:tools` is a capability on a User. An admin grants and revokes it.
- The server checks it at profile save (`CreateProfile` with a `tools` list, or a selection that names a `tool` Catalog item, ADR-0053), at Job submit and batch submit when a pinned Profile has `tools`, and when it serves the pinned blob to a leased Box. The blob check uses the job owner's (`jobs.user_id`) grant, read live in the same transaction.
- A User without the capability gets a fixed refusal that names `profile:tools`. The store is not written.
- A revoke refuses a leased Job that has not yet fetched its blob. A Job whose Box already holds the blob keeps running.
- A request under the client token (`FLEET_CLIENT_TOKEN`) acts as the bootstrap user. That user holds the capability only if an admin grants it, and the grant path has no bootstrap guard.

### Removal of `FLEET_ALLOW_PROFILE_TOOLS`

- The server no longer reads the value as a switch. It refuses to start while the variable is set, to any value, including `false` and the empty string.
- The startup error names `FLEET_ALLOW_PROFILE_TOOLS` and the replacement: grant the `profile:tools` capability to a user.
- A silent ignore would leave an operator believing the old switch still gates `tools`. Failing the start surfaces the change at deploy.

### Model allowlist

- `FLEET_MODEL_ALLOWLIST` in the server config is a comma-separated list of model ids.
- Match is exact and case-sensitive. No prefix, glob, alias or trimming beyond the list separator. An empty entry is a config error.
- The server checks the model of a Job at submit, whether it comes from the request or from the pinned Profile, and refuses a model outside the list.
- When `FLEET_MODEL_ALLOWLIST` is unset the server applies no model restriction.
- fleetd re-checks the model before spawn against its own config key `model_allowlist`, same exact match. A mismatch fails the Job with a fixed error before any process starts. The server is not trusted alone, because fleetd holds the Box and the credentials.
- When fleetd has no `model_allowlist`, fleetd trusts the server and does not check. The deploy docs must recommend setting it on every Box, since an unset list leaves the server as the only gate.

## Consequences

- An operator upgrading must remove `FLEET_ALLOW_PROFILE_TOOLS` and grant `profile:tools` to each user that needs it, or the server does not start.
- Existing Profiles with `tools` stay stored and keep their hash. Submitting a Job that uses one needs a User with the capability, and a revoke refuses a leased Job of that owner before it fetches its blob.
- Blob serve also checks the model allowlist against the pinned blob, so a Job queued before the list was set or narrowed is refused at lease time.
- The admin RPC and the admin UI gain grant and revoke for the capability. `fleet-server admin` gains `grant-admin` and `revoke-admin` instead (ADR-0056).
- A fleetd with an allowlist and a server without one still enforces on the Box. A server with one and a fleetd without one enforces at submit only.
- Model ids that vendors rename need an allowlist edit in both configs.

## Considered and rejected

- **Keep the global flag.** One switch grants every client the capability and cannot separate users.
- **Keep the flag as a deprecated no-op.** An operator would read a passing start as an enforced gate.
- **Server-only model check.** A compromised or misconfigured server could then send any model to a Box.
- **fleetd-only model check.** The submitter would learn of a refusal only after lease and clone, and the server could not reject at submit.
- **Case-insensitive or prefix match.** It widens the allowed set past what the operator wrote and makes aliases a way around the list.
- **Deny by default when fleetd has no allowlist.** It breaks every existing Box on upgrade. The deploy note covers the gap instead.
- **Deny by default when the server has no allowlist.** Same upgrade break, and existing Jobs set models freely today.
- **Role instead of capability.** A role bundles rights, and `profile:tools` is a single narrow grant.

## Amendment (ADR-0058)

ADR-0058 (proposed, not built) adds the capability `forge:github_app`. The server checks it at `PutCredential` for the `github_app` kind and live at release. Holders can mint write tokens for any repository in the installation, clamped to the Job repository.
