# User capabilities and model allowlist

Status: Proposed 2026-11-02. Not built. Amends ADR-0048 (the server gate for `tools`). Builds on ADR-0035, ADR-0042 and ADR-0044.

ADR-0048 gates Profile `tools` with one server switch, `FLEET_ALLOW_PROFILE_TOOLS`, because the server then had only box and client scopes. The server now has Users and an admin (ADR-0042), so a grant can attach to a principal. A global switch lets every client install toolchains once an operator flips it. This ADR replaces it with a per-user capability and adds a model allowlist so a Job cannot select a model the operator never approved.

## Decision

### Capability `profile:tools`

- `profile:tools` is a capability on a User. An admin grants and revokes it.
- The server checks it twice: at profile save (`CreateProfile` with a `tools` list) and again at Job submit when the Job pins a Profile that has `tools`. The second check catches a revoke between save and submit.
- A User without the capability gets a fixed refusal that names `profile:tools`. The store is not written.
- A Job already leased keeps running. Revoke affects later saves and submits only.
- The client token (`FLEET_CLIENT_TOKEN`) carries no User. A request under it never holds the capability, so it cannot save or submit a Profile with `tools`.

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
- Existing Profiles with `tools` stay stored and keep their hash. Submitting a Job that uses one needs a User with the capability.
- The admin UI and `fleet-server admin` gain grant and revoke for the capability.
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
