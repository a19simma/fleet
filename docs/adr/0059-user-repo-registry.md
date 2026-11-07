# User repository registry

Status: Proposed 2026-11-07, partly built. The operator decided every point below. Builds on
ADR-0043, ADR-0045 and ADR-0058. Amends ADR-0043 and ADR-0045, and ADR-0058 (SEC-009 only, see
Relation to the App ceiling).

Built: the repository reference parser in fleet-core (`crates/fleet-core/src/repo.rs`: `RepoRef`,
`ForgeKind`, `RepoVerdict`) and the `FLEET_REPO_HOSTS` config (`crates/fleet-server/src/config.rs`,
documented in `infra/README.md` and `crates/fleet-server/README.md`). Also built, as contract only:
the `FleetRepos` proto (`AddRepo`, `ListRepos`, `RemoveRepo`, `RepoInfo`), migration 0036 (the
`user_repos` table and the nullable `github_app_mint.job_id`, required only for scope `job`), the
five `PRECONDITION_REPO_*` constants in `fleet-proto` with their `Reason` variants and
`CredentialNotice` mappings. Not built: the `FleetRepos` server handlers, `RepoVerifier`,
`REPO_CHECK_BUDGET`, the `credentials.host` column and the `forgejo_pat` kind. The `path` column
holds at most 141 bytes: a Forgejo owner of 40, a slash and a name of 100.

A User names the repositories they work on, so the CLI and the web page can list them and later
features can offer them. Today a repository exists only as a field on a Job. This ADR adds a
per-User registry of repositories on several forges. The motivation for more than GitHub is cost:
GitHub Actions minutes are paid, so users want Forgejo and later GitLab as CI hosts.

## Decision

### Surface

- `fleet repo add`, `fleet repo list` and `fleet repo remove` in the CLI, and a repositories page
  in the web console. Both call the same server RPCs.
- Any User adds their own repositories. No capability gates it.
- The RPCs are `FleetRepos` `AddRepo`, `ListRepos` and `RemoveRepo`. `ListRepos` returns
  `RepoInfo` rows, each with a `runnable` field (see Runnable).
- Migration 0036 adds the registry table and makes `github_app_mint.job_id` nullable. Migration
  0037 adds `credentials.host` and the `forgejo_pat` kind.
- Only the interactive User caller kind may call them. Job-scoped tokens and agent tokens are
  refused.
- The registry is keyed `(user, host, path)`. `host` is the forge hostname and `path` is the
  repository path on it, for example `github.com` and `owner/name`.

### Record only

A registry row grants nothing. The only grants of App access stay the operator ceiling
`FLEET_GITHUB_APP_REPOS` and the `forge:github_app` capability (ADR-0058). Registration does not
widen either.

Submit does not enforce registration in v1 and does not recheck it. Enforcement stays where it is:
at job claim and at clone or push, through the repository host allowlist and the token host of
ADR-0024.

### Verify before insert

`add` runs a **Repo verifier** before it inserts. The verifier checks that the User's own stored
credential for that host can read the repository.

- Push permission is recorded as optional: set when the forge reports permissions, unset otherwise.
- `add` refuses when the host has no configured verifier, and when the User has no credential for
  the host. No unverified rows exist.
- The check is made by the server. A check by fleetd or by the CLI would run outside the sealed
  store and outside the audit path.

### Hosts

The operator lists the allowed hosts in `FLEET_REPO_HOSTS` (the operator host list). Entries are
`host=H,forge=github|forgejo,api=URL[,allow_private=true|false]`, joined by `;`. An unset variable
allows `github.com` only. An empty value refuses every add. Each host has:

- a **Forge kind**: `github` and `forgejo` are accepted by the config today. `gitlab` is planned and
  the config refuses it. The kind selects a `RepoVerifier` trait implementation, one per kind. The
  GitHub verifier is built first behind the trait. The config enum `Forge` and the core enum
  `ForgeKind` are separate types: `Forge` picks the verifier, `ForgeKind` picks the path grammar.
- an `allow_private` opt-in. Without it, private, loopback, link-local and cloud-metadata
  addresses are refused. With it, private ranges are allowed, but loopback, link-local and
  cloud-metadata addresses stay refused.

The verifier's outbound call follows these rules:

- Resolve DNS once and dial the checked IP (see Security rules for the vetting).
- Follow no redirects.
- Trust the webpki roots only, a public CA, so a host with a private CA is unsupported.
- Port 443 only in v1.
- The whole check fits `REPO_CHECK_BUDGET` (planned, 7 seconds), under `fleet_proto::CALL_BUDGET`
  (10 seconds, `crates/fleet-proto/src/lib.rs`), so the server answers before the client's
  deadline. This is the same arrangement as `MINT_BUDGET` in ADR-0058.

### GitHub verifier

`GET /repos/{owner}/{repo}` with the User's unsealed `github_pat`, or with a probe-scope App mint
when the User holds a `github_app` credential. The App wins over the PAT, with no fallback to the
PAT on a mint failure, as in `release_for_job` (`crates/fleet-server/src/cred/store.rs`, ADR-0058).
A no-job probe has no Job id, so `github_app_mint.job_id` becomes nullable
(`crates/fleet-server/migrations/0033_github_app_mint.sql` declares it `NOT NULL`).

### Forgejo verifier

`GET /api/v1/repos/{owner}/{repo}` with the header `Authorization: token <token>`. Forgejo tokens
are 40 hex characters with no prefix, and a repository the token cannot see answers 404. Sources:
the [Forgejo API usage guide](https://forgejo.org/docs/latest/user/api-usage/) and the
[Forgejo token scope page](https://forgejo.org/docs/latest/user/token-scope/) (official docs).

Unverified, to confirm on a live instance:

- the status for an invalid token (401 is assumed),
- whether a renamed repository redirects over REST,
- 403 against 404 when the token lacks a scope,
- the API path under an instance served from a subpath,
- whether `permissions` is present on every reply.

### Credentials

The `credentials` table gains a `host` column and a `forgejo_pat` kind (migration 0037). This
lands with the verifier, ahead of any registry code.

### Runnable

`fleet repo list` prints a `runnable` field per row. It is false for every non-GitHub host until
fleetd delivers a token per host (REPO-9). Today `RepoPolicy` in `crates/fleetd/src/workspace.rs`
carries a single `token_host`, and the Gitea slot in `crates/fleetd/src/forge/gitea.rs` returns
`ForgeError::Unsupported`. A row on a host that is not runnable still lists and still verifies.

### Relation to the App ceiling

ADR-0058 SEC-009 says only an admin or operator config sets the repository allowlist. The registry
does not set it. A registered repository outside `FLEET_GITHUB_APP_REPOS` still fails at mint with
`PRECONDITION_APP_REPO`.

### Security rules

Wire reasons. The client sees a closed `PRECONDITION_REPO_*` set only: `NOT_ALLOWED_HOST`,
`NO_CREDENTIAL`, `NOT_FOUND_OR_NO_ACCESS`, `UPSTREAM_UNAVAILABLE` and `TIMEOUT`. A forge 404 and a
forge 403 collapse to `NOT_FOUND_OR_NO_ACCESS`. A host with no verifier returns the same reason as
a host outside the list, `NOT_ALLOWED_HOST`. Upstream bodies and resolved IPs go to server logs
only.

Host matching. The host is normalised first: lowercase, no trailing dot, no userinfo, no port, no
IP literal, IDN as punycode. It is matched as an exact string against the operator list before any
DNS lookup.

Address vetting. The verifier accepts an address only if it is global unicast, by a named rule and
not a blocklist. It unmaps IPv4-mapped IPv6 first. It refuses loopback, link-local, ULA, multicast,
broadcast, `0.0.0.0/8`, CGNAT `100.64/10`, NAT64 `64:ff9b::/96`, 6to4 and cloud metadata
addresses. Every resolved A and AAAA record must pass, or the call fails closed. The verifier dials
a vetted address only. Vetting reruns on every call, with no cache. `allow_private` relaxes the
private ranges for that host and never loopback, link-local or metadata.

Outbound call. The credential is selected by the exact `(user, host)` pair and never another
host's. TLS SNI and certificate verification use the hostname, not the IP. TLS 1.2 is the minimum
and no option skips verification. Test seams are injected parameters. The `Authorization` header
is never sent on a redirect: a 3xx is an error and its body is not parsed. The forge response body
is read with `take(cap + 1)` and a truncated JSON body fails. The token is opaque, with no format
validation. It is redacted in `Debug` and tracing and never logged. Storing a credential for a
host also checks the operator host list.

Authorization. The user comes from the session and any client-supplied user is ignored. `ListRepos`
and `RemoveRepo` filter by the authenticated user in the SQL `WHERE`, so a missing row and another
user's row return the same not-found. `fleet_core::RepoRef` validates the `owner/name` grammar
before it is interpolated into a URL. A per-User row cap bounds the registry.

Rate. A per-User rate limit and a global concurrency cap, both named constants, bound verifier
calls. Probe mints share the per-User mint rate (ADR-0058) and do not count toward the per-Job
cap.

Probe mint. It is read-only with `metadata:read`, for a single repository, short-lived, never
returned and discarded after the call. An audit row records the user, host, path and outcome. The
`forge:github_app` capability and the `FLEET_GITHUB_APP_REPOS` ceiling apply to the probe.

Operator config. Startup rejects a host entry with userinfo, port, scheme, IP literal or wildcard,
and normalises case and the trailing dot. The environment source of `FLEET_REPO_HOSTS` (deployment
manifest or service unit) must be owned by the service operator and not writable by others. A
Forgejo subpath prefix is operator config, or the host is refused. A User never supplies one.

Registry meaning. A row grants nothing. Any consumer must re-verify and never use membership as an
authorisation input. A removed credential or a host-list change marks rows stale.

Dependency review. The new HTTP client and its TLS settings need a dependency review when the code
lands.

## Consequences

- A User can see which repositories Fleet can read for them, per host.
- A registry row can go stale: access can be revoked after `add`. Nothing rechecks it, and job
  claim, clone and push stay the enforcement points.
- A refused `add` names the cause: no verifier for the host, or no credential for it.
- The probe path adds `github_app_mint` rows of scope `probe` with a null `job_id`. They count
  toward the per-User mint rate (ADR-0058).
- The operator host list is server config, built as `FLEET_REPO_HOSTS` in
  `crates/fleet-server/src/config.rs`.
- GitLab has no verifier until a later ADR amends this one.

## Considered and rejected

- **GitHub only.** It leaves the cost motivation unmet: Actions minutes are paid.
- **Reuse the fleetd `Forge` trait (ADR-0045).** That trait runs in fleetd on a Box and covers
  push, pull request and CI. The registry check runs in the server before any Job exists and needs
  a read-only call, so the interfaces and their hosts of execution differ.
- **Record unverified rows.** A row would then claim nothing checkable, and a typo or a missing
  credential would surface only at job claim.
- **Forge kind per host in the credential.** A host maps to one kind in operator config, so a User
  cannot point a `github` kind at a hostile host.
- **Check in fleetd or in the CLI.** Both sit outside the sealed store and the audit rows.
- **Recheck at submit.** It adds a network call to every submit and duplicates the enforcement at
  claim, clone and push.
