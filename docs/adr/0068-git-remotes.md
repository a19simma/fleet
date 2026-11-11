# Git remotes

Status: Proposed 2026-11-10, not built. The user decided every point below: any User adds any host, a private-address host needs an admin-approved per-host flag with `approved_ips` pinned at approval, GitHub goes through REST and not `gh`, `fleet-forge` is a new crate, a User-added host is Forgejo only in v1, and migration 0045 is the next free number. Builds on ADR-0033, ADR-0043, ADR-0045 and ADR-0059. Amends ADR-0059 (host source, credentials, Forgejo, runnable) and amends ADR-0045, ADR-0043, ADR-0040, ADR-0033, ADR-0024, ADR-0037, ADR-0038 and ADR-0054.

ADR-0059 lets a User register repositories on hosts the operator lists in `FLEET_REPO_HOSTS`. Only `github.com` is runnable. The motivation is cost: GitHub Actions minutes are paid, and a Forgejo host runs CI for free. This ADR makes Forgejo a second, fully supported forge: verify, clone, push, pull request and CI status. Any User may add a git host. Both forges sit behind one interface with one shared contract test suite, so feature parity is enforced by tests.

Target host for the first slice: the dev Forgejo 17.0.1 on the Gitea 1.22 API, valid public certificate, port 443, root path, resolving to a private address.

## Decision

### Git host table

A new `git_hosts` table replaces `FLEET_REPO_HOSTS` as the source of hosts (migration 0045). A row holds: `host` (primary key, normalised), `kind` (`github` or `forgejo`), `allow_private` (default false), `approved_ips` (the private addresses an admin approved, empty unless `allow_private`), `added_by`, `approved_by`, `approved_at` and timestamps. Migration 0045 seeds `github.com` as kind `github` and, for each entry of an existing `FLEET_REPO_HOSTS`, one row; the variable is then read once at startup for seeding only and is deprecated.

- Any User adds a host: `fleet host add <host>` and the Git remotes page. No capability gates it and the admin is not involved for a public host.
- A User-added host has kind `forgejo`. The Gitea API is the only one probed. Kind `github` rows exist only for `github.com`, seeded by migration. GitHub Enterprise Server is out of scope. A User cannot choose a kind, so a hostile host cannot claim to be GitHub.
- Port 443 and a root path only. A User never supplies a subpath, a port or a scheme.
- A host row is global and carries no secret. Credentials stay per User (below).
- Add runs the verifier probe (`GET /api/v1/version`) before it inserts, under `REPO_CHECK_BUDGET`. A host that does not answer as Forgejo or Gitea is refused, so no unverified row exists.
- Limits: 20 hosts added per User, 500 hosts in total, and the add shares the per-User check limiter of ADR-0059.
- Only an admin removes a host. A host with credentials or registered repositories refuses removal until they are gone.

### User-supplied hosts are an SSRF surface

The server dials a hostname a User typed. Anyone with an account can aim the server at any DNS name they control. This ADR accepts that, by user decision, and contains it with these controls. Every control applies to every host, whoever added it.

1. Public hosts only by default. Every resolved A and AAAA record must be global unicast under the rule of ADR-0059 (Address vetting). A host with one private, loopback, link-local, ULA, CGNAT (`100.64/10`), multicast, broadcast, `0.0.0.0/8`, NAT64, 6to4 or metadata record is refused, with the closed reason `PRECONDITION_REPO_NOT_ALLOWED_HOST`. The check runs at add and again on every outbound call, with no cache.
2. Dial the vetted IP (`cred::pinned`). The connector resolves once, vets the set and dials one vetted address. SNI and certificate verification use the hostname. A DNS rebind between check and connect cannot land on another address.
3. No redirects. A 3xx is an error and its body is not parsed. `Authorization` is never sent on a followed hop because no hop is followed.
4. Size and time caps. `MAX_BODY_BYTES` (256 KiB) on each reply, `REPO_CHECK_BUDGET` (7 s total) on each call, TLS 1.2 minimum, webpki roots only, no option skips verification.
5. Credentials keyed by `(user, host)`. A token is selected by the exact pair. A token never goes to a host it was not stored for, and never to a host named only by a Job field. Storing a credential for a host the table does not hold is refused.
6. Rate limits. The per-User check limiter (10 per 60 s, 8 concurrent) covers add, verify and the probe. A global concurrency cap bounds the server.
7. Closed wire reasons. The client sees `PRECONDITION_REPO_*` only. Resolved IPs, upstream bodies and DNS errors go to server logs, not to the client. A refusal for a private address is indistinguishable from `NOT_ALLOWED_HOST`, so the add path does not scan a private network.
8. Private addresses need an admin (next section).
9. Audit. Add, remove, probe outcome, approval and revocation of `allow_private`, and every credential put and delete on a host write an audit row (user, host, outcome).
10. Blind probes only. The probe sends no credential. The reply is parsed as a closed Forgejo version document and everything else is discarded.

Residual risk, accepted: a public host can answer slowly or send a large body up to the caps, and a User can fill their own 20 host slots. A malicious public host receives only the requests and the token the same User stored for it.

### Private addresses: `allow_private`

A host whose records are not all public is refused unless an admin approved that host.

- `allow_private` is a flag on the host row. Only an admin sets it, by `fleet host approve-private <host>` or the admin button on the Git remotes page. Both are audited and both name the resolved addresses the admin is approving.
- Approval records `approved_ips`, the private addresses seen at approval. A later call whose resolved set holds a private address outside `approved_ips` is refused, with the reason `NOT_ALLOWED_HOST`, until an admin re-approves. This blocks a host that an admin approved for one private address from moving to another internal service.
- Loopback, link-local and cloud-metadata addresses stay refused with the flag set (the rule of ADR-0059).
- The flag is a revocable grant: `fleet host revoke-private`. Revoking marks the host's registered repositories stale and a running Job keeps its already-open connections only until job end.
- A User who adds a private-resolving host gets the plain refusal and the hint "ask an admin to approve this host". No row is created until approval, so the admin approves from a pending request: the refusal inserts a `pending` request row (host, user, resolved set) that the admin lists.

Choice A for the dev Forgejo 17.0.1: it resolves to a private address, so it needs this approval. Its certificate is public, so no private CA is needed.

### One Forge interface for GitHub and Forgejo

A new crate `fleet-forge` holds the interface, both adapters and the contract test suite. The server and fleetd both depend on it. ADR-0045 put `Forge` in fleetd with three operations. ADR-0059 kept a separate server-side `RepoVerifier` and rejected reuse. This ADR merges them.

Two traits, one adapter type per forge:

- `ForgeApi` (HTTP, runs where the caller's `Http` seam points: the server for `verify` and `identify`, fleetd for the rest): `identify` (is this host a Forge of the expected kind, used by host add), `verify`, `create_pr` and `ci_result`.
- `ForgeGit` (git over HTTPS, fleetd only): `fetch` and `push`.

`GitHubForge` and `GiteaForge` each implement both. The `Http` seam is a trait the caller injects: the server injects `cred::pinned`, fleetd injects its own pinned client (`netguard`). The `Git` seam is an injected command runner, so tests use a fake. No adapter reads the environment.

`verify` answers read evidence and, when the forge reports it, push permission. `ci_result` returns the normalised `CiResult` of ADR-0028. On Forgejo it reads the combined commit status of the pull request head first and reads Actions runs only if the statuses are empty. The live e2e task (FGJ-28) proved this on the dev Forgejo 17.0.1: a commit with no status answers `statuses: null` with `total_count: 0`, and the adapter then reads Actions runs, which answer `{"total_count": 0, "workflow_runs": []}`. `ci_result` is in the first slice. `push` and `create_pr` take the same `PushTarget`. The broker dispatches through the trait only: `Forges::for_host(host)` returns the adapter by the host row's kind. The broker contains no `gh` call and no forge-specific branch. For GitHub, `create_pr` and `ci_result` use the REST API so one fake HTTP server serves both adapters; `push` and `fetch` stay git over HTTPS with askpass.

Documented exceptions, GitHub only, outside the trait and outside the parity suite:

- GitHub App leasing (ADR-0058): minting, installation tokens, the bot identity, revoke on job end, the `forge:github_app` capability and the `FLEET_GITHUB_APP_REPOS` ceiling. Forgejo has no App equivalent. The adapter receives an already minted token.
- The GitHub release feed (ADR-0060, ADR-0061): fleetd self-update only.
- `allow_private` never applies to GitHub rows.

Every other feature of a forge that the Fleet uses appears on the trait. A new operation lands on the trait and in the contract suite together, or it is listed here as an exception.

### Contract test suite

`fleet-forge/tests/contract.rs` holds one list of cases and runs it against both adapters, each against a fake server of its own forge (a GitHub-shaped fake and a Gitea-shaped fake behind the same scenario names). A case is a scenario plus an expected outcome in the shared vocabulary. The suite fails a build when an adapter lacks a case or a case lacks a fake response. Cases:

| Case | Expected outcome, both adapters |
|---|---|
| identify ok, identify refuses a non-forge or wrong-kind host | kind returned, or refused |
| verify ok, read and push | readable, push true |
| verify ok, read only | readable, push false |
| verify ok, no permissions field | readable, push unknown |
| verify 404 | not found or no access |
| verify 401 and 403 | not found or no access |
| verify 5xx and reset | upstream unavailable |
| verify slow body past budget | timeout |
| verify body over cap | fail closed |
| verify answers 3xx | error, `Authorization` never replayed (the fake counts it) |
| create_pr ok | URL returned |
| create_pr already exists | existing URL returned or a fixed error, same on both |
| create_pr rejected | fixed error, no token echoed |
| ci_result pending, success, failure, none, mixed | the five `CiResult` variants |
| ci_result 404 | fixed error |
| push ok, non-fast-forward, revoked token | status line, fixed errors |
| fetch ok, auth failure | status, fixed error |
| credential for another host | refused before any request |
| redacted error | no token appears in any error text |

Per-adapter extra tests (not in the suite) cover each forge's wire details.

### Credentials: `forgejo_pat` and `credentials.host`

Migration 0045 adds `credentials.host` and the kind `forgejo_pat` (shape `static_secret`, 40 lowercase hex, opaque, no prefix check). The `github_pat` and `github_app` kinds keep `host = 'github.com'`. The unique key becomes `(user, kind, host)`. `PutCredential` takes the host and refuses a host not in the table. `GetJobCredentials` returns one credential per host the Job needs, tagged with the host, and the credential holder keys by host.

Token scopes for Forgejo: `read:repository`, `write:repository`, `write:issue`. The live run on the dev Forgejo 17.0.1 observed that creating a repository over REST also needs `write:user`. The e2e token held `read:repository`, `write:repository`, `write:issue`, `read:issue`, `read:user`, `read:organization`, `read:notification` and `read:package`, plus `write:user` (its repository creation succeeded). The run shows what that token is granted, not the minimum that suffices for push, pull request and CI read.

### Per-job delivery

- Server: `GetJobCredentials` adds, for the Job's repository host, the host name, its kind, `allow_private` and `approved_ips`, and the owner's `forgejo_pat` for that host. A Job whose repository host has no credential for its owner fails with the fixed error of ADR-0033. The server sends the token for the Job's repository host only, never for another host.
- fleetd: `RepoPolicy` gets one token host per host (ADR-0024). Askpass answers a git request for host H with the token stored for H and refuses any other host. Clone and mirror fetch use the same rule.
- Box egress (ADR-0038): the per-job host list (`ConnectProxy::set_job_hosts` and the fetch policy) receives the Job's repository host from the server. The host is admitted for that Job even though it is outside the operator `egress_allow` ceiling, and only that host. For an `allow_private` host, fleetd's address check admits only the `approved_ips` of that host for that Job. A job end clears the host. fleetd never trusts a host name from a Job field.

### Surfaces

- CLI: `fleet host add|list|remove|approve-private|revoke-private`, and `fleet credential` accepts `--host` and the kind `forgejo_pat`. `fleet repo add` accepts any host in the table.
- Web: a credentials page for per-host tokens and a Git remotes page for hosts, pending private requests (admin sees approve and deny) and registered repositories. Every action has a CLI twin and a row in the parity tests.

### Runnable

`runnable` is true for a repository whose host has a credential for the owner and a delivering fleetd. Once fleetd delivers a token per host (the delivery tasks of the plan), every verified row is runnable.

## Hostile-input table

Every row is a test at the host normaliser and at the add RPC. Each result is `NOT_ALLOWED_HOST` unless a row says otherwise.

| Input | Result |
|---|---|
| `user@host` or `user:pw@host` (userinfo) | refused at normalise |
| `host:8443`, `host:443` (port) | refused, port not accepted in the field |
| `10.0.0.1`, `[::1]`, `0x7f000001`, `2130706433` (IP literal, decimal, hex) | refused |
| `*.example.com`, `exa*mple.com` (wildcard) | refused |
| `git.example.com.` (trailing dot) | normalised to no dot, one row |
| `GIT.Example.COM` (case) | normalised to lowercase, one row |
| `bücher.example`, `xn--bcher-kva.example` (IDN, punycode) | stored as punycode, both forms one row; mixed script and invalid punycode refused |
| `https://host`, `ssh://host`, `//host`, `host/path` (scheme, path) | refused |
| space, tab, CR, LF, NEL, U+2028, U+2029, NUL, backslash in the value | refused |
| empty label, leading or trailing hyphen, label over 63, name over 253 | refused |
| `localhost`, `*.local`, `*.internal` (no dot or reserved suffix) | refused at normalise |
| Public name whose A record is private | refused at vet unless approved |
| Name with a public and a private record | refused (every record must pass) |
| DNS rebinding: public at add, private at the call | refused at the call, the vetted-IP dial prevents a second lookup |
| TTL 0 flip between vet and dial | no effect, the dial uses the vetted address |
| Redirect (301, 302, 307, 308) to `169.254.169.254` or an internal name | error, never followed |
| 30x carrying `Location` to another host with the token sent | no second request, no `Authorization` replay |
| Approved private host later resolving to a different private address | refused until re-approved |
| Approved private host resolving to loopback or link-local | refused even with `allow_private` |
| Reply body over `MAX_BODY_BYTES`, or slow past `REPO_CHECK_BUDGET` | fails closed, `TIMEOUT` on time |
| Token for host A sent to host B | impossible, test selects by `(user, host)` and asserts no request to B |

## Consequences

- A User can run Forgejo Jobs end to end: verify, clone, push, pull request and CI status, with CI outside the paid GitHub Actions budget.
- The server now dials hostnames Users supply. The controls above contain it, and the admin approval is the only door to private networks.
- The broker has one code path for both forges. A GitHub-only regression and a Forgejo-only regression both fail the same suite.
- A new migration and a new crate land. `FLEET_REPO_HOSTS` becomes a seed, so an operator's old variable keeps working for one release.
- The host table is global. One User's added host is usable by every User, with their own credentials.
- `approved_ips` makes a DHCP change on a private Forgejo host an admin task.

## Considered and rejected

- **Admin-only host add.** Safer, and the earlier recommendation. The user chose open add, so the SSRF controls carry the weight.
- **Per-User host rows.** Simpler to reason about, but one host approved for a private address would need approving once per User.
- **Approve private by name only, no `approved_ips`.** One approval then covers any later address the name takes. Pinning costs an admin action on a real address change.
- **A private CA or a custom root for hosts.** Out of scope: the target host has a public certificate.
- **A User-supplied kind or subpath.** A hostile host could claim to be GitHub, or smuggle a path to a different service.
- **Two separate interfaces, server verifier and fleetd forge (the ADR-0059 decision).** Parity then relies on discipline, and a feature lands on one forge first and stays there.
- **Keep `gh` for GitHub inside the adapter.** One fake HTTP server could not serve both adapters, so parity would be asserted by hand.
- **Build Forgejo as an extra GitHub-shaped special case in the broker.** It fails the "broker dispatches only through the trait" rule.

## Live results

Run 2026-11-11 by `mise run live:forgejo` (`crates/fleet-forge/tests/live`) against the dev Forgejo 17.0.1, reached over HTTPS with the token from fnox. The token now carries `write:user`, so the suite creates and deletes its own throwaway repositories. Of the 35 contract cases 22 run live and pass, and 13 are skipped, each with the reason recorded in the live plan (`crates/fleet-forge/tests/live/cases.rs`). The skipped cases are listed under Not run live.

| Probe | Result |
|---|---|
| `GET /api/v1/version`, no credential | 200, body `{"version":"17.0.1+gitea-1.22.0"}`, so the closed version document of `identify` matches |
| Invalid token (40 zeros) on `GET /api/v1/user`, `/repos/search` and a repository | 401, message `token is malformed: token contains an invalid number of segments` |
| Real token on `GET /api/v1/user` and `/repos/search?limit=1` | 200 |
| No credential on `/repos/search?limit=1` | 200 |
| No credential on a private repository, and on a missing one | 404 for both |
| Real token on a missing repository | 404 |
| Real token on `GET /api/v1/repos/{o}/{r}` for its own repository | 200, `permissions` is `{"admin":true,"pull":true,"push":true}`, `private` is true |
| Second `POST /api/v1/user/repos` with the same name | 409 |
| Scopes granted (status of one probe per scope) | `read:repository=200 write:repository=200 write:issue=201 read:issue=200 read:user=200 read:organization=200 read:notification=200 read:package=200`; none denied |
| `PATCH /api/v1/repos/{o}/{r}` with a new `name` | 200 |
| `GET /api/v1/repos/{o}/{old}` after the rename | 301, `Location: /api/v1/repos/{o}/{new}` (a relative path), no body parsed |
| `GET .../commits/{sha}/status?page=1&limit=50` with no status posted | 200, keys `commit_url`, `repository` (null), `sha`, `state` (string), `statuses` (null), `total_count` (number 0), `url` |
| `GET .../actions/runs?head_sha={sha}&page=1&limit=50` with no run | 200, `{"total_count": 0, "workflow_runs": []}` |

Findings:

- A token without the needed scope answers 403 with a scope message, and a malformed token answers 401. `status_error` maps both to `Unauthorized`, and `verify` maps both to `NotFound`, as the contract table owes.
- Creating a repository over REST needs `write:user`.
- Renaming a repository leaves the old name answering 301 with a relative `Location`. `verify` makes one request and returns `Redirected`, because decision 3 follows no redirect, so the token never leaves the first request. The contract case `verify-redirect` owes exactly one request and the live run meets it. The rename changes the name a stored credential's repository is known by, so the user must update the remote after a rename.
- A commit with no status makes the dev Forgejo 17.0.1 send `statuses: null` with `total_count: 0`, where the fake sent `[]`. The adapter read the null as malformed. It now reads `null` as an empty list only when `total_count` is the number zero, and then reads Actions runs, which answer an empty list. The fake serves the live shape, so `ci-none` and `ci-checks-none` hold live and in the fake.
- Posting commit statuses `pending`, `success` and `failure` on a pull request head yields `InProgress`, `Success` and `Failure`, and a mix of the three yields `Failure`, so the combined status field names (`status`, `context`) hold.
- Push, non-fast-forward push, fetch with a valid and with a bad token, pull request creation, the second creation that returns the existing pull request, and the rejected creation from `main` onto `main` all match the contract.
- Cleanup of a renamed repository must delete the newest name first, because the old name answers 301 on `DELETE`.

## Not run live

The 13 skipped contract cases, one row each:

| Case | Reason recorded |
|---|---|
| `identify-non-forge` | needs a second host that is not Forgejo |
| `identify-wrong-kind` | needs a second host that is not Forgejo |
| `verify-read-only` | needs a token without write permission |
| `verify-no-permissions` | the live forge always reports permissions |
| `verify-403` | needs a second account; the anonymous probe records it |
| `verify-5xx` | needs a fault the live forge cannot be told to inject |
| `verify-reset` | needs a fault the live forge cannot be told to inject |
| `verify-slow` | needs a fault the live forge cannot be told to inject |
| `verify-over-cap` | needs a fault the live forge cannot be told to inject |
| `redacted-error` | needs a fault the live forge cannot be told to inject |
| `ci-checks-bad-name` | needs a fault the live forge cannot be told to inject |
| `ci-checks-over-cap` | needs a fault the live forge cannot be told to inject |
| `ci-checks-mixed` | commit status contexts are unique, so no duplicate name can be posted |

Consequences for what stays unverified:

- The 403 against 404 split for a repository the token cannot see: it needs a second account. Only the anonymous 404 on a private repository is verified.
- `permissions` on a token without write access: the live token is the owner's, so only the owner shape is verified.
- The minimum scopes for push, pull request and CI read: only the granted set above was observed.
- The fault-injection behaviour (5xx, reset, slow body, over-cap body, bad check name, redacted error text) holds in the fake only.
- `identify` against a non-Forgejo host or a wrong kind holds in the fake only.
- A Forgejo host behind a subpath is unsupported until a later ADR.
