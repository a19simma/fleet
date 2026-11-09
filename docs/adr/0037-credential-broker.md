# Credential broker

Status: Proposed 2026-10-28. Built and wired under the systemd launcher: `BrokerWiring` in `jobs.rs` builds the broker and the runner registers it on the job socket. Builds on ADR-0028 and ADR-0036. Amends ADR-0024 (push and `gh` sections) and the "A credential broker only" rejection in ADR-0031.

Decision by the user: the agent never holds `GH_TOKEN` or `FLEET_TOKEN`. fleetd performs `git push` and `gh` calls on its behalf over the per-job socket of ADR-0036.

## Finding

Under ADR-0031 P1 on systemd, the exposure is already closed: `secrets.env` is `0600 fleetd:fleetd`, `InaccessiblePaths=/etc/swarm` hides it and `ProtectProc=invisible` hides fleetd's environ. Only the direct launcher leaks. The agent also never pushes today: the Floor denies `git push` and `gh`, and fleetd publishes after the agent exits. The broker therefore adds agent-initiated operations and removes no credential the agent uses.

## Decision

### Operations

Requests carry no branch, repo, URL or job id.

| Op | Arguments |
|---|---|
| `push` | none |
| `pr_create` | title and body |
| `pr_checks` | none |
| `fetch` | none, own repo only |

Not exposed: arbitrary `git` or `gh`, `gh api`, merge, other repos, branch names and PR URLs from the agent.

### Push target

fleetd derives a `PushTarget` from the claimed Job on the server side: `Own(job id)` or `Chain(root job id)`. The agent never supplies it. Fix Jobs (ADR-0028) push to the chain root's branch `swarm/<root id>`. The server validates the target at `INSERT_FIX` and in `validate_terminal` against `^swarm/[A-Za-z0-9]{1,64}$`. The pattern is a lint over the branch text, shared as `fleet_proto::is_swarm_branch`, and the server also requires the branch to equal `swarm/` plus the chain root job id.

### Ordering

A mid-run push was raceable before ADR-0031 P3: an agent-owned clone made with `git clone --reference`, from which fleetd fetches with hooks and fsmonitor off and `GIT_ALLOW_PROTOCOL=file`, then pushes from the mirror. The `push` op depends on P3, whose clone and publish are built. The read ops (`pr_checks` and mirror `fetch`) ship first. `pr_create` is a write op and ships with `push`. The finish step stays as fallback and is idempotent with a broker push through the shared Published state.

### Push and pr_create implementation

`push` runs the finish step's publish path (`PublishGit` in `publish.rs`) for the bound target only: the same scratch repo, the same fast-forward refspec without `+`, no leftover commit. A head already pushed replies `already published`. `pr_create` (`PublishGh`) replies with the URL the shared state holds, else the open pull request of the bound branch, else creates one with the agent's title and body after the broker's bounds, redaction and attribution checks. A Job with `open_pr` off, or a branch not yet pushed, fails. The shared Published state holds the pushed head and the URL under a per-Job lock held by every publish operation, so the broker and the finish step never run git in the scratch repo at once. The finish step skips a head already pushed, pushes any commit made after it, reuses the URL, and looks for an open pull request first after a failed broker `pr_create`, which may have created one. A broker failure changes nothing the finish step needs.

### Caps

Pushes per Job (10, at least 5 s apart), one `pr_create` call per Job that reaches `gh` (a repeat after a returned URL costs nothing), title 256 chars, body 8 KiB, no attribution lines, redacted output. Errors are fixed messages and never echo a token or a client value. Each op has a timeout.

## Failure modes

- Direct launcher: the socket is refused (ADR-0036), so the broker is absent.
- Lease lost: the job context cancels the services.
- fleetd restart: the socket ends and the Job is LOST.
- Non-fast-forward push or a revoked token: a fixed error.
- Op timeout: a fixed error.

## Consequences

- The agent can push and open a PR without any credential in its reach.
- The broker does not shrink the P2 `CONNECT` proxy. The Claude token stays visible to the agent and `api.anthropic.com` stays reachable.
- Redaction of broker output is an exact-substring match on held credential values. An encoded or split secret in executor output passes. The control for that is the argv and environment the executor gets, not the redactor.
- The attribution check reduces text to lowercase ASCII letters and digits, so it folds case (the Kelvin sign U+212A folds to `k`) and drops every other non-ASCII character. It does not map homoglyphs such as a Cyrillic `o`.
- Unverified: the per-op cap values beyond those stated, and the `pr_checks` output format.
- Residual, accepted: the title and body check allows the characters in U+200C..=U+200F (ZWNJ, ZWJ, LRM, RLM) and refuses every other hostile character, U+2028 and U+2029 included. A joiner can split an `@mention` or an auto-close keyword for GitHub. The attribution check folds case and drops every non-ASCII character per line, so these do not hide an attribution line. The check does not apply NFKC, so a fullwidth letter does not fold to ASCII.

## Considered and rejected

- **Broker only, without P1 to P3.** Amends the "A credential broker only" rejection in ADR-0031: the broker alone leaves the shared mirror and `/proc` open, so it is accepted as one layer on top of P1 to P3.
- **A wrapper on PATH.** Bypassing a wrapper yields no credential, so it is convenience only.
- **Flipping the default launcher to systemd now.** Out of scope here.

## Amendment (ADR-0033, ADR-0045)

The broker holds the Job owner's credentials from `GetJobCredentials` in memory, in place of the Box PAT. Its `push`, `pr_create` and `pr_checks` ops call the `Forge` trait, with GitHub as the only v1 implementation.
