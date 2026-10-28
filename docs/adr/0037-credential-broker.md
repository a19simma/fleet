# Credential broker

Status: Proposed 2026-10-28. Not built. Builds on ADR-0028 and ADR-0036. Amends ADR-0024 (push and `gh` sections) and the "A credential broker only" rejection in ADR-0031.

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

fleetd derives a `PushTarget` from the claimed Job on the server side: `Own(job id)` or `Chain(root job id)`. The agent never supplies it. Fix Jobs (ADR-0028) push to the chain root's branch `swarm/<root id>`. The server validates the target at `INSERT_FIX` and in `validate_terminal` against `^swarm/[A-Za-z0-9]{1,64}$`. This closes TEL-J3 SEC-001.

### Ordering

A mid-run push is raceable until ADR-0031 P3 ships: an agent-owned clone made with `git clone --reference`, from which fleetd fetches with hooks and fsmonitor off and `GIT_ALLOW_PROTOCOL=file`, then pushes from the mirror. The `push` op depends on P3. The read ops (`pr_checks`, mirror `fetch`, `pr_create`) ship first. The finish step stays as fallback and is idempotent with a broker push through the shared Published state.

### Caps

Pushes per Job, one PR per Job, title 256 chars, body 8 KiB, no attribution lines, redacted output. Errors are fixed messages and never echo a token or a client value. Each op has a timeout.

## Failure modes

- Direct launcher: the socket is refused (ADR-0036), so the broker is absent.
- Lease lost: the job context cancels the services.
- fleetd restart: the socket ends and the Job is LOST.
- Non-fast-forward push or a revoked token: a fixed error.
- Op timeout: a fixed error.

## Consequences

- The agent can push and open a PR without any credential in its reach.
- The broker does not shrink the P2 `CONNECT` proxy. The Claude token stays visible to the agent and `api.anthropic.com` stays reachable.
- Unverified: the per-op cap values beyond those stated, and the `pr_checks` output format.

## Considered and rejected

- **Broker only, without P1 to P3.** Amends the "A credential broker only" rejection in ADR-0031: the broker alone leaves the shared mirror and `/proc` open, so it is accepted as one layer on top of P1 to P3.
- **A wrapper on PATH.** Bypassing a wrapper yields no credential, so it is convenience only.
- **Flipping the default launcher to systemd now.** Out of scope here.
