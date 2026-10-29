# Fetch tool and Box egress policy

Status: Proposed 2026-10-28. The fetch core (`fetch.rs`), the fetch event recorder and the fetch service on the job socket (`fetch_service.rs`) are built and wired: `jobs::job_services` registers `Fetch` and `EgressProxy` under the systemd launcher, and the runner registers each job's feed with the recorder while its agent runs. Forgetting the fetch service's per-job counters when a job ends is not wired, and the migration is not built. The `fleetd fetch` command, the default `fetch` skill and the Floor allow-set (`FLOOR_ALLOW`, `Bash(fleetd fetch *)`, merged into the generated `settings.json` allow list) are built. Amends ADR-0029, ADR-0031 and ADR-0034. Refers to ADR-0036 for the per-job unix socket and ADR-0037 for the credential broker.

A Job needs to read web pages: documentation, issue threads, package pages. The Floor denies the built-in `WebFetch` (ADR-0034), and `curl` is denied by pattern. The built-in `WebSearch` stays allowed. This ADR fixes how a Job fetches a URL, which hosts it may reach, where the egress policy lives, and what gets recorded.

## Decision

### Form

- A skill tells the agent to call `fleetd fetch <url>` through Bash. The command talks to the daemon over the per-job unix socket of ADR-0036 and prints the result.
- Built-in `WebFetch` stays denied in the Floor. Built-in `WebSearch` stays allowed.
- Unverified: whether Claude Code discovers a skill under the systemd launcher, with `CLAUDE_CONFIG_DIR` inside the per-job directory (ADR-0031 lists the same gap for `.claude.json` and managed-settings hooks).

### Default policy: allow all public hosts

By explicit user decision, the first policy is `FetchPolicy::AllowAllPublicHosts`: any public host may be fetched.

This is an exfiltration path. An agent can put data in a URL path or query string and send it to any public host, and a host that logs requests receives it. Redaction (ADR-0014) covers exact secret values only, so a repo file, a prompt or any other Job data can leave this way. Even after ADR-0031 P2 ships, allow-all fetch and the server-side `WebSearch` remain exfiltration paths, because both reach the public internet on the agent's behalf.

Fetch still enforces these limits:

- Scheme and port: https on port 443 only. A URL with userinfo is refused.
- Addresses: private, loopback, link-local, carrier-grade NAT (the `100.64` block, range /10), unique local (ULA), multicast and other non-public addresses are refused. IPv4-mapped IPv6 addresses are unwrapped and checked as IPv4.
- DNS: the answer is rechecked, and so is every redirect hop.
- Dial: fetch connects only to an address that passed the check, with the name as SNI and as `Host`. A DNS rebind between the check and the connect cannot land on a private address.
- Caps: body size, decoded size (after content decoding), connect time, total time, redirect count, URL length (1024 bytes) and fetches per job. The values are set in the build task.

### Egress policy is Box-level only

- The egress policy is Box configuration. A Profile has no egress field in v1 and cannot add hosts or widen the policy.
- ADR-0034 gives a Profile a closed field list with `deny_unknown_fields`, and its Deferred list does not name egress. Checked by search across `docs/adr`: no ADR text claims a Profile egress field. A Profile field would need an amendment to ADR-0034.

### Telemetry

- A new `EventKind::Fetch` and proto value `JOB_EVENT_KIND_FETCH = 6`. Migration `0016` widens the `job_event` kind CHECK, which holds five values today.
- Fetch events count toward the 2000-event cap (ADR-0029). Summary figures do not change.
- An intent event is recorded before the fetch and an outcome event after it.
- Fail closed: if the intent event cannot be recorded, the fetch is refused with a fixed error. "Recorded" means the fleetd event feed accepted the event and has not truncated. It does not mean the server confirmed it.
- A failed outcome record adds `fetch_outcome` to the summary `missing` list.
- If the fetch is cut off after the intent (socket cancelled, lease lost, panic), the handler records a failed outcome with no status. If the feed refuses that record, `fetch_outcome` is added to `missing`, so every intent has an outcome or a mark.
- A cap slot is spent once the intent is recorded. A refusal before that point, including a failed intent record, spends none.
- Build order: the recorder first, then the fetch handler.

### Output

The agent receives the raw body when it is text-like and under the cap, labelled as untrusted data. A binary body is refused. Extraction and summarising are the job of a later service.

### Floor allow-set

ADR-0034 lets a Profile `allow` list replace the default allow list. A Profile with any allow rule would then lose the permission for `fleetd fetch` without notice. fleetd gains a fixed `FLOOR_ALLOW`, holding `Bash(fleetd fetch *)` and `Bash(fleetd broker *)`. A Profile allow list cannot drop it. The rule for `fleetd broker` belongs to ADR-0037.

## Findings

- The Box runs with `PrivateNetwork=no` today, and the Floor denies only `curl` and `WebFetch` by pattern. `python3` through Bash reaches any host. Fetch is not a boundary until ADR-0031 P2 ships. Until then it is a logged, address-checked path that a determined agent can bypass.
- Search of `docs/adr` found no Profile egress field in any ADR.

## Radiant migration

A later standalone service, radiant (spec only, own repo), takes over search and fetch with real allowlists.

- `fleetd fetch` becomes a thin client. It sends the request to radiant under a per-job credential that fleetd mints and the agent never holds.
- `FetchPolicy::AllowAllPublicHosts` is replaced by a radiant backend variant.
- The Fetch event stays in fleetd as the local audit.
- The address checks of the netguard stay, for the P2 CONNECT proxy.
- At that time `WebSearch` joins the Floor deny set and `fleetd search` replaces it. That is an amendment to ADR-0034 then.

## Consequences

- Jobs can read the public web at once, with the exfiltration risk above accepted by decision.
- Every fetch leaves a local audit pair of events, and a Job that cannot record cannot fetch.
- A skill and a daemon subcommand join the Template. The migration, the proto value and the Floor constant change together.
- Moving to radiant changes the backend and leaves the command, the event and the Floor rule as they are.

## Considered and rejected

- **Re-enable `WebFetch` and route it through the proxy.** The built-in tool gives no hook for the per-fetch event and the address checks.
- **An egress field in Profiles.** A Profile is stored and shown widely (ADR-0034). A Profile that adds hosts widens the boundary per Job.
- **Server-confirmed recording before the fetch.** It adds a round trip and a dependency on the server for each fetch. The fleetd feed is the local audit.
- **An allowlist now.** The user chose allow-all for the first version. The allowlist arrives with radiant.

## Amendment (ADR-0029)

Adds `EventKind::Fetch` and migration `0016`, described above. The event kinds are then `tool`, `denial`, `api_retry`, `phase`, `stuck` and `fetch`. The summary `missing` list gains `fetch_outcome`.

## Amendment (ADR-0031)

The P2 CONNECT proxy serves the model API only. The allowlist `egress_allow` is Box config. No Profile or bundle can add hosts. This replaces the "per-bundle additions" wording in P2.

## Amendment (ADR-0034)

The Floor bullet "WebFetch: fetches go through the egress proxy (ADR-0031), not the tool" is replaced: fetch goes through `fleetd fetch` on the per-job socket (ADR-0036). The Floor gains `FLOOR_ALLOW` as described above, so the Overlay rule that a Profile `allow` replaces the default allow list does not remove the fetch and broker rules.

## Amendment (ADR-0044)

A non-claude runner calls its own model API. Those hosts must be in the Box `egress_allow` for the P2 proxy to pass them. No Profile can add them.
