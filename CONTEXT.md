# Fleet

Fleet runs coding-agent Jobs on Boxes and records what each Job did. This file defines the terms used by the telemetry and metrics ADRs (0029, 0030) and the profile ADRs (0034, 0035) and the job socket, broker and registration ADRs (0036, 0037, 0039).

## Language

**Job Event**:
One row of `job_event`: a tool call, denial, API retry, phase change or stuck signal of a Job, keyed by `(job_id, seq)`.
_Avoid_: log line, trace span

**Job Summary**:
The one `job_summary` row per Job holding its figures, its `complete` flag and its `missing` list.
_Avoid_: report, stats row

**Incomplete**:
A **Job Summary** with `complete` false or a non-empty `missing` list, where each unobserved figure is `NULL`, never 0.
_Avoid_: partial, zero-filled

**Stuck rule**:
One of `repeat_action_observation`, `repeat_error`, `alternating` and `monologue`, checked by a detector that only records the first rule to fire and changes nothing about the Job (shadow mode).
_Avoid_: loop detector, watchdog

**Profile**:
A named, versioned, immutable config that overlays a **Bundle** for one Job: `claude_md`, context files, prompt template, skills, allow and deny rules, model, caps and settings. It holds no MCP, hooks or secrets (ADR-0034).
_Avoid_: preset, template

**Profile version**:
One numbered entry of a named **Profile**, pointing at one **Profile hash**.
_Avoid_: revision

**Profile hash**:
The `sha256("fleet-profile-v1\0" + canonical JSON)` content hash of a **Profile**, recorded on each Job.
_Avoid_: etag

**Batch**:
One prompt dispatched once per **Profile** so the outcomes can be compared.
_Avoid_: run group, experiment

**Floor**:
The fixed deny set and permission mode (`dontAsk`) in fleetd that no **Profile** can loosen.
_Avoid_: baseline, default policy

**Bundle**:
The on-disk files fleetd installs for the agent: CLAUDE.md, settings.json, skills and hooks. A **Profile** overlays it for one Job.
_Avoid_: profile, config version

**Bundle channel**:
Planned, not built: a release channel for the agent config bundle a Box loads, meant for a canary rollout of config changes.
_Avoid_: config version

**Egress proxy**:
Planned, not built: a proxy that would restrict the hosts a Job's agent can reach.
_Avoid_: firewall

**Agent unit**:
The systemd unit `fleet-agent@<job id>.service` that runs one Job's agent under the **Job uid** when `agent_launcher` is `systemd`.
_Avoid_: job service, runner unit

**Job uid**:
The user `fleet-job` that an **Agent unit** runs as, in the group `fleet-work`, apart from the `fleetd` uid that holds the secrets.
_Avoid_: agent user, sandbox user

**Launcher**:
The seam in fleetd that starts an agent, either `direct` as a child process or `systemd` as an **Agent unit**.
_Avoid_: spawner, executor

**Hook socket**:
The unix socket `hook_socket` that serves only `/healthz` and `/hook/<event>`, in its own directory so the **Job uid** can reach it.
_Avoid_: main socket

**Run dir**:
The directory `/run/fleet/<job id>/` holding a Job's `env`, `spec.json` and `stdout` FIFO for an **Agent unit**.
_Avoid_: job dir, workspace

**Job socket**:
The per-job unix socket under the **Run dir** that carries one handshake line selecting a service (broker, fetch, egress proxy). fleetd accepts a peer only when its cgroup is the Job's **Agent unit** (ADR-0036).
_Avoid_: proxy socket, main socket

**Broker**:
The fleetd service on the **Job socket** that performs `push`, `pr_create`, `pr_checks` and `fetch` for the agent, which never holds the token (ADR-0037).
_Avoid_: wrapper, credential helper

**Push target**:
`Own(job id)` or `Chain(root job id)`, derived server side from the claimed Job. Names the branch `swarm/<id>` the **Broker** may push; the agent never supplies it (ADR-0037).
_Avoid_: branch argument

**Fixture**:
Planned, not built: a recorded Job input with an expected outcome, meant to run through `fleet eval run`.
_Avoid_: test case

**Service registry**:
The per-Job map of services behind the **Job socket**, keyed by the Job id the listener sets. The runner registers before launch and unregisters on every end path; an unknown id closes the connection with no reply (ADR-0039).
_Avoid_: service map, handler table

**Job end hook**:
The one call site that runs on every end path of a Job (success, failure, cancel, lease loss, timeout, panic) and unregisters the Job from the **Service registry** (ADR-0039).
_Avoid_: cleanup callback, finalizer

**Fetch policy**:
The Box-level rule for which hosts `fleetd fetch` may reach. Planned, not built: allow all public hosts first, a radiant allowlist later. A Profile cannot change it (ADR-0038).
_Avoid_: egress allowlist, proxy policy

**User**:
A person who owns **Credentials** and submits Jobs. Planned, not built (ADR-0040, ADR-0043).
_Avoid_: account, tenant

**Credential**:
One secret a **User** stores for a Job: an agent key or token, or a forge token. Sealed in the `credentials` table (ADR-0040).
_Avoid_: token, secret, key

**Credential kind**:
Which service a **Credential** is for: `anthropic_api_key`, `claude_subscription_token`, `github_pat`, `kimi_membership_key`, `kimi_platform_key` or `codex_api_key` (ADR-0043).
_Avoid_: credential type, provider

**Credential shape**:
How a **Credential** behaves over time: `static_secret` (accepted in v1) or `refreshing_file` (reserved, rejected in v1) (ADR-0043).
_Avoid_: credential format

**Fingerprint**:
A plaintext display value derived from a **Credential** so the **User** can tell stored credentials apart. It never reveals the secret (ADR-0040).
_Avoid_: hash, checksum

**Sealer**:
The trait that seals and opens **Credential** ciphertext. `FileSealer` is the first implementation; a KMS or Vault Transit backend can replace it (ADR-0040).
_Avoid_: encryptor, vault

**Master key**:
The key file mounted into the server pod from a Kubernetes Secret that a **Sealer** uses. It protects DB backups and read-only SQL, not a compromised server pod (ADR-0040).
_Avoid_: root key, secret key

**Key ring**:
The set of **Master keys** selected by `key_id`, so rotation needs no downtime (ADR-0040).
_Avoid_: key store

**API token**:
Planned, not built: a bearer token a **User** uses with the API or CLI, in place of the shared client token.
_Avoid_: token, client token

**Web session**:
Planned, not built: the browser login state of a **User**.
_Avoid_: login token, cookie

**Credential holder**:
The server component that opens a **Credential** for one claimed Job and records the read in `credential_use`. Planned, not built (ADR-0040).
_Avoid_: vault, secret manager

**Job credentials**:
The **Credentials** the server releases to a Box for one Job and no other. Planned, not built (ADR-0043).
_Avoid_: job secrets, job tokens

**Agent runner**:
The agent CLI a Job runs, such as Claude Code, Codex or Kimi, which a **Credential kind** feeds. Planned, not built.
_Avoid_: agent, model

**Forge**:
The git host of a repository: GitHub, Gitea or Forgejo (ADR-0043, ADR-0045).
_Avoid_: git server, SCM

**CI result**:
The pass or fail outcome of a forge check on a Job's pull request, read through the **Broker** (ADR-0028, ADR-0037).
_Avoid_: build status

**Mirror key**:
Planned, not built: the key that grants read access to a repository mirror. Owned by another ADR.
_Avoid_: deploy key

**Owner**:
The **User** a **Credential** or Job belongs to. Planned, not built.
_Avoid_: creator, tenant

**Box token**:
The bearer token a Box uses with the server, `FLEET_TOKEN`, in box scope (ADR-0014, ADR-0023).
_Avoid_: token, worker token

**Client token**:
The bearer token the CLI uses with the server, `FLEET_CLIENT_TOKEN`, in client scope (ADR-0014, ADR-0023).
_Avoid_: token, API token

## Relationships

- A **Job** has many **Job Events** and at most one **Job Summary**.
- A **Job Summary** records at most one **Stuck rule**, the first that fired.
- An **Incomplete** **Job Summary** lists what it never observed in `missing`.

## Flagged ambiguities

- "token" now means **Box token**, **Client token**, **API token**, **Web session** or **Credential**. Always use the qualified term.
- "egress" and "fixture" appear in planning notes only. No product code defines them, and ADR-0030 lists them as out of scope.
- "bundle" and "profile" overlap. A **Bundle** is the on-disk files; a **Profile** is the named config overlaying it for one Job (ADR-0034, ADR-0035).
