# Fleet

Fleet runs coding-agent Jobs on Boxes and records what each Job did. This file defines the terms of the ADRs on telemetry and metrics (0029, 0030), profiles (0034, 0035, 0052, 0053, 0057), capabilities and the model allowlist (0054), job timing (0055), the job socket, broker and registration (0036, 0037, 0039), fetch policy (0038), credentials and users (0040, 0042, 0043), the GitHub App lane (0058), agent runners and forges (0044, 0045), the mirror key (0046), the update trust root (0047, 0050), the release feed (0060, 0061), the transcript view (0062), and the work tracker (0064, 0065, 0066).

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
A named, versioned, immutable config that overlays a **Bundle** for one Job: `claude_md`, context files, prompt template, skills, allow and deny rules, model, caps and settings. It holds no MCP, hooks or secrets (ADR-0034). It can also carry a **Selection** of **Catalog items** to switch off (ADR-0053, Proposed and partly built).
_Avoid_: preset, template

**Profile identity**:
The `profile.id` of a **Profile**. Version streams, the Job pin and every Profile RPC key on it (ADR-0057).
_Avoid_: profile name as key

**Profile name**:
A per-owner label for a **Profile**, resolved to a **Profile identity** by an owner-scoped lookup. Two owners can use the same name (ADR-0057).
_Avoid_: profile id

**Profile version**:
One numbered entry of a **Profile** (by **Profile identity**), pointing at one **Profile hash**.
_Avoid_: revision

**Profile hash**:
The `sha256("fleet-profile-v1\0" + canonical JSON)` content hash of a **Profile**, recorded on each Job. A Profile with a **Selection** or an authored prompt hashes under the `fleet-profile-v3\0` prefix (ADR-0053, Proposed and partly built).
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
The fleetd service on the **Job socket** that tunnels `CONNECT` requests for a Job's agent, only to hosts inside the Box `egress_allow` ceiling and the model host (ADR-0031, ADR-0038, ADR-0044). Built in `crates/fleetd/src/connect_proxy.rs`.
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
The Box-level rule for which hosts `fleetd fetch` may reach. Set by `fetch_policy` in the Box config file: `allow_all_public` (the default) or `allowlist` with `fetch_allow`. No environment variable and no Profile field changes it (ADR-0038).
_Avoid_: egress allowlist, proxy policy

**User**:
A person who owns **Credentials** and submits Jobs. Built in fleet-server (ADR-0042). Jobs without an owner default to the **Bootstrap user**.
_Avoid_: account, tenant

**Admin**:
A user with `users.is_admin` set. The first user created by setup is admin, and `fleet-server admin grant-admin` and `revoke-admin` change the flag. The bootstrap user is never admin (ADR-0056).

**Bootstrap user**:
The reserved legacy owner `bootstrap`, created lazily. `FLEET_CLIENT_TOKEN` and Jobs submitted without an owner act as it. It has no passkey, so it can never log in, and no one can create or reset a user with that name in any letter case (`BOOTSTRAP_USERNAME` in `crates/fleet-server/src/cred/users.rs`, ADR-0042).
_Avoid_: admin, root user

**First admin**:
The ordinary first **User**, created through a **Setup code** while no user other than the **Bootstrap user** exists. It is a normal row with a passkey and can log in.
_Avoid_: bootstrap user, root user

**Credential**:
One secret a **User** stores for a Job: an agent key or token, or a forge token. Sealed in the `credentials` table (ADR-0040).
_Avoid_: token, secret, key

**Credential kind**:
Which service a **Credential** is for: `anthropic_api_key`, `claude_subscription_token`, `github_pat`, `github_app`, `kimi_membership_key`, `kimi_platform_key` or `codex_api_key` (ADR-0043, ADR-0058).
_Avoid_: credential type, provider

**Credential shape**:
How a **Credential** behaves over time: `static_secret` (accepted in v1) or `refreshing_file` (reserved, rejected in v1) (ADR-0043).
_Avoid_: credential format

**Fingerprint**:
A plaintext display value derived from a **Credential** so the **User** can tell stored credentials apart. It is the first 12 hex characters of a SHA-256 over a fixed label and the secret, never a prefix of the secret (ADR-0040).
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
A hashed bearer token a **User** uses with the API or CLI, in place of the shared client token. Built in fleet-server (ADR-0042).
_Avoid_: token, client token

**Web session**:
The server-side browser login state of a **User**, created by passkey login. Built in fleet-server (ADR-0042).
_Avoid_: login token, cookie

**Setup code**:
The one-time code behind `/setup/{code}` that creates the **First admin**. The server holds it in memory only, issues it at start when no user other than the **Bootstrap user** exists, logs the path, replaces it on every restart and drops it once any user exists. The page asks for a username and a passkey (`Users::issue_setup_code`, `redeem_setup`, ADR-0042).
_Avoid_: enroll code, admin code

**Enroll code**:
The one-time code behind `/enroll/{code}` that registers a passkey for an existing **User**. `fleet-server admin` issues it on create-user and on a passkey reset. The server stores a SHA-256 of it in the `setup_codes` table, which also names it "setup code" in code, and it expires after 24 hours (`SETUP_CODE_TTL_HOURS`). The page asks for no username (`redeem_user_setup`, ADR-0042).
_Avoid_: setup code, invite

**Credential holder**:
The server component that opens a **Credential** for one claimed Job and records the read in `credential_use`. Built in `crates/fleet-server/src/cred/store.rs` (ADR-0040).
_Avoid_: vault, secret manager

**Job credentials**:
The **Credentials** the server releases to a Box for one Job and no other (`release_for_job` in `crates/fleet-server/src/cred/store.rs`, ADR-0043).
_Avoid_: job secrets, job tokens

**Agent runner**:
The agent CLI a Job runs, such as Claude Code, Codex or Kimi, which a **Credential kind** feeds. The `claude`, `codex` and `kimi` runners are built in fleetd (ADR-0044).
_Avoid_: agent, model

**Forge**:
The git host of a repository: GitHub, Gitea or Forgejo (ADR-0043, ADR-0045).
_Avoid_: git server, SCM

**Repo host**:
A forge hostname the operator allows in the operator host list, with its **Forge kind** and an `allow_private` opt-in. A User registers repositories only on a **Repo host** (ADR-0059).
_Avoid_: git server, remote

**Forge kind**:
The family of a **Repo host**: `github` is built, `forgejo` is accepted in config, `gitlab` is planned. The config `Forge` enum and the core `ForgeKind` enum are separate types. It selects the **Repo verifier**. It is set per host in operator config, never by the User (ADR-0059).
_Avoid_: forge type, provider

**Repo key**:
The `(user, host, path)` triple that names a **Registered repository**. It differs from the Mirror key, which is the (user, repo) pair (ADR-0059).
_Avoid_: repo id

**Repo verifier**:
The server-side `RepoVerifier` implementation of one **Forge kind**. The `AddRepo` handler runs it before the insert: it reads the repository with the User's own stored credential and records push as optional. `add` is refused when the host has no verifier or the User has no credential for it. Built: the trait, the GitHub verifier, the registry and the public `FakeVerifier`. Not built: the Forgejo verifier (ADR-0059).
_Avoid_: repo checker, forge check

**Registered repository**:
A row in a User's repository registry, keyed by **Repo key**. It is a record only and grants nothing: the App repository ceiling and the `forge:github_app` capability stay the only App grants. Submit does not enforce it in v1 (ADR-0059). The CLI (`fleet repo`) and the web page list its host in punycode form. Elsewhere in this file "repo" means the repository of a Job, not a **Registered repository**.
_Avoid_: project, saved repo

**CI result**:
The pass or fail outcome of a forge check on a Job's pull request, read through the **Broker** (ADR-0028, ADR-0037).
_Avoid_: build status

**Mirror key**:
The `(user, repo)` pair that names a repository mirror, so each user fetches into a separate mirror (ADR-0046). Built in fleetd (`Workspace::mirror_dir_for`).
_Avoid_: deploy key

**Owner**:
The **User** a **Credential**, Job or **Profile** belongs to (`jobs.user_id`, ADR-0042).
_Avoid_: creator, tenant

**Box token**:
The bearer token a Box uses with the server, `FLEET_TOKEN`, in box scope (ADR-0014, ADR-0023).
_Avoid_: token, worker token

**Client token**:
The bearer token the CLI uses with the server, `FLEET_CLIENT_TOKEN`, in client scope (ADR-0014, ADR-0023).
_Avoid_: token, API token

**Trust root**:
The key source fleetd verifies update manifests against: the file `/etc/fleetd/update.pub` when it exists, else the **Baked key**. A present but invalid file disables updating and never falls back (ADR-0047, ADR-0050).
_Avoid_: trust anchor, signing key

**Baked key**:
The default minisign public key embedded in the fleetd binary from `crates/fleetd/trust/update.pub` (`BAKED_TRUST_KEY`). Only a new fleetd build changes it (ADR-0050).
_Avoid_: update.pub, signing key

**Release feed**:
The feed is the signed `manifest.json` and `manifest.json.minisig` of the latest published GitHub release of `FLEET_UPDATE_REPO`, which the server fetches itself on a timer. Fully built (ADR-0060): the redirect-following fetcher (`ReleaseFetcher`, ADR-0061), the cache, seq gate and poller (`update_feed`), and the relay wiring: `UpdateRelay::from_feed` serves the cache and `main.rs` spawns the poller only when `FLEET_UPDATE_REPO` is set. The Deployment sets it to the public repository. File mode (`FLEET_UPDATE_MANIFEST`) stays as break-glass (ADR-0060, ADR-0061).
_Avoid_: update channel, manifest URL

**Update relay**:
The server component, `UpdateRelay`, that holds the **Last good pair** and passes it to boxes in `HeartbeatReply`. It signs and verifies nothing (ADR-0047, ADR-0060).
_Avoid_: update server, mirror

**Last good pair**:
The manifest bytes and signature bytes the **Update relay** last accepted, held in memory with no maximum age. A failed fetch never evicts it (ADR-0060).
_Avoid_: cache entry, current manifest

**Seq gate**:
The server rule that replaces the **Last good pair** only for a higher `seq`, and rejects a lower `seq` or an equal `seq` with different bytes. A sanity check on storage, not a trust decision: fleetd still checks `seq` itself (ADR-0060).
_Avoid_: version check, replay guard

**Console theme**:
The dark, dense daisyUI theme named `console`, defined in `crates/fleet-server/ui/input.css` and described in `DESIGN.md`. Every web page renders through the shared shell in `src/web/layout.rs` (ADR-0051).
_Avoid_: skin, dark mode

**Generated stylesheet**:
`crates/fleet-server/assets/ui.css`, built from `ui/input.css` by `mise run css` and committed. CI rebuilds it and fails on any diff (ADR-0051).
_Avoid_: style.css, build output

**Catalog**:
The admin-curated global set of **Catalog items** that **Profiles** inherit from and switch off through a **Selection** (ADR-0053).
_Avoid_: library, registry

**Catalog item**:
One entry of the admin-curated global Catalog: a kind (`skill`, `subagent`, `tool` or `context`), an id, a body and an `enabled` flag only an Admin sets. Items are insert-only and versioned; an Admin disables one by clearing `enabled`, never by deleting it (ADR-0053).
_Avoid_: plugin, library entry

**Selection**:
The sorted, duplicate-free list of **Catalog item** ids a **Profile** switches off (`disabled`). A Profile inherits every enabled item it does not list, and the list holds at most `MAX_SELECTION` (256) ids (ADR-0053).
_Avoid_: opt-in list, enabled list

**Visibility**:
The `private` or `shared` setting of a **Profile**. A new Profile is `private`, seen by its **Owner** alone; `shared` lets every User list, read and submit its published versions. It is not part of the **Profile hash** (ADR-0052).
_Avoid_: access level, sharing mode

**Capability**:
A grant an **Admin** gives a **User**. `profile:tools` is needed to save or submit a **Profile** that lists `tools` or selects a `tool` **Catalog item**. `forge:github_app` gates the `github_app` credential kind (ADR-0058). A request under the **Client token** acts as the **Bootstrap user**, which holds the Capability only if an Admin grants it (ADR-0054).
_Avoid_: role, permission

**Model allowlist**:
The exact, case-sensitive list of model ids a Job may use. The server reads it from `FLEET_MODEL_ALLOWLIST` and checks at profile save, submit and blob serve; fleetd re-checks before spawn against its own `model_allowlist`. An unset list restricts nothing (ADR-0054).
_Avoid_: model whitelist, model policy

**Span**:
One timed interval of a Job with a kind (`Shell`, `BgShell`, `Tool` or `ApiWait`), in job-relative milliseconds (ADR-0055).
_Avoid_: trace span

**Timing summary**:
The five parts `api_wait`, `tool`, `shell`, `idle` and `overhead` that sum to a Job's wall time. fleetd reconciles **Spans** into it with `fleet_core::timing::aggregate` and reports it with `ReportTiming`. The server recomputes it from the spans and refuses a report that differs (ADR-0055).
_Avoid_: timing report, time breakdown

**Idle**:
Part of the **Timing summary**: agent window time covered by no **Span** (ADR-0055).
_Avoid_: wait time

**Overhead**:
Part of the **Timing summary**: wall time outside the agent window, spent on clone, setup, push, pull request and teardown (ADR-0055).
_Avoid_: setup time

**Background command**:
A shell command with no completion event. fleetd measures it as a `BgShell` **Span**. `BgWatcher` polls `pueue status --json` for tasks created after the Job started, and a pueue task still open at Job exit ends with `ended_by=job_exit` (ADR-0055).
_Avoid_: detached command, async shell

**GitHub App credential**:
The `github_app` **Credential kind**: a **User**'s installation id for the operator's GitHub App. The App id and private key are server config, never stored. Built: the kind, the installation id parser, the mint client with response validation, the App id and key file config, the mint audit schema and rows, the per-Job mint cap, the tombstone set by deleting a credential with mint history, and the `forge:github_app` capability gate. `PutCredential`, the web form and `fleet credential put` save the kind for a **User** with the capability, and `VerifyCredential` mints once under the release gate and drops the token; its audit rows have scope `probe`, count toward the per-User rate and never toward a Job's mint cap (ADR-0058). The release path mints the token after the capability check and the transaction commit (ADR-0058, SEC-011). fleetd consumes the released token and identity. fleetd refreshes the token under 10 minutes before expiry, before a Push or Gh child, a mirror fetch and a broker `gh` call, and revokes the replaced token and the held token at Job end. The server limits mints per User per minute and answers past the limit with a retryable reason, `github app token rate limited`, which fleetd waits out on the first fetch and keeps the held token through on a refresh; the per-Job cap is terminal. The installation allowlist, the repository allowlist and the owner binding are built, set by `FLEET_GITHUB_APP_ACCOUNT`, `FLEET_GITHUB_APP_INSTALLATIONS` and `FLEET_GITHUB_APP_REPOS` (ADR-0058). A release or verify dropped mid-mint closes its `attempt` row as `failed`, and the lookup and mint fit inside fleetd's call budget. Not built: the per-credential repository list, the audit of revokes inside the mint client, a revoke of a token created while the mint call was cut off (its value was never read), and a fleetd revoke that survives a daemon exit (ADR-0058).
_Avoid_: app token, app key

**Installation token**:
The one-hour GitHub token the server mints from a **GitHub App credential** for one Job, clamped to the Job repository and delivered as wire kind `github_installation_token`. It is never stored. Built: `GetJobCredentials` mints it for a User who holds a `github_app` credential and the capability, and the App wins over a `github_pat`. fleetd holds it as the git and `gh` token of the Job and carries its expiry, and refreshes it before a Push or Gh child when fewer than 10 minutes remain, up to a terminal per-Job mint cap and a retryable per-User rate limit. The mirror fetch and the broker `gh` call resolve the token again on every call, through the same refresh and lease as a Push or Gh child, and hold the lease until the child exits. fleetd revokes the replaced token once the children that started with it have exited and, at Job end, the held one, and any token in a reply it rejects. A late refresh never overwrites an entry a re-fetch replaced. A token with no expiry is refused at the first fetch, and a box clock ahead of the server's refreshes every 45 minutes (ADR-0058). The server mints only for an installation on `FLEET_GITHUB_APP_INSTALLATIONS` that GitHub reports as active, of this App and owned by `FLEET_GITHUB_APP_ACCOUNT`, and only for a Job repository on `FLEET_GITHUB_APP_REPOS`; unset lists deny everything (ADR-0058).
_Avoid_: app token

**Mint scope**:
`MintScope` in `cred/app_lane.rs`: `Job` for a release or refresh row that counts toward the per-Job cap and the per-User rate, `Probe` for a `VerifyCredential` row that counts toward the per-User rate only.

**Mint policy**:
`MintPolicy` in `cred/app_lane.rs`: the per-Job mint cap, the per-User rate and the `denied` row dedupe window of a credential store, set with `with_policy`.

**Bot identity**:
The git name and email (`GitIdentity`) a Job commits under when it uses a **GitHub App credential**. The server sends it and fleetd re-validates it with `BotIdentity::new`, failing the Job before the clone when it is missing or invalid. Built on the server from `FLEET_GITHUB_APP_BOT_NAME` and `FLEET_GITHUB_APP_BOT_EMAIL`. fleetd sets it as the author and committer of the Job (ADR-0058).
_Avoid_: bot user

**Forge credential**:
A **Credential** for a **Forge**: a `github_pat` today, or a **GitHub App credential** (ADR-0043, ADR-0058). The App kind can be saved, and fleetd uses its released token and identity (ADR-0058).

**Transcript**:
The redacted stream-json lines of one Job, stored as `job_transcript` chunks (ADR-0022, ADR-0062).

**Transcript entry**:
One typed unit that the view parser in `fleet_core::transcript` emits from a line of a **Transcript** (ADR-0062).

**Tool pair**:
A `tool_use` joined to its `tool_result` by id in one **Transcript entry** (ADR-0062).

**Hostile text**:
A control character, format character, line or paragraph separator, or tag-block character. One set in `fleet_core::text` (ADR-0063). Strip paths remove it. Reject paths refuse it but allow ZWNJ and ZWJ.

**Fleet note**:
A non-JSON line that starts with `fleet: ` and that fleetd writes into a **Transcript**. Not authoritative: the Job row is (ADR-0062).

**Work project**:
The server record binding one registered repository to an **Owner** and holding its **Work items** and **Slices** (ADR-0064). Every graph write locks its row.
_Avoid_: board, tracker

**Work item**:
One unit of change in a **Work project**, with a key, **Slice** membership and dependencies. It has many **Attempts** (ADR-0064).
_Avoid_: task, issue, ticket

**Slice**:
A named set of repository paths that one **Attempt** at a time may change. Two Slices overlap when a path of one equals or contains a path of the other (ADR-0064).
_Avoid_: lane, area

**Slice lease**:
The row that holds a **Slice** for one **Attempt**, keyed by the Slice. A claim inserts one per Slice of the **Work item**. It has a TTL and a reaper (ADR-0064).
_Avoid_: lock

**Attempt**:
One claim of a **Work item**, ending in a **Verdict** or lost when its **Slice leases** expire (ADR-0064).
_Avoid_: run, try

**Verdict**:
The `pass` or `fail` an **Attempt** reports, with a note and a redacted 8 KiB evidence tail (ADR-0064).
_Avoid_: result, outcome

**Ready**:
A **Work item** whose dependencies all passed, which no **Attempt** holds and whose **Slices** have no **Slice lease**. Computed, never stored (ADR-0064).
_Avoid_: unblocked, available

**Defer**:
Work found during an **Attempt** and left out of scope, with a reason and a vertical. Not a **Work item** until a person promotes it (ADR-0064).
_Avoid_: backlog item, todo

**Retro**:
A review of a span of finished **Work items**. It cannot close while an **Improvement** lacks a disposition (ADR-0065).
_Avoid_: postmortem, review

**Improvement**:
One proposed change to how the loop works, ranked by its count of occurrences, ending as accepted, rejected, deferred or applied (ADR-0065).
_Avoid_: lesson, suggestion

**Pitfall**:
A known trap with a symptom, a cause and a fix, kept per **User** or per **Work project** and ranked into the brief a worker reads before an **Attempt** (ADR-0065).
_Avoid_: gotcha, known issue

**Suggested edit**:
A stored proposal to change a **Slice**, a **Pitfall** or a repository file, applied only after an interactive **User** accepts it. It goes stale when its base hash changes (ADR-0066).
_Avoid_: patch, auto-fix

## Relationships

- A **Job** has many **Job Events** and at most one **Job Summary**.
- A **Job Summary** records at most one **Stuck rule**, the first that fired.
- An **Incomplete** **Job Summary** lists what it never observed in `missing`.
- A **Work project** has many **Work items** and **Slices**. A **Work item** has many **Attempts**; a claim takes one **Slice lease** per **Slice** of the item.
- A **Retro** has many **Improvements**. An accepted **Improvement** can create a **Pitfall**. A **Suggested edit** changes a **Slice** or a **Pitfall** only after a **User** accepts it.

## Flagged ambiguities

- "token" now means **Box token**, **Client token**, **API token**, **Web session** or **Credential**. Always use the qualified term.
- "egress" and "fixture" appear in planning notes only. No product code defines them, and ADR-0030 lists them as out of scope.
- "bundle" and "profile" overlap. A **Bundle** is the on-disk files; a **Profile** is the named config overlaying it for one Job (ADR-0034, ADR-0035).
