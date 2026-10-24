# fleetd box daemon

Status: Accepted

Hooks, workmux and pueue each hold part of what a Box is doing. workmux has no status-change or exit hook, and a `claude -p` run reports its cost only in its own output. Today the laptop reads Box state over ssh, so state exists only while the laptop is awake and polling.

## Decision

A daemon `fleetd` runs on every Box and is the only Box component that talks to the Fleet server.

- **Language.** Rust, one static musl binary, matching the server stack (ADR-0013).
- **Unit.** A system unit `fleetd.service` with `User=agent`, `RuntimeDirectory=fleetd`, `StateDirectory=fleetd`, `Restart=always` and a watchdog. A system unit needs no login session and no `XDG_RUNTIME_DIR` of its own. It reaches pueue through a socket in `/run/user/<uid>`, so it orders itself `After=` and `Wants=user@<uid>.service`. It sets `ProtectSystem=strict`, `ProtectHome=read-only` and `ReadWritePaths` for its state dir and `~agent/.local/state/workmux`, because `ProtectSystem=strict` alone leaves `/home` writable on the Box (T9).
- **Listeners.** HTTP on `127.0.0.1:<port>`, fixed in config. Claude Code reaches it with one `type: "http"` hook per event to `http://127.0.0.1:<port>/hook/<Event>`. A unix socket at `/run/fleetd/fleetd.sock` serves `fleet-job` and local tools. The socket cannot serve hooks: Claude Code's http hook rejects `unix:` and `http+unix:` URLs on 2.1.289 (T3).
- **Sources.** Hooks, a watcher on `~/.local/state/workmux/agents/*.json` plus `workmux status --all --json` and `workmux wait` (exit 3 means the agent crashed, but only when the wait started before the crash), its own pane-process liveness check, pueue task results (callback with id and group only, plus a reconcile poll), and the `result` object of `claude -p --output-format json` including `total_cost_usd`.
- **Transcript read.** After a delay following `Stop`, and again at `SessionEnd`, fleetd reads the file at `transcript_path` for preview text and a session timeline. It never reads inline in the `Stop` handler. This is best-effort. The docs call the entry format internal and changing between versions, and say the file is written asynchronously and may lag a Stop hook. Cost comes from the `result` message, never from the transcript. `last_assistant_message` supplies the immediate preview, and a parse failure degrades to it. Token counts, if ever derived, de-duplicate on `message.id`. The Claude version is pinned in the Template, and a pin bump requires re-running the transcript test (T10 in the plan).
- **Stamps.** Configured box name, hostname, machine-id and boot id on every event (ADR-0012). No VPN identity is read.
- **Server address and token.** `FLEET_SERVER_URL` from `/etc/swarm/box.env` and the bearer token from `/etc/swarm/secrets.env` (ADR-0014). fleetd calls no VPN tool and reads no VPN state.
- **Event list.** The recorded hook events are a config list in fleetd, not hardcoded. The default is provisional (plan, decision 6).
- **Hook config.** Managed settings, baked into the Template as `/etc/claude-code/managed-settings.json` or a `managed-settings.d/10-fleetd.json` drop-in. T4 settled it: hooks merge across managed, user and `--settings` sources, so a Job cannot suppress the managed hook. The loopback hook appears only there. Each hook sets a `timeout`, and `onFailure` is not used.
- **Bake.** The binary and its config join the Template at a pinned, checksummed version. An upgrade is a Template rebuild.
- **No git.** fleetd never pushes and holds no git credential: a Box pushes only its own `swarm/` branch, and fleetd is not the pusher. It runs read-only git commands to count unpushed commits.

## Phase 0 results

Ten throwaway tests ran on one Box on 2026-10-24 (Claude Code 2.1.289, workmux 0.1.276, pueue 4.0.4). Records are in `docs/phase0/`. This ADR was Proposed during Phase 0 and is Accepted.

Verified: `Stop` fires once per `claude -p` run (T1). The hook field names exist as the plan listed them (T2). http hooks work on loopback (T3), and a down fleetd costs about 2 ms per hook (T8). Managed settings load on Linux and merge with user hooks (T4). A system unit with `User=agent` reaches the real pueue socket and the workmux state (T9). Transcript entries carry `usage` and `model` (T10).

Where a result contradicts or narrows this ADR:

- **Transcript read on `Stop`.** The ADR assumed a read at `Stop` works. T10 contradicts it: the final assistant entry was missing at `Stop` in all three modes, and present 2 s later. The decision above now reads after a delay, in fleetd.
- **Hook URL.** The ADR said `/hook`. The event name is only in the path, so the URL is `/hook/<Event>` (T3).
- **Unix socket for hooks.** Not possible on 2.1.289 (T3). The socket stays for `fleet-job` and local tools.
- **System unit and the user session.** The ADR said a system unit needs no user session. It needs none of its own, but the pueue socket lives in the tmpfs of `user@<uid>.service`, so the unit depends on that service (T9).
- **`workmux wait` exit 3.** It reports a crash only when the wait started before the crash. After it, the exit is 1 (`No agent found`). A killed agent also leaves a `working` state file and emits no event, so fleetd needs its own liveness check (T5).
- **Hook config.** Left open to T4 and T8. Resolved above as managed settings.

Still unverified: a stalled listener with a hook `timeout`, the `http` hook type inside a managed file, interactive sessions, and the transcript lag over more than one sample per mode. The plan lists them as Phase 1 pre-checks.

## v1 cut and recovery (2026-10-24)

v1 builds this ADR without `fleet-job`, claim and lease, drain, the KEDA seam and transcript summaries beyond the last assistant text (plan, v1 cut). The unix socket stays for `fleetd pueue-callback`.

- **Session registry.** SQLite table `sessions_seen` in `queue.db`: `session_id`, `transcript_path`, `cwd`, `kind`, `last_seen_size`, `last_mtime`, `last_event_at`, `state`. Hooks upsert it. A registry change and the event it derives commit in one transaction.
- **Reconciler.** At start and every 30 to 60 s (`reconcile_interval`, default 45 s) fleetd discovers `~/.claude/projects/*/*.jsonl` and `~/.local/state/workmux/agents/*.json`, stats every registered transcript (size and mtime only) and parses only a changed file from the last seen offset, for the last assistant text and last entry time. It runs the pane and process liveness check.
- **Derived events.** `session.discovered`, `session.stalled`, `session.ended_unseen` and `workmux.agent_crashed`, tagged `source=reconcile` (ADR-0012).
- **Supervision.** `Restart=always`, `RestartSec=2`, `WatchdogSec=60`. fleetd pings the watchdog only while the listener, forwarder and reconcile loop each progress. The server marks a Box `stale` at 90 s and `lost` at 10 min without a heartbeat.
- **Gap.** The lost hook payloads stay unrecoverable. The gap is accepted because the reconciler restores state and the last assistant text.
- **Distribution.** The binary comes from a public release installed through mise (ADR-0017). The repo holds no hostname, address or token, and fleetd reads all of them from env and files.

## Decisions (2026-10-24)

- Accepted 2026-10-24 together with ADRs 0012 to 0017.
- The docs live in this repo, with the plan in `docs/plan.md`.
- v1 builds fleetd without `fleet-job`, so v1 carries no Job cost (deferred).

## Consequences

- One more process per Box, run as `agent`. It adds no privilege and no inbound port beyond loopback.
- Any local process can post events to the loopback port. Boxes are single-user.
- Hook events fired while fleetd is down are lost: Claude Code logs the failure once at ERROR and does not retry (T8). The watchers and the pueue poll reconcile state on restart. The lost hook payloads are not recoverable.
- A fleetd fix costs a Template rebuild and re-created Boxes. Event and handshake versions keep mixed Boxes working (ADR-0012).
- Adds fleetd to the Template contents.
- The transcript read ties preview quality to the pinned Claude version.

## Considered and rejected

- **Command hooks that call the server directly.** A process spawn per event, no queue, and lost events whenever the server or the network is away.
- **Polling only (extend the existing ssh poll).** Needs the laptop awake, and misses `Stop` and `Notification` content.
- **A user systemd unit.** Depends on linger and `XDG_RUNTIME_DIR`. The system unit shares the linger dependency through `user@<uid>.service` (T9), so the gap is smaller than first assumed. It stays preferred because ssh logins leave `XDG_RUNTIME_DIR` unset and it restarts without a session.
- **Patch workmux for a status hook.** Upstream has no such hook, and a fork adds a pinned binary to maintain.
- **Cost from the transcript.** Per-step `output_tokens` is a placeholder and messages repeat by id. T10 confirmed both: summing all entries gave 370 output tokens against 196 de-duplicated by id, and subagent transcripts do not reconcile with `result` (236 against 415). The `result` message is simpler.
