# Plan: fleetd and the fleet server

Status: draft. Phase 1 is in: the listeners, the SQLite queue and the hook normalizer. The pueue callback, forwarder, reconciler, watchers and heartbeat are not built. ADRs 0011 to 0017 are Accepted (2026-10-24). Decisions answered on 2026-10-24 are marked Decided below. Phase 0 finished on 2026-10-24: all ten tests ran on one Box (Claude Code 2.1.289, workmux 0.1.276, pueue 4.0.4). The results are folded in below. The records are `docs/phase0/T1.md` to `T10.md` in this repo, indexed by `docs/phase0/README.md`.

v1 cut and recovery design added 2026-10-24 (see v1 cut). ADRs 0011 to 0017 flipped to Accepted on 2026-10-24.

Network stance: the Fleet server is a hosted service reached over a VPN or any routable path, for example Tailscale or netbird. Tailscale is not a hard dependency. Nothing in fleetd, the server, the proto, the CLI or the ADRs depends on one VPN product. The server address is plain config and a VPN switch is a config change plus an ADR note. In the existing setup a VPN carries only ssh access to Boxes and Template provisioning, which are separate from fleet traffic.

## Background

This plan builds on an existing setup. The facts it relies on:

- A Box is a single-user Linux VM named `box-<n>`, cloned from a Template image. The Template bakes in the software (Claude Code, workmux, pueue, mise) at pinned versions and three credentials: a Claude subscription token, a git credential and a VPN auth key. The Box count is one number in the infrastructure config. Changing it means editing it and applying. Scale-down is manual and happens only after a Box drains: nothing running and nothing unpushed. Box destruction loses anything not yet pushed.
- Interactive agents run as workmux windows in tmux. Background Jobs run as pueue tasks. A Job is a headless `claude -p` run.
- A Box pushes only its own branch, named `swarm/<id>`, and only when `SWARM_BOX=1`. Results leave a Box only through git remotes.
- Workers load the full global Claude config, so hooks in the baked `settings.json` fire on the Box.
- Today a laptop `fleet` picker lists Boxes from the VPN peer list and polls tmux and pueue on each Box over ssh. Line formats are `box-N`, `box-N/<session>` and `box-N#<task id>`. Connect is `ssh -t box-N tmux new -A`. Preview is an ssh pane capture. A fixed Claude Code and workmux version is pinned in the Template.
- Remote Control (Claude Code's hosted remote session feature) is out of scope.

## Decisions (2026-10-24)

Recorded 2026-10-24 when the plan moved into the public repo.

- Licence: Apache-2.0 (ADR-0017). Closes open decision 11.
- Repo owner and name: github.com/a19simma/fleet.
- Docs live in this repo: the plan, ADRs 0011 to 0017 and the Phase 0 records. Closes open decision 13.
- `fleet watch` is a client poll of `ListFleet` in v1. No `Watch` rpc in v1. Closes open decision 10.
- Job cost is deferred. Cost is only available through `fleet-job`, which is out of v1. The `claude -p` runs use a subscription, so API cost is not the driver. Closes open decision 12.
- ADRs 0011 to 0017 are Accepted.
- Tailscale is not a hard dependency.

## v1 cut

Decided 2026-10-24. The phases below stay as the full map. v1 is the smallest slice that answers "what is every Box doing, and did anything die".

In v1:

- fleetd: loopback http hook listener, SQLite queue, forwarder, session registry and reconciler (see Recovery and reconcile), workmux watcher using `workmux wait` exit codes, pueue poll plus the finish callback (id and group only), heartbeat. The unix socket stays, because the `fleetd pueue-callback` subcommand writes to it.
- Server: `FleetIngest` (`PushEvents`, `Heartbeat`) and `FleetQuery.ListFleet` on Postgres, shared bearer token (ADR-0014).
- CLI: `fleet list` and `fleet watch`. `fleet watch` polls `ListFleet` from the client and prints changes (decision 10).

Out of v1: `FleetJobs`, `ClaimJob`, `RenewLease`, `ReportJob`, claim and lease, drain and `SetDrain`, the KEDA seam, `fleet-job`, `GetPreview`, `ListEvents`, the `Watch` rpc, and transcript summaries beyond the last assistant text. v1 has no Job cost, since cost arrives only through `fleet-job` (decision 12, deferred).

Defaults accepted with the cut:

- Reconcile polls stat-only (size and mtime) every 30 to 60 s and parses a transcript only when it changed.
- Subagent hand-back prompts are marked `synthetic`.
- The pueue group `fleet` runs with parallel 1.
- The hook gap is accepted, because the recovery poll covers it (ADR-0012).
- ADRs 0011 to 0017 are Accepted.

Public repo: the fleet repo ships publicly with GitHub releases, and Boxes install the binaries through mise (ADR-0017). Nothing in it may hold a hostname, a VPN address, a token or a private infra detail. Config comes from env and files. The licence is Apache-2.0 (decision 11).

## Goals and non-goals

Goals:

- One place that knows what every Box is doing: sessions, Jobs, results, cost, health.
- No event lost across laptop sleep, server restarts or network blips between a Box and the server.
- Catch what hooks miss: crashed agents, killed pueue tasks, Boxes that go quiet.
- Replace ssh polling in `fleet list` and `fleet preview` with reads from the server (see Background).
- A seam for the later KEDA work queue: a Job lifecycle, claim and lease, and a readable queue depth.

Non-goals:

- Remote Control. Out of scope.
- Moving where Jobs run. Jobs stay pueue tasks, interactive agents stay workmux in tmux.
- fleetd pushing to git or holding git credentials. Results leave the Box only through git remotes (see Background).
- Storing transcripts on the server. They stay on the Box under `transcript_path`. fleetd reads them for derived preview text and a timeline only.
- Autoscaling Boxes. Scale stays the Box count plus apply. The queue seam only exposes depth.
- A web UI. The laptop `fleet` CLI is the only client for now.

## Component diagram

```
 laptop                          VPN (any routable path)                hosted service
+--------------+                                              +-------------------------+
| fleet CLI    |--gRPC FleetQuery/FleetJobs (bearer token)---->|  fleet server (Rust)    |
| sesh picker  |                                              |  tonic + sqlx           |
+--------------+                                              |   ingest | query | jobs |
       |  ssh -t box-N tmux/pueue (attach only)               +------------+------------+
       v                                                                   |
+---------------------------------------------- box-N -------------+   +---v--------+
| claude (cc-yolo via swarm-claude)                                |   | Postgres   |
|   hooks --HTTP POST--> 127.0.0.1:PORT  --+                       |   +------------+
| fleet-job --unix socket /run/fleetd/fleetd.sock --+              |        ^
| pueue (callback, status) ------------------------+|              |        | queue depth
| workmux state files + status --all --json --------+|              |   +----+-------+
|                                                    v              |   | KEDA       |
|   fleetd: listeners -> normalizer -> SQLite queue -> forwarder ---+-->| (later)    |
|           watchers (workmux, pueue)   heartbeat      gRPC FleetIngest +------------+
+------------------------------------------------------------------+
```

fleetd is the only component on a Box that talks to the server. Everything else on the Box talks to fleetd over loopback or the unix socket.

## Event model

### Envelope

Every event carries the same envelope. The payload varies by type.

| Field | Meaning |
|---|---|
| `event_id` | ULID. Random for hook and job events. Derived (hash of source and natural key) for watcher events, so a restart re-derives the same id |
| `schema_version` | Integer. Server accepts the current and previous version |
| `box` | Configured box name, `box-N`, from `FLEET_BOX_NAME` in `/etc/swarm/box.env`, default the hostname. Stored as claimed. The server rejects names not matching `box-<n>` (ADR-0014) |
| `hostname` | Box hostname at capture |
| `machine_id` | `/etc/machine-id` |
| `boot_id` | `/proc/sys/kernel/random/boot_id`. A clone gets a new one at each boot |
| `seq` | u64, monotonic per `boot_id`, assigned when the event commits to the disk queue |
| `source` | `hook`, `workmux`, `pueue`, `job`, `fleetd`, `reconcile` |
| `type` | See below |
| `occurred_at` | Box clock, UTC. Advisory |
| `captured_at` | Box clock at commit |
| `session_id` | Claude session id when known |
| `job_id` | Fleet job id, from `FLEET_JOB_ID` or the pueue label, when known |
| `workdir` | Working directory when known |
| `payload` | JSON object |

### Event types

| Type | Source | Payload highlights |
|---|---|---|
| `hook.session_start`, `hook.user_prompt_submit`, `hook.stop`, `hook.notification`, `hook.session_end` | hook | Raw hook JSON kept verbatim under `raw`, plus the normalized subset in the hook normalizer section below. `hook.stop` carries `transcript_path` and `last_assistant_message`. `hook.user_prompt_submit` carries `synthetic: true` when the prompt is a subagent hand-back |
| `hook.<other>` | hook | Allowlist in config. Tool events (`PreToolUse`, `PostToolUse`) are off by default |
| `transcript.summary` | fleetd | Best-effort, from a delayed read after `Stop` and a read at `SessionEnd`: preview text and timeline entries (entry type, time) read from `transcript_path`, truncated and redacted. Carries `source` (`stop_delayed` or `session_end`) and `complete` (the last assistant entry has `stop_reason` `end_turn`). Absent when parsing fails. Never carries cost or token totals |
| `workmux.status_changed` | workmux | `pane_id`, `window_name`, `session_name`, `status` (`null`, `working` or `done`; `waiting` is expected and not yet seen), `status_ts`, `workdir`, `agent_session_id`. No `prompt`: workmux stores null in every state file (T5). The prompt comes from `hook.user_prompt_submit` or the Job record |
| `workmux.agent_gone` | workmux | State file deleted, pane missing, or `workmux wait` exit 1 right after spawn. Deduped with `agent_crashed` per pane id |
| `workmux.agent_crashed` | workmux | From `workmux wait` exit 3 (`agent exited unexpectedly`), or from the fleetd liveness check when no claude process runs under the pane while the state is `working` |
| `pueue.task_queued`, `pueue.task_started`, `pueue.task_finished` | pueue | Task id, label, command (redacted), result, exit code, start and end time. `task_finished` comes from `fleet-job`, the pueue callback or the reconcile poll. `task_queued` and `task_started` have no callback and come from `fleet-job` or the poll. A task killed with `pueue kill` has no exit code (T6) |
| `job.result` | job | From `claude -p --output-format json`: `total_cost_usd`, `is_error`, `session_id`, `duration_ms`, `num_turns`, result text truncated to 16 KiB, `result_branch`, exit code |
| `job.claimed`, `job.lease_lost` | fleetd | Queue seam events (Phase 5) |
| `fleetd.started`, `fleetd.queue_overflow`, `fleetd.watcher_error` | fleetd | Version, boot id, dropped count |
| `session.discovered`, `session.stalled`, `session.ended_unseen` | reconcile | `session_id`, `transcript_path`, `cwd`, `kind`, `last_mtime`, last assistant text when parsed. Derived by the registry reconciler (Recovery and reconcile). `workmux.agent_crashed` also carries `source=reconcile` when the liveness check finds it first |

### Hook normalizer

Field names measured on 2.1.289 (T1, T2). `raw` always keeps the verbatim body.

| Event | Fields |
|---|---|
| all | `session_id`, `transcript_path`, `cwd`, `hook_event_name`, `prompt_id` |
| `UserPromptSubmit` | `prompt`, `permission_mode` |
| `Stop` | `last_assistant_message`, `stop_hook_active`, `permission_mode`, `effort` (object, for example `{"level":"low"}`), `background_tasks`, `session_crons` |
| `Notification` | `message`, `notification_type` (`permission_prompt` seen, `idle_prompt` not seen) |
| `SessionEnd` | `reason` (`other` in `claude -p`) |

Rules:

- `prompt_id` joins the events of one turn and is the correlation id. A `SessionEnd` after a failed `claude -p` start has no `prompt_id`, so the normalizer tolerates its absence.
- `UserPromptSubmit` also fires for a subagent hand-back, with the same `session_id` and `prompt_id` as the human prompt and a `prompt` that starts `<agent-message from=`. The normalizer sets `synthetic: true` and the server projections skip it as a human prompt. `raw` keeps it.
- `Stop` fires once per `claude -p` run even with tool calls, and `SessionEnd` follows about 16 ms later. An interactive session fires `Stop` once per turn.
- `permission_mode` is `auto` in `claude -p` and `default` in the interactive run. No logic depends on it.
- `Notification` arrives late and best-effort (7.5 s in the one observation, see the T2 record). No state depends on it.
- The POST body equals the command-hook stdin. Only the URL path carries the event name.
- `SessionStart` cannot use an http hook: Claude Code accepts only `command` and `mcp_tool` hooks for it. The managed settings run `fleetd hook SessionStart`, which reads the stdin payload and POSTs it to the same `/hook/SessionStart` route over the unix socket, else loopback. It exits 0 on every failure. The other events stay http.
- The same event can arrive once per settings source (T4). The hook lives only in managed settings, and fleetd also drops an exact repeat of a body seen in the last 10 s (proposed window).

Heartbeat and the box snapshot are state, not events. They go through the unary `Heartbeat` call, not the queue.

### Delivery

- **At least once.** fleetd deletes a queued event only after the server acks it. A crash between send and ack resends. The guarantee starts at fleetd. Claude Code logs a failed http hook at ERROR, and the debug log shows a single attempt (T8), so treat it as not retried: a hook event fired while fleetd is down is lost. The workmux watcher, the pueue reconcile and a transcript read cover the gap.
- **Dedupe.** Server primary key on `event_id`, plus unique `(box, boot_id, seq)`. Insert is `ON CONFLICT DO NOTHING`. Ack is idempotent.
- **Ordering.** Per box, by `(boot_id, seq)`. fleetd sends in seq order on one stream and the server acks a cumulative high-water mark per `(box, boot_id)`. Across boxes there is no order. `occurred_at` is for display and can skew.
- **Derived ids.** Watcher events hash `(source, box, boot_id, natural key)`, for example `(state file path, status_ts)`. A watcher restart emits the same ids and the server drops the repeats. workmux writes a repeat `working` with an unchanged `status_ts` (T5), which hashes to the same id. `agent_crashed` and `agent_gone` hash `(pane id, last status_ts)`, so a race between `workmux wait`, the DELETE event and the liveness check emits one event.
- **Backpressure.** A full queue drops the lowest priority events first (tool events, then `workmux.status_changed` duplicates) and emits `fleetd.queue_overflow` with the count. `job.result`, `pueue.task_finished` and hook `stop` and `session_end` are never dropped before others.

## fleetd internals

Language: Rust, one static musl binary, tokio, tonic, axum for the HTTP listener, sqlx with its SQLite driver, `notify` for inotify. Matches the deployment stack and bakes as a single file (ADR-0011).

### Listeners

- **HTTP, loopback.** `127.0.0.1:<port>`, fixed port in config (default 7071). Claude Code reaches it with one `type: "http"` hook per recorded event, to `http://127.0.0.1:<port>/hook/<EventName>`. The POST body is the same JSON a command hook gets on stdin, and the event name is only in the path: there is no event header (T3). A `200` returns an empty JSON object so the hook is a no-op for Claude Code. `GET /healthz`. fleetd commits the event to the disk queue before it answers. A Unix socket cannot serve hooks: `unix:` and `http+unix:` URLs fail with `Unsupported protocol` on 2.1.289 (T3).
- **Unix socket.** `/run/fleetd/fleetd.sock`, mode 0600, owner `agent`. fleetd and `fleet-job` run as the same user. Fixed path from systemd `RuntimeDirectory=fleetd`. It does not use `XDG_RUNTIME_DIR`, which is unset in ssh logins. Today it serves `POST /event` and the hook routes. `POST /job/<event>` for `fleet-job` and `GET /state` for local tools are not built.
- **Responses.** `200` with `{}` for an accepted or filtered hook, `400` with `{"error": ...}` for a body that is not a JSON object or an unusable path, `500` with `{"error": ...}` when the queue write fails.
- **Wire names.** The envelope serializes `id` and `kind`, not `event_id` and `type`. `occurred_at`, `captured_at`, `job_id` and `workdir` arrive with the proto in the server step.
- **Hook headers.** Intended: the http hook sets `X-Fleet-Job: $FLEET_JOB_ID` with `allowedEnvVars: ["FLEET_JOB_ID"]`, so a hook from a Job carries its job id. Not tested in Phase 0 (the T3 capture used no custom header), so it is a Phase 1 pre-check. `fleet-job` exports `FLEET_JOB_ID`. Interactive sessions have no job id.
- **Failure behaviour.** Verified (T8): with nothing listening, a hook costs about 2 ms and the run exits 0 with the normal result. Mean wall time over three runs was 1.58 s with a closed-port hook and 1.61 s without, inside the 0.2 s noise. Claude Code logs the failure at ERROR in the debug log and nowhere else. Every hook sets an explicit `timeout`. A listener that accepts a connection and never answers was not tested, so the effect of the timeout is a Phase 1 pre-check. `onFailure` is dropped from the hook config: 2.1.289 accepts it without a warning and it changes nothing, including on a refused connection (T3, T8). The docs tie it to 2.1.295, which the pin does not reach.
- **Where hooks are configured.** Decided and verified (T4): the loopback http hooks live in the Template at `/etc/claude-code/managed-settings.json`, or in a drop-in `/etc/claude-code/managed-settings.d/10-fleetd.json` that keeps fleetd's file apart from other managed policy. Both load on 2.1.289 (the drop-in was tested alone, not together with the main file). Hooks merge across managed, user and `--settings` sources: a managed hook does not replace a user hook, both fire, and a Job's `--settings` cannot suppress the managed hook. The loopback hook therefore appears only in managed settings, never in the laptop's user `settings.json` or in a Job's `--settings`, or fleetd sees each event twice. A managed file that fails to parse stops Claude Code from starting (docs), so the Template build validates the JSON. Do not set `allowManagedHooksOnly`: the docs say it restricts which hooks run, which could silence the user hooks workers load (see Background), and it was not tested. Not yet run: the `http` hook type inside a managed file (T4 used command hooks) and interactive sessions. Both are Phase 1 pre-checks.

Shape of one entry in the managed file, one per recorded event. The `timeout` value and its unit follow the hooks docs and are not verified on 2.1.289.

```json
{
  "hooks": {
    "Stop": [
      {
        "hooks": [
          { "type": "http", "url": "http://127.0.0.1:7071/hook/Stop", "timeout": 5 }
        ]
      }
    ]
  }
}
```

### Transcript reader

On `Stop`, fleetd emits `hook.stop` at once, with `last_assistant_message` as the preview text. It then reads the file at `transcript_path` after a delay, again at `SessionEnd`, and emits `transcript.summary`. Best-effort by design.

- The docs say "The entry format is internal to Claude Code and changes between versions, so scripts that parse these files directly can break on any release" (official docs, [sessions](https://code.claude.com/docs/en/sessions#where-transcripts-are-stored)).
- The docs say the transcript "is written asynchronously and may lag the in-memory conversation, so it may not yet include the current turn's most recent messages when a hook fires", and tell hooks to use `last_assistant_message` on Stop for the final text (official docs, [hooks, common input fields](https://code.claude.com/docs/en/hooks#common-input-fields)). Wording checked against the page on 2026-10-24.
- Measured on 2.1.289 (T10, one sample per mode: `claude -p` reply, `claude -p` tool call, interactive): at `Stop` the final assistant entry is missing in all three, although it was written about 23 ms earlier. It is present 2 s later. The last entry at `Stop` was `atis-latch` or `ai-title`. So fleetd never reads inline in the `Stop` handler. The lag is bounded only by those samples: more than 23 ms, at most 2 s. Initial rule: read 2 s after `Stop` (`transcript_read_delay`), accept the read when the last assistant entry has `stop_reason: "end_turn"`, retry with backoff up to 10 s, then emit with `complete: false`.
- The delay cannot live in a hook. In `claude -p` a backgrounded copy never ran, because the process tree is gone at exit, and a sleep inside the `SessionEnd` hook is cut short. A synchronous sleep inside the `Stop` hook did work, but it holds the turn open and pushes `SessionEnd` back by the same 2 s. fleetd outlives the run, so the delayed read lives there.
- A `SessionEnd` read is not proven complete. T10 saw the full file at `SessionEnd`, including the final assistant entry and `cost-state`, but its `Stop` hook had slept 2 s first, so that read came about 2 s after `Stop`. The real gap is about 16 ms (T1).
- Tokens only by de-duplicating on `message.id`. A message with a thinking block and a tool_use block is written as several entries with one id: summing all gave 370 output tokens, de-duplicated by id 196, which equals `result.usage.output_tokens`. Main-session transcript entries hold the final `output_tokens`. stream-json `assistant` lines carry a placeholder (2 against 174 final).
- Subagent transcripts live in `<session_id>/subagents/agent-<id>.jsonl`, with placeholder-looking token values. Main plus subagent (236) does not match `modelUsage.outputTokens` (415). Cost and token totals come from the `result` object only. The `cost-state` entry at the end of the file equals `total_cost_usd` but is written after `Stop`, so it is corroboration.
- Store summaries, not raw entries. Entry types seen: `assistant`, `user`, `attachment` (11 subtypes, about 100 KB before any model call), `queue-operation`, `last-prompt`, `atis-latch`, `system`, `cost-state`, plus `mode`, `permission-mode`, `file-history-snapshot` and `ai-title` in interactive sessions. Ignore unknown types. `usage` and `model` are on every assistant entry.
- Path: `~/.claude/projects/<cwd with / replaced by ->/<session_id>.jsonl`, file mode 600, directory 700, owner `agent`. Replacement of `.` in a cwd was not exercised.
- A parse failure degrades to the hook payload (`last_assistant_message`) and emits a `fleetd.watcher_error`.
- The Claude version is pinned in the Template. A pin bump requires re-running T10, with more samples (see the Phase 1 pre-checks).

### Disk queue

SQLite in WAL mode at `/var/lib/fleetd/queue.db` (systemd `StateDirectory=fleetd`). One table `events(seq integer primary key autoincrement, id text unique, ts, kind, priority, payload, state, attempts, next_try_at)`, where `payload` is the envelope JSON and a repeat of `id` is ignored. `synchronous=NORMAL` and a checkpoint on shutdown. The commit is the durability point.

- **Cap.** 256 MiB of payload bytes or 14 days, whichever first. When over the byte cap, fleetd deletes the lowest priority, oldest rows first (tool, then status, then normal, then terminal), and records the count in one `fleetd.queue_overflow` event that later drops add to.
- **Survives.** fleetd restart, server outage, Box reboot. It does not survive Box destruction. fleetd reports pending count and oldest age in the heartbeat so the drain check can include "queue empty".
- **Alternatives.** Append-only segment files are simpler but need hand-rolled crash recovery and cursor tracking. An embedded KV (redb, sled) has no ad hoc inspection. See ADR-0012.

### Forwarder

- One long-lived bidirectional `PushEvents` stream. Batches of up to 100 events or 256 KiB or 500 ms.
- Retry with exponential backoff, 1 s doubling to a 5 min cap, full jitter. Reset on first ack.
- On connect fleetd sends `Hello` with box identity claim, boot id, fleetd version, last acked seq. The server replies with its high-water mark so fleetd skips events already stored.
- Stream-level keepalive 20 s. A stalled stream is dropped after 60 s without an ack.

### workmux watcher

- Watch `~/.local/state/workmux/agents/` with inotify for create, moved_to and delete. A write is CREATE of a temp file, MODIFY of the temp file, then MOVED_TO the real name (T5). The real file never sees a plain MODIFY. The file name is `tmux__<instance>__<pane_id>.json` and the pane id is the agent identity: a new agent in a new pane is a new file. Read the JSON and diff against the last seen `status` and `status_ts`, because a repeat `working` write with an unchanged `status_ts` occurs.
- State fields (T5): the twelve planned ones (`status`, `status_ts`, `updated_ts`, `workdir`, `pane_pid`, `command`, `boot_id`, `agent_kind`, `agent_session_id`, `prompt`, `window_name`, `session_name`) plus `pane_key` (`backend`, `instance`, `pane_id`), `activity_ts` and `pane_title`. `status` is `null` after registration and before the first hook: a distinct pre-working state. Values seen: `null`, `working`, `done`. `waiting` was not seen. `prompt` is always null. `pane_pid` is the pane's login shell and claude is its child (`pgrep -P <pane_pid> claude`). `command` stays `claude` after the process dies.
- `workmux status --all --json` renames fields (`session` for `session_name`) and drops `pane_pid`, `boot_id`, `agent_session_id` and `status_ts`. It adds `worktree`, `branch`, `project`, `elapsed_secs` and `title`. The watcher reads the state file for the dropped fields.
- Poll `workmux status --all --json` every 10 s as a reconcile pass, and once at startup for a full snapshot. Polling catches missed inotify events. It also deletes stale state files as a side effect (T5).
- Crash detection: start `workmux wait <target> --status done` as a child on the `working` transition, and for every `working` agent at fleetd start. Exit 3 (`agent exited unexpectedly`, about 1 s after `kill -9`) emits `workmux.agent_crashed`. Exit 1 (`No agent found`) right after spawn emits `workmux.agent_gone`: the agent died before the wait existed. Exit 0 means the status was reached.
- A killed agent writes nothing. Its state file stays `working` and is deleted only when some workmux command runs, so a DELETE of a file whose last status was `working` means crashed or gone. The DELETE, the `wait` exit and the liveness check can race: dedupe `agent_crashed` and `agent_gone` per pane id and last `status_ts`.
- Liveness check, fleetd's own: on each reconcile pass, for every `working` agent, test that `pane_pid` exists and has a claude child. A live pane with no claude child emits `agent_crashed`. A missing pane emits `agent_gone`. `workmux wait` alone is not enough, since it only covers agents fleetd was already watching.
- `done` is not proof that work ended: it can arrive while a backgrounded command still runs. Do not treat `done` as a Job result.
- `workmux rm` leaves its state file until the next reconcile, so `agent_gone` for a removed worktree lags by at most one poll cycle.
- workmux has no status-change or exit hook, so the watcher is the only source for these.

### pueue integration

- Primary: `fleet-job` reports `job.result` to the unix socket as the last step. It has the `claude -p --output-format json` object, so cost and result come from it. `fleet-job` redirects stdin of `claude -p` from `/dev/null`, because `claude -p` swallowed a `bash -s` heredoc on stdin in T10. It passes `--verbose` whenever it uses `stream-json`, which exits 1 without it (T1).
- Dedicated group: fleet work runs in its own pueue group (proposed name `fleet`) with its own parallel setting. The default group runs one job at a time, and in Phase 0 it queued unrelated work behind a running job (T5, T7). The claim's free-slot count (ADR-0016) is the free parallelism of that group.
- Backstop: the pueue `callback` in `pueue.yml`, verified on v4.0.4 (T6). It fires for success, failure, `pueue kill` (`Killed`, exit code `None`), an external kill (`Failed`, exit 137) and grouped tasks, 0.2 to 0.3 s after the task ends. It fires only for finished tasks: there is no queued or started callback. Variables: `id`, `group`, `result`, `exit_code`, `start`, `end`, `path`, `command`, `output`.
- Callback injection: pueued pastes `{{ command }}` and `{{ output }}` raw into the shell string, and a task command with double quotes injected shell text in T6. The callback string therefore passes only `{{ id }}` and `{{ group }}`, for example `fleetd pueue-callback "{{ id }}" "{{ group }}"`. The subcommand is fast and fire-and-forget: it writes to the unix socket and exits. fleetd fetches command, output and times with `pueue status --json`. The callback lives in the shared `pueue.yml`, which needs a pueued restart, so the Template provisions it.
- Reconcile: poll `pueue status --json` every 5 s. It is the only source for `task_queued` and `task_started`, and the recovery path for callbacks fired while fleetd was down. Read the whole output: closing the pipe early made pueue panic with rc 134 (T9).
- fleetd reaches the pueue daemon through the user's socket. `unix_socket_path` in `pueue.yml` is absolute (`/run/user/1000/pueue_agent.socket`, mode 700, owner `agent`), so the unit needs neither `XDG_RUNTIME_DIR` nor `--config`. The socket lives in the tmpfs of `user@1000.service`, hence the ordering in the systemd unit section. Verified on a Box (T9). The `systemd-run --user` fallback is not needed.

### Recovery and reconcile

Hooks are the fast path and have a known gap: an event fired while fleetd is down is gone (T8). The session registry and the reconciler close that gap at the state level. They do not recover the lost payloads.

Registry: table `sessions_seen` in `/var/lib/fleetd/queue.db`, so a registry change and the event it derives commit in one transaction.

| Column | Meaning |
|---|---|
| `session_id` | Claude session id, primary key |
| `transcript_path` | `~/.claude/projects/<cwd>/<session_id>.jsonl` |
| `cwd` | Working directory |
| `kind` | `interactive`, `job` or `unknown` |
| `last_seen_size` | Transcript size at the last pass |
| `last_mtime` | Transcript mtime at the last pass |
| `last_event_at` | Last time fleetd saw any sign of life: a hook, a size change or a status write |
| `state` | `active`, `stalled`, `ended` or `crashed` |

Hook handlers upsert the row from `session_id`, `transcript_path` and `cwd`. A pane id and `agent_session_id` from the workmux state file join a row to its agent.

Discovery runs once at fleetd start and every `reconcile_interval` (default 45 s, allowed 30 to 60 s, jittered):

1. Read `~/.claude/projects/*/*.jsonl`. The glob skips `<session_id>/subagents/`.
2. Read `~/.local/state/workmux/agents/*.json`.
3. Stat every registered transcript. Compare size and mtime with the row. Parse only a changed file, and only from `last_seen_size` forward (from zero if the size shrank). The parse extracts the last assistant text and the last entry time. It never builds a timeline or a token count in v1.
4. Run the liveness check for `working` agents (workmux watcher section) and for sessions with no workmux file: a `claude` process whose `/proc/<pid>/cwd` equals the row's `cwd`.

Derived events, all with `source=reconcile`:

| Event | When | Id discriminator |
|---|---|---|
| `session.discovered` | A transcript or state file has no row and its mtime is within `stall_after`. A hook usually registers a session first, so this means hooks missed it | `session_id` |
| `session.stalled` | State `active`, a live process or a `working` agent, and no size or mtime change for `stall_after` (default 10 min) | `session_id`, `last_mtime` |
| `session.ended_unseen` | No `SessionEnd` seen, no live process or agent, and the transcript idle past `end_grace` (default two passes). Payload carries the last assistant text when parsed | `session_id`, `last_mtime` |
| `workmux.agent_crashed` | The liveness check finds a live pane with no claude child while the state is `working` | `(pane id, last status_ts)`, shared with the watcher |

Rules:

- First run and a rebuilt registry baseline silently. A transcript older than `stall_after` at discovery is inserted as `ended` with no event, so history does not flood the server.
- Every derived id is a hash of its kind and discriminator. A restart re-derives the same id and the server drops the repeat. `agent_crashed` hashes the same as the watcher event, so the `workmux wait` exit, the DELETE and the reconcile emit one event. Whichever source arrives first sets `source`.
- A `SessionEnd` hook moves the row to `ended`. A size change on a `stalled` row returns it to `active` with no event.
- Rows in `ended` or `crashed` older than 30 days are pruned.
- Poll cadences differ by cost. pueue stays at 5 s and `workmux status` at 10 s, since both are one process call. The transcript pass stats files only.
- systemd runs `Restart=always`, `RestartSec=2`, `WatchdogSec=60`. fleetd sends `WATCHDOG=1` from a supervisor task only when the listener, the forwarder and the reconcile loop each made progress in the last 30 s, so a wedged loop restarts the daemon.
- The server marks a Box `stale` after 90 s and `lost` after 10 min without a heartbeat. A server sweeper task sets the status, since missing heartbeats are not events.

### Health and self-report

- `Heartbeat` every 30 s, unary. Carries: fleetd version, boot id, uptime, queue pending and oldest age, last ack time, claude version, workmux and pueue health, disk free, load, memory, agent and task counts, a snapshot of sessions and tasks, `draining` flag, per-worktree unpushed commit count under `~/jobs`.
- Server marks a Box `stale` after 90 s and `lost` after 10 min without a heartbeat. In v1 the `draining` flag and `running_job_ids` are absent.
- `fleetd` health check is also `GET /healthz` for systemd watchdog (`WatchdogSec`, `sd_notify`).

### Config

`/etc/fleetd/config.toml`, baked. Fields: `server_url` (default from `FLEET_SERVER_URL`, any routable address or name, so an address change needs no rebuild and no VPN feature is assumed), `http_port`, `socket_path`, `queue_max_bytes`, `queue_max_age`, `hook_events` allowlist (provisional default in decision 6), `heartbeat_interval`, `transcript_read_delay` (default 2 s), `pueue_group` (default `fleet`), `reconcile_interval` (default 45 s), `stall_after` (default 10 min), `end_grace` (default two passes), `redact_files` (default `/etc/swarm/secrets.env`). Environment from `/etc/swarm/box.env`, including `FLEET_SERVER_URL` and `FLEET_BOX_NAME`. The bearer token is `FLEET_TOKEN` in `/etc/swarm/secrets.env`. No secret in this file.

### systemd unit

System unit `fleetd.service`, `User=agent`, `Group=agent`, `RuntimeDirectory=fleetd`, `StateDirectory=fleetd`, `EnvironmentFile=/etc/swarm/box.env`, `Environment=XDG_RUNTIME_DIR=/run/user/<uid>`, `Restart=always`, `RestartSec=2`, `WatchdogSec=60`, `After=network-online.target user@<uid>.service`, `Wants=user@<uid>.service`. The ordering matters because the pueue socket sits in `/run/user/<uid>`, a tmpfs that exists only while `user@<uid>.service` runs (linger is on). `XDG_RUNTIME_DIR` is not needed when the socket path is absolute (T9). It is kept because it costs nothing and covers a config that drops `unix_socket_path`.

The directives live in `deploy/fleetd.service`. Hardening: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, and `ReadWritePaths` for the state dir and `~agent/.local/state/workmux`. `ProtectSystem=strict` alone leaves `/home` writable on a Box (T9), so `ProtectHome=read-only` is what makes `~/jobs` read-only. The workmux path must be writable because `workmux status` and `workmux wait` delete stale state files (T5). T9 confirmed a unit as `User=agent` with these settings lists and writes `~/.local/state/workmux` and reads the real pueue daemon. Any worktree path fleetd must write needs its own `ReadWritePaths` entry or a separate process. The unit is a system unit so it needs no login session, and it still depends on `user@<uid>.service` for the pueue socket. pueue's linger user unit stays as is.

### Upgrade path

Bake into the Template at a pinned version, checksummed. A new fleetd is a Template rebuild plus re-created Boxes. Iteration shortcut for development only: `scp` a binary to one Box and `systemctl restart fleetd`, lost at the next re-create. Protocol compatibility: `schema_version` on events and a `Hello` version check, server supports N and N-1, so Boxes of mixed vintage coexist during a rolling re-create.

## gRPC API sketch

Package `fleet.v1`. Proto outline only.

```proto
service FleetIngest {
  rpc PushEvents(stream EventBatch) returns (stream Ack);
  rpc Heartbeat(BoxState) returns (HeartbeatReply);
  rpc ClaimJob(ClaimRequest) returns (ClaimReply);
  rpc RenewLease(RenewRequest) returns (RenewReply);
  rpc ReportJob(JobReport) returns (JobReportReply);
}

service FleetQuery {
  rpc ListFleet(ListFleetRequest) returns (FleetView);
  rpc GetPreview(PreviewRequest) returns (Preview);
  rpc ListEvents(ListEventsRequest) returns (stream Event);
  rpc Watch(WatchRequest) returns (stream FleetUpdate);
}

service FleetJobs {
  rpc SubmitJob(SubmitJobRequest) returns (Job);
  rpc GetJob(GetJobRequest) returns (Job);
  rpc CancelJob(CancelJobRequest) returns (Job);
  rpc QueueDepth(QueueDepthRequest) returns (QueueDepth);
  rpc SetDrain(SetDrainRequest) returns (BoxView);
}

message Envelope { string event_id; uint32 schema_version; string box; string hostname; string machine_id;
  string boot_id; uint64 seq; string source; string type; Timestamp occurred_at;
  Timestamp captured_at; string session_id; string job_id; string workdir; Struct payload; }
message EventBatch { Hello hello; repeated Envelope events; }
message Ack { string boot_id; uint64 high_water_seq; }
message BoxState { string boot_id; string fleetd_version; uint64 queue_pending; Duration queue_oldest;
  repeated SessionState sessions; repeated TaskState tasks; repeated string running_job_ids;
  bool draining; uint32 unpushed_commits; Health health; }
message HeartbeatReply { bool drain; Duration next_in; }
message ClaimRequest { string boot_id; uint32 free_slots; }
message ClaimReply { Job job; Duration lease; }
message Job { string job_id; string prompt; string repo; string base_ref; string result_branch;
  JobState state; string box; uint32 attempt; Timestamp lease_expires_at; JobResult result; }
enum JobState { QUEUED = 0; CLAIMED = 1; RUNNING = 2; SUCCEEDED = 3; FAILED = 4; CANCELLED = 5; LOST = 6; }
```

The service split lets auth differ per service: all three services take the same shared bearer token for the proof of concept (decided 2026-10-24). The split stays in the proto so a separate read credential can be added later without an API change.

### Auth between box and server

Decided (2026-10-24, ADR-0014): a shared bearer token for the proof of concept. fleetd sends gRPC metadata `authorization: Bearer <token>`. The token is `FLEET_TOKEN` in `/etc/swarm/secrets.env`, mode 0640 `root:agent` (the existing secrets pattern), sourced from `~/.config/fleet/token` on the laptop and baked like the other secrets. fleetd's redaction covers it. The server compares in constant time and answers `UNAUTHENTICATED` on a mismatch. It rejects a `box` that does not match `box-<n>`.

Verified in Phase 0 (T7), with a throwaway python grpcio 1.84.1 server on loopback, plain, no TLS: no token and a wrong token both give `UNAUTHENTICATED`, and the right token gives OK, from a python client and from grpcurl 1.9.4. The metadata key must be lowercase `authorization`. The secrets file at 0640 `root:agent` is readable by `agent` and denied to `nobody`. The interceptor must wrap every service, because it also blocks gRPC reflection: `grpcurl` without `-proto` fails at reflection without a token. Behind the interceptor reflection leaks nothing, so it may stay on. Not run: a tonic client, TLS, and a real VPN path (Phase 1 pre-check).

Identity comes from the Box (configured name, hostname, machine-id, boot id), never from the VPN. A valid token proves swarm membership, not which Box, so box names are claims.

Downsides: one leaked token exposes the fleet, and every Box holds it. Rotation means a Template rebuild or a secrets push. Upgrade path: per-Box tokens minted at first boot, then mTLS or JWT.

## Server schema outline (Postgres)

| Table | Key columns | Notes |
|---|---|---|
| `boxes` | `box` pk, `hostname`, `machine_id`, `first_seen`, `last_seen`, `status`, `boot_id`, `fleetd_version`, `draining`, `state jsonb` | `state` is the latest `BoxState`. Updated by heartbeat |
| `box_boots` | `(box, boot_id)` pk, `started_at`, `high_water_seq` | Ingest cursor |
| `events` | `event_id` pk, `(box, boot_id, seq)` unique, `source`, `type`, `occurred_at`, `received_at`, `session_id`, `job_id`, `payload jsonb` | Partitioned monthly on `received_at` |
| `sessions` | `(box, session_key)` pk, `kind` (interactive or job), `status`, `status_ts`, `workdir`, `window_name`, `agent_session_id`, `prompt`, `last_message`, `last_event_at` | Projection from events and snapshots |
| `jobs` | `job_id` pk, `idempotency_key` unique, `prompt`, `repo`, `base_ref`, `result_branch`, `state`, `box`, `attempt`, `max_attempts`, `priority`, `lease_expires_at`, `created_at`, `claimed_at`, `finished_at`, `cost_usd`, `result jsonb` | Queue and history in one table |
| `job_attempts` | `(job_id, attempt)` pk, `box`, `boot_id`, `pueue_task_id`, `started_at`, `ended_at`, `outcome` | One row per claim |

Indexes: `events(box, received_at desc)`, `events(session_id)`, `events(job_id)`, partial index `jobs(priority desc, created_at) where state='queued'`.

Retention (proposed): `events` 30 days, tool-event types 7 days, dropped by partition. `jobs` and `job_attempts` 1 year. `boxes` and `sessions` kept, `sessions` older than 90 days pruned. Prompts and last messages are stored, so the database is sensitive data (see security).

Projections update in the same transaction as the event insert. The change feed for `Watch` uses `LISTEN/NOTIFY` so more than one server replica works.

## Fleet CLI read path

| Command | Today | With the server |
|---|---|---|
| `fleet list` | VPN peer list, then ssh per Box for tmux and pueue | One `ListFleet` call. Same line format: `box-N`, `box-N/<session>`, `box-N#<task id>`. Each line shows data age. Unreachable becomes `stale` or `lost` from heartbeat age |
| `fleet preview` | ssh `tmux capture-pane` or pueue log per cursor move | `GetPreview`: session status, prompt, last assistant message, last notification, task state, cost, result tail. Plus the best-effort transcript summary and session timeline. Live pane capture stays an explicit ssh action (`fleet preview --live`), and it is ssh access, not fleet traffic |
| `fleet pick` | fzf over `sesh list` and `fleet list` | Unchanged except for the list source |
| connect | `ssh -t box-N tmux new -A`, `pueue follow` | Unchanged. Attach is ssh access: it needs the Box up and the laptop able to ssh to it |
| `fleet watch` | none | v1: the client polls `ListFleet` and prints transitions: a session going idle, a Box going stale. Later: the `Watch` stream of `FleetUpdate`, which also covers a Job finishing with cost |
| `fleet drain box-N` | manual | `SetDrain`, then show readiness: pueue idle, queue empty, no unpushed commits, fleetd queue pending zero |

The laptop can sleep. On wake the CLI reads current state, and `ListEvents --since` replays what it missed. If the server is unreachable the CLI falls back to the ssh poll for `list` for one release, then drops it. Decided (decision 7): `fleet` is a Rust binary sharing the proto crate with the server. It reads the server address from config (`FLEET_SERVER_URL`) and makes no VPN call, identity lookup or MagicDNS assumption. The ssh fallback and attach are the only paths that need the VPN, as ssh access. The nushell script stays as that fallback. To debug the server with `grpcurl`, pass `-H "authorization: Bearer $FLEET_TOKEN"`: reflection sits behind the same auth interceptor, so even listing services needs the token.

## Job queue seam

### Lifecycle

```
submitted -> QUEUED -> CLAIMED -> RUNNING -> SUCCEEDED
                          |           |----> FAILED
                          |           |----> LOST (lease expired while running)
              (lease expired before start) -> QUEUED, attempt+1
 QUEUED/CLAIMED/RUNNING -> CANCELLED
```

### Claim and lease

- `SubmitJob` writes a `QUEUED` row. The caller supplies an `idempotency_key` so a retry does not double-submit.
- An idle fleetd (the dedicated `fleet` pueue group has a free parallel slot, not draining) calls `ClaimJob`. The server picks the head with `SELECT ... FOR UPDATE SKIP LOCKED`, sets `CLAIMED`, `box`, `lease_expires_at = now + 120 s`, `attempt + 1`, and returns the Job.
- fleetd hands the Job to `fleet-job`, which creates the worktree under `~/jobs`, exports `FLEET_JOB_ID` and `SWARM_BOX=1`, and adds the pueue task. Result branch is `swarm/<job_id>` (see Background).
- The lease renews through the heartbeat, which lists `running_job_ids`. State moves to `RUNNING` when `pueue.task_started` arrives. pueue has no started callback, so that event comes from `fleet-job` or the 5 s poll.
- Lease expiry while `CLAIMED` returns the Job to `QUEUED`. Lease expiry while `RUNNING` marks it `LOST` and does not retry by default, because a Job may have pushed commits. A per-job `retry_on_lost` flag opts in.
- fleetd pulls. The server never pushes to a Box, so a Box needs no inbound port and a sleeping or rebooting Box simply claims later.

### Scaler read

The server exposes queue depth two ways: a SQL query over `jobs where state='queued'` for the KEDA PostgreSQL scaler, and `FleetJobs.QueueDepth` for a KEDA external scaler. KEDA scales Kubernetes workloads. It cannot create virtual machines, so the Box count stays a config number plus apply. What consumes the depth is parked (decision 5).

Parked sketch, no further design: KEDA is driven through the server. fleetd on the Box pulls and claims Jobs and starts them, as in the claim and lease section above.

## Security model

- **Loopback listener.** Any local process can post events. Boxes are single-user, so this is accepted. The unix socket is 0600.
- **No secrets in events.** fleetd redacts exact values of the secrets loaded from `redact_files` from every string field before queueing. Tool events, which can carry commands with secrets, are off by default. Raw transcripts and raw pueue logs never leave the Box. Derived transcript text (preview and timeline) leaves truncated and redacted. Redaction (T7) matches exact values in nested JSON, sorted longest first, and skips very short values. It does not catch base64, URL-encoded or split forms.
- **Sensitive content.** Prompts, `last_assistant_message` and transcript-derived preview text reach the server. The server has no public ingress and is reachable only over the VPN. The database is treated like the Box credentials in sensitivity.
- **Transport.** Plain gRPC over any routable path. TLS is optional and set by the deployment. The VPN, whichever it is, protects the link, and the plan assumes nothing about which. Without TLS the bearer token crosses the VPN in clear text.
- **Authorization.** One shared bearer token covers ingest, job claim, query and job control (decided 2026-10-24, ADR-0014). Any holder can read every Box's data and submit or cancel Jobs. A claim returns only the claiming Box's Job, and ingest and claim reject a `box` that does not match `box-<n>`. A read-only credential is a later upgrade.
- **Git.** fleetd never pushes and holds no git credential. It runs read-only git commands to count unpushed commits. That rule is unchanged.
- **Blast radius.** fleetd runs as `agent`, the same as workers. It adds no privilege and exposes no new inbound port beyond loopback.
- **Secrets never printed.** fleetd logs event ids and types, never payloads, at default level.

## Failure modes

| Failure | Effect | Handling |
|---|---|---|
| Server down or unreachable | Events queue on the Box | Backoff, resend from the acked seq. Heartbeat gaps show as stale once the server is back |
| fleetd down | Hooks fail non-blocking (about 2 ms each, T8). Claude Code does not retry, so hook events are lost for the gap. Workers continue | systemd restart in 2 s. On start the watchers reconcile and emit a full snapshot, and the pueue poll covers task results. The lost hook payloads are not recoverable. A transcript read at start can rebuild a summary for known sessions |
| Duplicate delivery | Repeated rows | `event_id` and `(box, boot_id, seq)` unique, `ON CONFLICT DO NOTHING` |
| Box destroyed with pending events | Events lost | Drain check includes queue empty and unpushed commits |
| Box clock skew | Misordered display | Order by `(boot_id, seq)`, `received_at` on the server |
| Queue full | Low priority events dropped | `fleetd.queue_overflow` event with count |
| SQLite corruption | Queue lost | Rename the file aside at start, create a new one, emit `fleetd.watcher_error` |
| Hook JSON shape differs from assumption | Normalized fields empty | Raw JSON kept verbatim under `raw`. Normalizer is tolerant. T2 recorded the shape on 2.1.289. Re-check on a pin bump |
| workmux state schema changes | Watcher misparses | Pinned workmux version. Parse errors emit `fleetd.watcher_error` and the reconcile poll still runs |
| Agent crash with no hook | No `Stop`. The state file stays `working` and emits no event | `workmux wait` started on the `working` transition (exit 3), the DELETE watch, and the fleetd liveness check. Deduped per pane id |
| Claude killed mid Job | No `job.result` | The pueue callback (id and group only) or the poll emits `pueue.task_finished`. Job goes `FAILED` with no cost |
| Box reboots mid Job | Task and agent gone | New `boot_id`. Lease expires, Job goes `LOST` |
| Two fleetd claim the same Job | Double run | `SKIP LOCKED` claim is atomic. A lease belongs to one box |
| Misconfigured or duplicate box name, such as `box-<n>-<n>` | Wrong identity | Names not matching `box-<n>` are rejected at ingest. The drain check stays |
| Token rejected or rotated | Same as server down | Events queue on the Box. Heartbeat gap shows on the laptop side. Fix by secrets push or rebuild |
| Transcript lags `Stop`, is unreadable, or the entry format changed | The read at `Stop` misses the final assistant entry (T10). Otherwise no `transcript.summary` | Delayed read in fleetd with the `complete` flag. Preview from `last_assistant_message`. Re-run T10 on a pin bump |
| Server schema upgrade | Old fleetd rejected | N and N-1 `schema_version` support |
| Network path or VPN change blocks the server | Same as server down | Heartbeat gap alert on the laptop side |
| Pueue socket unreachable from the system unit | No task events | `After=` and `Wants=user@<uid>.service`. Verified in T9, so the `systemd-run --user` fallback is dropped. Poll errors emit `fleetd.watcher_error` |
| Killed agent's state file lingers | Status stays `working`, no event, deleted only when some workmux command runs | fleetd liveness check, DELETE watch, 10 s reconcile (T5) |
| pueue callback injection | `{{ command }}` and `{{ output }}` are pasted raw into the shell string, so quotes in a task command inject shell text (T6) | The callback passes only `{{ id }}` and `{{ group }}`. fleetd reads the rest from `pueue status --json` |
| Hook listener stalled (accepts, never answers) | A hook could hold a turn | Explicit hook `timeout`. Untested, Phase 1 pre-check |
| Same hook event from two settings sources | Duplicate `hook.*` events | Loopback hook only in managed settings. fleetd drops exact body repeats within 10 s |
| Fleet work queues behind other pueue work | The default group runs one job at a time | Dedicated pueue group with its own parallel setting |
| `claude -p` started from a script on stdin | It swallows the script from stdin | `fleet-job` redirects stdin from `/dev/null` |
| Hook event lost while fleetd is down | A session exists with no `session_start`, `stop` or `session_end` | Registry discovery emits `session.discovered`, `session.stalled` or `session.ended_unseen` with `source=reconcile`. Payloads are not recovered, only state and the last assistant text |
| fleetd wedged but alive | No events, no restart | `WATCHDOG=1` only when listener, forwarder and reconcile each progressed. systemd restarts after `WatchdogSec` |
| Box stops sending heartbeats | Stale data on the laptop | Server sweeper marks `stale` at 90 s and `lost` at 10 min |
| Registry lost or rebuilt | Every old session looks new | Baseline run inserts old sessions as `ended` with no event |

## Phased rollout

| Phase | Deliverable | Exit check |
|---|---|---|
| 0 | Pre-build tests below, on one Box. Done 2026-10-24 | Satisfied: all ten have a recorded result (`docs/phase0/README.md`) |
| 1 | The Phase 1 pre-checks below, then the fleetd walking skeleton: HTTP and socket listeners, SQLite queue, file sink instead of server. Baked into the Template, managed-settings hooks configured | Hook events from an interactive session and a `claude -p` run land in the queue |
| 2 | Server: schema, `FleetIngest`, auth, deploy. fleetd forwarder | Kill the server for 10 min, restart it, and no event is missing or doubled |
| 3 | workmux watcher, pueue integration, `fleet-job`, heartbeat | Kill an agent pane and see `agent_crashed`. A Job's cost appears on the server |
| 4 | `FleetQuery`, fleet CLI read path, `watch`, `drain` | `fleet list` makes no ssh call. Laptop sleep and wake loses nothing |
| 5 | `FleetJobs`: submit, claim, lease, `LOST` handling | A queued Job runs on an idle Box. Killing the Box returns or marks it per policy |
| 6 | Queue depth exposure and the scaler consumer | Depth visible to the chosen consumer |

### v1 mapping

v1 is Phases 1 to 4 minus `fleet-job` and Job cost, minus `drain`, `GetPreview`, `ListEvents` and the `Watch` rpc. `fleet watch` in v1 is a client poll of `ListFleet`. Phases 5 and 6 follow v1.

The six build phases in the table above are the build steps. Phase 1 is the first and starts with the pre-checks below.

### Pre-build tests (Phase 0): results

Ran on one Box on 2026-10-24. Each record is `docs/phase0/T<n>.md` in this repo.

- **T1. Does `Stop` fire at the end of `claude -p`? Pass.** `Stop` fires once per run, tool calls included, and `SessionEnd` follows about 16 ms later. `result` carries all six fields. `stream-json` exits 1 without `--verbose`.
- **T2. Raw hook JSON field names. Pass.** All planned fields exist. `prompt_id` is on every event except a failed-start `SessionEnd`. A subagent hand-back fires a synthetic `UserPromptSubmit` with the same `prompt_id`.
- **T3. Do http hooks accept a unix-socket URL? Fail for sockets, Pass for loopback.** `unix:` and `http+unix:` give `Unsupported protocol`. Loopback http hooks work on 2.1.289. `onFailure` is accepted and does nothing.
- **T4. Managed settings on Linux. Pass.** `/etc/claude-code/managed-settings.json` and `managed-settings.d/*.json` load, and hooks merge with user and `--settings` hooks. The http hook type inside a managed file was not run.
- **T5. workmux state and crash exit code. Partial.** `workmux wait` exits 3 for a crash that happens after it starts, and 1 after. `prompt` is null, `pane_pid` is the shell, a killed agent's file lingers, `waiting` was not seen.
- **T6. pueue callback. Pass for firing, Partial for safe use.** It fires for success, failure, kill and external kill in 0.2 to 0.3 s. `{{ command }}` and `{{ output }}` inject shell text, so pass only `id` and `group`.
- **T7. Bearer token rejected and accepted. Pass.** Wrong and missing tokens give `UNAUTHENTICATED`, the right one succeeds. The 0640 file works for `agent` only, and redaction removes the token. No tonic client was run.
- **T8. Hook failure latency with fleetd down. Pass.** A refused connection costs about 2 ms and the run is unaffected, 1.58 s against 1.61 s. A stalled listener was not tested.
- **T9. System unit reaching pueue. Pass.** The unit reaches the real pueue socket and workmux state. `ProtectSystem=strict` leaves `/home` writable, so add `ProtectHome=read-only`.
- **T10. Transcript contents and drift. Partial.** `usage` and `model` are on every assistant entry, but the file lacks the final assistant entry at `Stop`, ids repeat, and subagent tokens do not reconcile with `result`.

### Phase 1 pre-checks

Unknowns left from Phase 0. Each is a short throwaway test, run before or during the walking skeleton, which is Phase 1 of the six build phases (see Phased rollout). v1 covers Phases 1 to 4.

1. A stalled http listener with a hook `timeout`: does the turn proceed, and after how long?
2. The `http` hook type inside a managed file (T4 used command hooks).
3. `managed-settings.json` and `managed-settings.d/` together: both load, and the order.
4. Interactive sessions with http hooks from managed settings: `Stop` per turn, `Notification` timing, `idle_prompt`.
5. A tonic client: the `authorization: Bearer <token>` metadata passes the interceptor, ideally over a real VPN path with and without TLS.
6. The `waiting` status from workmux, with an agent that asks for permission.
7. Repeated T10 lag samples: many runs, long turns, many tool calls, `--resume`, disk load, and a `SessionEnd` read at the real 16 ms gap with no sleeping `Stop` hook.
8. The `X-Fleet-Job` header with `allowedEnvVars` (added after Phase 0: no test covered it).
9. The user's own `workmux set-window-status done` `Stop` hook still fires beside the managed file (T4 did not observe it).

## Open decisions

Numbering is stable. Decided on 2026-10-24 unless marked otherwise.

1. **Where does the fleet server run?** Decided 2026-10-24.
   - Answer: a hosted service reachable over a VPN or any routable path, for example Tailscale or netbird. Tailscale is not a hard dependency anywhere: no whois, no VPN identity, no `tailscale` CLI calls, no MagicDNS-only assumption, no ACL tag as the auth mechanism.
   - Server address: plain config, `FLEET_SERVER_URL` in `/etc/swarm/box.env`. Any routable network path. TLS optional by deployment.
   - Box identity in events: the Box's own hostname, machine-id and boot id, plus a configured box name. Never from the VPN.
   - VPN switch: a config change plus an ADR note.
   - The existing setup still uses a VPN, separate from fleet traffic: ssh access to Boxes, the picker's peer list, and the first-boot join key baked into the Template.
   - Left to deployment, not decided here: the host platform of the server (Kubernetes, a VM or a VPS).

2. **How does a Box authenticate to the server?** Decided 2026-10-24.
   - Answer: a shared bearer token, for the proof of concept. gRPC metadata `authorization: Bearer <token>`. `FLEET_TOKEN` in `/etc/swarm/secrets.env`, mode 0640 `root:agent` (the existing secrets pattern), baked into the Template. ADR-0014.
   - Downside: one leaked token exposes the fleet. Rotation is a Template rebuild or a secrets push.
   - Upgrade path: per-Box tokens minted at first boot, then mTLS or JWT.
   - Test: T7 passed with python grpcio and grpcurl. A tonic client is a Phase 1 pre-check.

3. **How do hooks reach fleetd, and where is the hook config?** Decided 2026-10-24.
   - Answer: a Claude Code `type: "http"` hook to `http://127.0.0.1:<port>/hook` on fleetd, loopback.
   - Managed settings (`/etc/claude-code/managed-settings.json` or a `managed-settings.d` drop-in), settled by T4: hooks merge with user hooks and both fire. T8: a down fleetd costs about 2 ms.

4. **What fills the fleet preview?** Decided 2026-10-24.
   - Answer: event-derived preview. `fleet preview --live` does an ssh capture.
   - fleetd reads the transcript at `transcript_path` for preview text and a session timeline, best-effort, from a delayed read after `Stop` (T10: the file lacks the final entry at `Stop`) and again at `SessionEnd`. `last_assistant_message` fills the immediate preview. Cost comes from the `result` message. A parse failure degrades to `last_assistant_message`. The Claude pin bump requires re-running T10.
   - Sources: [sessions, where transcripts are stored](https://code.claude.com/docs/en/sessions#where-transcripts-are-stored) and [hooks, common input fields](https://code.claude.com/docs/en/hooks#common-input-fields), both official docs. The lag wording was verified against the page.

5. **What does the KEDA seam act on?** Parked 2026-10-24.
   - The user said to leave it. The sketch: KEDA driven through the server, with fleetd on the Box pulling, claiming and starting Jobs. ADR-0016 keeps the seam. No further design until it is picked up again.
   - Blocked: Phase 6 only.

6. **Which hook events are recorded by default?** Decided 2026-10-24.
   - Answer: `SessionStart`, `UserPromptSubmit`, `Stop`, `Notification`, `SessionEnd`. Explicitly provisional, to be refined during testing. The list is config in fleetd, not hardcoded.

7. **What language and shape is the laptop `fleet` CLI?** Decided 2026-10-24.
   - Answer: a Rust binary sharing the proto crate with the server. The nushell script stays as the ssh fallback.

8. **Does `fleet-job` use `--output-format json` or `stream-json`?** Decided 2026-10-24.
   - Answer: `claude -p --output-format json` first. One object at exit with `total_cost_usd`.
   - `stream-json` is the later option for live progress. It emits line-delimited JSON events and ends with a `result` message. The user lists its fields as result, `session_id`, `total_cost_usd`, `usage`, `num_turns`, `duration_ms`, `is_error` and error subtypes. The docs page says only that the last line is a `result` message "with the final response text, cost, and session metadata", so the field list was unverified until T1. T1 confirmed the last line is a `result` message with `total_cost_usd`, `session_id`, `usage`, `num_turns`, `duration_ms` and `is_error`, and that `stream-json` exits 1 with no output unless `--verbose` is passed. `fleet-job` passes `--verbose` whenever it uses `stream-json`. Source: [headless, stream responses](https://code.claude.com/docs/en/headless#stream-responses), official docs.
   - Test: T1 ran it: Pass.

## Open since the v1 cut

Numbering continues the list above. All Decided 2026-10-24.

9. **Public repo and mise distribution.** Decided 2026-10-24: the fleet repo is public at github.com/a19simma/fleet, releases carry binaries, Boxes install through mise. Detail in ADR-0017 (Accepted).
10. **`fleet watch` mechanism.** Decided 2026-10-24: client poll of `ListFleet` in v1. No `Watch` rpc in v1. The server `Watch` stream stays in the proto sketch for later.
11. **Licence.** Decided 2026-10-24: Apache-2.0 (ADR-0017).
12. **Job cost in v1.** Decided 2026-10-24: deferred. v1 has no `fleet-job`, so no cost on the server. Jobs run on a subscription, not the API, so cost is not a v1 driver.
13. **Where the plan and ADRs live once the fleet repo is public.** Decided 2026-10-24: in this repo, under `docs/`, in sanitized form.

## ADRs

All Accepted on 2026-10-24. Index and status in `docs/adr/README.md`.

| ADR | Title | Relation |
|---|---|---|
| 0011 | fleetd box daemon | Adds fleetd to the Template contents. Supersedes none |
| 0012 | Event model and delivery | New |
| 0013 | Fleet server stack | New |
| 0014 | Box to server bearer token | Adds a fourth baked credential to the three in Background. Supersedes none |
| 0015 | Fleet reads from the server | Replaces the ssh polling and preview parts of the existing picker. Picker, line formats and connect stay |
| 0016 | Job queue, claim and lease | New, parked sketch. Leaves manual scale-down in force |
| 0017 | Public repo and mise distribution | New. The pinned fleetd comes from a public release through mise. Licence Apache-2.0 |

Relation to the existing setup: the ssh polling in the picker conflicts with ADR-0015, hence the partial replacement. The existing design deferred `fleet-job` to its first phase. This plan builds it in Phase 3 of the fleetd rollout, which still fits. A pending check on the `workmux status --json` schema is absorbed by T5. Workers use the full global config, so hooks in the baked `settings.json` fire on the Box. Workmux hooks failing harmlessly on a Box is a pre-existing item and is orthogonal.

## Glossary

Terms used in this plan:

- **fleetd**: the daemon on each Box.
- **Fleet server**: the hosted service that stores events and Box snapshots.
- **Event**: one record in the envelope of ADR-0012.
- **Box snapshot**: the latest heartbeat state of a Box, kept on the Fleet server (ADR-0012).
- **Lease**: the time-limited claim a Box holds on a queued Job (ADR-0016).
- Job states are defined in ADR-0016 and stay parked with the queue seam.

## Review follow-ups (deferred)

- Rename `Queue` to `Store`, with free-function `events` and `registry` modules over `&mut SqliteConnection` and `sqlx::migrate!`, before the registry lands.
- Replace the task set with a Supervisor that tracks per-task progress heartbeats for the watchdog.
- Flatten `Identity` into `Envelope`.
- Choose a collision-resistant hash (blake3 or sha2) before derived ids persist.
- Split `Error` into `ParseIdError` and `NotAnObject`.
- Add an `EVENT_FIELDS` table to the normalizer.
- Build the image through a dist `github-custom-jobs` workflow_call, or ship a dist-built fleet-server archive.
- SHA-pin actions and base images, split the push job so `packages:write` applies to tags only, and attest provenance.
- Add `scripts/private-scan`.
- Add an auth header to the hook endpoint.
- Dedupe raw against normalized payload size.
- Fail closed on redaction when the secrets file is missing.
- Redact encoded variants of secrets.
