# Event model and delivery

Status: Accepted. The one-stream and cumulative-ack parts of Order and Dedupe are superseded by ADR-0018.

Events come from four sources on a Box and must reach the Fleet server across laptop sleep, server restarts and network gaps. The server must be able to drop repeats without losing anything.

## Decision

Every event has one envelope. Delivery is at least once, deduplicated by id.

- **Envelope.** `event_id`, `schema_version`, `box`, `hostname`, `machine_id`, `boot_id`, `seq`, `source`, `type`, `occurred_at`, `captured_at`, `session_id`, `job_id`, `workdir`, `payload`.
- **Identity fields.** `box` is the configured box name (`FLEET_BOX_NAME` in `/etc/swarm/box.env`, default the hostname). `hostname` and `machine_id` come from the Box itself. None comes from the VPN. The server stores `box` as claimed (ADR-0014).
- **Ids.** Hook and job events use a random ULID. Watcher events use a hash of source and natural key (for example state file path and `status_ts`), so a watcher restart derives the same id. `workmux.agent_crashed` and `workmux.agent_gone` hash `(pane id, last status_ts)`, so the `workmux wait` exit, the state file DELETE and the liveness check emit one event (T5). A hook body that repeats within 10 s (proposed) is dropped, since the same event can arrive once per settings source (T4).
- **Order.** `seq` is a u64, monotonic per `boot_id`, assigned at commit to the disk queue. fleetd sends in `seq` order on one stream. The server acks a cumulative high-water mark per box and boot. There is no order across Boxes, and `occurred_at` is advisory.
- **Dedupe.** The server keeps `event_id` as primary key and `(box, boot_id, seq)` unique, and inserts with `ON CONFLICT DO NOTHING`.
- **Disk queue.** SQLite in WAL mode at `/var/lib/fleetd/queue.db`. The commit is the durability point, and fleetd deletes an event only after the ack. The cap is 256 MiB or 14 days. When full, tool events drop first, then repeated status changes. fleetd emits a `fleetd.queue_overflow` event with the count. Results, `pueue.task_finished`, `Stop` and `SessionEnd` drop last.
- **Retry.** Exponential backoff from 1 s to a 5 min cap with full jitter, reset on the first ack.
- **State is not an event.** A 30 s `Heartbeat` carries the Box snapshot (sessions, tasks, queue age, health, drain flag, unpushed commit count). The server keeps the latest copy.
- **Raw payload kept.** Hook events keep the verbatim JSON under `raw` beside a normalized subset, so a wrong field assumption loses nothing. T2 fixed the subset for 2.1.289 (plan, hook normalizer). A `UserPromptSubmit` from a subagent hand-back is marked `synthetic`, not dropped, and projections skip it as a human prompt (T1). `prompt_id` correlates one turn and is absent on a `SessionEnd` after a failed start.
- **Redaction.** fleetd scrubs exact values from `/etc/swarm/secrets.env` out of every string before queueing, longest value first, skipping very short values. T7 showed it removes a token that appears twice in nested JSON. It does not catch base64, URL-encoded or split forms. Tool events are off by default.
- **Recorded hook events.** A config list in fleetd, not hardcoded. The default is `SessionStart`, `UserPromptSubmit`, `Stop`, `Notification`, `SessionEnd`, and it is provisional until testing refines it. T1 and T2 confirmed `UserPromptSubmit`, `Stop`, `Notification` and `SessionEnd` fire with the expected fields. `Notification` arrives late (7.5 s in one observation) and `idle_prompt` was not seen. `SessionStart` was not exercised.
- **Transcript-derived events.** From a delayed read after `Stop` and a read at `SessionEnd`, fleetd may add a `transcript.summary` event with preview text and timeline entries, truncated and redacted. It carries `source` and a `complete` flag, and no cost or token totals. Best-effort, and a parse failure emits none. Raw transcripts never leave the Box. The transcript lags `Stop` and lacks the final assistant entry at that moment (T10). Totals come from the `result` object. The behaviour was measured on 2.1.289 and is re-run on any pin bump.

## v1 cut and recovery (2026-10-24)

The reconciler adds a fifth `source`, `reconcile`, and three event types: `session.discovered`, `session.stalled` and `session.ended_unseen`. `workmux.agent_crashed` carries `source=reconcile` when the liveness check reports it first. The change is additive, so `schema_version` does not move.

- **Ids.** A hash of the event kind and its discriminator: `session_id` for `discovered`, `(session_id, last_mtime)` for `stalled` and `ended_unseen`, `(pane id, last status_ts)` for `agent_crashed`. A restart re-derives the same id and the server drops the repeat. `source` does not enter the hash, so the first source to arrive wins.
- **Priority.** Derived session events rank with `Stop` and `SessionEnd`: dropped after tool events and status repeats.
- **Reading the guarantee.** The Phase 0 gap stands: a hook payload fired while fleetd is down never reaches the queue. The reconciler replaces the missing state with a derived event, so a consumer can tell reconstruction (`source=reconcile`) from observation (`source=hook`). It does not recreate the prompt, the notification or the stop payload.
- **Baseline.** On first run or after a registry rebuild, sessions whose transcript is older than `stall_after` are recorded as `ended` with no event, so history does not flood the server.
- **Cost bound.** The pass stats files and parses only a changed one from its last offset. It extracts the last assistant text and the last entry time, and builds no timeline or token count in v1.

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- Job cost events (`job.result`) are deferred past v1, since cost arrives only through `fleet-job`.

## Consequences

- Events survive fleetd and server restarts and a Box reboot once they are committed to the disk queue. They do not survive Box destruction, so the drain check adds "fleetd queue empty".
- Phase 0 narrows the guarantee: delivery is at least once from fleetd's commit onward. A hook event fired while fleetd is down never reaches the queue, because Claude Code does not retry a failed http hook (T8). This contradicts the reading of the opening paragraph that no event is lost across gaps. Watchers, the pueue poll and a transcript read reconstruct state, and the lost hook payloads are not recoverable.
- Per-Box order holds and cross-Box order does not.
- A full queue loses detail, and says so.
- SQLite adds a dependency and a file to recover. A corrupt file is moved aside and a new one is created.
- `schema_version` lets the server accept the current and previous version while Boxes are re-created in turn.

## Amendments

- **SessionStart hook.** `SessionStart` is a command hook, `fleetd hook SessionStart`, because Claude Code accepts only `command` and `mcp_tool` hooks for that event. It forwards to the same route and always exits 0.
- **Job header.** Only the `SessionStart` command hook sends `X-Fleet-Job`: `fleetd hook` reads `FLEET_JOB_ID` and sends it when set. The four http hooks send no job header, and the managed settings set no `allowedEnvVars`. The `allowedEnvVars` route was never built or tested.

## Considered and rejected

- **At most once.** Drops events on any server blip.
- **Exactly once.** Needs a two-phase protocol. At least once plus idempotent insert reaches the same result.
- **Append-only segment files.** Hand-rolled crash recovery and cursor tracking.
- **An embedded key-value store (redb, sled).** No ad hoc inspection with `sqlite3` on a Box.
- **Random ids for watcher events.** A restart would duplicate every state change.
