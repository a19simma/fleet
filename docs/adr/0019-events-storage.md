# Events storage

Status: Accepted

ADR-0013 partitioned `events` monthly on `received_at` and kept events 30 days, tool events 7 days, by dropping partitions. The server built in step 3 stores events in one plain table. This ADR records the storage that runs.

## Decision

- **One `events` table.** Primary key `(box, id)`. Columns: `boot_id`, `seq`, `schema_version`, `source`, `kind`, `captured_at_ms`, `occurred_at_ms`, `received_at` (server clock), `session_id`, `prompt_id`, `workdir` and `payload jsonb`. It is not partitioned. Indexes: `(box, boot_id, seq)`, `(box, received_at desc)` and a partial `(session_id) where session_id is not null`.
- **Retention is by delete.** Expired rows are removed with `DELETE ... WHERE received_at < ...`, not by dropping partitions. The retention figures of ADR-0013 stay the targets. No job runs the delete yet, so the table only grows until one is added.
- **Projections in the ingest transaction.** `boxes.last_event_at` and the `sessions` row update in the same transaction as the insert, and only for rows that were new. A repeated event changes nothing. Rows project in `seq` order.
- **Session rules.** `session_start` sets `active`. A prompt with `payload.synthetic` not true sets `working` and `last_prompt`. A synthetic prompt changes nothing. `stop` sets `idle` and `last_message`. `session_end` and `session.ended_unseen` set `ended`. `notification` sets `last_notification` only. `session.stalled` sets `stalled`. `session.discovered` sets `active` only when no row exists. An `ended` session reopens only on `session_start` or a non-synthetic prompt.
- **Box status is computed on read.** `ListFleet` derives it from `boxes.last_heartbeat_at` and the database clock: `UNKNOWN` with no heartbeat, `LIVE` under 90 seconds, `STALE` under 10 minutes, `LOST` beyond. All ages are computed the same way. No sweeper writes status and nothing stores it.
- **Heartbeat state.** `boxes.state` (jsonb) holds the queue figures and uptime from the latest heartbeat. Sessions and tasks in the heartbeat body are not part of the v1 request.

Supersedes the monthly-partition line of ADR-0013 (`events` partitioned monthly on `received_at`, dropped by partition).

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- Migrations run at server start (`sqlx::migrate!`).
- Queries are plain runtime `sqlx::query` calls. There are no compile-time checked macros and no `.sqlx` cache.

## Consequences

- Fewer moving parts: no partition creation job, no partition-aware primary key.
- Deleting old rows leaves bloat that autovacuum must reclaim. A large delete is slower than a partition drop. Acceptable at tens of events per second.
- Because the table is not partitioned the primary key does not need `received_at`, so `(box, id)` dedupes across all time.
- A status that cannot go stale in storage: a dead server cannot leave a box marked `LIVE`. The cost is one `CASE` per read.
- `sessions` rows are never pruned in this build, and `ListFleet` returns them all, ended ones included.
- Prompts and last messages are stored, so the database remains sensitive data (ADR-0013).

## Considered and rejected

- **Monthly partitions.** The primary key would have to include `received_at`, which breaks `(box, id)` as the dedupe key.
- **A sweeper that writes box status.** A second writer and a failure mode where the status lags the clock.
- **Status computed in Rust from timestamps.** Splits the clock between the app and the database. One clock keeps the thresholds testable by backdating a column.
