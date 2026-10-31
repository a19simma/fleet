# Job telemetry

Status: Accepted. Built: fleetd parses and hooks telemetry, the server stores, serves and prunes it, and `fleet status` shows it. Amends ADR-0021 and sits beside ADR-0022.

A Job leaves a transcript (ADR-0022) but no figures: turns, cost, tool errors, how long until the first edit. A laptop had to read the whole stream to learn what a Job did. The stream-json output omits some facts, such as a Bash exit code, so one source cannot give a complete record.

## Decision

fleetd records two tiers of telemetry per Job and reports them through `ReportJob`. The server stores them in Postgres.

- **Tier A.** A pure stream-json parser in fleetd (`telemetry.rs`) reads each redacted transcript line. It builds events and a summary: turns, durations, stop reason, result subtype, estimated cost, token counts, tool calls and errors, Bash calls, denials, API retries and the arrival time of the first `Edit`, `Write` or `MultiEdit`.
- **Tier B.** Claude Code `PostToolUse` and `PostToolUseFailure` hooks run `fleetd hook`, which reduces the payload to `tool_use_id`, tool name, exit code and duration and posts it to the local daemon. An in-process `HookHub` hands each report to the running Job it belongs to. The feed joins it to the tier A event on `tool_use_id`. A report that arrives first waits, at most 256 at a time, and a second report for one id is counted and ignored. The reduced form carries no file contents or command output.
- **Not built.** No OTLP receiver, no pueue, no wrapper around Bash. Hooks give the exit code the stream lacks without either.
- **Events.** Table `job_event`, primary key `(job_id, seq)`, kinds `tool`, `denial`, `api_retry`, `phase` and `stuck`, and `fetch` after the ADR-0038 amendment. A repeated `(job, seq)` is a no-op. A Job keeps at most 2000 events, with a truncation marker, and a `ReportJob` carries at most 256. `cmd` is cut at 512 bytes and `detail` at 1024, at a UTF-8 boundary. The parser also stops storing events past about 1 MiB of event text.
- **Summary.** Table `job_summary`, one row per Job, upserted. Migration `0006_job_telemetry.sql` creates both tables, `0007_retention_indexes.sql` adds `jobs(created_at)` and a partial index on `COALESCE(finished_at, created_at)` for terminal states, `0008_stuck_shadow.sql` adds the stuck columns, `0009_job_summary_stamp.sql` adds `bundle_sha`, `claude_version` and `model` (ADR-0030) and `0010_job_summary_phases.sql` adds `clone_ms`, `push_ms`, `pr_ms` and `queue_wait_ms`.
- **Phase and queue durations.** fleetd times the workspace clone, the push and the pull request step through an injected clock (`phase::Clock`), and the summary carries them as `clone_ms`, `push_ms` and `pr_ms`. A phase that did not run is unset and stored as `NULL`: a job with no commits has no push or pr time, and a job with `open_pr` off has no pr time. A phase that ran and failed keeps its time. fleetd caps each value at seven days (`MAX_PHASE_MS`), and the server rejects a larger one with the fixed error `invalid job telemetry`, and the columns carry the same `CHECK`. `queue_wait_ms` is never taken from the report: the server derives it when it stores the summary, as `jobs.claimed_at` minus `jobs.created_at`. `claimed_at` is rewritten on each claim, so the figure is the wait until the latest claim, which equals the first lease for a job on its first attempt. It is `NULL` while `claimed_at` is unset. A negative difference from clock skew is stored as 0, the one case where this column holds a zero that was not observed.
- **Incompleteness.** A figure nobody observed is `NULL`, never 0. The summary carries `complete`, true once a `result` line was seen, and `missing[]`. Names in use are `result`, `exit_codes`, `hooks`, `events_truncated`, `tool_results` and `parser`. `hooks` marks a Job with at least one Tier A tool call and no `PostToolUse` report joined to any call; a Job with no tool calls never carries it. `parser` marks a Job whose parser panicked and was dropped. A zero in a stored figure means zero observed, except a `queue_wait_ms` clamped from clock skew.
- **Redaction before truncation.** The parser applies the redactor to decoded `tool`, `cmd` and `detail` text before it cuts them. A secret escaped in JSON only matches after decoding, and a cut first would leave a prefix of it. `convert` runs a second pass over the remaining fields.
- **Retention.** The server deletes events of terminal Jobs after 90 days and summaries after 365. Age counts from `COALESCE(finished_at, created_at)`, and only `SUCCEEDED`, `FAILED`, `CANCELLED` and `LOST` Jobs qualify. Each delete is a batch of 5000 rows chosen with `FOR UPDATE ... SKIP LOCKED`, at most 20 batches per table per sweep, one sweep per hour by default. Settings: `FLEET_EVENTS_RETENTION_DAYS`, `FLEET_SUMMARIES_RETENTION_DAYS` (each 1 to 3650, summaries not below events) and `FLEET_RETENTION_INTERVAL_SECS` (at least 60).
- **Read side.** `FleetJobs.ReadJobEvents{job_id, after_seq, limit}` returns events and `next_seq`. `Job.summary` is field 21 of the `Job` message. `fleet status <id>` prints a `telemetry:` block, and `fleet status <id> --tools` lists the tool calls.
- **Amends ADR-0021.** `ReportJob` gains events and a summary, and `Job` gains `summary`.

## Consequences

- Stored `cmd` text is redacted by exact value only (ADR-0014). A command string can hold a secret in another form, so event rows are sensitive. The database stays sensitive as ADR-0022 says, and backups carry the same care.
- Averages over summaries need the per-figure count, because a `NULL` is absent data. ADR-0030 returns that count.
- A Job past 2000 events loses the later ones and its summary lists `events_truncated`.
- Inferred, not part of the design: the Bash exit code in `job_event` stays `NULL` when the hook did not reach the daemon in time, and a late hook report changes the summary only for an event already acked.
- Telemetry never gates the transcript. A parser panic or an oversize line raises a counter and the Job continues.
- A deleted event row removes detail but not the summary figures for 275 more days.

## Considered and rejected

- **An OTLP receiver in fleetd.** A second protocol and a listener for figures the stream and hooks already give.
- **Hooks only.** Hooks carry no turns, cost or tokens.
- **Wrapping Bash to capture exit codes.** It changes what the agent runs and can break its commands.
- **Pueue task state.** ADR-0020 removed pueue.
- **Zero for unobserved figures.** It makes a missing result look like a free Job and corrupts every average.

## Amendment (ADR-0034)

A profile column and a batch comparison read from the existing summary and event data under the same `NULL` and own-n rules. No new metric is added.

## Amendment (ADR-0038)

Kinds gain `fetch` (`EventKind::Fetch`, proto `JOB_EVENT_KIND_FETCH = 6`) and migration `0016` widens the `job_event` kind CHECK. Fetch events count toward the 2000-event cap. The `missing` list gains `fetch_outcome`. Summary figures are unchanged.

## Amendment (ADR-0044)

A Job Summary from a non-claude runner is marked Incomplete until that runner's output parser exists. Figures it cannot supply stay `NULL`.
