# Job protocol

Status: Accepted. Built: the server serves `FleetWorker` and `FleetJobs`, and the daemon claims and reports through them. Supersedes the claim and lease sketch of ADR-0016 where they differ.

ADR-0016 placed claim and lease on `FleetIngest` and the heartbeat, with a `CLAIMED` state and a `job_attempts` table. ADR-0020 removes pueue, so a Job no longer needs an intermediate state before it runs.

## Decision

Jobs are rows in the server's Postgres, driven by two new gRPC services in package `fleet.v1`.

- **`FleetJobs`, laptop scope.** `SubmitJob{idempotency_key, prompt, repo, base_ref, open_pr}` returns `Job`. `GetJob`. `ListJobs{state?, limit}`. `CancelJob`. `ReadTranscript{job_id, after_seq, limit}` returns chunks plus `done`.
- **`FleetWorker`, box scope.** `ClaimJob{box}` returns an optional `Job`, `lease_s` and `next_in_s`, and an empty reply means no Job. `ReportJob{job_id, attempt, box, phase, progress, terminal_state?, pr_url?, error?, exit_code?, chunks[]}` returns `{lease_expires_at, cancel_requested}`.
- **States.** `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `LOST`. `CLAIMED` is gone.
- **Phases.** `CLONING`, `RUNNING`, `PUSHING`, `PR`, `DONE`.
- **Claim.** One transaction takes the head of `created_at` among `QUEUED` rows with `FOR UPDATE SKIP LOCKED`, through a partial index on `jobs(created_at) WHERE state='QUEUED'`. It sets `RUNNING`, `box`, `claimed_at`, increments `attempt` and sets `lease_expires_at`. The lease is 120 s.
- **Report.** `ReportJob` carries progress, transcript chunks and the lease renewal in one call. fleetd flushes chunks every 2 s or 64 KiB when there is data, and sends `ReportJob` at least every 30 s even when the agent produced no output. Any `ReportJob` renews the lease. A stale `attempt` or `box` gets `FAILED_PRECONDITION`. A repeated chunk `seq` is a no-op, so retries are safe.
- **Reaper.** A background task every 15 s moves `RUNNING` rows with an expired lease to `LOST`. It never retries them, since a Job may have pushed commits.
- **Cancel.** `CancelJob` on a `QUEUED` Job sets `CANCELLED` at once. On a `RUNNING` Job it sets `cancel_requested`, which the next `ReportJob` reply returns.
- **Submit.** The idempotency key is unique and nullable, so a retried submit does not duplicate.
- **Schema.** Migration `0003_jobs.sql` adds `jobs` (`job_id` as a ULID, `idempotency_key`, `prompt`, `repo`, `base_ref`, `branch`, `open_pr`, `state`, `box`, `attempt`, `lease_expires_at`, `phase`, `progress` capped at 200 chars, `pr_url`, `error`, `exit_code`, `cancel_requested`, `transcript_bytes`, `created_at`, `claimed_at`, `finished_at`) and `job_transcript` (ADR-0022).
- **Errors.** `UNAUTHENTICATED` for a bad or missing token, `PERMISSION_DENIED` for a token whose scope does not cover the path (ADR-0023), `FAILED_PRECONDITION` for a stale attempt or box, `INVALID_ARGUMENT` for a bad `box-<n>` name, never retried (ADR-0018). The 1 MiB decode limit stays.
- **CLI.** `fleet submit --repo --base [--no-pr] <prompt|->`, `jobs [--state]`, `status <id>`, `logs <id> [-f]` (polls `ReadTranscript` every 1 s) and `cancel <id>`. `list` and `watch` stay as ADR-0015 plans them.
- **Pull only.** The server never connects to a Box (ADR-0016).

## Consequences

- Claim and lease share one transaction boundary. No broker.
- Inferred, not part of the design: throughput is bounded by Postgres.
- Idempotent submit and one lease per Job give no double runs on a healthy server.
- A Box that dies mid Job leaves a `LOST` row for a human, not a silent retry.
- A quiet agent cannot let the 120 s lease lapse, because the runner sends `ReportJob` at least every 30 s even with no output. Any `ReportJob` renews the lease.
- No retries, priority, `max_attempts`, `QueueDepth`, drain, KEDA seam or `job_attempts` table in this design. They stay out until picked up again.
- Job events do not enter the event stream, and `events.job_id` is not added.
- The `Watch` stream and `GetPreview` stay out of scope.

## Considered and rejected

- **Keep `CLAIMED`.** It existed to cover the gap before pueue started a task. With a child process the claim and the start are one step.
- **Lease renewal through the heartbeat.** Inferred, not part of the design: couples Job liveness to the 30 s heartbeat and a separate rpc. `ReportJob` already carries the data.
- **Streaming `ReportJob`.** ADR-0018 chose unary calls for the same reasons.
- **Automatic retry of `LOST` Jobs.** A rerun repeats side effects such as pushes.
