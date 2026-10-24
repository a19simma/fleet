# Job queue, claim and lease

Status: Accepted. The pueue runner, `CLAIMED` state, heartbeat lease and `retry_on_lost` are superseded by ADR-0020 (built as library code, daemon wiring pending) and ADR-0021 (planned).

A KEDA work queue will later feed Jobs, each a prompt. The first design choices fix how a Box gets work and how a lost Box is told from a slow one.

## Decision

The KEDA work is parked. This ADR is a sketch of the seam and adds no design past it.

The queue lives in the Fleet server's Postgres. KEDA is driven through the server, and fleetd on the Box pulls and claims Jobs and starts them. Boxes pull work with a lease.

- **States.** `QUEUED`, `CLAIMED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `LOST`.
- **Submit.** `FleetJobs.SubmitJob` writes a `QUEUED` row. The caller sets an idempotency key so a retry does not duplicate.
- **Claim.** An idle fleetd (a free parallel slot in the dedicated `fleet` pueue group, not draining) calls `ClaimJob`. The server takes the head of `priority desc, created_at` with `FOR UPDATE SKIP LOCKED`, sets `CLAIMED`, the Box, an attempt number and a 120 s lease.
- **Run.** fleetd gives the Job to `fleet-job`, which makes the worktree under `~/jobs`, exports `FLEET_JOB_ID` and `SWARM_BOX=1`, and adds the pueue task. The result branch is `swarm/<job_id>`, the only branch namespace a Box may push.
- **Lease.** The heartbeat renews the lease for every id in `running_job_ids`.
- **Expiry.** A `CLAIMED` Job returns to `QUEUED`. A `RUNNING` Job becomes `LOST` and is not retried unless the Job sets `retry_on_lost`, since it may have pushed commits.
- **Pull only.** The server never connects to a Box. A Box needs no inbound port, and a sleeping or rebooting Box claims later.
- **Scaler read.** Queue depth is `count(*) where state = 'QUEUED'`, readable by a KEDA PostgreSQL scaler and by `FleetJobs.QueueDepth` for an external scaler.
- **Scaling unchanged.** KEDA scales Kubernetes workloads and cannot create virtual machines. Box count stays a config number plus apply, and scale-down stays manual. What acts on queue depth is parked (plan, decision 5).

## Phase 0 results

T5, T6, T9 and T10 touch this seam. They contradict one implicit assumption and fix several details.

- **Free slot.** The sketch assumed a free pueue slot. The default group runs one job at a time and queued unrelated work behind a running job (T5, T7). Fleet Jobs run in their own pueue group with its own parallel setting, and `free_slots` is that group's free parallelism.
- **`RUNNING` transition.** pueue has no started callback, only a finished one (T6). `pueue.task_started` comes from `fleet-job` or the 5 s `pueue status --json` poll.
- **Finish and kill.** The callback fires for success, failure, `pueue kill` (`Killed`, exit code `None`) and an external kill (`Failed`, exit 137), 0.2 to 0.3 s after the end. Any of these maps to `FAILED`, not `LOST`, because the Box is alive and reported it. `LOST` stays for a lease that expires with no report.
- **Callback input.** The callback passes only the task id and group. `{{ command }}` and `{{ output }}` inject shell text (T6).
- **`fleet-job`.** It redirects stdin of `claude -p` from `/dev/null` (T10), passes `--verbose` with `stream-json` (T1), and reads `pueue status --json` to the end (T9).
- **Cost.** `job.result` takes cost from the `result` object. The transcript cannot supply it (T10).

## Decisions (2026-10-24)

- Accepted 2026-10-24 as a parked sketch. Nothing in it is built in v1.
- Job cost is deferred. v1 has no `fleet-job`, so no cost reaches the server. The jobs run on a subscription, not the API.

## Consequences

- No broker. The queue, history and lease share one transaction boundary.
- Throughput is bounded by Postgres, ample for Jobs that run minutes.
- A Box that dies mid Job leaves a `LOST` row for a human, not a silent retry.
- Idempotent submit and one lease per Job give no double runs on a healthy server.
- The claim path adds a second reason to keep the server up.

## Amendments

Accepted 2026-10-24: ADR-0020 and ADR-0021 build this seam and supersede the parts below. The runner (ADR-0020) is built as library code, daemon wiring pending. The lease and protocol parts (ADR-0021) are planned, not built.

- **Runner.** There is no `fleet-job`, no pueue group and no `free_slots`. fleetd runs the Job as a child process in a git worktree (ADR-0020). The pueue paragraphs of Phase 0 results no longer apply to Jobs.
- **States.** `CLAIMED` is dropped. `ClaimJob` moves a Job from `QUEUED` straight to `RUNNING` and sets the Box, the attempt and the lease. The `CLAIMED` expiry rule (return to `QUEUED`) goes with it.
- **Lease.** The lease is 120 s and renews through `ReportJob`, not the heartbeat (`running_job_ids`). The runner sends `ReportJob` at least every 30 s even when the agent is quiet (ADR-0021). A reaper every 15 s moves expired `RUNNING` rows to `LOST`.
- **Retry.** `retry_on_lost` is cut. A `LOST` Job is never retried, and a human resubmits. There is no `job_attempts` table, priority or `max_attempts`, and the head of the queue is the oldest `created_at`.
- **Services.** Claim is on `FleetWorker`, not `FleetIngest` (ADR-0021).
- **Scaler and drain.** `QueueDepth`, drain and the KEDA read stay parked.
- **Parked status.** "Nothing in it is built in v1" still describes v1. The Job system follows v1.

## Considered and rejected

- **An external broker (SQS, NATS JetStream).** A second stateful service and a second source of truth for Job status.
- **Server pushes work to Boxes.** Needs an inbound path to each Box and a reachable-Box check before dispatch.
- **Automatic retry of `LOST` Jobs.** May rerun side effects such as pushes.
