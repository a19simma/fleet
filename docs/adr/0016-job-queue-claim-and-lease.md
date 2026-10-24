# Job queue, claim and lease

Status: Accepted. The pueue runner, `CLAIMED` state, heartbeat lease and `retry_on_lost` are superseded by ADR-0020 (built, run by the daemon) and ADR-0021 (built in the server and the daemon).

A KEDA work queue will later feed Jobs, each a prompt. The first design choices fix how a Box gets work and how a lost Box is told from a slow one.

## Decision

The KEDA work is parked. This ADR is a sketch of the seam and adds no design past it.

The queue lives in the Fleet server's Postgres. KEDA is driven through the server, and fleetd on the Box pulls and claims Jobs and starts them. Boxes pull work with a lease.

- **States.** `QUEUED`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`, `LOST`. There is no `CLAIMED` state: a claim goes straight to `RUNNING`.
- **Submit.** `FleetJobs.SubmitJob` writes a `QUEUED` row. The caller sets an idempotency key so a retry does not duplicate.
- **Claim.** An idle fleetd calls `ClaimJob`. The server takes the head of the queue, ordered by `created_at`, with `FOR UPDATE SKIP LOCKED` and in the same statement sets `RUNNING`, the Box, the next attempt number and a 120 s lease. There is no priority.
- **Run.** The server side ends at the claim. Inferred, not part of the design: fleetd starts the run on the Box, exports `FLEET_JOB_ID` and `SWARM_BOX=1`, and works in a worktree. `claude -p` runs with stdin from `/dev/null`, because an open stdin pipe blocks it. The result branch is `swarm/<job_id>`, the only branch namespace a Box may push.
- **Lease.** Each `ReportJob` from the holding Box renews the lease by 120 s.
- **Expiry.** A reaper in the server runs every 15 s. It moves each `RUNNING` Job with an expired lease to `LOST`. A `LOST` Job is never retried, since it may have pushed commits. A report that arrives after the reap gets `FAILED_PRECONDITION`.
- **Pull only.** The server never connects to a Box. A Box needs no inbound port, and a sleeping or rebooting Box claims later.
- **Scaler read.** Queue depth is `count(*) where state = 'QUEUED'`, readable by a KEDA PostgreSQL scaler and by `FleetJobs.QueueDepth` for an external scaler.
- **Scaling unchanged.** KEDA scales Kubernetes workloads and cannot create virtual machines. Box count stays a config number plus apply, and scale-down stays manual. What acts on queue depth is parked (plan, decision 5).

## Decisions (2026-10-24)

- Accepted 2026-10-24 as a sketch. The v1 job design builds the claim and lease above.
- Cut: pueue, `fleet-job`, the `CLAIMED` state, `job_attempts`, priority, `max_attempts`, `retry_on_lost` and `fleet retry`.
- Job cost is deferred. v1 has no `fleet-job`, so no cost reaches the server. The jobs run on a subscription, not the API.

## Consequences

- No broker. The queue, history and lease share one transaction boundary.
- Throughput is bounded by Postgres, ample for Jobs that run minutes.
- A Box that dies mid Job leaves a `LOST` row for a human, not a silent retry.
- Idempotent submit and one lease per Job give no double runs on a healthy server.
- The claim path adds a second reason to keep the server up.

## Amendments

Accepted 2026-10-24: ADR-0020 and ADR-0021 build this seam and supersede the parts below. The runner (ADR-0020) is built and run by the daemon. The lease and protocol parts (ADR-0021) are built in the server and the daemon.

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
