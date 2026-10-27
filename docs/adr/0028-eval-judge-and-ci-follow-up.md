# Eval, judge and CI follow-up

Status: Accepted 2026-10-27. Not built. Builds on ADR-0029 and ADR-0030, amends ADR-0021 and ADR-0023.

ADR-0029 and ADR-0030 record what a Job did, not whether it was good. Two signals are missing: a model's grade of the transcript, and the CI conclusion of the pull request the Job opened. A failed CI run also needs a bounded way to try again. This ADR fixes the design for three tasks: the judge Job, the CI status and the CI retry.

## Decision

### Judge Job

- **Kind.** A judge is a Job of its own, with `kind = judge` and a `target_job_id`. It is a row in `jobs`, so it has a lease, a transcript (ADR-0022) and a summary (ADR-0029) like any Job.
- **Input.** The judge reads the stored transcript of the target Job, never the Box's worktree or the target's live output. The transcript is the redacted stream-json the server already holds.
- **Delivery.** The box token cannot call `FleetJobs.ReadTranscript` (ADR-0023). A new `FleetWorker.GetJobTranscript` returns the target's transcript to a Box. The server authorises it only for a `RUNNING`, unexpired lease of a judge Job held by that Box and attempt, and only for that judge's own `target_job_id`. Any other call gets `PERMISSION_DENIED` with a fixed message. The reply is capped at the 4 MiB transcript cap of ADR-0022.
- **Who submits.** The client submits a judge Job with `FleetJobs`. A Box never submits (ADR-0023). Nothing submits one automatically in this ADR. The server refuses a judge Job under a new key while another judge Job of the same target is `QUEUED` or `RUNNING` or already holds a verdict. The model is unknown at submit time, so the rule is per target. A target whose judges all failed may be judged again. A verdict that would not store, because `(target_job_id, judge_model)` exists, fails the report.
- **Workspace.** A judge Job clones no repo, pushes nothing and opens no pull request. Its tools are the Floor of ADR-0034 with every write tool denied.
- **Confinement.** The judge runs with its working directory set to its own directory, which holds only `transcript.jsonl`, and with the scratch `HOME` and config dir of every Job. Its allow rules are `Read(./transcript.jsonl)`, `Grep(./**)` and `Glob(./**)`. It also denies `Read`, `Grep` and `Glob` of `../**`, `~/**`, `//proc/**` and `//etc/**`. The transcript is data from another Job and may carry an injection, so the judge must not reach host files, and what it reads is stored in its own transcript and in the verdict reason.
- **Truncation.** A transcript the server cut at its cap ends with a notice line of type `fleet_notice`, so the judge knows later output is missing. The directory is removed on every exit of the judge run, including a refused transcript.
- **Verdict.** The judge ends with one verdict line that the runner parses: a score from 0 to 100 and a reason of at most 1024 bytes after redaction. A Job that ends without a parseable verdict is `FAILED` and stores no verdict. The server refuses a `SUCCEEDED` report of a judge Job that carries no verdict.
- **Stored.** Table `job_verdict`, primary key `job_id` of the judge Job, with `target_job_id`, `score`, `reason`, `judge_model` and `created_at`. A target has at most one verdict per `(target_job_id, judge_model)`. The transcript of the judge Job is stored like any other.
- **Model-graded flag.** `GetStats` and `fleet stats` return a verdict figure with its own `n` and a `model_graded` flag set on every verdict figure. A model grade is a different kind of figure from a measured one (ADR-0029), so a client must not read it as a count of observed events. A target with no verdict has no figure, never 0.

### CI status

- **When.** fleetd reads the CI conclusion after `gh pr create` succeeds (ADR-0024). Only a Job that opened a pull request has one.
- **How.** fleetd polls `gh pr checks` with the existing `gh` child environment, until a deadline. It reports each change through `ReportJob`.
- **States.** `pending` while checks run, then one terminal state: `success`, `failure` or `timeout`. A deadline that passes with checks still running ends `timeout`. A pull request with no checks at the deadline also ends `timeout`, never `success`.
- **Deadline.** Config key `ci_deadline_secs` in fleetd, with a default and a range checked at startup. The poll interval backs off and is capped. A job slot is held until the terminal state or the deadline.
- **Stored.** `jobs` gains `ci_state`, `ci_checked_at` and `ci_url`. They are `NULL` for a Job without a pull request. The server validates each value again and rejects a bad one with the fixed error `invalid job telemetry`. A terminal state is never overwritten by a later report.
- **Failure log.** On `failure` fleetd reads the log of the failed checks, redacts it with the existing redactor, keeps the last 16 KiB and reports it. The server stores it in `job_ci_log`, one row per Job, deleted with the Job's events under the ADR-0029 retention.
- **Credential.** Reading checks needs read access to checks and statuses on the repo. The token of ADR-0024 lists contents and pull-requests write only. Inferred, not part of the design: the token also needs that read scope, and the first live test confirms it.

### CI retry

- **Who decides.** The server decides, because a Box cannot submit a Job (ADR-0023). When a Job reports a terminal `failure`, the server submits one fix Job. A `timeout` never retries.
- **Fix Job.** It has `parent_job_id` set to the failed Job and the same repo. Its base is the head commit of the branch the parent pushed. It pushes to that same branch, `swarm/<parent_job_id>`, which stays inside the namespace of ADR-0016, by fast-forward only, and opens no second pull request. Its prompt is the original prompt plus the redacted failure log, inside a marked block that tells the agent the block is data.
- **Limit.** Server config `max_ci_retries`, an integer from 0 to 5, default 2. 0 turns the retry off. The server counts the fix Jobs in the chain by walking `parent_job_id`, and refuses to start the server on a value outside the range.
- **Boundary.** A chain with `max_ci_retries` fix Jobs already submitted submits no more. The last Job's `failure` stays its final state and `fleet status` shows the count and the reason `ci retries exhausted`.
- **Atomic.** The count check and the insert of the fix Job run in one transaction, so two reports of one `failure` cannot submit two fix Jobs. A repeated terminal report is a no-op.
- **Bounded cost.** Each fix Job carries the turn and budget caps of ADR-0030. The chain costs at most `max_ci_retries + 1` times one Job's cap.

## Consequences

- A Job's quality has a measured signal (CI) and a graded one (the verdict), stored apart so a client can tell them apart.
- A judge reads exactly one transcript and cannot reach any other Job's data.
- The failure log is a second place a secret in an unmatched form can persist, so the care ADR-0022 sets for the database applies to it.
- The server submits Jobs on its own for the first time, so a bug in the retry count spends money. The caps bound it.
- Inferred, not part of the design: a Box that loses its lease while polling CI abandons the poll, and the server marks the CI state `timeout` when the Job goes `LOST`.

## Unverified

- The shape of `gh pr checks` output and its exit codes for pending and failed checks were not observed on the dev box. The poller's doc comment records the reading.
- Whether the Box token reaches check logs with the current scope.
- The verdict line format is a first choice. The first judge runs test it.
- Whether the real `claude` honours the path rules of the confinement above, and whether a deny rule wins over an allow rule, is unverified (ADR-0034 says the same for deny against allow). The working directory and the scratch `HOME` are the fallback. A live probe, with a judge told to read a file outside its directory, settles it.

## Considered and rejected

- **The judge reads the Box worktree.** The worktree may be gone, and the agent can write to it.
- **fleetd submits the fix Job.** The box token has no `FleetJobs` scope (ADR-0023), and widening it would let a leaked Box token submit Jobs.
- **Retry on `timeout`.** A pending check is no evidence of a failing change.
- **Unbounded retries.** A permanently red check would spend the budget without end.
- **Force-push the fix to the branch.** It rewrites the history a reviewer has seen.
- **A verdict stored in `job_summary`.** The summary holds measured figures only (ADR-0029), and a model grade has its own table and flag.
