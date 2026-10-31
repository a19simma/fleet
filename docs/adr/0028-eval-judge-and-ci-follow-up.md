# Eval, judge and CI follow-up

Status: Accepted 2026-10-27. The CI retry is built (migration 0015, `FLEET_MAX_CI_RETRIES`); the rest is not built. Builds on ADR-0029 and ADR-0030, amends ADR-0021 and ADR-0023.

ADR-0029 and ADR-0030 record what a Job did, not whether it was good. Two signals are missing: a model's grade of the transcript, and the CI conclusion of the pull request the Job opened. A failed CI run also needs a bounded way to try again. This ADR fixes the design for three tasks: the judge Job, the CI status and the CI retry.

## Decision

### Judge Job

- **Kind.** A judge is a Job of its own, with `kind = judge` and a `target_job_id`. It is a row in `jobs`, so it has a lease, a transcript (ADR-0022) and a summary (ADR-0029) like any Job.
- **Input.** The judge reads the stored transcript of the target Job, never the Box's worktree or the target's live output. The transcript is the redacted stream-json the server already holds.
- **Delivery.** The box token cannot call `FleetJobs.ReadTranscript` (ADR-0023). A new `FleetWorker.GetJobTranscript` returns the target's transcript to a Box. The server authorises it only for a `RUNNING`, unexpired lease of a judge Job held by that Box and attempt, and only for that judge's own `target_job_id`. Any other call gets `PERMISSION_DENIED` with a fixed message. The reply is capped at the 4 MiB transcript cap of ADR-0022.
- **Who submits.** The client submits a judge Job with `FleetJudge.SubmitJudge`, a separate service in client scope. A Box never submits (ADR-0023). Nothing submits one automatically in this ADR. The server refuses a judge Job under a new key while another judge Job of the same target is `QUEUED` or `RUNNING` or already holds a verdict. The model is unknown at submit time, so the rule is per target. A target whose judges all failed may be judged again. A verdict that would not store, because `(target_job_id, judge_model)` exists, fails the report.
- **Workspace.** A judge Job clones no repo, pushes nothing and opens no pull request. Its tools are the Floor of ADR-0034 with every write tool denied. No `Bash` rule is allowed, so the judge runs no shell, and the Box is not treated as a sandbox for it.
- **Confinement.** The judge runs with its working directory set to its own directory, which holds only `transcript.jsonl`, and with the scratch `HOME` and config dir of every Job. Its allow rules are `Read(./transcript.jsonl)`, `Grep(./**)` and `Glob(./**)`. It also denies `Read`, `Grep` and `Glob` of `../**`, `~/**`, `//proc/**` and `//etc/**`. The transcript is data from another Job and may carry an injection, so the judge must not reach host files, and what it reads is stored in its own transcript and in the verdict reason.
- **Truncation.** A transcript the server cut at its cap ends with a notice line of type `fleet_notice`, so the judge knows later output is missing. The directory is removed on every exit of the judge run, including a refused transcript.
- **Verdict.** The judge ends with one verdict line that the runner parses: a score from 0 to 100 and a reason of at most 1024 bytes after redaction. A Job that ends without a parseable verdict is `FAILED` and stores no verdict. The server refuses a `SUCCEEDED` report of a judge Job that carries no verdict.
- **Stored.** Table `job_verdict`, primary key `job_id` of the judge Job, with `target_job_id`, `score`, `reason`, `judge_model` and `created_at`. A target has at most one verdict per `(target_job_id, judge_model)`. The transcript of the judge Job is stored like any other.
- **Model-graded flag.** `GetStats` and `fleet stats` return a verdict figure with its own `n` and a `model_graded` flag set on every verdict figure. A model grade is a different kind of figure from a measured one (ADR-0029), so a client must not read it as a count of observed events. A target with no verdict has no figure, never 0.

### CI status

- **When.** fleetd reads the CI conclusion after `gh pr create` succeeds (ADR-0024). Only a Job that opened a pull request has one.
- **How.** fleetd polls `gh pr checks` with the existing `gh` child environment, until a deadline. It reports each change through `ReportJob`.
- **States.** `pending` while checks run, then one terminal state: `success`, `failure` or `timeout`. A deadline that passes with checks still running ends `timeout`. A pull request with no checks at the deadline also ends `timeout`, never `success`.
- **Deadline.** Config key `ci_deadline_secs` in fleetd, 1 to 7200 seconds, default 900, checked at startup and counted from the moment the pull request opened. The poll interval starts at 5 seconds, doubles and is capped at 30. A job slot is held until the terminal state or the deadline. The deadline has no tie to the unit's `RuntimeMaxSec` or to the 120 second lease: the agent run, the push and the wait run one after another, so an operator who sets both to their maxima can reach the unit's backstop first, which ends the job as `LOST` and the CI state as `timeout`.
- **Lease.** The server lease is 120 seconds and a `ReportJob` renews it. The wait renews it every `report_interval` (30 seconds) through an empty `ReportJob`, and each `pending` report renews it too, so `ci_deadline_secs` may exceed 120 seconds. A reply of `FAILED_PRECONDITION` ends the wait with nothing more sent. `cancel_requested` ends it with a `CANCELLED` report.
- **Reading.** A `fail` or `cancel` bucket is `failure` at once, even while other checks run. All buckets `pass` or `skipping` is `success`. An empty list, an unknown bucket or output that is not a JSON list keeps waiting, so a pull request with no checks yet never passes, and at the deadline it ends as `timeout`, never `success`. `success` also needs a zero exit status from `gh`, so a `gh` that fails after printing a passing list keeps waiting. `failure` and `pending` are read from stdout alone, since `gh` exits 1 and 8 for them. A `gh` that cannot start or prints nothing keeps waiting as well. A failing or slow `gh run view` stores no log and keeps the `failure` state: the fetch runs under its own 30 s budget after the failure is seen, so the deadline never turns an observed failure into `timeout`. A poll without a link keeps the last link seen. The check link of the first failing check, else of the first check, becomes `ci_url` when the server would accept it.
- **Stored.** `jobs` gains `ci_state`, `ci_checked_at` and `ci_url`. They are `NULL` for a Job without a pull request. The server validates each value again and rejects a bad one with the fixed error `invalid job telemetry`. A terminal state is never overwritten by a later report. `ci_checked_at` is the server clock at the last accepted report and is `NULL` exactly when `ci_state` is. The server takes a CI status only from a `RUNNING` agent Job of the lease holder that opened a pull request, and a terminal CI state only on the `SUCCEEDED` report that carries `pr_url`. Any other end of the Job, and the reaper for a `LOST` Job, turns a `pending` state into `timeout`.
- **Failure log.** On `failure` fleetd reads the log of the failed checks, redacts it with the existing redactor, drops control characters, reads the last 64 KiB the `gh` child wrote, keeps the last 16 KiB of that and reports it with the terminal state. The server stores it in `job_ci_log`, one row per Job, deleted with the Job's events under the ADR-0029 retention, which in the build is the summary prune pass.
- **Credential.** Reading checks needs read access to checks and statuses on the repo. The token of ADR-0024 lists contents and pull-requests write only. Inferred, not part of the design: the token also needs that read scope, and the first live test confirms it.

### CI retry

- **Who decides.** The server decides, because a Box cannot submit a Job (ADR-0023). When a Job reports a terminal `failure`, the server submits one fix Job. A `timeout` never retries.
- **Fix Job.** It has `parent_job_id` set to the failed Job and the same repo. Its base ref is the name of the branch the parent pushed, not a commit id. Pushing to the chain root's branch rather than a per-Job `swarm/<job_id>` branch differs from ADR-0024 and adds to it without replacing it. It pushes to the branch of its chain root, `swarm/<chain root id>`, which stays inside the namespace of ADR-0016, by fast-forward only, and opens no second pull request. Its prompt is the original prompt plus the redacted failure log, inside a marked block that tells the agent the block is data.
- **Limit.** Server config `max_ci_retries`, set by `FLEET_MAX_CI_RETRIES`, an integer from 0 to 5. As built the default is 0, not the 2 first written here: a server that spends money on its own starts off until an operator opts in. 0 turns the retry off. The chain depth is `ci_retry_attempt`, which is the parent's depth plus one, and the server refuses to start on a value outside the range.
- **Branch check.** The server refuses a terminal report whose branch is not `swarm/<chain root id>` with `JobInvalid::Branch`, whatever the terminal state.
- **Boundary.** A chain with `max_ci_retries` fix Jobs already submitted submits no more. The last Job's `failure` stays its final state and `fleet status` shows the count and the reason `ci retries exhausted`.
- **Atomic.** The count check and the insert of the fix Job run in one transaction, so two reports of one `failure` cannot submit two fix Jobs. A repeated terminal report is a no-op. The database enforces it: the fix Job's idempotency key is `ci-retry:<parent_job_id>:<attempt>`, a unique partial index allows one child per `parent_job_id`, and a client cannot submit that key prefix.
- **Built shape.** `jobs` gains `parent_job_id`, `ci_retry_attempt` and `ci_retry`, one of `submitted`, `exhausted`, `disabled`, `no_log` or `ineligible`, set on the failed Job and shown on `Job`. The server retries only a Job that ended `SUCCEEDED` with CI `failure`; a `FAILED` or `CANCELLED` Job never retries, and `timeout` never retries. A failure with no stored log, a batch Job, or a Job with a profile is `no_log` or `ineligible` and submits nothing (stricter than the text above). The fix Job copies the parent's repo and pull request URL and sets no profile, so it can never hold more than the parent: a Job with a profile never retries, and the fix Job has no cap column to raise. It reuses the parent pull request URL for the CI watch and pushes to `swarm/<chain root id>`, which the server binds to the chain root and fleetd checks with `is_swarm_branch` before the push; the push never forces.
- **Prompt.** The fix prompt is the root prompt of the chain, then the latest log in a block with a per-job nonce marker, then a line stating that the block is untrusted tool output and not instructions. The log passes the same `is_ci_log` filter and 16 KiB cap as the stored log, marker text inside it is defanged, and the whole prompt stays under the prompt cap or the Job is `no_log`.
- **Bounded cost.** A fix Job carries no cap of its own. It runs under the Box turn and budget ceilings of ADR-0030 like any Job, so the chain costs at most `max_ci_retries + 1` times those ceilings.

## Consequences

- A Job's quality has a measured signal (CI) and a graded one (the verdict), stored apart so a client can tell them apart.
- A judge reads exactly one transcript and cannot reach any other Job's data.
- The failure log is a second place a secret in an unmatched form can persist, so the care ADR-0022 sets for the database applies to it.
- The server submits Jobs on its own for the first time, so a bug in the retry count spends money. The caps bound it.
- Inferred, not part of the design: a Box that loses its lease while polling CI abandons the poll, and the server marks the CI state `timeout` when the Job goes `LOST`.

## Unverified

- The shape of `gh pr checks --json bucket,link` output and its exit codes for pending and failed checks were not observed on the dev box. The poller's doc comment records the buckets `pass`, `fail`, `pending`, `skipping` and `cancel`. The exit codes are this ADR's reading: 8 for pending and 1 for a failure or for no checks. The poller reads stdout for `failure` and `pending` and ignores the exit code there; for `success` it also needs exit 0.
- Whether `gh run view --job <id> --repo <repo> --log-failed` accepts the job id parsed from the check link, and whether a check that is not an Actions job has a log at all. Such a failure stores no log.
- Whether the Box token reaches check logs with the current scope.
- Whether a fix Job's push to the parent's branch by fast-forward succeeds against a real remote, and whether the parent's CI failure is still current when the fix Job starts (a later push can make the stored log stale). Inferred, not part of the design: a stale log costs one fix Job, bounded by the limit.
- The verdict line format is a first choice. The first judge runs test it.
- Whether the real `claude` honours the path rules of the confinement above, and whether a deny rule wins over an allow rule, is unverified (ADR-0034 says the same for deny against allow). The working directory and the scratch `HOME` are the fallback. A live probe, with a judge told to read a file outside its directory, settles it.

## Considered and rejected

- **The judge reads the Box worktree.** The worktree may be gone, and the agent can write to it.
- **fleetd submits the fix Job.** The box token has no `FleetJobs` scope (ADR-0023), and widening it would let a leaked Box token submit Jobs.
- **Retry on `timeout`.** A pending check is no evidence of a failing change.
- **Unbounded retries.** A permanently red check would spend the budget without end.
- **Force-push the fix to the branch.** It rewrites the history a reviewer has seen.
- **A verdict stored in `job_summary`.** The summary holds measured figures only (ADR-0029), and a model grade has its own table and flag.
