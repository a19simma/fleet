# Job runner in fleetd

Status: Accepted. The workspace, agent runner, push and pull request step, poller and gRPC reporter are built and run by the daemon while `FLEET_SERVER_URL` and `FLEET_TOKEN` are set. Cancel and lease-lost handling are built in the runner. Supersedes the pueue and `fleet-job` parts of ADR-0016 and the "No git" rule of ADR-0011.

ADR-0016 sketched Jobs as pueue tasks started by `fleet-job`. pueue has no Kubernetes story, adds a callback and poll layer, and `fleet-job` does not exist. The goal is a Job that runs on a Box, shows up in the server and ends on a pushed branch with a pull request.

## Decision

fleetd runs each Job itself, as a child process in a git worktree. There is no pueue group and no `fleet-job`.

- **Poll.** A poller task starts when `FLEET_SERVER_URL` is set. While no Job is running it calls `ClaimJob` every 5 s with jitter. Errors back off with the forwarder's 1 s to 5 min full-jitter schedule. Concurrency is 1.
- **Workspace.** A bare mirror at `~/jobs/.cache/<hash(repo)>.git`, then `git fetch` and `git worktree add -b swarm/<id> ~/jobs/<id> origin/<base>`. The Job names its own `repo` and `base_ref`.
- **Run.** `claude -p <prompt> --output-format stream-json --verbose`, with stdin from `/dev/null`, cwd the worktree and env `FLEET_JOB_ID` and `SWARM_BOX=1`. The child runs in its own process group. Permission flags come from fleetd config (ADR-0024).
- **Stream.** fleetd reads stdout lines, redacts each with the existing redactor and flushes every 2 s or 64 KiB through `ReportJob` (ADR-0021). `progress` is the last assistant text. The stream-json stdout is the transcript, so fleetd does not parse Claude's session `.jsonl`.
- **Finish.** On exit 0 with commits ahead of the base, fleetd runs `git push origin swarm/<id>` (credential through `GIT_ASKPASS=fleetd askpass`) from a throwaway bare repo, not the agent's worktree, then `gh pr create --repo <repo> --head <branch> --base <base> --title <tip commit subject, capped> --body "Fleet job <id>"` unless the job sets `open_pr` off, with a 300 s finish timeout, and sends one terminal `SUCCEEDED` report carrying the branch and `pr_url`. Exit 0 with no commits is one terminal `SUCCEEDED` report with no branch and no `pr_url`. A nonzero exit, a push failure or a `gh` failure is `FAILED` with phase `agent`; the `error` string distinguishes "git push failed" from "pull request could not be opened".
- **Timeout.** The default hard timeout is 30 min. fleetd then kills the process group and reports `FAILED`.
- **Cancel.** The `ReportJob` reply carries `cancel_requested`. fleetd sends SIGTERM to the process group, waits 10 s, then sends SIGKILL and reports `CANCELLED`.
- **Server unreachable mid run.** The child keeps running and chunks buffer in memory, bounded at about 8 MiB. If the lease lapses first, the server marks the Job `LOST`. The next `ReportJob` returns `FAILED_PRECONDITION`, and fleetd kills the child and discards the rest. The branch may already be pushed, so a human checks.
- **fleetd or Box death.** The lease lapses and the Job goes `LOST`. A human resubmits.
- **Push namespace.** fleetd pushes only `swarm/<job_id>`, only after the agent exits. The agent never pushes. This is the only git write fleetd performs.
- **Where it runs.** fleetd runs on Boxes. Kubernetes runs the server only.

## Consequences

- No pueue dependency for Jobs and no Kubernetes blocker.
- The `pueue status` view of a running Job is gone. `fleet status` and `fleet logs` replace it.
- ADR-0011's "No git" rule changes: once the runner is wired into the daemon, fleetd pushes `swarm/<job_id>` and holds a GitHub credential (ADR-0024).
- `fleetd.service` needs `ReadWritePaths` for `~/jobs`, because `ProtectHome=read-only` otherwise blocks the worktrees.
- Concurrency is 1. A Box runs one Job at a time.
- Job cost stays deferred. The stream-json `result` object carries it, and v1 does not forward it.
- After the terminal report fleetd removes the job's worktree and its `.finish-<id>` scratch dir and keeps the bare mirror. A removal failure is logged by job id only. A killed fleetd still leaves a worktree behind, and no cleanup of old worktrees is specified (inferred, not part of the design).

## Considered and rejected

- **Keep pueue and `fleet-job`.** More moving parts, an unbuilt tool and a callback layer that needs injection-safe handling.
- **fleetd on Kubernetes.** Needs an image with claude, git and gh, a writable workspace and credentials in a Secret. A new design, out of scope.
- **Workmux windows for Jobs.** Inferred, not part of the design: adds tmux state to a headless run.
- **Parsing Claude's session `.jsonl` for the transcript.** The entry format is internal and changes between versions (ADR-0011).
