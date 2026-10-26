# Fleet

Fleet runs coding-agent Jobs on Boxes and records what each Job did. This file defines the terms used by the telemetry and metrics ADRs (0029, 0030).

## Language

**Job Event**:
One row of `job_event`: a tool call, denial, API retry, phase change or stuck signal of a Job, keyed by `(job_id, seq)`.
_Avoid_: log line, trace span

**Job Summary**:
The one `job_summary` row per Job holding its figures, its `complete` flag and its `missing` list.
_Avoid_: report, stats row

**Incomplete**:
A **Job Summary** with `complete` false or a non-empty `missing` list, where each unobserved figure is `NULL`, never 0.
_Avoid_: partial, zero-filled

**Stuck rule**:
One of `repeat_action_observation`, `repeat_error`, `alternating` and `monologue`, checked by a detector that only records the first rule to fire and changes nothing about the Job (shadow mode).
_Avoid_: loop detector, watchdog

**Bundle channel**:
Planned, not built: a release channel for the agent config bundle a Box loads, meant for a canary rollout of config changes.
_Avoid_: config version

**Egress proxy**:
Planned, not built: a proxy that would restrict the hosts a Job's agent can reach.
_Avoid_: firewall

**Agent unit**:
The systemd unit `fleet-agent@<job id>.service` that runs one Job's agent under the **Job uid** when `agent_launcher` is `systemd`.
_Avoid_: job service, runner unit

**Job uid**:
The user `fleet-job` that an **Agent unit** runs as, in the group `fleet-work`, apart from the `fleetd` uid that holds the secrets.
_Avoid_: agent user, sandbox user

**Launcher**:
The seam in fleetd that starts an agent, either `direct` as a child process or `systemd` as an **Agent unit**.
_Avoid_: spawner, executor

**Hook socket**:
The unix socket `hook_socket` that serves only `/healthz` and `/hook/<event>`, in its own directory so the **Job uid** can reach it.
_Avoid_: main socket

**Run dir**:
The directory `/run/fleet/<job id>/` holding a Job's `env`, `spec.json` and `stdout` FIFO for an **Agent unit**.
_Avoid_: job dir, workspace

**Fixture**:
Planned, not built: a recorded Job input with an expected outcome, meant to run through `fleet eval run`.
_Avoid_: test case

## Relationships

- A **Job** has many **Job Events** and at most one **Job Summary**.
- A **Job Summary** records at most one **Stuck rule**, the first that fired.
- An **Incomplete** **Job Summary** lists what it never observed in `missing`.

## Flagged ambiguities

- "bundle", "egress" and "fixture" appear in planning notes only. No product code defines them, and ADR-0030 lists them as out of scope.
