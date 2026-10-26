# Agent isolation

Status: Accepted 2026-10-26. P1 is built behind `agent_launcher = "systemd"` and cut over live on the first Box; P2 and P3 are not built. Supersedes the Known limit paragraph of ADR-0024. Amends the credential and mirror-hardening sections of ADR-0024.

Supersedes: the "Known limit" paragraph of ADR-0024.
Amends: the "Credential", "Who sees it", "Mirror hardening" and "Fetch credential" sections of ADR-0024, and the unit and hook sections of ADR-0011.

The agent runs as the uid of fleetd (`User=agent` in `deploy/fleetd.service`). `claude` is launched with `--dangerously-skip-permissions` on a disposable Box (ADR-0024) and runs arbitrary shell. ADR-0024 records the result: the agent can read `/etc/swarm/secrets.env`, the fleetd environment through `/proc/<pid>/environ`, the mirror and the Box's other files. The env allowlist in `runner.rs` (`STRIPPED_ENV`, `AGENT_ENV`) only cleans the child's own env block. A prompt-injected or hostile Job therefore holds `GH_TOKEN`, `FLEET_TOKEN` and the Claude token, can rewrite the shared mirror and can reach any host and any local port, including the fleetd hook port.

## Decision

Isolate the agent in phases with systemd and a second uid. Each phase ships alone and each removes one exposure. A microVM is held back until the prompt sources are untrusted.

### P1: uid split, no network change

- **Users.** `fleetd` owns the daemon and `/etc/swarm/secrets.env` (mode 0600). `fleet-job` runs agents.
- **Unit.** A template unit `fleet-agent@.service` with `User=fleet-job`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ProtectProc=invisible`, `ProcSubset=pid`, an empty `CapabilityBoundingSet=`, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` (plus `AF_NETLINK` only when a tool needs it), `MemoryMax`, `TasksMax` and `ReadWritePaths` set to the per-job directory. `HOME` and `CLAUDE_CONFIG_DIR` point inside the per-job directory.
- **Launch.** A polkit rule lets user `fleetd` start and stop units matching `fleet-agent@*` and nothing else. fleetd writes a per-job `EnvironmentFile` under `/run/fleet/<id>/` and starts `fleet-agent@<id>.service`. The agent stdout goes to a file or FIFO that fleetd tails, and the redactor and reporter work on that stream as today.
- **Cancel.** `systemctl stop fleet-agent@<id>.service`, which kills the whole cgroup. This replaces the process-group SIGTERM, 10 s wait and SIGKILL of ADR-0020.
- **No `DynamicUser=`.** File ownership across fleetd restarts needs a stable uid.
- **Binding constraints from the live run.** Each came from a failed probe (see Verification).
  1. The job directory lives outside `/var/tmp`, for example `/var/lib/fleet/jobs` or `StateDirectory=`. `PrivateTmp=yes` makes a `ReadWritePaths=/var/tmp/...` entry fail with status 226/NAMESPACE.
  2. The template allows `AF_INET` and `AF_INET6`. `RestrictAddressFamilies=AF_UNIX` alone blocks every `socket()`, loopback included. In P2 the network namespace provides the isolation, so the family list stays open.
  3. P1 requires a system-wide Claude install that `fleet-job` can execute. Today the binary is a mise shim under `~agent` with mode 0700, so the job uid cannot run it.
- **Hook client trust check.** Built in P1-2. The hook client uses `hook_socket` when set, and accepts the socket only when its owner is `hook_socket_uid` (default the caller's effective uid), the parent directory belongs to root or that uid with no group or other write bit, and the connected peer's `SO_PEERCRED` uid equals that uid. Otherwise it counts as a failed connect and falls back to `127.0.0.1:7071`. The socket directory must be reachable by `fleet-job`, and `/run/fleetd` is mode 0700, so the hook socket lives in `/run/fleet/hook`, mode 0750 `fleetd:fleet-work`, with `hook_socket_uid` set to the uid of `fleetd`.

### P2: network namespace and egress proxy

- **Namespace.** `PrivateNetwork=yes` in the template.
- **Launcher.** `fleetd agent-exec` runs inside the unit. It listens on `127.0.0.1:PORT` in the private namespace and forwards each connection to the unix socket `/run/fleet/proxy.sock`, then execs `claude`. `HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1` point at that port. `runner.rs` already passes `HTTPS_PROXY` and `HTTP_PROXY` through `AGENT_ENV`. `NODE_USE_ENV_PROXY` appears nowhere in the crates (checked by search).
- **Proxy.** Inside fleetd, `CONNECT` only, with a hostname allowlist: `api.anthropic.com` plus per-bundle additions such as crates.io, npm and pypi hosts. The proxy resolves names itself and refuses loopback, RFC1918, link-local and tailnet address ranges.
- **Accepted risk.** Domain fronting through an allowed host.
- **Hooks.** The hook port `127.0.0.1:7071` is unreachable from the namespace. `deploy/managed-settings.json` sets `PostToolUse` and `PostToolUseFailure` and `SessionStart` to `command` hooks already. `UserPromptSubmit`, `Stop`, `SessionEnd` and `Notification` are `http` hooks to `127.0.0.1:7071`. P2 switches those four to `command` hooks (`fleetd hook X`) that reach fleetd over a bind-mounted unix socket.

### P3: workspace and limits

- **Clone.** Replace the shared worktree with `git clone --reference <mirror>` (alternates) into a directory owned by the job uid. The mirror is read-only to the job uid.
- **Publish.** fleetd fetches `swarm/<job_id>` from the job directory under its own uid, with hooks and fsmonitor off and `GIT_ALLOW_PROTOCOL=file`, then pushes from the mirror. The push and `gh pr create` steps of ADR-0020 and ADR-0024 are unchanged in what they publish.
- **Retires** the mirror-hardening window of ADR-0024: the agent no longer writes the mirror, so the `commondir` and `config.worktree` deletion, the config rewrite and the lock cleanup stop being needed once P3 ships. The pins on the workspace git calls stay as defense in depth.
- **Limits.** `MemoryMax`, `TasksMax`, `CPUQuota` and a job-directory quota.

### P4: optional inner sandbox

bwrap or Landlock inside the unit. bwrap is not installed on the test box and unprivileged user namespaces work there. Not scheduled.

### MicroVM

Option (iv), a microVM per Job, is adopted only if untrusted prompt sources appear (for example Jobs from a public issue tracker). `/dev/kvm` and AMD-V exist on the test box, so the path is open.

## As built in P1

- **Launcher seam.** `agent_launcher` is `direct` (default) or `systemd`. `systemd` selects `SystemdLauncher`, which calls `systemctl` by the absolute path in `systemctl_path` with an argv array and an empty environment.
- **Run dir.** Per job, `/run/fleet/<job id>/`, mode 0750 with the group in `job_group`. It holds `env` (mode 0600, the `EnvironmentFile`), `spec.json` (`argv` and `cwd` only, mode 0640 with the job group) and `stdout` (a FIFO, mode 0660 with the job group). The environment never goes into `spec.json`.
- **Unit contract.** `fleet-agent@<id>.service` loads `env`, writes stdout to the FIFO with `StandardOutput=file:/run/fleet/%i/stdout` and runs `fleetd agent-exec <id>`. `agent-exec` reads `spec.json`, checks the id, changes into `cwd` and execs the agent. It exits 2 on a missing, mismatched or empty spec. The launcher starts the unit with `--no-block`, polls `systemctl show`, then calls `reset-failed` and removes the run dir.
- **Cancel.** `systemctl kill` and `stop` on the unit, which kill the control group. `RuntimeMaxSec=2h` bounds a unit the launcher loses track of.
- **Files.** `deploy/fleet-agent@.service`, `deploy/fleetd-systemd.service`, `deploy/sysusers.d`, `deploy/tmpfiles.d` and `deploy/polkit/50-fleet-agent.rules` (user `fleetd`, verbs start, stop, kill and reset-failed on `^fleet-agent@[A-Za-z0-9_]{1,64}\.service$`, every other manage-units request from `fleetd` denied). `deploy/README.md` has the install order and the rollback.
- **Not verified.** The unit files were not run through `systemd-analyze verify`, and the full launcher has not run a real agent on a box.

## Amendment (TEL-A11)

Jobs run with `--disallowedTools Edit Write NotebookEdit MultiEdit`, and `deploy/managed-settings.json` denies the same tools. Edits go through Bash heredocs, so the stored command holds every edit. The live comparison of heredoc edits against Edit and Write (calls, output tokens, error rate) is outstanding.

## Decisions (2026-10-26)

Recorded as the architect's recommendations.

- **Launch mechanism.** A polkit rule plus a static template unit. Rejected: a helper binary and a root fleetd. The polkit rule scopes fleetd to one unit pattern and keeps fleetd unprivileged.
- **Isolation target.** Option (i), systemd and uid isolation in P1 to P3. Option (iv) waits for untrusted prompt sources.
- **Claude token.** It stays visible to the agent, because the agent needs it to call the API. The bound is the egress allowlist in P2 plus token rotation. Wording only: ADR-0024 text that says the credentials stay secret is limited to `GH_TOKEN` and `FLEET_TOKEN`.
- **Stuck detection.** It stays in shadow mode (ADR-0030). Isolation does not change that decision.

## Verification on the test box (2026-10-26)

The heading names a generic box because CI rejects box names with a digit suffix in tracked files. The probes ran on one Debian 13 (trixie) box, kernel 6.12.113, systemd 257.13, polkit 126. The `agent` user has passwordless sudo. `fleetd.service` there runs as `agent` with `ProtectSystem=strict`, `NoNewPrivileges=yes` and no `MemoryMax`. `/etc/swarm/secrets.env` is mode 0640 `root:agent`, so any Job running as `agent` can read it today. P1 closes that exposure.

A probe unit ran as user `fleet-probe`:

- `secrets.env` was unreadable.
- `/proc/<pid>/environ` of fleetd was unreadable.
- `ProtectProc=invisible` showed only the unit's own pids.
- `$HOME` and `CLAUDE_CONFIG_DIR` were writable. `/etc` was read-only. The agent's home directory was denied.
- `MemoryMax`, `TasksMax`, `ProtectSystem` and `User` applied as set.
- A polkit rule scoped to `fleet-probe@*.service` let `agent` start that unit with no prompt. `systemctl start ssh.service` and `systemctl stop fleetd.service` were denied with "Interactive authentication required".
- With `PrivateNetwork=yes` and the address families above, the unit saw only `lo` (127.0.0.1/8 and ::1/128) and no routes. A connection to 127.0.0.1:7071, the host hook port, was refused. 1.1.1.1:443 and 169.254.169.254:80 gave "Network is unreachable". Loopback TCP and unix sockets worked.

Three design corrections came out of the run and are binding constraints in P1: the job directory outside `/var/tmp`, `AF_INET` and `AF_INET6` allowed, and a system-wide Claude install.

### Unverified

- Where Claude writes `.claude.json` under `CLAUDE_CONFIG_DIR`. Untestable until the job uid can run `claude`.
- Whether managed-settings hooks fire under the new uid.
- The bwrap and `RestrictNamespaces` interaction (P4).
- The egress proxy itself. It is not built, and its behaviour with the Claude client under `NODE_USE_ENV_PROXY=1` is untested.
- Inferred, not part of the design: the hook client fix in P1 is the only repo change P1 needs besides the unit, the polkit rule and the launcher. Other code paths that assume one uid (the `.finish-<id>` scratch dir, askpass socket checks) were not audited.

## Open items

- The startup sweep runs only after the daemon holds its sockets, so a second instance cannot sweep a running one. It removes stale run dirs and resets their failed units only. The job worktree and `.agent/<id>` of a crashed job stay, because `Workspace::remove` needs the repo, which a crash no longer records.
- On a `systemctl show` error the launcher runs `reset-failed` but not `kill`, so a still-running unit could outlive its removed run dir.
- Egress and the credential proxy (P2) are not built. Until then the template has no route to the model API, and a box needs the `PrivateNetwork=no` drop-in (`deploy/fleet-agent@.service.d/allow-network.conf.example`) to run a real agent.
- A Firecracker microVM per job stays the escalation path if third-party repos or public prompt sources are ever run.

## Consequences

- Jobs share the host kernel. A kernel escape from a Job reaches the host and everything fleetd holds. The uid split, `NoNewPrivileges` and the unit sandbox do not change that. A microVM per Job is the answer if the prompt sources become untrusted.
- A Job can no longer read `GH_TOKEN`, `FLEET_TOKEN` or `secrets.env` once P1 ships. The "Any claim here that the token stays secret holds against a process under a uid other than fleetd's" caveat of ADR-0024 then holds for the agent too.
- The agent keeps the Claude token. A leak is bounded by the egress allowlist and by rotation.
- P1 alone leaves the network open, so a Job can still reach any host and the host loopback services. P2 closes that.
- P1 and P2 leave the shared mirror writable by the agent until P3.
- fleetd gains a polkit rule, a second uid, a template unit and a launcher subcommand, and loses the process-group cancel path. A Box needs a system-wide Claude install, which changes the Template.
- Per-job state moves out of `StateDirectory=fleetd` or needs a second state directory owned by `fleet-job`.
- The allowlist is a new thing to maintain per bundle. A missing host fails a Job at the first request.

## Considered and rejected

- **Helper binary or root fleetd for launch.** More privileged code than a polkit rule scoped to one unit pattern.
- **`DynamicUser=`.** Ownership across fleetd restarts needs a stable uid.
- **A credential broker only.** Keeps the Claude token and the open network, and the agent still reads `/proc` and the mirror.
- **A microVM now.** Cost and complexity with no untrusted prompt source today. Revisit per the trigger above.
- **bwrap as the first step.** Not installed on the test box, and it leaves the uid shared with fleetd.
