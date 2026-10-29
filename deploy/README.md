# Deploying fleetd

Two files configure a box: a systemd unit for the daemon and a Claude Code managed settings file that points the hooks at it. The paths and the user name `agent` are examples. Change them to match the box.

## Install

1. Put the `fleetd` binary at `/usr/local/bin/fleetd`. The [root README Install section](../README.md#install) says how to get it.
2. Copy `fleetd.service` to `/etc/systemd/system/`. Adjust `User=`, the uid in `user@1000.service` and `XDG_RUNTIME_DIR`, and the `ReadWritePaths=` home path. workmux and pueue keep their sockets and state under the user runtime directory, so the unit orders after `user@1000.service` and sets `XDG_RUNTIME_DIR` (plan, systemd unit section; T9). The uid 1000 is an assumption: match it to `User=`. The `-` prefix on a `ReadWritePaths=` path makes systemd skip it when it does not exist.

   `ProtectHome=read-only` makes all of `/home` read-only, and `ReadWritePaths=` reopens only the workmux state. The unit no longer reopens `~/.claude`, `~/.config` or `~/.cache`: the agent child runs with `HOME` set to a per-job directory under the jobs dir (see [Job agent environment](#job-agent-environment)), and nothing else in fleetd writes under the home directory. Mirrors and the workspace git home live under the jobs dir, and `claude_bin` and `gh_bin` are only looked up and run.

   Claude Code state that used to sit in `~/.claude.json` now goes to the per-job home. Whether `~/.claude.json` moves with `CLAUDE_CONFIG_DIR` is unverified, so check on a live box that a job leaves nothing in the real home.

   This path set is unverified on a live box and `systemd-analyze verify` was not run (not available where this was written).
3. Copy `managed-settings.json` to `/etc/claude-code/managed-settings.json`. The file must be root-owned and read-only to the agent uid, so the agent cannot drop the tool hooks. Or copy it to `/etc/claude-code/managed-settings.d/10-fleetd.json` to keep it apart from other managed policy. If you change the port, change it in the URLs too.
4. Start it:

   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now fleetd
   curl http://127.0.0.1:7071/healthz
   ```

## Settings

fleetd reads `/etc/fleetd/config.toml` when it exists, then these environment variables, which win:

| Variable | Setting | Default |
| --- | --- | --- |
| `FLEETD_PORT` | loopback hook port | `7071` |
| `FLEET_BOX_NAME` | box name | the hostname |
| `FLEETD_DB` | SQLite queue file | `$STATE_DIRECTORY/queue.db`, else `./fleetd.db` |
| `FLEETD_SOCKET` | unix socket, mode 0600 | `$RUNTIME_DIRECTORY/fleetd.sock`, else `./fleetd.sock` |
| `FLEETD_HOOK_SOCKET` | absolute path of a second unix socket, mode 0660, that serves only `GET /healthz` and `POST /hook/{event}` (`/event` answers 404). The hook client connects here instead of `FLEETD_SOCKET`. Must differ from `FLEETD_SOCKET` | unset, no second socket |
| `FLEETD_HOOK_SOCKET_GROUP` | group that owns the hook socket, a numeric gid or a name in `/etc/group`. Needs `FLEETD_HOOK_SOCKET` | process default group |
| `FLEETD_HOOK_SOCKET_UID` | uid that must own the socket the hook client connects to and be its peer | the client's own effective uid |
| `FLEETD_SECRETS_FILE` | env file whose values are scrubbed from every event | `/etc/swarm/secrets.env`, optional |
| `FLEETD_JOBS_DIR` | job worktrees and git mirrors (the mirror cache lives under it) | `$STATE_DIRECTORY/jobs`, else `./jobs` |
| `FLEET_SERVER_URL` | server URL, `http://` or `https://`. While set, fleetd heartbeats and polls for jobs. `https://` uses TLS with the bundled webpki roots and sends the token encrypted to the gateway. A bad or untrusted certificate fails the call within 11 seconds and the error never holds the token. The gateway-to-pod hop depends on the cluster: plaintext h2c unless a `BackendTLSPolicy` or mesh is configured | unset, no server link |
| `FLEET_TOKEN` | box bearer token for the server. Required when `FLEET_SERVER_URL` is set | unset |
| `GH_TOKEN` | GitHub PAT for the job push, the private repo mirror fetch and `gh pr create`, passed to `fleetd askpass` and `gh` only, and only while a token host is set. `gh` gets `GH_HOST` set to the token host, and `GH_ENTERPRISE_TOKEN` only when that host is not `github.com` | unset |

The default jobs dir is `/var/lib/fleetd/jobs`, inside `StateDirectory=fleetd`, so the unit needs no extra path for it. fleetd removes a job's worktree after the job ends, and keeps the mirror cache. A failed workspace prepare, a shutdown during prepare and a killed fleetd leave a worktree behind, and nothing removes it, so clear old directories from the jobs dir by hand. If you set `FLEETD_JOBS_DIR` or `jobs_dir` elsewhere, add that path to `ReadWritePaths=` with a drop-in (`systemctl edit fleetd`), or the worktree and mirror writes fail under `ProtectSystem=strict`. `claude_bin` and `gh_bin` are config-file keys only, with no env variable. They default to `claude` and `gh`, resolved through `PATH`. Set absolute paths in `/etc/fleetd/config.toml` when the unit's `PATH` does not include them.

A missing secrets file disables redaction and fleetd logs a warning only. It does not refuse to start.

`EnvironmentFile=-/etc/swarm/box.env` in the unit loads variables from that file. Put non-secret settings there: `FLEETD_PORT`, `FLEET_BOX_NAME`, `FLEETD_DB`, `FLEETD_SOCKET`, `FLEETD_SECRETS_FILE`, `FLEETD_JOBS_DIR` and `FLEET_SERVER_URL`. Put `FLEET_TOKEN` and `GH_TOKEN` in `secrets.env` only, because fleetd scrubs that file's values from events. In the direct launcher layout `secrets.env` is mode 0600 and owned by `agent`; the [Systemd agent launcher](#systemd-agent-launcher) section changes the owner and splits the uid. The `-` prefix makes the file optional: a missing file is not an error. The unit also loads `/etc/swarm/secrets.env` into the environment, so `FLEET_TOKEN` and `GH_TOKEN` reach fleetd, and fleetd reads the same file by path through `FLEETD_SECRETS_FILE` for the redaction list. The agent child environment block is stripped of `GH_TOKEN` and `FLEET_TOKEN`, but with the direct launcher the agent runs as the same uid as fleetd and can read the fleetd process environment through `/proc/<pid>/environ` and any file fleetd reads, such as `/etc/swarm/secrets.env`. The git push child, the mirror fetch child for a repo on `token_host` and their askpass helper receive `GH_TOKEN`, and `gh` receives it too. The PAT is exposed to the agent on this box and hidden only from processes under another uid. Use a fine-grained PAT scoped to throwaway repos on disposable Boxes only. The [Systemd agent launcher](#systemd-agent-launcher) section builds the uid split. A credential broker is not built. The unit sets `StateDirectory=fleetd` and `RuntimeDirectory=fleetd`, so systemd exports `STATE_DIRECTORY` and `RUNTIME_DIRECTORY` and the db and socket land in `/var/lib/fleetd` and `/run/fleetd`.

Config file keys: `http_port`, `socket_path`, `db_path`, `queue_max_bytes`, `queue_max_age_secs`, `hook_events`, `secrets_file`, `box_name`, `dedupe_window_secs`, `claude_bin`, `gh_bin`, `disposable`, `jobs_dir`, `repo_hosts`, `token_host`, `agent_config_dir`, `agent_env_passthrough`, `max_turns`, `max_budget_usd`, `agent_timeout_secs`, `ci_deadline_secs`, `agent_launcher`, `systemctl_path`, `hook_socket`, `hook_socket_uid`, `hook_socket_group`, `job_group`. Unknown keys are an error. `max_turns` (1 to 1000, default 100) and `max_budget_usd` (above 0, at most 1000, default 5.0) bound every job: fleetd always passes them as `--max-turns` and `--max-budget-usd`, an agent config bundle cannot change them, and an invalid value stops startup with an error naming the key, while a missing one uses the default. `agent_timeout_secs` (1 to 6900, default 1800) is the longest one agent run may take, config file only. `ci_deadline_secs` (1 to 7200, default 900) is the longest fleetd waits for the checks of the pull request it opened, config file only. The wait renews the lease, so it may exceed the 120 s lease. Checks that have not settled by then end the CI state as `timeout`. The unit's `RuntimeMaxSec=2h` outlasts the 6900 s maximum by 5 minutes, so fleetd's deadline fires before the unit's. A job that hits either cap ends `FAILED` with the error `max turns reached` or `budget exceeded`, and fleetd publishes no branch or pull request for it, the same as for any failed agent run. `repo_hosts` lists the hosts a job repo may name, `["github.com"]` by default. A job repo must be `https://<host>/...` on one of them, with no port and no userinfo, and fleetd rejects every other scheme. An empty list rejects every job. Only `token_host` gets the PAT: `fleetd askpass` answers a git prompt only for that one host, for the push and for the mirror fetch of a private repo. `token_host` is a config-file key with no env override, defaults to `github.com` when `repo_hosts` lists it, else is unset and no host gets the PAT, and must be one of `repo_hosts` or fleetd fails to start. Adding `gitlab.com` to `repo_hosts` therefore never sends it the GitHub token. Local `file://` repos have no config key and are not accepted in production. `hook_events` lists the hook names to record. Add a name there and a matching hook in the managed settings to record more events.

## Job agent environment

`claude` and `gh` must be real binaries on the `PATH` of the unit, or set by absolute path in `claude_bin` and `gh_bin`. For broker `pr` operations `gh` must exist at an absolute `gh_bin` (default `/usr/bin/gh`). On the test box `gh` exists only as a mise shim, so install the distro package or set `gh_bin`. A version manager shim (a mise or asdf shim) resolves its tool from the home directory and the working directory, and the agent no longer has the operator home, so the shim fails or picks another version.

Each job runs `claude` with `HOME` set to `<jobs_dir>/.agent/<job id>/home`, outside the worktree. `CLAUDE_CONFIG_DIR` is `home/.claude`, the four `XDG_*_HOME` variables point under `home`, `GIT_CONFIG_GLOBAL` is `home/.gitconfig` (author `Fleet Job`, no commit signing), and `XDG_RUNTIME_DIR` and the real `HOME` are not passed. fleetd builds the directory as `<job id>.tmp`, renames it, and removes it when the agent ends. The workspace cleanup also removes it after a crash.

The agent environment is an allowlist: `PATH`, `LANG`, `LC_*`, `TERM`, `CLAUDE_CODE_OAUTH_TOKEN`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and the lowercase forms), `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` and `DISABLE_TELEMETRY`, plus `FLEET_JOB_ID` and `SWARM_BOX=1`. `agent_env_passthrough` adds names to the list, for example `["ANTHROPIC_BASE_URL"]`. fleetd refuses to start when an entry is not a plain variable name, holds a credential name (`GH_TOKEN`, `FLEET_TOKEN` and the rest of `STRIPPED_ENV`) or starts with `FLEETD_`.

The default `home/.claude` holds a short `CLAUDE.md` and a `settings.json` with permissions only: allow `git add`, `git commit`, `git status`, `git diff`, `git log` and `git checkout -b`, deny `git push` and `gh`, and empty commit and PR attribution. `agent_config_dir` names a directory whose files replace the defaults of the same name and add others under `home/.claude`. It is a plain copy and fleetd refuses to start on: a path with `..`, a symlink or any entry that is not a regular file or directory, more than 64 entries, more than 4 MiB, or a `settings.json` with a top-level key other than `permissions`, `model` and `attribution` or a `bypassPermissions` default mode.

The agent runs with `--setting-sources user`, `--permission-mode dontAsk` (only `--dangerously-skip-permissions` on a disposable box), an appended protocol prompt, and `--disallowedTools "Bash(git push *)" "Bash(gh *)" Edit Write NotebookEdit MultiEdit` as a floor no settings file can lift. The managed settings file denies the same four edit tools, so a job changes files through Bash (a quoted `python3` heredoc) and the stored command holds every edit. The managed settings file still applies.

After a clean agent exit fleetd commits what the agent left uncommitted, as `chore: uncommitted job changes (fleet job <id>)` on the job branch. It runs with no tokens, a scratch home, no hooks, no fsmonitor and no clean or smudge filter, and it fails the job without committing when the staged diff holds a value from the secrets file. A job that changed nothing still ends `SUCCEEDED`, with a `fleet: no_changes` line in the transcript and no branch.

## Hooks

The managed settings hold one hook per default `hook_events` entry (`SessionStart`, `UserPromptSubmit`, `Stop`, `Notification`, `SessionEnd`, `PostToolUse`, `PostToolUseFailure`), each with `"timeout": 5` seconds. All are command hooks, `fleetd hook <event>`. Claude Code accepts only `command` and `mcp_tool` hooks for `SessionStart`, the tool hooks use a command so the hook process can reduce the payload, and the other four moved from `http` to `command` because the host port 7071 is unreachable from the agent's network namespace (ADR-0031 P2). For the two tool events the process keeps only the job id, `tool_use_id`, tool name, exit code and duration, and never forwards `tool_response`, content, stdout or stderr. Reports for unknown jobs or with garbage fields are dropped and counted. The daemon applies them to the job's telemetry, so the summary shows `bash_nonzero`. The `SessionStart` rationale: Claude Code accepts only `command` and `mcp_tool` hooks for that event. Claude Code spawns that process, so it does not share the unit's environment or `STATE_DIRECTORY` and `RUNTIME_DIRECTORY`. It loads `/etc/fleetd/config.toml` and its own env. Set a non-default port or socket in `/etc/fleetd/config.toml`; without them it skips the relative `./fleetd.sock` and uses loopback port 7071. The subcommand reads the payload from stdin and POSTs it to `/hook/SessionStart` on the unix socket, else the loopback port. It uses `hook_socket` when that is set, else the main socket, and only when the path is absolute, the socket is owned by `hook_socket_uid` (default the current uid), the parent directory belongs to root or that uid and has no group or other write bit, and the connected peer's `SO_PEERCRED` uid equals that uid; otherwise it counts as a failed connect. It falls back to the loopback port only when the socket connect fails or the socket gives no status line within 1 second; any HTTP status from the socket is final and is not replayed. When `FLEET_JOB_ID` is set it sends it as an `X-Fleet-Job` header, cut to printable ASCII and 128 bytes. Config loading counts against the same budget. It caps input at 1 MiB and 2 seconds, prints errors to stderr only and always exits 0, so a down fleetd never blocks Claude Code. `fleetd` must be on the `PATH` of the Claude Code process. The hooks have no `onFailure`: on 2.1.289 it had no observable effect ([T8](../docs/phase0/T8.md)). A hook fired while fleetd is down was lost in the T8 runs, which saw no retry.


Keep these hooks out of user settings and `--settings` files. Hooks merge across sources, so a second copy makes fleetd see every event twice. By default fleetd also drops an identical body that repeats within 10 seconds (`dedupe_window_secs`).

A managed settings file that fails to parse stops Claude Code from starting. Check it before you bake it into an image:

```sh
python3 -m json.tool /etc/claude-code/managed-settings.json
```

## Inspect the queue

```sh
sudo -u agent env FLEETD_DB=/var/lib/fleetd/queue.db fleetd dump --limit 20
sqlite3 /var/lib/fleetd/queue.db 'select seq, kind, state from events order by seq'
```

`fleetd dump` prints one JSON object per queued event. The unit runs with `Type=notify` and a 60 second watchdog. Every half `WatchdogSec` fleetd makes a real `GET /healthz` round trip to the loopback listener and the unix socket. It sends the watchdog ping only when both answer 200 with body `ok` within 3 seconds, so a wedged or ended listener makes systemd restart it. The ping comes from its own task and does not wait on job progress, so a long running job does not trip `WatchdogSec`. Only a wedged runtime or listener does.

## Systemd agent launcher

`agent_launcher = "systemd"` runs each agent as a `fleet-agent@<job id>.service` unit under a second uid, so a job under the second uid cannot read `/etc/swarm/secrets.env` or `/proc/<fleetd pid>/environ`. Under this launcher the agent asks fleetd for `push`, `pr_create`, `pr_checks` and `fetch` through `fleetd broker` on its per-job socket (ADR-0037), and holds no GitHub token. The direct launcher serves no job socket, so no broker runs there and the agent shares fleetd's uid and can read both. These claims come from the code and its tests. The live probe in [Credential isolation probe](#credential-isolation-probe) has not run yet, so none of them is proven on a box. The design and the live findings are in [ADR-0031](../docs/adr/0031-agent-isolation.md). The default is `direct`, the legacy path above.

### Files

| File | Install to |
| --- | --- |
| `sysusers.d/fleet.conf` | `/etc/sysusers.d/fleet.conf` |
| `tmpfiles.d/fleet.conf` | `/etc/tmpfiles.d/fleet.conf` |
| `polkit/50-fleet-agent.rules` | `/etc/polkit-1/rules.d/50-fleet-agent.rules` |
| `fleet-agent@.service` | `/etc/systemd/system/fleet-agent@.service` |
| `fleetd-systemd.service` | `/etc/systemd/system/fleetd.service`, replacing the legacy unit |

The units and `sysusers.d` file were installed live on systemd 257. `systemd-analyze verify ./fleet-agent@.service ./fleetd.service` on a scratch copy of the repo units (with the mount lines above, `fleetd-systemd.service` copied as `fleetd.service`) on systemd 257.13 exited 0 with no output. That checks syntax only, not the mount behaviour. Run `systemd-analyze verify /etc/systemd/system/fleet-agent@.service /etc/systemd/system/fleetd.service` on the box before the first start anyway.

### Users and groups

- `fleetd` owns the daemon, its state under `/var/lib/fleetd` and `/etc/swarm/secrets.env`.
- `fleet-job` runs agents. Its primary group is `fleet-work`.
- `fleet-work` is the shared group. `fleetd` is a member, through `sysusers.d` and `SupplementaryGroups=fleet-work`. A non-root daemon can only chown to a group it belongs to.
- `/var/lib/fleet/jobs` is mode 3770 `fleetd:fleet-work`: group-writable, setgid and sticky. Each job has its clone there, plus `.agent/<job id>` (the per-job home) and the `.cache` mirror, which `fleetd` owns and the job group reads but never writes. The daemon unit's `ReadWritePaths=` covers only this directory. The agent unit reopens it too, then `ReadOnlyPaths=-/var/lib/fleet/jobs/.cache` makes the mirror read-only inside the agent's mount namespace, on top of the file modes.
- The broker scratch check (`scratch_is_private`) accepts the jobs root only when it is owned by the daemon uid or root, has no world write, and has group write only with the sticky bit. Mode 3770 passes; 2770 or 0775 without the sticky bit and any mode with world write make every job fail with `job broker could not be set up`. The `.broker` dir and each scratch dir must be mode 0700 owned by the daemon.
- `/run/fleet` is mode 0750 `fleetd:fleet-work` and holds the per-job run dirs. `/run/fleet/hook` holds the hook socket, mode 0750 `fleetd:fleet-work`.

The agent unit mounts an empty read-only tmpfs over `/run/fleet` (`TemporaryFileSystem=/run/fleet:ro`) and bind-mounts back only `/run/fleet/%i` (`BindPaths=`, its own run dir with the per-job socket) and `/run/fleet/hook` (`BindReadOnlyPaths=`). Other jobs' run dirs and sockets are absent from the agent's mount namespace (ADR-0036). This is the first isolation layer; the cgroup check in `jobsock.rs` is the second.

Unverified:

- The mount shape on a live box: that the per-job socket stays connectable through the bind, and that the agent still reads `env` and writes what it needs in its run dir.
- Ordering of `TemporaryFileSystem=` and `BindPaths=`. systemd documents that bind mounts are applied after the tmpfs, but no probe was run here.
- `BindReadOnlyPaths=` for the hook dir is stricter than ADR-0036's plain `BindPaths=`. Linux lets `connect()` reach a socket on a read-only mount, but this was not probed. If the hook client fails to connect, switch that line to `BindPaths=`.
- The fixed path `/run/fleet`: it must equal the `run_dir` fleetd uses. A different run dir needs a drop-in that changes all three lines.
- The hook dir path `/run/fleet/hook` is taken from `tmpfiles.d/fleet.conf` and the `hook_socket` example; it is not read from fleetd config.
- `systemd-analyze verify`: see the note under the unit table for what ran.

`tmpfiles.d` creates `/run/fleet` and `/run/fleet/hook` instead of a second `RuntimeDirectory=` in the unit, because `RuntimeDirectoryMode=` applies to every name in the unit and `/run/fleetd` must stay 0700.

### Install order

1. Install a system-wide Claude (see [Claude install](#claude-install)).
2. `sudo systemd-sysusers` and `sudo systemd-tmpfiles --create`.
3. Install the polkit rule. polkit reloads rules on its own.
4. Install `fleet-agent@.service` and `fleetd-systemd.service` (as `fleetd.service`), then `sudo systemctl daemon-reload`.
5. Change the ownership of the secrets file: `sudo chown fleetd:fleetd /etc/swarm/secrets.env && sudo chmod 0600 /etc/swarm/secrets.env`. `/etc/swarm/box.env` stays root-owned and world-readable, with no secrets in it. A host with a legacy reader of `secrets.env` can use the group-read route instead: `sudo chown fleetd:agent /etc/swarm/secrets.env && sudo chmod 0640 /etc/swarm/secrets.env`, where `agent` is the reader's group.
6. Write `/etc/fleetd/config.toml` (below) with `sudo install -m 0644 -o root -g root <file> /etc/fleetd/config.toml`, so the writer never owns it. The file must be root-owned, mode 0644, not writable by `fleetd` or `fleet-job`, because the hook client trusts `hook_socket_uid` from this file. The hook process runs as the job uid and reads this file, so the job uid must be able to read it.
7. `sudo systemctl restart fleetd`, then `curl http://127.0.0.1:7071/healthz`.
8. Run the canary (below).

### fleetd settings

Set these in `/etc/fleetd/config.toml`, which must be root-owned, mode 0644, not writable by `fleetd` or `fleet-job`, because the hook client trusts `hook_socket_uid` from this file. The hook client reads only the config file, so `hook_socket_uid` and `hook_socket` must be there. The daemon also accepts the environment variable in the second column, and the variable wins.

| Key | Variable | Value for this mode |
| --- | --- | --- |
| `agent_launcher` | `FLEETD_AGENT_LAUNCHER` | `"systemd"` (default `"direct"`) |
| `systemctl_path` | `FLEETD_SYSTEMCTL_PATH` | absolute path, default `/usr/bin/systemctl` |
| `hook_socket` | `FLEETD_HOOK_SOCKET` | `"/run/fleet/hook/hook.sock"` |
| `hook_socket_uid` | `FLEETD_HOOK_SOCKET_UID` | the numeric uid of `fleetd` (`id -u fleetd`) |
| `hook_socket_group` | `FLEETD_HOOK_SOCKET_GROUP` | `"fleet-work"` |
| `job_group` | `FLEETD_JOB_GROUP` | `"fleet-work"` |
| `jobs_dir` | `FLEETD_JOBS_DIR` | `"/var/lib/fleet/jobs"` |
| `claude_bin` | none | `"/usr/local/bin/claude-real"` |

```toml
agent_launcher = "systemd"
hook_socket = "/run/fleet/hook/hook.sock"
hook_socket_uid = 996
hook_socket_group = "fleet-work"
job_group = "fleet-work"
jobs_dir = "/var/lib/fleet/jobs"
claude_bin = "/usr/local/bin/claude-real"
```

The `996` is an example. Use the uid `id -u fleetd` prints. Without `job_group`, the run dir keeps no job group and the job uid cannot read `spec.json`, so set it in this mode.

A hook socket under `/run/fleetd` is unreachable by the job uid, because that directory is mode 0700. That is why `hook_socket` lives in `/run/fleet/hook`. The hook client accepts the socket when its owner and its `SO_PEERCRED` peer are `hook_socket_uid` and the parent directory has no group or other write bit. Mode 0750 satisfies that.

### Run dir and unit contract

For each job the launcher creates `/run/fleet/<job id>/` (the job id matches `[A-Za-z0-9_]{1,64}`), mode 0750 with the job group, holding:

- `env`, mode 0600, the agent environment as an `EnvironmentFile`. systemd reads it as root, so the job uid never needs it.
- `spec.json`, `argv` and `cwd` only, written by the launcher and read by `fleetd agent-exec <job id>` as the job uid. Mode 0640 with the job group. It never holds the environment.
- `stdout`, a FIFO with mode 0660 and the job group. The unit's `StandardOutput=file:/run/fleet/%i/stdout` writes to it, and fleetd reads it.

The launcher runs `systemctl start --no-block fleet-agent@<job id>.service`, polls `systemctl show`, and when the unit ends (`inactive`, `failed`, or `active (exited)`) calls `stop` and `reset-failed` and removes the run dir. Cancel is `systemctl kill` and `stop`, which kill the whole cgroup. The `stop` runs on every end path and may run the unit's `ExecStop=` and `ExecStopPost=` commands; the shipped unit sets none. The unit runs at most `RuntimeMaxSec=2h`.

At startup, after it holds its port and sockets and before it polls for work, fleetd removes every directory under `/run/fleet` whose name is a job id, since none belongs to a live job of the new process. A unit for that id is handled by state: an active-like unit is stopped, then reset-failed; a `failed` unit is reset-failed; an inactive unit gets no call. The sweep leaves symlinks, files, `hook` and other names alone. The job worktree under `/var/lib/fleet/jobs/<id>` and `.agent/<id>` are not swept: remove them by hand after a crash. The sweep runs only after the daemon holds its sockets, so a second instance cannot sweep a running one. fleetd reports ready only after the sweep, so `TimeoutStartSec` governs a long sweep; the unit leaves it at the systemd default.

The unit sets `RemainAfterExit=yes` and no `CollectMode=`. systemd unloads a unit that exits cleanly, and with `CollectMode=inactive-or-failed` a failed one too, and `systemctl show` then reports `Result=success` and `ExecMainStatus=0` for every exit code, so the launcher would read a failure as no result. With `RemainAfterExit=yes` a clean exit stays `active (exited)` and a failed unit stays `failed`, both with the real status, until `systemctl stop` or `reset-failed`. The launcher must stop the unit after reading the status, because `reset-failed` leaves an `active (exited)` unit loaded. polkit allows `stop` for these units.

The unit sets `ProtectProc=invisible`, `ProcSubset=pid`, `PrivateTmp=yes`, `NoNewPrivileges=yes` and `MemoryMax=2300M` with `TasksMax=512`. `CPUQuota` is unset. `PrivateTmp=yes` is required: with `ProtectSystem=strict` and a shared `/tmp`, Claude Code fails at start with `EROFS: read-only file system, mkdir '/tmp/claude-<uid>'`. `PrivateTmp=yes` also fails a `ReadWritePaths=` entry under `/var/tmp` with status 226/NAMESPACE, which is why the jobs dir lives outside `/var/tmp`. `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` stays open because `AF_UNIX` alone blocks loopback. `InaccessiblePaths=/etc/swarm` hides the secrets directory from the job.

`fleetd-systemd.service` omits `RestrictSUIDSGID=yes`. fleetd chmods each shared job dir to mode 2770, and that filter makes the chmod fail with EPERM, so every job ends with `workspace could not be prepared`. The daemon has no capabilities and `NoNewPrivileges=yes`, and the agent unit keeps `RestrictSUIDSGID=yes`.

### Network

The template sets `PrivateNetwork=yes`, and no drop-in relaxes it. ADR-0031 P2 is done on the unit side: inside the namespace the job sees only its own loopback. `fleetd agent-exec` listens on an ephemeral `127.0.0.1` port there and forwards each connection to the egress proxy over `/run/fleet/<job id>/job.sock`. `HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1` point at that port, so the model API is the only reachable host, and only through fleetd's `egress_allow` list. A unix socket on the filesystem crosses a network namespace, and the unit bind-mounts both paths the job needs: `BindPaths=/run/fleet/%i` for `job.sock` and `BindReadOnlyPaths=/run/fleet/hook` for the hook socket. A connect to a socket in a read-only bind mount still works.

The unit needs the wiring: `PrivateNetwork=yes` leaves the job no route to the model API except through the egress proxy that fleetd serves on the job socket. A fleetd that runs `agent_launcher = "systemd"` with no services registered cuts the model API for every job, and logs `agent_launcher is systemd and no services are registered` at startup. Deploy the unit and a fleetd that registers the egress proxy together, never the unit alone.

The host hook port `127.0.0.1:7071` is unreachable from the namespace. All seven managed hooks are therefore `command` hooks, `fleetd hook <event>`, which reach fleetd over the hook socket. Set `hook_socket` in `/etc/fleetd/config.toml` to a socket under `/run/fleet/hook`.

To verify on a box:

1. `systemd-analyze verify /etc/systemd/system/fleet-agent@.service /etc/systemd/system/fleetd.service` exits 0.
2. `python3 -m json.tool /etc/claude-code/managed-settings.json` parses and `grep -c '"type": "http"'` prints 0.
3. Run one job. In its unit, `systemctl show fleet-agent@<job id>.service -p PrivateNetwork` prints `PrivateNetwork=yes`, and the hook events for the job arrive in the fleetd queue.
4. Upgrading a box that has the old `allow-network.conf` drop-in (keep this note until EGRESS-4 passes): delete `/etc/systemd/system/fleet-agent@.service.d/allow-network.conf` and run `sudo systemctl daemon-reload`.

### Claude install

The job uid cannot run `claude` from a per-user mise shim under a mode 0700 home. Install one system-wide copy:

1. Put the binary at `/opt/claude/<version>/claude`, root-owned and world-executable.
2. Symlink it: `sudo ln -sfn /opt/claude/<version>/claude /usr/local/bin/claude-real`.
3. Set `claude_bin = "/usr/local/bin/claude-real"`.
4. Set `DISABLE_UPDATES=1` in `/etc/swarm/box.env` and in the agent environment through `agent_env_passthrough`, so a job does not self-update. Update by installing a new version directory and moving the symlink.
5. Record the version in `/opt/claude/VERSION` and check it in the canary, so a drifted version shows up.

### Managed settings

Install `managed-settings.json` as in the legacy steps, with two checks:

- Validate before install: `python3 -m json.tool managed-settings.json`. An unparsable managed file stops the CLI from starting, for every job.
- Managed sources are first-wins by default. A server-managed settings source would replace this file and drop the hooks unless `managedSourcesBehavior` is `"merge"`. Set it if the account uses server-managed settings.
- The canary must check that the managed hooks fired under the job uid: run one job and confirm the hook events arrived for it. Whether they fire under the new uid is unverified until then.

### Secrets

After the ownership change in step 5, `/etc/swarm/secrets.env` is mode 0600 `fleetd:fleetd`. The legacy layout (mode 0640 `root:agent`) let any job running as `agent` read it. Whether the job uid is refused on a live box is the first check of the probe below.

### Credential isolation probe

Status: not run. Set `BOX` to the test box host name and `SERVER` to the fleet server URL. Run the steps as the operator over `ssh agent@$BOX`. Every command prints a status or a count, never a value. `JOBUID` is `fleet-job` and `FPID` is the fleetd main pid.

1. Job uid cannot read fleetd secrets. Expect `denied` twice.

   ```sh
   ssh agent@$BOX 'FPID=$(systemctl show -p MainPID --value fleetd); for f in /proc/$FPID/environ /etc/swarm/secrets.env; do sudo -u fleet-job sh -c "head -c1 $f >/dev/null 2>&1 && echo readable || echo denied"; done'
   ```

2. Job env and argv hold no token. A job must be running. The loop runs under `sudo` so every `/proc/<pid>/environ` is readable, and errors stay visible. Expect `sampled` of at least 1 and `tokens=0`. `sampled=0` or any read error fails the step, so `tokens=0` means the environ files were read and were clean.

   ```sh
   ssh agent@$BOX sudo sh -s <<'EOF'
   n=0; t=0
   for p in $(pgrep -u fleet-job); do
     e=$(tr "\0" "\n" < /proc/$p/environ) || { echo "unreadable environ for pid $p"; exit 1; }
     [ -n "$e" ] || { echo "empty environ for pid $p"; exit 1; }
     c=$(printf "%s\n" "$e" | grep -c -E "^(GH_TOKEN|GITHUB_TOKEN|GH_ENTERPRISE_TOKEN|GIT_ASKPASS|FLEET_TOKEN|FLEETD_ASKPASS)=") || true
     n=$((n+1)); t=$((t+c))
   done
   echo "sampled=$n tokens=$t"
   [ "$n" -ge 1 ] || { echo "no fleet-job process sampled"; exit 1; }
   EOF
   ```

3. Broker push and `pr_checks` work. Submit a job whose prompt makes one commit, then runs `fleetd broker push`, `fleetd broker pr_create "t" "b"` and `fleetd broker pr_checks`. Expect each to print its reply, and the job to finish `SUCCEEDED` with a `pr_url`.

   ```sh
   fleet submit --server $SERVER --repo <test repo url> --prompt 'commit one file, then run: fleetd broker push; fleetd broker pr_create "probe" "probe"; fleetd broker pr_checks'
   fleet status --server $SERVER <job id>
   ```

4. Plain `git push` and `gh` fail with no credential. Submit a job that runs `git push origin HEAD`, `gh auth status` and `gh pr list`. Expect a refusal or an authentication failure for each, and no token in the transcript.

   ```sh
   fleet submit --server $SERVER --repo <test repo url> --prompt 'run each of: git push origin HEAD; gh auth status; gh pr list; report only exit codes'
   fleet logs --server $SERVER <job id>
   ```

5. Another job's socket is refused. Start two jobs together. In job A, connect to job B's socket path and print only the outcome. Expect `refused`.

   ```sh
   fleet submit --server $SERVER --repo <test repo url> --prompt 'sleep 120'
   fleet submit --server $SERVER --repo <test repo url> --prompt 'python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/fleet/<job B id>/job.sock\")" 2>&1 | tail -1; echo done'
   ```

6. A push to another branch is impossible. `fleetd broker push` takes no branch argument, and the target is the bound `swarm/<job id>` branch. Expect the extra argument refused and the branch list unchanged.

   ```sh
   fleet submit --server $SERVER --repo <test repo url> --prompt 'run: fleetd broker push refs/heads/main; fleetd broker push --branch main'
   ssh agent@$BOX 'git ls-remote --heads <test repo url> | grep -c " refs/heads/main$"'
   ```

   Compare the `main` count before and after the job. Expect no change.

Record each outcome in `.ralph/progress.md`. Do not mark A28 passed until all six hold on the box.

### Limits

- Jobs share the host kernel. A kernel escape from a job reaches the host and every secret fleetd holds. If jobs from third-party repos or public prompt sources ever run, move to a Firecracker microVM per job (ADR-0031, MicroVM).
- The Claude token stays visible to the agent, since the agent needs it to call the API.
- The mirror is read-only to the job (P3), so `fleetd` no longer rewrites its config. Before each fetch `fleetd` checks the mirror (owner, modes, symlinks, alternates, config content) and deletes and rebuilds one that fails, so a mirror created before P3 that may hold agent-written config is replaced on the next job. Deleting `/var/lib/fleet/jobs/.cache` once at cutover is optional. `fleetd` still clears stale `*.lock` files in the mirror before each fetch.

### Rollback

Fast, with the units installed: set `agent_launcher = "direct"` (or remove the line) in `/etc/fleetd/config.toml`, then `sudo systemctl restart fleetd`. The new unit runs the agent as the daemon uid, as before. The restart stops running agent units, because `fleet-agent@.service` has `BindsTo=fleetd.service`, so a running job ends.

Full: stop fleetd, restore the legacy `fleetd.service`, run `sudo chown root:agent /etc/swarm/secrets.env && sudo chmod 0640 /etc/swarm/secrets.env`, remove `agent_launcher`, `hook_socket`, `hook_socket_uid`, `hook_socket_group` and `job_group` from `/etc/fleetd/config.toml` (a stale `hook_socket_uid` makes the hook client reject the socket), remove `/etc/polkit-1/rules.d/50-fleet-agent.rules`, remove `/etc/systemd/system/fleet-agent@.service` and any drop-in, run `sudo systemctl daemon-reload`, and start fleetd. The users, groups and directories can stay.
