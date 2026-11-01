# Deploying fleetd

Two files configure a box: a systemd unit for the daemon and a Claude Code managed settings file that points the hooks at it. The paths and the user name `agent` are examples. Change them to match the box.

## Install

1. Put the `fleetd` binary at `/usr/local/bin/fleetd`. The [root README Install section](../README.md#install) says how to get it.
2. Copy `fleetd.service` to `/etc/systemd/system/`. Adjust `User=`, the uid in `user@1000.service` and `XDG_RUNTIME_DIR`, and the `ReadWritePaths=` home path. workmux and pueue keep their sockets and state under the user runtime directory, so the unit orders after `user@1000.service` and sets `XDG_RUNTIME_DIR` (plan, systemd unit section; T9). The uid 1000 is an assumption: match it to `User=`. The `-` prefix on a `ReadWritePaths=` path makes systemd skip it when it does not exist.

   `ProtectHome=read-only` makes all of `/home` read-only, and `ReadWritePaths=` reopens only the workmux state. The unit no longer reopens `~/.claude`, `~/.config` or `~/.cache`: the agent child runs with `HOME` set to a per-job directory under the jobs dir (see [Job agent environment](#job-agent-environment)), and nothing else in fleetd writes under the home directory. Mirrors and the workspace git home live under the jobs dir, and `claude_bin` and `gh_bin` are only looked up and run.

   Claude Code state that used to sit in `~/.claude.json` now goes to the per-job home. Whether `~/.claude.json` moves with `CLAUDE_CONFIG_DIR` is unverified, so check on a live box that a job leaves nothing in the real home.

   This path set is unverified on a live box. The `systemd-analyze verify` result for the systemd-launcher units is under [Files](#files).
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
| `GH_TOKEN` | Ignored on the job path, where the owner's held `github_pat` from `GetJobCredentials` is the only source for the push, the private repo mirror fetch and `gh pr create`. Reaches `fleetd askpass` and `gh` only, and only while a token host is set. `gh` gets `GH_HOST` set to the token host, and `GH_ENTERPRISE_TOKEN` only when that host is not `github.com` | unset |

The default jobs dir is `/var/lib/fleetd/jobs`, inside `StateDirectory=fleetd`, so the unit needs no extra path for it. fleetd removes a job's worktree after the job ends, and keeps the mirror cache. A failed workspace prepare, a shutdown during prepare and a killed fleetd leave a worktree behind, and nothing removes it, so clear old directories from the jobs dir by hand. If you set `FLEETD_JOBS_DIR` or `jobs_dir` elsewhere, add that path to `ReadWritePaths=` with a drop-in (`systemctl edit fleetd`), or the worktree and mirror writes fail under `ProtectSystem=strict`. `claude_bin` and `gh_bin` are config-file keys only, with no env variable. They default to `claude` and `gh`, resolved through `PATH`. Set absolute paths in `/etc/fleetd/config.toml` when the unit's `PATH` does not include them.

A missing secrets file disables redaction and fleetd logs a warning only. It does not refuse to start.

`EnvironmentFile=-/etc/swarm/box.env` in the unit loads variables from that file. Put non-secret settings there: `FLEETD_PORT`, `FLEET_BOX_NAME`, `FLEETD_DB`, `FLEETD_SOCKET`, `FLEETD_SECRETS_FILE`, `FLEETD_JOBS_DIR` and `FLEET_SERVER_URL`. Put `FLEET_TOKEN` and `GH_TOKEN` in `secrets.env` only, because fleetd scrubs that file's values from events. In the direct launcher layout `secrets.env` is mode 0600 and owned by `agent`; the [Systemd agent launcher](#systemd-agent-launcher) section changes the owner and splits the uid. The `-` prefix makes the file optional: a missing file is not an error. The unit also loads `/etc/swarm/secrets.env` into the environment, so `FLEET_TOKEN` and `GH_TOKEN` reach fleetd, and fleetd reads the same file by path through `FLEETD_SECRETS_FILE` for the redaction list. The agent child environment block is stripped of `GH_TOKEN` and `FLEET_TOKEN`, but with the direct launcher the agent runs as the same uid as fleetd and can read the fleetd process environment through `/proc/<pid>/environ` and any file fleetd reads, such as `/etc/swarm/secrets.env`. The git push child, the mirror fetch child for a repo on `token_host` and their askpass helper receive `GH_TOKEN`, and `gh` receives it too. The PAT is exposed to the agent on this box and hidden only from processes under another uid. Use a fine-grained PAT scoped to throwaway repos on disposable Boxes only. The [Systemd agent launcher](#systemd-agent-launcher) section builds the uid split. A credential broker is not built. The unit sets `StateDirectory=fleetd` and `RuntimeDirectory=fleetd`, so systemd exports `STATE_DIRECTORY` and `RUNTIME_DIRECTORY` and the db and socket land in `/var/lib/fleetd` and `/run/fleetd`.

Config file keys: `http_port`, `socket_path`, `db_path`, `queue_max_bytes`, `queue_max_age_secs`, `hook_events`, `secrets_file`, `box_name`, `dedupe_window_secs`, `claude_bin`, `gh_bin`, `disposable`, `jobs_dir`, `repo_hosts`, `token_host`, `agent_config_dir`, `agent_env_passthrough`, `max_turns`, `max_budget_usd`, `agent_timeout_secs`, `ci_deadline_secs`, `agent_launcher`, `systemctl_path`, `hook_socket`, `hook_socket_uid`, `hook_socket_group`, `job_group`. Unknown keys are an error. `max_turns` (1 to 1000, default 100) and `max_budget_usd` (above 0, at most 1000, default 5.0) bound every job: fleetd always passes them as `--max-turns` and `--max-budget-usd`, an agent config bundle cannot change them, and an invalid value stops startup with an error naming the key, while a missing one uses the default. `agent_timeout_secs` (1 to 6900, default 1800) is the longest one agent run may take, config file only. `ci_deadline_secs` (1 to 7200, default 900) is the longest fleetd waits for the checks of the pull request it opened, config file only. The wait renews the lease, so it may exceed the 120 s lease. Checks that have not settled by then end the CI state as `timeout`. The unit's `RuntimeMaxSec=2h` outlasts the 6900 s maximum by 5 minutes, so fleetd's deadline fires before the unit's. A job that hits either cap ends `FAILED` with the error `max turns reached` or `budget exceeded`, and fleetd publishes no branch or pull request for it, the same as for any failed agent run. `repo_hosts` lists the hosts a job repo may name, `["github.com"]` by default. A job repo must be `https://<host>/...` on one of them, with no port and no userinfo, and fleetd rejects every other scheme. An empty list rejects every job. Only `token_host` gets the PAT: `fleetd askpass` answers a git prompt only for that one host, for the push and for the mirror fetch of a private repo. `token_host` is a config-file key with no env override, defaults to `github.com` when `repo_hosts` lists it, else is unset and no host gets the PAT, and must be one of `repo_hosts` or fleetd fails to start. Adding `gitlab.com` to `repo_hosts` therefore never sends it the GitHub token. Local `file://` repos have no config key and are not accepted in production. `hook_events` lists the hook names to record. Add a name there and a matching hook in the managed settings to record more events.

## Job agent environment

`claude` and `gh` must be real binaries on the `PATH` of the unit, or set by absolute path in `claude_bin` and `gh_bin`. For broker `pr` operations `gh` must exist at an absolute `gh_bin` (default `/usr/bin/gh`). On the test box `gh` exists only as a mise shim, so install the distro package or set `gh_bin`. A version manager shim (a mise or asdf shim) resolves its tool from the home directory and the working directory, and the agent no longer has the operator home, so the shim fails or picks another version.

Each job runs `claude` with `HOME` set to `<jobs_dir>/.agent/<job id>/home`, outside the worktree. `CLAUDE_CONFIG_DIR` is `home/.claude`, the four `XDG_*_HOME` variables point under `home`, `GIT_CONFIG_GLOBAL` is `home/.gitconfig` (author `Fleet Job`, no commit signing), and `XDG_RUNTIME_DIR` and the real `HOME` are not passed. fleetd builds the directory as `<job id>.tmp`, renames it, and removes it when the agent ends. The workspace cleanup also removes it after a crash. claude creates `home/.claude/sessions` with mode 0700 owned by `fleet-job`, and fleetd cannot delete that directory otherwise. The unit therefore sets `ExecStopPost=-/bin/chmod -R g+rwX /var/lib/fleet/jobs/.agent/%i`, which makes the tree group-writable for `fleet-work`, so fleetd can remove it. The command runs as `fleet-job` inside the unit sandbox, with no `+` or `!` prefix. The `-` prefix makes systemd ignore any non-zero exit of the chmod, not only a missing path. A real chmod failure no longer fails the unit and shows only as fleetd's `job workspace could not be removed` warning, with credentials left on disk. The live finding behind the `-` prefix is under [Job home cleanup finding](#job-home-cleanup-finding). The chmod is cleanup that makes entries listable for fleetd's removal, so a vanished path is expected. The command must never run as root. The agent controls what `.agent/<job id>` points at, and a root chmod on a path the agent can write could be redirected by a symlink swap. GNU `chmod -R` follows no symlink, whether named on the command line or met during traversal, unless `-H` or `-L` is given, which narrows that risk. This is GNU behaviour and unverified on other chmod builds. As `fleet-job` the command reaches only files `fleet-job` can already change. `ReadWritePaths=/var/lib/fleet/jobs` covers the path. Beyond the finding above, whether the chmod works as intended on a live box is unverified. Recommendation: give `/var/lib/fleet/jobs/.agent` the sticky bit, so the agent cannot swap another job's entry; the mode is set in `agent_config.rs`, which this change does not touch. After the stop, the `fleet-work` members can read the job home, credential files included. `fleet-job` is the only member besides `fleetd` (`deploy/sysusers.d`). A `job workspace could not be removed` warning means `.agent/<job id>` stays behind. Remove it with `sudo -u fleetd rm -r /var/lib/fleet/jobs/.agent/<job id>`.

The agent environment is an allowlist: `PATH`, `LANG`, `LC_*`, `TERM`, `CLAUDE_CODE_OAUTH_TOKEN`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and the lowercase forms), `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` and `DISABLE_TELEMETRY`, plus `FLEET_JOB_ID` and `SWARM_BOX=1`. `agent_env_passthrough` adds names to the list, for example `["ANTHROPIC_BASE_URL"]`. fleetd refuses to start when an entry is not a plain variable name, holds a credential name (`GH_TOKEN`, `FLEET_TOKEN` and the rest of `STRIPPED_ENV`) or starts with `FLEETD_`.

The default `home/.claude` holds a short `CLAUDE.md` and a `settings.json` with permissions only: allow `git add`, `git commit`, `git status`, `git diff`, `git log` and `git checkout -b`, deny `git push` and `gh`, and empty commit and PR attribution. `agent_config_dir` names a directory whose files replace the defaults of the same name and add others under `home/.claude`. It is a plain copy and fleetd refuses to start on: a path with `..`, a symlink or any entry that is not a regular file or directory, more than 64 entries, more than 4 MiB, or a `settings.json` with a top-level key other than `permissions`, `model` and `attribution` or a `bypassPermissions` default mode.

The agent runs with `--setting-sources user`, `--permission-mode dontAsk` (only `--dangerously-skip-permissions` on a disposable box), an appended protocol prompt, and `--disallowedTools "Bash(git push *)" "Bash(gh *)" Edit Write NotebookEdit MultiEdit` as a floor no settings file can lift. The managed settings file denies the same four edit tools, so a job changes files through Bash (a quoted `python3` heredoc) and the stored command holds every edit. The managed settings file still applies.

After a clean agent exit fleetd commits what the agent left uncommitted, as `chore: uncommitted job changes (fleet job <id>)` on the job branch. It runs with no tokens, a scratch home, no hooks, no fsmonitor and no clean or smudge filter, and it fails the job without committing when the staged diff holds a value from the secrets file. A job that changed nothing still ends `SUCCEEDED`, with a `fleet: no_changes` line in the transcript and no branch.

## Job home cleanup finding

Live finding on a test box, with the unit lacking the `-` prefix on `ExecStopPost=`: `.agent/<id>` was removed correctly, but the chmod exited 1 on every job (`No such file or directory` for a missing path), systemd logged `Failed with result 'exit-code'`, and the unit ended `failed`. By the timestamps, fleetd removes `.agent/<id>` while the agent exits, so the chmod loses a race. The race is inferred from timing. The chmod stderr is unverified, because the unit has no `StandardError=` routing to the journal and `StandardOutput=file:/run/fleet/%i/stdout` is the only output routing. The chmod is cleanup that makes entries listable for fleetd's removal, so a vanished path is expected, and the `-` prefix makes the unit ignore it.

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
| `fleet-tool-install@.service` | `/etc/systemd/system/fleet-tool-install@.service` |
| `fleetd-systemd.service` | `/etc/systemd/system/fleetd.service`, replacing the legacy unit |

`fleet-tool-install@.service` (ADR-0048) runs `mise install --locked` as `fleet-job` with `MISE_SAFE=1` against a fleetd-written `/run/fleet/<id>/mise.toml`. The agent unit has `Requires=` and `After=` on it, so a failed install fails the job before the agent starts. The install writes only to `/var/lib/fleet/tools` (`MISE_DATA_DIR`, created by tmpfiles.d as `fleet-job` 0750), never under the `.cache` mirror. The agent unit mounts that directory read-only. A job without a `mise.toml` skips the install unit through `ConditionPathExists`. `PrivateNetwork=yes` stays on. The unit's `ExecStart` is `/usr/local/bin/fleetd tool-install-exec %i`, the install counterpart of `fleetd agent-exec`. It reads the `[mise]` pins from Box config, verifies the bundled `/usr/local/libexec/fleet/mise` (sha256, minisign, owner and mode), binds the in-namespace egress forwarder on `127.0.0.1:3128` aimed at `/run/fleet/<id>/job.sock`, and runs `mise install --locked` as a child with the four proxy variables naming the forwarder and `NO_PROXY` and `ALL_PROXY` removed. With no pins, or a binary that does not verify, it exits 2 with a fixed message and starts nothing. The job socket accepts the cgroup `system.slice/system-fleet\x2dtool\x2dinstall.slice/fleet-tool-install@<id>.service` of the same job id as well as the agent unit, and lets that unit select only the `egress proxy` service. Another job's install unit, another template and the agent of another job are refused. Before the launcher starts the agent unit, which pulls in the install unit, it requires the Box `egress_allow` exact host names to cover `tool_hosts` (`check_tool_hosts`) and writes `/run/fleet/<id>/tool-env` (`write_tool_env`, mode 0600, created through an `O_DIRECTORY|O_NOFOLLOW` handle on the job dir, the four proxy variables naming `http://127.0.0.1:3128`, no file when the job has no tools). A refused set fails the launch before any run directory or unit exists, with the fixed error `tool install hosts are not covered by egress_allow`. The host set derives from the closed tool registry (`tool_hosts`, exact names, no wildcard); a wildcard `egress_allow` entry does not count as covering an exact host. The production launcher does not set `with_tool_install` yet: no code maps a Profile's `tools` to a job or writes `mise.toml`, so the call site is covered by fakes only. Tested with a fake `systemctl`, a fake mise script and a fake job socket peer. Unverified: `MISE_SAFE=1` taking effect with `install`; the install slice name `system-fleet\x2dtool\x2dinstall.slice`; `/etc/fleetd/config.toml` being readable by `fleet-job`; connecting to `job.sock` through the read-only `BindReadOnlyPaths=/run/fleet/%i`; every host in `tool_hosts` (the mise-versions host, `nodejs.org`, `go.dev`, `dl.google.com`, `api.adoptium.net`, the GitHub asset hosts); the proxy path from the private network namespace. No live run has happened.

Tool cache (TOOL-6, `ToolCache` in `crates/fleetd/src/tools.rs`): an entry is `/var/lib/fleet/tools/<name>/<version>`, keyed by a name from the closed registry and an exact version pin. `lookup` reads only and returns a hit when the name directory and the entry are real directories (no symlink), owned by the install uid and free of group and other write bits; a hit means the caller skips the install unit, any other state is a miss. Hostile names and versions (slash, `..`, NUL, empty, over-long, case variants, non-ASCII) fail the registry validators before a path is built. `touch` writes the `.last-used` marker in the entry (temp file with `O_EXCL`, then rename, the caller supplies the time, atime is never read) and `evict` runs one bounded pass: oldest marker first (no marker counts as oldest) while the total exceeds `MAX_CACHE_BYTES` (8 GiB) or the count exceeds `MAX_CACHE_ENTRIES` (64), each entry renamed to `.evicting-*` and then deleted with std recursive delete, stale aside directories swept first. In-use protection is a shared `flock` on the entry directory (`lease`): eviction takes the exclusive lock with `LOCK_NB` and skips a leased entry. `touch` and `evict` write, so they must run as `fleet-job` (the owner of the 0750 directory); the install unit is the only writer and the agent unit has `/var/lib/fleet/tools` in `ReadOnlyPaths=` only, which a test pins. No unit was widened. Nothing calls the cache from the runner yet (TOOL-7, TOOL-8), and no production code sets the install uid or the run time for `touch`. Unverified live: `flock` on a directory handle across the real install and agent units, the read-only mount permitting the agent side to open the entry directory, how mise lays out installs under `MISE_DATA_DIR` against the `<name>/<version>` key, and eviction under a real concurrent job.

The units and `sysusers.d` file were installed live on systemd 257. `systemd-analyze verify ./fleet-agent@.service ./fleetd.service` on a scratch copy of the repo units (with the mount lines above, `fleetd-systemd.service` copied as `fleetd.service`) on systemd 257.13 exited 0 with no output. That checks syntax only, not the mount behaviour. Run `systemd-analyze verify /etc/systemd/system/fleet-agent@.service /etc/systemd/system/fleetd.service` on the box before the first start anyway.

### Users and groups

- `fleetd` owns the daemon, its state under `/var/lib/fleetd` and `/etc/swarm/secrets.env`.
- `fleet-job` runs agents. Its primary group is `fleet-work`.
- `fleet-work` is the shared group. `fleetd` is a member, through `sysusers.d` and `SupplementaryGroups=fleet-work`. A non-root daemon can only chown to a group it belongs to.
- `/var/lib/fleet/jobs` is mode 3770 `fleetd:fleet-work`: group-writable, setgid and sticky. Others have no access, so `fleet-job` reaches the jobs dir only as a member of `fleet-work`. Each job has its clone there, plus `.agent/<job id>` (the per-job home) and the `.cache` mirror, which `fleetd` owns and the job group reads but never writes. The daemon unit's `ReadWritePaths=` covers only this directory. The agent unit reopens it too, then `ReadOnlyPaths=-/var/lib/fleet/jobs/.cache` makes the mirror read-only inside the agent's mount namespace, on top of the file modes.
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

### Self-update layout

`fleetd-systemd.service` runs `ExecStart=/var/lib/fleet/bin/current/fleetd serve`. `tmpfiles.d/fleet.conf` creates `/var/lib/fleet/bin` (0755, `fleetd:fleet-work`) and seeds `current` as a symlink to `/usr/local/bin`, so a box that never updated runs the baked binary through the same path. The unit lists `-/var/lib/fleet/bin` in `ReadWritePaths=`, because `ProtectSystem=strict` otherwise keeps the swap read-only. The `-` prefix follows the rule in `deploy/CLAUDE.md`. The job units (`fleet-agent@.service`, `fleet-tool-install@.service`) are unchanged: they run the baked `/usr/local/bin/fleetd` and gain no path. The legacy `fleetd.service` (`User=agent`) is unchanged and stays on `/usr/local/bin/fleetd`: its user does not own the bin dir.

`fleetd::update::Swapper` unpacks `<ver>/fleetd.tar.gz` into `<ver>/fleetd` (0755, the version dir opens to 0755 so `fleet-job` can run it) and flips the links with `rename(2)` over a temp symlink: `previous` takes the old `current` target first, then `current` flips. Entries that are links, absolute paths, `..` paths or non-regular files refuse the archive, and the binary and total unpacked sizes are capped. Covered by `crates/fleetd/tests/update_swap.rs` against temp dirs and a relative root.

Restart and rollback: `ExecStartPre=-/usr/local/bin/fleetd update-guard` runs the guard from the baked, root-owned binary, never from `current`, so a broken update cannot disable its own rollback. The `-` prefix makes systemd start the daemon even when the guard cannot run, and the guard itself always exits 0. The guard keeps three files in `/var/lib/fleet/bin`, each written to a temp file and renamed over its name: `health` (the version that last proved healthy), `starts` (starts of `current` since then, with the version) and `bad_versions` (one version per line). On each start it reads `current`. A `health` file naming it clears `starts`. Otherwise `starts` grows by one, and once it already holds 3 (`MAX_UNHEALTHY_STARTS`, so the fourth start of an unproven version) the guard writes the version to `bad_versions`, moves `current` back to `previous` through `Swapper::rollback` (which also drops `previous`), marks the restored version healthy and clears `starts`. A corrupt, oversized, non-regular or non-UTF-8 `starts` file counts as the limit: with no proof of health and no trustworthy count the guard rolls back, the stricter reading. With no `previous`, a `previous` that is itself in `bad_versions`, or a `current` that is not a version name (the `/usr/local/bin` seed), the guard changes nothing and the daemon starts. `bad_versions` is checked by `Updater::apply`, so a rolled-back version is never swapped in again. The new binary writes `health` only after it has sent `READY=1` and one heartbeat the server accepted, so a daemon with no `FLEET_SERVER_URL` never marks itself healthy and an update on such a box rolls back. After a swap `Updater::apply` keeps claiming paused (`ClaimGate` through `Poller::with_gate` in `jobs.rs`), waits until `LeaseTracker` reports no held job, swaps, and raises `RestartSignal`, which ends `run` with exit 0 so `Restart=always` starts the new binary. `LeaseTracker` holds a job from the start of its runner until the runner returns or the job-end hook fires, so a lease that outlives its poller task still blocks the swap, and the 30 minute drain cap aborts the update, never a job. Covered by `crates/fleetd/tests/update_guard.rs`, `update_guard_process.rs` and `update_restart.rs` against temp dirs (a relative root included) and fakes.

Wired: the unit, tmpfiles, the swap module, the guard subcommand, the health marker and the restart request. A swap off the `/usr/local/bin` seed records no `previous`, so the first update has no rollback target and the guard only starts the daemon. Not wired: nothing calls `Updater::apply` yet, because the daemon has no manifest poll, fetch and stage loop, so no running daemon swaps by itself. Nothing in this section has run on a live box.

Unverified, no live run: `systemd-analyze verify` on the changed unit; that `ReadWritePaths=-/var/lib/fleet/bin` makes the path writable for `fleetd`; that systemd-tmpfiles `L` leaves an existing `current` alone after a swap; `rename(2)` over a symlink on the target host; the unpacked layout against a real cargo-dist archive (the reader takes the single entry named `fleetd` at any depth and rejects pax headers).

### Self-update runbook

Design: `docs/adr/0047-fleetd-self-update.md`. This section is the operator view and names the code each rule comes from.

Status, stated plainly: nothing in the update path has run on a real box. The pieces are unit and process tested against temp dirs and fakes only. Two gaps are known. `fleetd` has no code that reads `HeartbeatReply.update_manifest` (`grep update_manifest crates/fleetd/src` finds nothing), so no running daemon polls, verifies, stages and applies a manifest by itself; `Updater::apply` has no caller in the daemon. The release workflow (`.github/workflows/release.yml`) has no step that signs archives or writes a manifest. Every step below that needs those two pieces is a procedure for when they exist, and is marked as such.

#### Trust root

- Path: `/etc/fleetd/update.pub` (`DEFAULT_TRUST_ROOT` in `crates/fleetd/src/update.rs`). Content: one minisign public key file, at most 1024 bytes (`MAX_TRUST_ROOT_BYTES`), UTF-8.
- Needed owner and mode: a regular file owned by root (uid 0, `ROOT_UID`) whose mode has no group or other write bit (`mode & 0o022 == 0`). The same two checks apply to its parent directory, `/etc/fleetd`. A symlink at the path is refused (`O_NOFOLLOW`). `load_trust_root` returns `TrustRootWritable`, `TrustRootOwner`, `TrustRootNotRegular`, `TrustRootTooLarge` or `TrustRootInvalid` and the update stops. ADR-0047 asks for 0644 root-owned.
- Install: put the public half of the release key there as root, for example `sudo install -o root -g root -m 0644 update.pub /etc/fleetd/update.pub` with `/etc/fleetd` root-owned and 0755. Bake it into the Template so every Box starts with it. The `fleetd` user must not be able to write either path, so a compromised daemon cannot widen what it trusts.
- Rotate: the manifest signature is checked against this one file, so a new key means a new file on every Box. There is no multi-key or key-rollover support in `load_trust_root`. Replace the file as root (write beside it, then `mv` over it) on each Box or rebuild the Template, and publish manifests signed by the new key only after every Box holds it. A Box still on the old key refuses the new manifest with a `Signature` error and stays on its running version.
- The same loader checks the key that verifies the bundled mise binary (`crates/fleetd/src/tools.rs`, ADR-0048), so rotating the file affects both.

#### Signing

- Tool: minisign. `minisign_verify` 0.3 in `crates/fleetd/Cargo.toml` verifies. It accepts prehashed signatures only (`verify_manifest` calls `verify(manifest, &sig, false)`), so sign with the prehash flag.
- What is signed: the exact bytes of the manifest file. `verify_manifest` checks the size caps, then the signature over those bytes, and only then parses the JSON, so an unsigned body is never parsed. The archives are not signed by fleetd's check: the signed manifest carries each archive's sha256 and size, and staging checks both (`crates/fleetd/src/update.rs`, `stage`). The `.minisig` per archive that ADR-0047 lists is not read by any fleetd code.
- Manifest shape (`RawManifest` in `update.rs`, unknown fields refused, duplicate keys refused):

```json
{
  "version": "<semver, newer than the running version>",
  "min_protocol": 1,
  "seq": 1,
  "targets": {
    "<target name>": {"sha256": "<64 lowercase hex>", "size": 12345, "url": "https://..."}
  }
}
```

  `targets` holds 1 to 16 entries. A target name is 1 to 64 bytes of `a-z`, `0-9`, `_`, `-`, `.`. `size` is 1 to 268435456 bytes (`MAX_ARCHIVE_BYTES`). `url` is optional in the schema but staging refuses a target without one (`NoUrl`); it must start with `https://`, stay under 2048 bytes, and pass the box egress policy. The manifest is at most 16384 bytes and the signature at most 1024 bytes (`MAX_MANIFEST_BYTES`, `MAX_SIGNATURE_BYTES` in `crates/fleet-proto/src/lib.rs`). Which target name a Box looks up is unverified, because the daemon side that picks it is not wired.
- Accept rules (`Policy`, `verify_manifest`): `seq` strictly greater than the last accepted `seq` (kept in `update_seq` under the bin dir), `version` newer than the running one (`version_is_newer`), `min_protocol` not above what this fleetd serves.
- Archive layout: `fleetd-<target>.tar.gz` holding exactly one entry named `fleetd` (`crates/fleetd/src/update/unpack.rs`). Links, absolute paths, `..`, pax headers and non-regular entries refuse the archive.
- Sign and publish, as a procedure for a release holder:
  1. Build the cargo-dist archives and compute `sha256sum` and the byte size of each.
  2. Write `manifest.json` in the shape above with `seq` one higher than the last published value. Never reuse or lower a `seq`: fleetd then rejects the manifest forever.
  3. `minisign -S -H -s <release secret key> -m manifest.json` writes `manifest.json.minisig`. Check it with `minisign -V -p update.pub -m manifest.json` before publishing.
  4. Upload the archives to the `https://` urls named in the manifest.
  5. Copy `manifest.json` and `manifest.json.minisig` side by side onto the server host and set `FLEET_UPDATE_MANIFEST` to the manifest path (`crates/fleet-server/src/config.rs`). The server reads the signature from the same path with `.minisig` appended (`UpdateRelay::load` in `crates/fleet-server/src/service.rs`), relays both in `HeartbeatReply.update_manifest` and `update_signature`, and never signs. It drops the pair when a file is missing, the manifest is not JSON, or either is over its cap. The server never holds the release key, so a compromised server can withhold or replay a manifest and cannot forge one. A replay fails the `seq` check.

#### Update flow

1. The Box heartbeat reply carries the signed pair. Daemon side: not wired (see Status).
2. fleetd verifies the pair against `/etc/fleetd/update.pub` and the policy above.
3. Drain: claiming pauses and the drain waits until no lease is held. After 30 minutes (`DRAIN_CAP`, `crates/fleetd/src/update/drain.rs`) the attempt aborts and claiming resumes. The drain never kills a job.
4. Stage: fleetd downloads the archive through the egress policy, checks size and sha256 against the manifest, and stores it as `/var/lib/fleet/bin/<ver>/fleetd.tar.gz` (dir 0700 while staging, `crates/fleetd/src/update.rs`). `Swapper::unpack` writes `<ver>/fleetd` (0755) and opens the dir to 0755.
5. Swap: `Swapper` renames `previous` to the old `current` target, then flips `current` with `rename(2)` over a temp symlink (`crates/fleetd/src/update/swap.rs`).
6. Restart: `RestartSignal` ends the daemon run with exit 0 and `Restart=always` (`deploy/fleetd-systemd.service`) starts the binary behind `/var/lib/fleet/bin/current/fleetd`. `Updater::apply` refuses a version listed in `bad_versions`.

#### Rollback

- Guard: `ExecStartPre=-/usr/local/bin/fleetd update-guard` in the unit runs the baked, root-owned binary, never `current`. It always exits 0. The `-` prefix lets the daemon start even if the guard cannot run. Its state files are in `/var/lib/fleet/bin`: `health`, `starts`, `bad_versions` (`crates/fleetd/src/update/guard.rs`).
- Count: each start of an unproven `current` raises `starts`. `MAX_UNHEALTHY_STARTS = 3`: starts 1 to 3 are counted and the 4th start of that version rolls back.
- Health marker: the new daemon writes `health` with its version after it sent `READY=1` and one heartbeat the server accepted (`HealthGate` in `crates/fleetd/src/update/restart.rs`). A daemon with no `FLEET_SERVER_URL` never marks itself healthy.
- Rollback action: the guard appends the failed version to `bad_versions` (kept to the last 64), moves `current` back to `previous`, writes `health` for the restored version and clears `starts`. It does nothing when `previous` is missing, equals `current`, or is itself in `bad_versions`, and it does nothing when `current` is the `/usr/local/bin` seed. The first update off the seed therefore has no rollback target.
- Check state: `sudo -u fleetd /usr/local/bin/fleetd update-guard` prints one outcome line, but it also counts a start, so prefer `ls -l /var/lib/fleet/bin` and `cat /var/lib/fleet/bin/{health,starts,bad_versions}`.
- Manual rollback: on the Box, as the owner of `/var/lib/fleet/bin` (`fleetd`), flip the link the same way `Swapper` does: `ln -s <previous version> /var/lib/fleet/bin/.current.tmp && mv -T /var/lib/fleet/bin/.current.tmp /var/lib/fleet/bin/current`, where `<previous version>` is the target shown by `readlink /var/lib/fleet/bin/previous`, then `sudo systemctl restart fleetd`. Add the bad version to `bad_versions` (one version per line) so `Updater::apply` refuses it, and write that version to `health` only if it should count as proven. The `mv -T` form is an assumption about GNU coreutils on the Box and is unverified.
- Server side stop: remove `FLEET_UPDATE_MANIFEST` from the server environment and restart the server, or replace the manifest with one carrying a higher `seq`. Boxes already on the new version do not downgrade: the `seq` and version checks refuse an older manifest.

#### Release key custody

- Location: the private key lives offline (an encrypted removable drive or a hardware token held by the release owner) or as a secret of a protected CI environment that only the release workflow can read. It never lives on the fleet server, on a Box, or in this repository. ADR-0047 fixes this rule. The CI route does not exist yet, since `release.yml` signs nothing.
- Who may sign: the release owner named by the repository owner, and one backup holder. Signing needs a passphrase for the key. Keep the passphrase apart from the key file.
- Storage: two copies of the encrypted key on separate offline media in separate places. Keep the public key in the repository and in the Template.
- Rotation: generate a new key pair, ship the new `update.pub` to every Box as in Trust root, publish manifests signed by the new key, then destroy the old key. Plan a rotation before a Template rebuild, since a rebuild resets the Box to the baked key and binary.
- Compromise response: a leaked key lets an attacker ship a binary to every Box that fetches a manifest signed by it, and this is the one failure ADR-0047 names as fleet-wide. Steps: remove `FLEET_UPDATE_MANIFEST` from the server at once so no manifest is relayed; generate a new key; rebuild the Template with the new `update.pub` and replace Boxes, or replace the file on each Box as root; publish a manifest signed by the new key with a higher `seq`. A Box that already took a malicious binary runs it as `fleetd`, so treat the Box and its credentials as lost. A Box still holding the old key will accept any manifest signed by the leaked key until its file is replaced, and a higher `seq` signed with the leaked key outranks yours. Do not trust the old key again.

Unverified, no live run: the whole runbook on a real Box; `minisign -S -H` output against `minisign_verify` 0.3 prehash handling on a real manifest; the manual rollback commands; the file mode of the staged `fleetd.tar.gz` after publish; whether the egress policy admits the release host (ADR-0047 lists this too); the CI signing route.

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

For each job the launcher creates `/run/fleet/<job id>/` (the job id matches `[A-Za-z0-9_-]{1,64}`), mode 0750 with the job group, holding:

- `env`, mode 0600, the agent environment as an `EnvironmentFile`. systemd reads it as root, so the job uid never needs it.
- `spec.json`, `argv` and `cwd` only, written by the launcher and read by `fleetd agent-exec <job id>` as the job uid. Mode 0640 with the job group. It never holds the environment.
- `stdout`, a FIFO with mode 0660 and the job group. The unit's `StandardOutput=file:/run/fleet/%i/stdout` writes to it, and fleetd reads it.

The launcher runs `systemctl start --no-block fleet-agent@<job id>.service`, polls `systemctl show`, and when the unit ends (`inactive`, `failed`, or `active (exited)`) calls `stop` and `reset-failed` and removes the run dir. Cancel is `systemctl kill` and `stop`, which kill the whole cgroup. The `stop` runs on every end path and runs the unit's `ExecStopPost=` command, the `chmod` described in [Job agent environment](#job-agent-environment). The unit runs at most `RuntimeMaxSec=2h`.

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

### Build-chain egress preset

`deploy/box/config.toml` is an example Box config. It sets only `egress_allow`, with exact hosts for cargo, npm, pip, GitHub and Docker Hub (ADR-0049). It holds no wildcard, and `config.rs` rejects a wildcard TLD. Copy the list into `/etc/fleetd/config.toml` to enable build chains on a box.

The host list is unverified until the observe-mode task (BOX-3) captures real build traffic on a box. Expect to add or drop hosts then. Only the Box owner edits this list; a Job only narrows it.

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

The hand-installed `/etc/claude-code/managed-settings.json` is a copy and does not follow the repo. Copy it again after every upgrade. A stale copy from before the command hooks held four dead `http` hooks. After the copy, `grep -c '"type": "http"' /etc/claude-code/managed-settings.json` must print 0.
At startup fleetd parses that file and logs a warning with the count when it finds `http` hooks, and a separate line when the file is missing, unreadable or invalid JSON. None of these blocks startup.

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
   ssh agent@$BOX 'git ls-remote --heads <test repo url> refs/heads/main | cut -f1'
   ```

   Compare the `main` sha before and after the job. Expect no change. `git ls-remote` separates the sha and the ref with a tab, so a `grep -c " refs/heads/main$"` with a space always counts 0 and proves nothing.

Record each outcome in `.ralph/progress.md`. Do not mark A28 passed until all six hold on the box.

### Limits

- Jobs share the host kernel. A kernel escape from a job reaches the host and every secret fleetd holds. If jobs from third-party repos or public prompt sources ever run, move to a Firecracker microVM per job (ADR-0031, MicroVM).
- The Claude token stays visible to the agent, since the agent needs it to call the API.
- The mirror is read-only to the job (P3), so `fleetd` no longer rewrites its config. Before each fetch `fleetd` checks the mirror (owner, modes, symlinks, alternates, config content) and deletes and rebuilds one that fails, so a mirror created before P3 that may hold agent-written config is replaced on the next job. Deleting `/var/lib/fleet/jobs/.cache` once at cutover is optional. `fleetd` still clears stale `*.lock` files in the mirror before each fetch.

### Rollback

Fast, with the units installed: set `agent_launcher = "direct"` (or remove the line) in `/etc/fleetd/config.toml`, then `sudo systemctl restart fleetd`. The new unit runs the agent as the daemon uid, as before. The restart stops running agent units, because `fleet-agent@.service` has `BindsTo=fleetd.service`, so a running job ends.

Full: stop fleetd, restore the legacy `fleetd.service`, run `sudo chown root:agent /etc/swarm/secrets.env && sudo chmod 0640 /etc/swarm/secrets.env`, remove `agent_launcher`, `hook_socket`, `hook_socket_uid`, `hook_socket_group` and `job_group` from `/etc/fleetd/config.toml` (a stale `hook_socket_uid` makes the hook client reject the socket), remove `/etc/polkit-1/rules.d/50-fleet-agent.rules`, remove `/etc/systemd/system/fleet-agent@.service` and any drop-in, run `sudo systemctl daemon-reload`, and start fleetd. The users, groups and directories can stay.

## Self-hosted Box

This section collects the settings a self-hosted Box owner needs. Sources: `crates/fleetd/src/config.rs`, `deploy/box/config.toml`, ADR-0049.

### disposable

`disposable = true` in `/etc/fleetd/config.toml` declares that the Box holds nothing worth protecting from its jobs. It defaults to false. On a disposable Box jobs run with permission checks off. A kimi job starts only on a disposable Box: on any other Box fleetd never starts the binary. Set it only on a Box that holds nothing worth protecting. A Box that runs kimi must be such a Box, because kimi needs it and fleetd refuses the job otherwise. A Box shared between users, or one that holds data you care about, must leave it unset.

### egress_allow

`egress_allow` is the Box ceiling for outbound hosts. List exact hosts only: `config.rs` rejects a wildcard TLD, and a Job can only narrow the list. `deploy/box/config.toml` is the preset for cargo, npm, pip, GitHub (`github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`) and Docker Hub. The host list is unverified. It stays unverified until the observe mode of BOX-3 (`egress_observe`) has captured real traffic on a box. That key is not yet in running boxes, so do not rely on it. Expect to add or drop hosts after the capture.

### Credentials

Use a fine-grained PAT (`github_pat`) scoped to throwaway repos. A bot identity comes later. See [Settings](#settings) for where fleetd reads and scrubs the token.

### Docker mode

Docker in a Job is refused until the spike in [ADR-0049](../docs/adr/0049-job-docker-and-build-egress.md) passes. A Job never gets a root docker socket: `fleet-job` is not in the `docker` group and the agent unit lists the socket paths under `InaccessiblePaths=`. Jobs run without docker meanwhile.

### Warm caches

Warm caches (BOX-7). `/var/lib/fleet/seed` (tmpfiles.d: `fleetd:fleet-work` 0750, with `cargo` and `npm` subdirectories) is a read-only seed that an operator or install step fills as the fleetd uid: `cargo` holds a `CARGO_HOME` (registry and git checkouts), `npm` holds an npm cache. A job never writes it, and no cache is shared writable. `warm_job_caches` in `crates/fleetd/src/tools.rs` byte-copies the seed into `cargo-home` and `npm-cache` inside the job's own directory (new inodes, `nlink` 1, mode 0600 or 0700 with an execute bit, 0700 directories; no hardlink or reflink, so a write or delete in the copy cannot reach the seed, which a test pins by hashing the tree before and after). Caps are `MAX_SEED_BYTES` (2 GiB), `MAX_SEED_FILE_BYTES` (256 MiB), `MAX_SEED_ENTRIES` (200000) and `MAX_SEED_DEPTH` (32), each tested at the limit and one over with a shrunk value through `SeedLimits`. A symlink (absolute, relative, out of tree, or as a root or subdirectory), a file with `nlink` above 1, a fifo, a socket or a device refuses the whole copy and removes the partial result; a missing seed gives empty cache directories. `cache_env` is the pure function for the job env: `CARGO_HOME` and `npm_config_cache` name the copy, require absolute paths and refuse NUL, CR and LF. The agent unit adds `ReadOnlyPaths=-/var/lib/fleet/seed` (the `-` prefix because the directory is created at runtime). The install unit is unchanged: `ProtectSystem=strict` already leaves the seed read-only there and its `ReadWritePaths=` lists only the tool cache, so no unit was widened. Nothing calls `warm_job_caches` or `cache_env` from the runner yet (TOOL-8 owns the runner). Unverified: the npm cache layout a seed needs (`npm_config_cache` pointing at a copied `_cacache`), how cargo behaves offline or with `net.offline` against a seeded `CARGO_HOME`, whether a copied registry index is fresh enough to avoid a full index fetch, whether the seed is large enough to repay the per-job copy time, `fleet-job` reading the 0750 seed through `fleet-work`, and the populate step itself, which no code performs.

### Config file owner and mode

Any config file that selects a trusted principal must be owned by root, mode 0644, and not writable by `fleetd` or `fleet-job`. Install it with `sudo install -m 0644 -o root -g root <file> /etc/fleetd/config.toml`. The job uid must be able to read it. For `secrets.env` use `fleetd:fleetd` mode 0600 (see [Install order](#install-order)).

### Further variables

`infra/README.md` is to follow with these rows. Until then:

| Variable | Meaning |
| --- | --- |
| `FLEET_UPDATE_MANIFEST` | fleet-server setting: path of the signed update manifest. The signature is the file of the same name with `.minisig` appended. Unset or empty means no manifest. |
| `FLEET_ALLOW_PROFILE_TOOLS` | Unverified: no reader of this name exists in this tree at this base. Do not set it until the task that adds it documents it. |
