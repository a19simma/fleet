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
| `FLEET_SERVER_URL` | server URL, `http://` or `https://`. While set, fleetd heartbeats and polls for jobs. `https://` uses TLS with the bundled webpki roots and sends the token encrypted to the gateway. A bad or untrusted certificate fails the call within 11 seconds and the error never holds the token. The gateway-to-pod hop depends on the cluster: plaintext h2c unless a `BackendTLSPolicy` or mesh is configured. A plain `http://` URL stops startup unless its host is loopback or `FLEETD_ALLOW_PLAINTEXT_CREDENTIALS=1`, and the error shows `<redacted>` in place of the URL | unset, no server link |
| `FLEET_TOKEN` | box bearer token for the server. Required when `FLEET_SERVER_URL` is set | unset |
| `GH_TOKEN` | Ignored on the job path. With the server link, the owner's held `github_pat` from `GetJobCredentials` is the only token for the push, the private repo mirror fetch and `gh pr create`, and a job without one fails with `no github credential`. `GH_TOKEN` and `GH_ENTERPRISE_TOKEN` in the base environment are dropped there, so an enterprise host needs neither. `gh` gets `GH_HOST` set to the token host | unset |
| `FLEETD_AGENT_LAUNCHER` | `direct` or `systemd`, see [Systemd agent launcher](#systemd-agent-launcher) | `direct` |
| `FLEETD_SYSTEMCTL_PATH` | absolute path of `systemctl` for the systemd launcher | `/usr/bin/systemctl` |
| `FLEETD_JOB_GROUP` | group name or gid that owns each run dir under the systemd launcher | unset |
| `FLEETD_TOOL_CACHE_UID` | numeric uid that owns `/var/lib/fleet/tools`, normally `fleet-job`. Required when the `[mise]` table is set. Root and 4294967295 are refused. Wins over `tool_cache_uid` in the file. See [Bundled mise](#bundled-mise-and-the-mise-section) | unset |
| `FLEETD_ALLOW_PLAINTEXT_CREDENTIALS` | `1` lets a plain `http://` `FLEET_SERVER_URL` pass off loopback. Any other value keeps the refusal | unset |

`FLEET_UPDATE_REPO`, `FLEET_UPDATE_POLL_SECS` and `FLEET_UPDATE_MANIFEST` are fleet-server variables, not fleetd settings. They are in [Server variables](#server-variables) and in `infra/README.md`.

The default jobs dir is `/var/lib/fleetd/jobs`, inside `StateDirectory=fleetd`, so the unit needs no extra path for it. fleetd removes a job's worktree after the job ends, and keeps the mirror cache. A failed workspace prepare, a shutdown during prepare and a killed fleetd leave a worktree behind, and nothing removes it, so clear old directories from the jobs dir by hand. If you set `FLEETD_JOBS_DIR` or `jobs_dir` elsewhere, add that path to `ReadWritePaths=` with a drop-in (`systemctl edit fleetd`), or the worktree and mirror writes fail under `ProtectSystem=strict`. `claude_bin` and `gh_bin` are config-file keys only, with no env variable. They default to `claude` and `gh`, resolved through `PATH`. Set absolute paths in `/etc/fleetd/config.toml` when the unit's `PATH` does not include them.

A missing secrets file disables redaction and fleetd logs a warning only. It does not refuse to start.

`EnvironmentFile=-/etc/swarm/box.env` in the unit loads variables from that file. Put non-secret settings there: `FLEETD_PORT`, `FLEET_BOX_NAME`, `FLEETD_DB`, `FLEETD_SOCKET`, `FLEETD_SECRETS_FILE`, `FLEETD_JOBS_DIR` and `FLEET_SERVER_URL`. Put `FLEET_TOKEN` in `secrets.env` only, because fleetd scrubs that file's values from events. The `-` prefix makes the file optional: a missing file is not an error. The unit also loads `/etc/swarm/secrets.env` into the environment, so `FLEET_TOKEN` reaches fleetd, and fleetd reads the same file by path through `FLEETD_SECRETS_FILE` for the redaction list.

This paragraph describes the legacy direct launcher. ADR-0014 asks for mode 0640 `root:agent` on `secrets.env`; mode 0600 owned by `agent` also works there, because the agent uid reads the file either way. The [Systemd agent launcher](#systemd-agent-launcher) section changes the owner to `fleetd:fleetd` mode 0600 and splits the uid. The agent child environment block is stripped of `GH_TOKEN` and `FLEET_TOKEN`, but with the direct launcher the agent runs as the same uid as fleetd and can read the fleetd process environment through `/proc/<pid>/environ` and any file fleetd reads, such as `/etc/swarm/secrets.env`. On the job path the GitHub token does not come from this environment: the owner's held `github_pat` goes to the git push child, the mirror fetch child for a repo on `token_host`, their askpass helper and `gh`. That token is exposed to the agent on this box and hidden only from processes under another uid. Use a fine-grained PAT scoped to throwaway repos on disposable Boxes only. The [Systemd agent launcher](#systemd-agent-launcher) section builds the uid split. The direct launcher has no credential broker.

The unit sets `StateDirectory=fleetd` and `RuntimeDirectory=fleetd`, so systemd exports `STATE_DIRECTORY` and `RUNTIME_DIRECTORY` and the db and socket land in `/var/lib/fleetd` and `/run/fleetd`.

Config file keys: `http_port`, `socket_path`, `db_path`, `queue_max_bytes`, `queue_max_age_secs`, `hook_events`, `secrets_file`, `box_name`, `dedupe_window_secs`, `claude_bin`, `kimi_bin`, `gh_bin`, `disposable`, `host_netns_attested`, `jobs_dir`, `repo_hosts`, `model_allowlist`, `token_host`, `agent_config_dir`, `agent_env_passthrough`, `max_turns`, `max_budget_usd`, `agent_timeout_secs`, `ci_deadline_secs`, `agent_launcher`, `systemctl_path`, `hook_socket`, `hook_socket_uid`, `hook_socket_group`, `job_group`, `tool_cache_uid`, `fetch_policy`, `fetch_allow`, `fetch_max_body_bytes`, `fetch_max_decoded_bytes`, `fetch_connect_timeout_secs`, `fetch_total_timeout_secs`, `fetch_max_redirects`, `fetch_max_per_job`, `egress_allow`, `egress_observe`, `update_trust_root`, `update_hosts` and the `[mise]` table. Unknown keys are an error, in the table too. The `fetch_*` keys, `egress_allow` and `egress_observe` are config-file only and are described in ADR-0038 and ADR-0049. `update_trust_root` and `update_hosts` are under [Self-update runbook](#self-update-runbook). `tool_cache_uid` and `[mise]` are under [Bundled mise](#bundled-mise-and-the-mise-section).

`max_turns` (1 to 1000, default 100) and `max_budget_usd` (above 0, at most 1000, default 5.0) bound every job: fleetd always passes them as `--max-turns` and `--max-budget-usd`, an agent config bundle cannot change them, and an invalid value stops startup with an error naming the key, while a missing one uses the default.

`agent_timeout_secs` (1 to 6900, default 1800) is the longest one agent run may take, config file only. `ci_deadline_secs` (1 to 7200, default 900) is the longest fleetd waits for the checks of the pull request it opened, config file only. The wait renews the lease, so it may exceed the 120 s lease. Checks that have not settled by then end the CI state as `timeout`. The unit's `RuntimeMaxSec=2h` outlasts the 6900 s maximum by 5 minutes, so fleetd's deadline fires before the unit's. `ci_deadline_secs` has no tie to `RuntimeMaxSec`: the agent run, the push and the CI wait run one after another, and ADR-0028 says that setting both to their maxima (6900 s and 7200 s) can reach the unit's 2h backstop first, which ends the job as `LOST` and the CI state as `timeout`. The code does not check the sum, and how the unit timer behaves during the CI wait is unverified. A job that hits `max_turns` or `max_budget_usd` ends `FAILED` with the error `max turns reached` or `budget exceeded`, and fleetd publishes no branch or pull request for it, the same as for any failed agent run.

`host_netns_attested` (default `false`, config file only) says that fleetd runs in the host network namespace. Timing telemetry capture (ADR-0055) starts only when it is `true`.

`repo_hosts` lists the hosts a job repo may name, `["github.com"]` by default. A job repo must be `https://<host>/...` on one of them, with no port and no userinfo, and fleetd rejects every other scheme. An empty list rejects every job. Only `token_host` gets the PAT: `fleetd askpass` answers a git prompt only for that one host, for the push and for the mirror fetch of a private repo. `token_host` is a config-file key with no env override, defaults to `github.com` when `repo_hosts` lists it, else is unset and no host gets the PAT, and must be one of `repo_hosts` or fleetd fails to start. Adding `gitlab.com` to `repo_hosts` therefore never sends it the GitHub token. Local `file://` repos have no config key and are not accepted in production.

`model_allowlist` is a list of exact model ids a job may run, config file only. Set it on every Box (ADR-0054): an unset key adds no fleetd-side restriction, and an empty list or an invalid, duplicate or over-long entry stops startup with an error naming the key and never echoing the value. `hook_events` lists the hook names to record. Add a name there and a matching hook in the managed settings to record more events. A hook name missing from `hook_events` is not recorded. The tool events `PostToolUse` and `PostToolUseFailure` are then dropped with a 200 reply and a debug log line only, so job telemetry such as `bash_nonzero` loses them without any warning.

## Job agent environment

`claude` and `gh` must be real binaries on the `PATH` of the unit, or set by absolute path in `claude_bin` and `gh_bin`. For broker `pr` operations `gh` must exist at an absolute `gh_bin` (default `/usr/bin/gh`). On the test box `gh` exists only as a mise shim, so install the distro package or set `gh_bin`. A version manager shim (a mise or asdf shim) resolves its tool from the home directory and the working directory, and the agent no longer has the operator home, so the shim fails or picks another version.

Each job runs `claude` with `HOME` set to `<jobs_dir>/.agent/<job id>/home`, outside the worktree. `CLAUDE_CONFIG_DIR` is `home/.claude`, the four `XDG_*_HOME` variables point under `home`, `GIT_CONFIG_GLOBAL` is `home/.gitconfig` (author `Fleet Job`, no commit signing; an App job overrides the author through `GIT_AUTHOR_*` and `GIT_COMMITTER_*`), and `XDG_RUNTIME_DIR` and the real `HOME` are not passed. fleetd builds the directory as `<job id>.tmp`, renames it, and removes it when the agent ends. The workspace cleanup also removes it after a crash. claude creates `home/.claude/sessions` with mode 0700 owned by `fleet-job`, and fleetd cannot delete that directory otherwise. The unit therefore sets `ExecStopPost=-/bin/chmod -R g+rwX /var/lib/fleet/jobs/.agent/%i`, which makes the tree group-writable for `fleet-work`, so fleetd can remove it. The command runs as `fleet-job` inside the unit sandbox, with no `+` or `!` prefix. The `-` prefix makes systemd ignore any non-zero exit of the chmod, not only a missing path. A real chmod failure no longer fails the unit and shows only as fleetd's `job workspace could not be removed` warning, with credentials left on disk. The live finding behind the `-` prefix is under [Job home cleanup finding](#job-home-cleanup-finding). The chmod is cleanup that makes entries listable for fleetd's removal, so a vanished path is expected. The command must never run as root. The agent controls what `.agent/<job id>` points at, and a root chmod on a path the agent can write could be redirected by a symlink swap. GNU `chmod -R` follows a symlink named on the command line (`-H` is the default) and ignores symlinks met during traversal unless `-L` is given (GNU coreutils manual, chmod invocation, and `src/chmod.c`, read 2026-11-01). The path `.agent/<job id>` is a command-line argument, so a symlink swapped in at that name is followed. That is why the command runs as `fleet-job`: it then changes only what `fleet-job` can already change. This is GNU behaviour and unverified on other chmod builds. As `fleet-job` the command reaches only files `fleet-job` can already change. `ReadWritePaths=/var/lib/fleet/jobs` covers the path. The `ExecStopPost=` path and `ReadWritePaths=` in `fleet-agent@.service` both hard-code `/var/lib/fleet/jobs`: an operator who moves the jobs dir must change both directives in a drop-in, not only `ReadWritePaths=`. Beyond the finding above, whether the chmod works as intended on a live box is unverified. Open item: `agent_config.rs` creates `.agent` and each job directory as mode 2770 (setgid, no sticky bit) for the job group, so a `fleet-work` member can rename or replace another job's entry in `.agent`. A sticky bit on `.agent` would stop that, and no code sets it today. After the stop, the `fleet-work` members can read the job home, credential files included. `fleet-job` is the only member besides `fleetd` (`deploy/sysusers.d`). A `job workspace could not be removed` warning means `.agent/<job id>` stays behind. Remove it with `sudo -u fleetd rm -r /var/lib/fleet/jobs/.agent/<job id>`.

The agent environment is an allowlist: `PATH`, `LANG`, `LC_*`, `TERM`, `CLAUDE_CODE_OAUTH_TOKEN`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and the lowercase forms), `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` and `DISABLE_TELEMETRY`, plus `FLEET_JOB_ID` and `SWARM_BOX=1`. `agent_env_passthrough` adds names to the list, for example `["ANTHROPIC_BASE_URL"]`. fleetd refuses to start when an entry is not a plain variable name, holds a credential name (`GH_TOKEN`, `FLEET_TOKEN` and the rest of `STRIPPED_ENV`) or starts with `FLEETD_`.

The default `home/.claude` holds a short `CLAUDE.md` and a `settings.json` with `permissions` and `attribution`: allow `Read`, `Glob`, `Grep` and `Bash`, deny `Bash(git push *)`, `Bash(gh *)`, `Bash(curl *)` and the four edit tools `Edit`, `Write`, `NotebookEdit` and `MultiEdit`, and empty commit and PR attribution. `agent_config_dir` names a directory whose files replace the defaults of the same name and add others under `home/.claude`. It is a plain copy and fleetd refuses to start on: a path with `..`, a symlink or any entry that is not a regular file or directory, more than 64 entries, more than 4 MiB, or a `settings.json` with a top-level key other than `permissions`, `model` and `attribution` or a `bypassPermissions` default mode.

The agent runs with `--setting-sources user`, `--permission-mode dontAsk` (a Job with no Profile on a disposable box gets `--dangerously-skip-permissions` instead, and an applied Profile sets its own permission mode), an appended protocol prompt, and `--disallowedTools "Bash(git push *)" "Bash(gh *)" Edit Write NotebookEdit MultiEdit` as a floor no settings file can lift. The managed settings file denies the same four edit tools, so a job changes files through Bash (a quoted `python3` heredoc) and the stored command holds every edit. The managed settings file still applies.

After a clean agent exit fleetd commits what the agent left uncommitted, as `chore: uncommitted job changes (fleet job <id>)` on the job branch. It runs with no tokens, a scratch home, no hooks, no fsmonitor and no clean or smudge filter, and it fails the job without committing when the staged diff holds a value from the secrets file. A job that changed nothing still ends `SUCCEEDED`, with a `fleet: no_changes` line in the transcript and no branch.

## Job home cleanup finding

Live finding on a test box, with the unit lacking the `-` prefix on `ExecStopPost=`: `.agent/<id>` was removed correctly, but the chmod exited 1 on every job (`No such file or directory` for a missing path), systemd logged `Failed with result 'exit-code'`, and the unit ended `failed`. By the timestamps, fleetd removes `.agent/<id>` while the agent exits, so the chmod loses a race. The race is inferred from timing. The chmod stderr is unverified, because the unit has no `StandardError=` routing to the journal and `StandardOutput=file:/run/fleet/%i/stdout` is the only output routing. The chmod is cleanup that makes entries listable for fleetd's removal, so a vanished path is expected, and the `-` prefix makes the unit ignore it.

## Hooks

The managed settings hold one hook per default `hook_events` entry (`SessionStart`, `UserPromptSubmit`, `Stop`, `Notification`, `SessionEnd`, `PostToolUse`, `PostToolUseFailure`), each with `"timeout": 5` seconds. All are command hooks, `fleetd hook <event>`. Claude Code accepts only `command` and `mcp_tool` hooks for `SessionStart`, the tool hooks use a command so the hook process can reduce the payload, and the other four moved from `http` to `command` because the host port 7071 is unreachable from the agent's network namespace (ADR-0031 P2). For the two tool events the process keeps only the job id, `tool_use_id`, tool name, exit code and duration, and never forwards `tool_response`, content, stdout or stderr. Reports for unknown jobs or with garbage fields are dropped and counted. The daemon applies them to the job's telemetry, so the summary shows `bash_nonzero`. Claude Code spawns that process, so it does not share the unit's environment or `STATE_DIRECTORY` and `RUNTIME_DIRECTORY`. It loads `/etc/fleetd/config.toml` and then applies its own environment, so `FLEETD_HOOK_SOCKET` and `FLEETD_HOOK_SOCKET_UID` also work when they are set in the Claude Code process environment. The unit's `box.env` does not reach it. Set a non-default port or socket in `/etc/fleetd/config.toml`; without them it skips the relative `./fleetd.sock` and uses loopback port 7071. The subcommand reads the payload from stdin and POSTs it to `/hook/<event>` on the unix socket, else the loopback port. It uses `hook_socket` when that is set, else the main socket, and only when the path is absolute, the socket is owned by `hook_socket_uid` (default the current uid), the parent directory belongs to root or that uid and has no group or other write bit, and the connected peer's `SO_PEERCRED` uid equals that uid; otherwise it counts as a failed connect. It falls back to the loopback port only when the socket connect fails or the socket gives no status line within 1 second; any HTTP status from the socket is final and is not replayed. When `FLEET_JOB_ID` is set it sends it as an `X-Fleet-Job` header, cut to printable ASCII and 128 bytes. Config loading counts against the same budget. It caps input at 1 MiB and 2 seconds, prints errors to stderr only and always exits 0, so a down fleetd never blocks Claude Code. `fleetd` must be on the `PATH` of the Claude Code process. The hooks have no `onFailure`: on 2.1.289 it had no observable effect ([T8](../docs/phase0/T8.md)). A hook fired while fleetd is down was lost in the T8 runs, which saw no retry.


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

## Smoke test

`deploy/smoke.sh` submits one tiny read-only job through the live server with the `fleet` CLI and waits for it. It reads everything from the environment: `FLEET_SERVER_URL`, `FLEET_CLIENT_TOKEN` and `SMOKE_REPO` are required, and it refuses to start with a one-line message when one is unset. The token never goes on a command line and the script never prints it. Run it under fnox so the secret stays out of your shell history and scrollback:

```sh
fnox -c <your fnox.toml> exec -- deploy/smoke.sh
```

Optional variables: `SMOKE_BASE` (default `main`), `SMOKE_AGENT` (default `claude`, matches `[a-z0-9_-]{1,32}`), `SMOKE_DEADLINE_SECS` (default 300, integer 10 to 3600) and `FLEET_BIN` (default `fleet`). It polls `fleet status` every 5 seconds and prints the state and phase each time. The deadline counts polls (`SMOKE_DEADLINE_SECS` divided by 5), not wall clock, and a `fleet status` call that hangs has no outer bound, so a hung call can run past the deadline. On a `FAILED` job it also prints the job's `error` line to stderr before the logs. On a failed, cancelled, lost or timed out job it prints up to 4000 bytes of `fleet logs`, minus lines starting with `chmod:`. Control characters are removed from the printed transcript. On the deadline it runs `fleet cancel` best effort.

| Exit | Meaning |
| --- | --- |
| 0 | job succeeded |
| 1 | submit failed |
| 2 | missing or invalid input |
| 3 | job failed |
| 4 | job cancelled |
| 5 | deadline passed |
| 6 | unknown or lost state |
| 7 | submit returned an unusable job id |

Test the script with `python3 -m unittest deploy/tests/test_smoke.py`. It drives `smoke.sh` against a fake `fleet` and a fake `sleep`.

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

`fleet-tool-install@.service` (ADR-0048) runs `mise install --locked` as `fleet-job` with `MISE_SAFE=1` against a fleetd-written `/run/fleet/<id>/mise.toml`. The agent unit has `Requires=` and `After=` on it, so a failed install fails the job before the agent starts. `Requires=` also starts the install unit as a side effect of starting the agent unit, and the polkit rule allows a direct `start` of the install unit. The install writes only to `/var/lib/fleet/tools` (`MISE_DATA_DIR`, created by tmpfiles.d as `fleet-job` 0750), never under the `.cache` mirror. The agent unit mounts that directory read-only. A job without a `mise.toml` skips the install unit through `ConditionPathExists`. `PrivateNetwork=yes` stays on. The unit's `ExecStart` is `/usr/local/bin/fleetd tool-install-exec %i`, the install counterpart of `fleetd agent-exec`. It reads the `[mise]` pins from Box config, verifies the bundled `/usr/local/libexec/fleet/mise` (sha256, minisign, owner and mode), binds the in-namespace egress forwarder on `127.0.0.1:3128` aimed at `/run/fleet/<id>/job.sock`, and runs `mise install --locked` as a child with the four proxy variables naming the forwarder and `NO_PROXY` and `ALL_PROXY` removed. With no pins, or a binary that does not verify, it exits 2 with a fixed message and starts nothing. The job socket accepts the cgroup `system.slice/system-fleet\x2dtool\x2dinstall.slice/fleet-tool-install@<id>.service` of the same job id as well as the agent unit, and lets that unit select only the `egress proxy` service. Another job's install unit, another template and the agent of another job are refused. Before the launcher starts the agent unit, which pulls in the install unit, it requires the Box `egress_allow` exact host names to cover `tool_hosts` (`check_tool_hosts`) and writes `/run/fleet/<id>/tool-env` (`write_tool_env`, mode 0600, created through an `O_DIRECTORY|O_NOFOLLOW` handle on the job dir, the four proxy variables naming `http://127.0.0.1:3128`, no file when the job has no tools). A refused set fails the launch before any run directory or unit exists, with the fixed error `tool install hosts are not covered by egress_allow`. The host set derives from the closed tool registry (`tool_hosts`, exact names, no wildcard); a wildcard `egress_allow` entry does not count as covering an exact host. The production launcher sets `with_tool_install` when `[mise]` is configured, with a lookup that returns no tools at agent launch, because the install runs earlier in the pre-flight (next paragraph). Tested with a fake `systemctl`, a fake mise script and a fake job socket peer. Unverified: `MISE_SAFE=1` taking effect with `install`; the install slice name `system-fleet\x2dtool\x2dinstall.slice`; `/etc/fleetd/config.toml` being readable by `fleet-job`; connecting to `job.sock` through the read-only `BindReadOnlyPaths=/run/fleet/%i`; every host in `tool_hosts` (the mise-versions host, `nodejs.org`, `go.dev`, `dl.google.com`, `api.adoptium.net`, the GitHub asset hosts); the proxy path from the private network namespace. No live run has happened.

Environment setup unit (ADR-0067). `fleet-env@.service` runs one setup step per start as `fleet-job`, in `system-fleet\x2denv.slice`, with `PrivateNetwork=yes` and `TemporaryFileSystem=/run/fleet-env:ro`. Only `/run/fleet-env/<id>` is bound read-only and its `out/` subdirectory is bound writable (`BindPaths=`); the script sees it as `$FLEET_ENV_OUT`. `SystemdSetupLauncher` in `crates/fleetd/src/env_launcher.rs` replaces `UnavailableLauncher` under the systemd launcher. Per step it binds `step.sock` in `/run/fleet-env/<id>`, writes the `attempt` file, calls `systemctl start --no-block fleet-env@<id>.service`, polls `systemctl show` for the exit status and copies the socket to the step output. A refused start fails the Job, also for an `on_fail = continue` step. The unit's `ExecStart` is `fleetd env-setup-exec <id>`: it reads the `a<N>/step` script, runs it through its shebang interpreter in `out/` with a cleared environment (`PATH`, `HOME`, `FLEET_ENV_OUT`, `FLEET_ENV_SECRETS`, and the proxy variables when `job.sock` exists), and sends its output to `step.sock`. Setup-only secrets are written one file per name under `/run/fleet-env/<id>/secrets` (dir 0750, files 0440, group `fleet-work`), and the whole directory is shredded (zero overwrite, then unlink, rename-aside first) on every end path. At startup `fleetd` stops leftover `fleet-env@*` units and shreds every directory under `/run/fleet-env`, a planted symlink as a link. A step timeout is clamped to 1 through 600 s, the whole run stops at 1200 s. The polkit rule gained `fleet-env@<id>.service` for `start`, `stop`, `kill` and `reset-failed`, the same shape as the two other templates. Tested with a fake `systemctl` running the real `fleetd` as the shim. Unverified on a live box: the `Slice=` cgroup path (the launcher logs the `ControlGroup` it sees for ENV-6c), `BindPaths=` of `out/` under `TemporaryFileSystem=`, `fleet-job` connecting to `step.sock` and `job.sock` through the read-only bind, and `out/` carry to the agent (not built).

Tool install wiring (ADR-0048). A box with a `[mise]` table, the systemd launcher and `tool_cache_uid` installs a tool the cache lacks before the agent starts. `SystemdToolInstaller` in `crates/fleetd/src/systemd.rs` runs once per job for all missing tools: it requires the Box `egress_allow` exact names to cover `tool_hosts`, makes `/run/fleet/<id>/` (it refuses a dir that exists), writes `mise.toml` (`[tools]`, one `name = "version"` line per tool, mode 0640 in the job group) and `tool-env`, binds the job socket, calls `systemctl start --no-block fleet-tool-install@<id>.service`, polls `systemctl show` until the unit ends, then stops it, resets it and removes the dir before it returns. A non-zero exit, a refused start, a unit past 16 minutes (above `RuntimeMaxSec=15min`), an idle unit after 60 seconds and any malformed or oversized `show` output end the install; the last three send a kill first and count as ended. The runner then reads the cache again, so a unit that exits 0 without filling the cache still fails. Every failure gives the job `tool preflight failed`, and the log holds only an I/O error kind. Before the unit starts the proxy is narrowed to the install hosts for that job id, and the agent start replaces that set. `tool_cache_uid` (env `FLEETD_TOOL_CACHE_UID`) is the numeric uid that owns `/var/lib/fleet/tools`, normally `fleet-job`; the ADR names no uid and it differs per box, so a box with `[mise]` and no key refuses to start the job poller with `invalid tool_cache_uid value`, and root and 4294967295 are refused. A box without `[mise]` fails every tool profile with the fixed message. A box with `[mise]` and the direct launcher has no installer: it serves cache hits and fails every miss. The polkit rule, the tmpfiles line (`/var/lib/fleet/tools` owned by `fleet-job`, 0750) and the install unit already matched the sibling rules in `deploy/CLAUDE.md`, so no unit or rule changed. Tested only against a fake `systemctl`. Unverified on a live box: that `mise install --locked` accepts a `mise.toml` with no lockfile, that mise lays an install out as `<name>/<version>` under `MISE_DATA_DIR` (the cache expects that layout, see the Tool cache paragraph), that `fleet-job` can read the 0640 `mise.toml` through `/run/fleet/<id>`, the 16 minute and 60 second deadlines, and the `ExecMainCode` values of the oneshot unit that `parse_show` reads as ended.

Tool cache (ADR-0048, `ToolCache` in `crates/fleetd/src/tools.rs`): an entry is `/var/lib/fleet/tools/<name>/<version>`, keyed by a name from the closed registry and an exact version pin. `lookup` reads only and returns a hit when the name directory and the entry are real directories (no symlink), owned by the install uid and free of group and other write bits; a hit means the caller skips the install unit, any other state is a miss. Hostile names and versions (slash, `..`, NUL, empty, over-long, case variants, non-ASCII) fail the registry validators before a path is built. The runner reads the cache: `ToolPreflight` builds `ToolCache::new(/var/lib/fleet/tools, tool_cache_uid)` when `[mise]` is set and looks up each tool of a job's Profile. The agent unit and the install unit both run as `fleet-job`, the owner `lookup` checks for, so the owner check adds no separation between them. The read-only mount in the agent unit (`ReadOnlyPaths=/var/lib/fleet/tools`, pinned by a test) is the only barrier.

`touch`, `evict` and `lease` exist but no code in the daemon calls them (no caller outside `tools.rs` and tests). No `.last-used` marker is written and nothing evicts in production. When called, `touch` writes the `.last-used` marker (temp file with `O_EXCL`, then rename, the caller supplies the time, atime is never read) and `evict` runs one bounded pass: oldest marker first (no marker counts as oldest) while the total exceeds `MAX_CACHE_BYTES` (8 GiB) or the count exceeds `MAX_CACHE_ENTRIES` (64), each entry renamed to `.evicting-*` and then deleted with std recursive delete, stale aside directories swept first. In-use protection is a shared `flock` on the entry directory (`lease`): eviction takes the exclusive lock with `LOCK_NB` and skips a leased entry. `touch` and `evict` write, so they would have to run as `fleet-job`, the owner of the 0750 directory. Unverified live: `flock` on a directory handle across the real install and agent units, the read-only mount permitting the agent side to open the entry directory, how mise lays out installs under `MISE_DATA_DIR` against the `<name>/<version>` key, and eviction under a real concurrent job.

Status on the test box, which is the dev box mentioned below, stated plainly: an earlier layout of `fleet-agent@.service`, `fleetd-systemd.service` and the `sysusers.d` file was installed live on systemd 257. The `ExecStartPre=` `update-guard`, `/var/lib/fleet/bin`, `/var/lib/fleet/tools`, `/var/lib/fleet/seed` and their `tmpfiles.d` lines are on the dev box as of 2026-11-08, installed by the steps in [Enable self-update on an existing box](#enable-self-update-on-an-existing-box). `fleet-tool-install@.service` and the current layout of `fleet-agent@.service` are not installed there. `systemd-analyze verify ./fleet-agent@.service ./fleetd.service` on a scratch copy of the earlier units (`fleetd-systemd.service` copied as `fleetd.service`) on systemd 257.13 first failed on `CollectMode=`, which commit 3eb44b5 removed, and then exited 0 with no output. That run predates `fleet-tool-install@.service`, so no verify result covers `fleet-tool-install@.service` or the current `fleet-agent@.service`. It checks syntax only, not the mount behaviour. Run `systemd-analyze verify /etc/systemd/system/fleet-agent@.service /etc/systemd/system/fleetd.service` on the box before the first start anyway.

### Users and groups

- `fleetd` owns the daemon, its state under `/var/lib/fleetd` and `/etc/swarm/secrets.env`.
- `fleet-job` runs agents. Its primary group is `fleet-work`.
- `fleet-work` is the shared group. `fleetd` is a member, through `sysusers.d` and `SupplementaryGroups=fleet-work`. A non-root daemon can only chown to a group it belongs to.
- `/var/lib/fleet/jobs` is mode 3770 `fleetd:fleet-work`: group-writable, setgid and sticky. Others have no access, so `fleet-job` reaches the jobs dir only as a member of `fleet-work`. Each job has its clone there, plus `.agent/<job id>` (the per-job home) and the `.cache` mirror, which `fleetd` owns and the job group reads but never writes. The daemon unit's `ReadWritePaths=` covers only this directory. The agent unit reopens it too, then `ReadOnlyPaths=-/var/lib/fleet/jobs/.cache` makes the mirror read-only inside the agent's mount namespace, on top of the file modes.
- The broker scratch check (`scratch_is_private`) accepts the jobs root only when it is owned by the daemon uid or root, has no world write, and has group write only with the sticky bit. Mode 3770 passes; 2770 or 0775 without the sticky bit and any mode with world write make every job fail with `job broker could not be set up`. The `.broker` dir and each scratch dir must be mode 0700 owned by the daemon.
- `/run/fleet` is mode 0750 `fleetd:fleet-work` and holds the per-job run dirs. `/run/fleet/hook` holds the hook socket, mode 0750 `fleetd:fleet-work`.

Directories under `/var/lib/fleet`, from `tmpfiles.d/fleet.conf`:

| Path | Owner and mode | Role |
| --- | --- | --- |
| `/var/lib/fleet` | `root:root` 0755 | parent only |
| `/var/lib/fleet/jobs` | `fleetd:fleet-work` 3770 | job worktrees, `.agent/<job id>` homes and the `.cache` mirror |
| `/var/lib/fleet/tools` | `fleet-job:fleet-work` 0750 | tool cache, written by the install unit, read-only in the agent unit |
| `/var/lib/fleet/seed` with `cargo` and `npm` | `fleetd:fleet-work` 0750 | read-only warm-cache seed, filled by an operator as `fleetd`, see Warm caches |
| `/var/lib/fleet/bin` | `fleetd:fleet-work` 0755 | self-update: `current` and `previous` symlinks, version directories and the guard state files, see Self-update layout |

The agent unit mounts an empty read-only tmpfs over `/run/fleet` (`TemporaryFileSystem=/run/fleet:ro`) and bind-mounts back only `/run/fleet/%i` (`BindPaths=`, its own run dir with the per-job socket) and `/run/fleet/hook` (`BindReadOnlyPaths=`). By design, other jobs' run dirs and sockets are absent from the agent's mount namespace (ADR-0036). The mount shape is unprobed on a box, see Unverified below. This is the first isolation layer; the cgroup check in `jobsock.rs` is the second.

Unverified:

- The mount shape on a live box: that the per-job socket stays connectable through the bind, and that the agent still reads `env` and writes what it needs in its run dir.
- Ordering of `TemporaryFileSystem=` and `BindPaths=`. systemd documents that bind mounts are applied after the tmpfs, but no probe was run here.
- `BindReadOnlyPaths=` for the hook dir is stricter than ADR-0036's plain `BindPaths=`. Linux lets `connect()` reach a socket on a read-only mount, but this was not probed. If the hook client fails to connect, switch that line to `BindPaths=`. The fallback must keep `/run/fleet/hook` unwritable for `fleet-job`: the directory is mode 0750 `fleetd:fleet-work`, so group members have no write bit, and the switch must not change that mode.
- The fixed path `/run/fleet`: it must equal the `run_dir` fleetd uses. A different run dir needs a drop-in that changes all three lines.
- The hook dir path `/run/fleet/hook` is taken from `tmpfiles.d/fleet.conf` and the `hook_socket` example; it is not read from fleetd config.
- `ProtectSystem=strict` against the writable `BindPaths=/run/fleet/%i`: `/run` is read-only under `strict` and `ReadWritePaths=` names only the jobs dir, so whether the bound run dir stays writable for the agent is unprobed.
- `systemd-analyze verify`: see the status paragraph under Files for what ran. No result covers the current units.

The agent unit fails to start with exit status 226/NAMESPACE when `/run/fleet/hook` is missing, because `BindReadOnlyPaths=/run/fleet/hook` has no `-` prefix. Fix it by running `systemd-tmpfiles --create`, which creates the directory. The polkit rule accepts only `[A-Za-z0-9_]` in the job id of a unit name, while `valid_job_id` in `jobsock.rs` also accepts `-`. A job id with `-` therefore fails closed: polkit refuses to start its unit. `tmpfiles.d` creates `/run/fleet` and `/run/fleet/hook` instead of a second `RuntimeDirectory=` in the unit, because `RuntimeDirectoryMode=` applies to every name in the unit and `/run/fleetd` must stay 0700.

### Self-update layout

`fleetd-systemd.service` runs `ExecStart=/var/lib/fleet/bin/current/fleetd serve`. `tmpfiles.d/fleet.conf` creates `/var/lib/fleet/bin` (0755, `fleetd:fleet-work`) and seeds `current` as a symlink to `/usr/local/bin`, so a box that never updated runs the baked binary through the same path. The unit lists `-/var/lib/fleet/bin` in `ReadWritePaths=`, because `ProtectSystem=strict` otherwise keeps the swap read-only. The `-` prefix follows the rule in `deploy/CLAUDE.md`. The job units (`fleet-agent@.service`, `fleet-tool-install@.service`) are unchanged: they run the baked `/usr/local/bin/fleetd` and gain no path. The legacy `fleetd.service` (`User=agent`) is unchanged and stays on `/usr/local/bin/fleetd`: its user does not own the bin dir.

`fleetd::update::Swapper` unpacks `<ver>/fleetd.tar.gz` into `<ver>/fleetd` (0755, the version dir opens to 0755 so `fleet-job` can run it) and flips the links with `rename(2)` over a temp symlink: `previous` takes the old `current` target first, then `current` flips. Entries that are links, absolute paths, `..` paths or non-regular files refuse the archive, and the binary and total unpacked sizes are capped. Covered by `crates/fleetd/tests/update_swap.rs` against temp dirs and a relative root.

Restart and rollback: `ExecStartPre=-/usr/local/bin/fleetd update-guard` runs the guard from the baked, root-owned binary, never from `current`, so a broken update cannot disable its own rollback. The `-` prefix makes systemd start the daemon even when the guard cannot run, and the guard itself always exits 0. The guard keeps three files in `/var/lib/fleet/bin`, each written to a temp file and renamed over its name: `health` (the version that last proved healthy), `starts` (starts of `current` since then, with the version) and `bad_versions` (one version per line). On each start it reads `current`. A `health` file naming it clears `starts`. Otherwise `starts` grows by one, and once it already holds 3 (`MAX_UNHEALTHY_STARTS`, so the fourth start of an unproven version) the guard writes the version to `bad_versions`, moves `current` back to `previous` through `Swapper::rollback` (which also drops `previous`), marks the restored version healthy and clears `starts`. A corrupt, oversized, non-regular or non-UTF-8 `starts` file counts as the limit: with no proof of health and no trustworthy count the guard rolls back, the stricter reading. With no `previous`, a `previous` that is itself in `bad_versions`, or a `current` that is not a version name (the `/usr/local/bin` seed), the guard changes nothing and the daemon starts. `bad_versions` is checked by `Updater::apply`, so a rolled-back version is never swapped in again. The new binary writes `health` only after it has sent `READY=1` and one heartbeat the server accepted, so a daemon with no `FLEET_SERVER_URL` never marks itself healthy and an update on such a box rolls back. After a swap `Updater::apply` keeps claiming paused (`ClaimGate` through `Poller::with_gate` in `jobs.rs`), waits until `LeaseTracker` reports no held job, swaps, and raises `RestartSignal`, which ends `run` with exit 0 so `Restart=always` starts the new binary. `LeaseTracker` holds a job from the start of its runner until the runner returns or the job-end hook fires, so a lease that outlives its poller task still blocks the swap, and the 30 minute drain cap aborts the update, never a job. Covered by `crates/fleetd/tests/update_guard.rs`, `update_guard_process.rs` and `update_restart.rs` against temp dirs (a relative root included) and fakes.

Wired: the unit, tmpfiles, the swap module, the guard subcommand, the health marker and the restart request. A swap off the `/usr/local/bin` seed records no `previous`, so the first update has no rollback target and the guard only starts the daemon. The manifest loop is wired too: `runtime.rs` builds it with `update::start_production` whenever `FLEET_SERVER_URL` is set (see Update flow). Live run on 2026-11-08: see [Enable self-update on an existing box](#enable-self-update-on-an-existing-box).

Verified live on the dev box (2026-11-08): `systemd-analyze verify` on the changed unit exited 0 (the dev box run, exit code only, no output kept), `ReadWritePaths=-/var/lib/fleet/bin` made the path writable for `fleetd`, `rename(2)` over a symlink worked, and the unpacked layout matched the repacked release archive. Unverified: that systemd-tmpfiles `L` leaves an existing `current` alone when `--create` runs again after a swap, and the guard's rollback on a live box.

### Self-update runbook

Design: `docs/adr/0047-fleetd-self-update.md`. This section is the operator view and names the code each rule comes from.

Status, stated plainly: on 2026-11-08 the dev box took v0.3.8 through the whole path: the server fetched the signed manifest from GitHub Releases and relayed it, fleetd verified it, downloaded and staged the archive, swapped `current`, restarted and wrote the health marker. The rollback path and the key rotation have not run on a real box. The rest of the pieces are unit and process tested against temp dirs and fakes. The daemon side is wired: the heartbeat hands each reply's manifest pair to `update::UpdateDriver`, which verifies, stages and calls `Updater::apply` (see Update flow), and `crates/fleetd/tests/update_drive.rs` drives that path against a fake server reply, a fake archive fetcher and a test minisign key. The release workflow (`.github/workflows/release.yml`) now writes and signs the manifest (see CI signing route under Signing), and the v0.3.8 release ran it. The real download over TLS worked from the box.

#### Trust root

- Default key: fleetd embeds the release public key at build time from `crates/fleetd/trust/update.pub` (`BAKED_TRUST_KEY` in `crates/fleetd/src/update.rs`). A Box needs no key file to verify updates. CI checks that line 2 of that file equals the repository variable `FLEET_UPDATE_PUBLIC_KEY`, and the release workflow fails a tag build when the variable is empty.
- Optional override: `/etc/fleetd/update.pub` (`DEFAULT_TRUST_ROOT`). When the file exists it replaces the embedded key. Content: one minisign public key file, at most 1024 bytes (`MAX_TRUST_ROOT_BYTES`), UTF-8. A stale override wins over the embedded key after a rotation, so remove it (`sudo rm /etc/fleetd/update.pub`) when you rotate. Setting `update_trust_root` in the config file makes that path required: a missing file then disables updating.
- Needed owner and mode: a regular file owned by root (uid 0, `ROOT_UID`) whose mode has no group or other write bit (`mode & 0o022 == 0`). The same two checks apply to its parent directory, `/etc/fleetd`. A symlink at the path is refused (`O_NOFOLLOW`). `resolve_trust_root` returns `TrustRootWritable`, `TrustRootOwner`, `TrustRootNotRegular`, `TrustRootTooLarge` or `TrustRootInvalid` or `TrustRootIo`, updating stops, and fleetd never falls back to the embedded key. Only a file that does not exist selects the embedded key. ADR-0047 asks for 0644 root-owned.
- Install an override: put the public half of a key there as root, for example `sudo install -o root -g root -m 0644 update.pub /etc/fleetd/update.pub` with `/etc/fleetd` root-owned and 0755. The `fleetd` user must not be able to write either path, so a compromised daemon cannot widen what it trusts.
- Rotate: the embedded key changes only with a new fleetd build, so rotation takes four steps. (1) Ship a release signed with the OLD key whose binary bakes the NEW key. (2) Wait until every Box runs that release. (3) Switch the repository secret `FLEET_UPDATE_SIGNING_KEY` and the variable `FLEET_UPDATE_PUBLIC_KEY` to the new key. (4) Sign later manifests with the new key. A Box with an override file keeps trusting that file, so remove it first. A compromised old key has no in-band route, since an attacker holding it can sign the step 1 release too: push `/etc/fleetd/update.pub` with the new key as root to each Box.
- `crates/fleetd/src/tools.rs` reuses the same loader (`load_trust_root`) for the key that verifies the bundled mise binary, but that key is a separate file named by `public_key_path` in `[mise]`. The embedded key and `update.pub` do not change it. See [Bundled mise](#bundled-mise-and-the-mise-section).

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

  `targets` holds 1 to 16 entries. A target name is 1 to 64 bytes of `a-z`, `0-9`, `_`, `-`, `.`. `size` is 1 to 268435456 bytes (`MAX_ARCHIVE_BYTES`). `url` is optional in the schema but staging refuses a target without one (`NoUrl`); it must start with `https://`, stay under 2048 bytes, and pass the box egress policy. The manifest is at most 16384 bytes and the signature at most 1024 bytes (`MAX_MANIFEST_BYTES`, `MAX_SIGNATURE_BYTES` in `crates/fleet-proto/src/lib.rs`). A Box looks up the target its own binary was built for: `<ARCH>-unknown-linux-musl` for the musl build the release ships, `<ARCH>-unknown-linux-gnu` for a gnu build (`host_target` in `crates/fleetd/src/update/driver.rs`, `<ARCH>` is `std::env::consts::ARCH`). The release manifest carries the real dist target names `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`, so a gnu development build finds no target and never updates from a release.
- Accept rules (`Policy`, `verify_manifest`): `seq` strictly greater than the last accepted `seq` (kept in `update_seq` under the bin dir), `version` newer than the running one (`version_is_newer`), `min_protocol` not above what this fleetd serves.
- Archive layout: `fleetd-<target>.tar.gz`, ustar. The reader copies out the one regular file whose last path component is `fleetd`, at any depth, and skips every other regular file and directory without writing it (`crates/fleetd/src/update/unpack.rs`). Two such files, links, absolute paths, `..`, pax headers, other entry types and more than 1024 entries refuse the archive. The release repack builds an archive with one top-level `fleetd`.
- CI signing route: on a tag build the job `sign-update-manifest` runs after `host`. It first runs `.github/scripts/repack_release_archives.sh`, which turns each cargo-dist archive `fleetd-x86_64-unknown-linux-musl.tar.gz` and `fleetd-aarch64-unknown-linux-musl.tar.gz` into a gzip ustar archive of one regular file `fleetd` (mode 0755, owner 0:0, mtime 0, no pax header; `.github/scripts/repack_archive.py`). It then calls `.github/scripts/build_release_manifest.sh`, which runs `.github/scripts/update_manifest.py` over the repacked archives. The script writes `manifest.json` in the shape above with `seq` set to the workflow run number (strictly increasing, gaps allowed), `min_protocol` 1, urls of the form `https://github.com/<repository>/releases/download/<tag>/<archive>`, and the sha256 and size of each archive. The targets are named `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl`. The script refuses a bad version, `seq`, url, target or archive name, an empty or oversize archive, a duplicate or missing target and a manifest over 16384 bytes, with the fleetd limits. The job then signs with `minisign -S -H`, checks the signature starts with the prehash marker `ED`, and uploads the repacked archives (replacing the dist ones and deleting their stale checksum assets), `manifest.json` and `manifest.json.minisig` to the release. The release is created as a draft by `host`; the job `publish-release` publishes it only after `sign-update-manifest` succeeds on a tag push, so a failed signing job leaves a draft.
  - Secrets the operator sets in the repository settings: `FLEET_UPDATE_SIGNING_KEY` (the content of the minisign secret key file) and `FLEET_UPDATE_SIGNING_PASSWORD` (its passphrase; leave unset for a key made with `minisign -G -W`). Repository variable `FLEET_UPDATE_PUBLIC_KEY` (the second line of `crates/fleetd/trust/update.pub`, not secret): when set, the job verifies the signature with `minisign -V` before the upload, and CI compares it with the embedded key. A tag build fails when it is empty. On other runs, when unset, the job logs a notice and skips both checks. The workflow never prints or stores these values. The key custody stays with the release owner, and nothing in this repository generates or holds a real key.
  - With `FLEET_UPDATE_SIGNING_KEY` absent on a tag build, the `Sign` step fails with an error and signs nothing. The release stays a draft without a manifest, so no Box updates from it. The signing secrets are set on the `Sign` step only. The job publishes the two files with the release, and the server fetches them (step 5 below).
  - Dry run: the job `update-manifest-dry-run` runs on `pull_request` and `workflow_dispatch`. It runs the script tests (`python3 -m unittest discover -s .github/scripts -p 'test_*.py'`, a golden manifest and a hostile-input table), builds fixture archives, writes a manifest, signs it with a key generated for that run, verifies it with `minisign -V`, checks the `ED` prefix, and checks that a changed manifest fails verification. It never reads the release secrets.
  - Gap: a tag build now yields a draft release that is published only after the manifest is signed, with archives the fleetd unpacker reads and target names a musl fleetd looks up. Nothing in CI verifies the signature with fleetd's own `minisign_verify` code, so `verify_manifest` accepting a CI-made manifest is unproven until a real manifest meets a real Box. The tests unpack a repacked fixture with the real unpacker, not an archive made by a real dist run. The dist plan accepting the edited workflow (`allow-dirty = ["ci"]` is set), the apt `minisign` version on `ubuntu-22.04` (tested against 0.12 only) and a tag with `+` build metadata (refused) are the remaining unknowns. The Verify step passes without `FLEET_UPDATE_PUBLIC_KEY`, so set it.
- Sign and publish by hand, as a procedure for a release holder:
  1. Build the cargo-dist archives and compute `sha256sum` and the byte size of each.
  2. Write `manifest.json` in the shape above with `seq` one higher than the last published value. Never reuse or lower a `seq`: fleetd then rejects the manifest forever.
  3. `minisign -S -H -s <release secret key> -m manifest.json` writes `manifest.json.minisig`. Check it with `minisign -V -p update.pub -m manifest.json` before publishing.
  4. Upload the archives to the `https://` urls named in the manifest.
  5. Publish the release. It carries `manifest.json` and `manifest.json.minisig` as assets. The server runs with `FLEET_UPDATE_REPO` set (the Deployment in `infra/deployment.yaml` sets it to the public repository `a19simma/fleet`) and polls the latest published release every 900 seconds by default, plus or minus 10 percent (`FLEET_UPDATE_POLL_SECS`, 60 to 86400). It caches the last good pair in memory and relays both in `HeartbeatReply.update_manifest` and `update_signature`, and never signs. The operator does nothing per release. The server never holds the release key, so a compromised server can withhold or replay a manifest and cannot forge one. A replay fails the `seq` check. `FLEET_UPDATE_MANIFEST` (a file on the server) stays as break-glass and cannot be set together with `FLEET_UPDATE_REPO`.

#### Update flow

1. The server polls the latest release of `FLEET_UPDATE_REPO` (default every 900 seconds, plus or minus 10 percent) and caches the signed pair. While a poll fails or the seq gate rejects its pair, the wait doubles up to one hour (or the interval, if that is longer), and returns to the interval after an accepted pair. The Box heartbeat reply carries that pair, so fleetd picks the manifest up at its next heartbeat after the server's next poll. `Heartbeat::with_on_reply` passes it to an `OfferSink`, a one-slot channel: the latest pair replaces an unread one and an identical pair does not wake the driver. The loop exists only while `FLEET_SERVER_URL` is set and the trust root resolves. An override file that is present but unsafe or invalid, or a missing file named by `update_trust_root`, logs one warning, `self-update disabled`, and turns off updating and nothing else. A missing default file selects the embedded key and logs the source at info.
2. fleetd verifies the pair against the trust root (the override `/etc/fleetd/update.pub` or `update_trust_root` in the config file when present, else the embedded key) and the policy above, and looks up its target. Any refusal changes nothing.
3. Stage: fleetd downloads the archive from the first URL and every redirect hop only if the host matches `update_hosts` (default `github.com`, `objects.githubusercontent.com`, `release-assets.githubusercontent.com`), through `PolicyArchiveFetcher`. It checks size and sha256 against the manifest and stores the file as `/var/lib/fleet/bin/<ver>/fleetd.tar.gz` (file mode 0600, dir 0700 while staging, `crates/fleetd/src/update.rs`). `Swapper::unpack` writes `<ver>/fleetd` (0755) and opens the dir to 0755. A leftover from a crashed earlier run (`fleetd.tar.gz`, `fleetd` and their temp files) in a real 0700 directory owned by fleetd is unlinked first, without following symlinks, and the attempt proceeds. A symlinked, foreign-owned or loose version directory is refused and left alone. A failed stage deletes the version directory unless it is `current` or `previous`.
4. Drain: claiming pauses and the drain waits until no lease is held. After 30 minutes (`DRAIN_CAP`, `crates/fleetd/src/update/drain.rs`) the attempt aborts, claiming resumes and the staged copy is deleted. The drain never kills a job. A runner that panics ends its lease, so one panic does not block updates.
5. Swap: `Swapper` renames `previous` to the old `current` target, then flips `current` with `rename(2)` over a temp symlink (`crates/fleetd/src/update/swap.rs`).
6. Restart: `RestartSignal` ends the daemon run with exit 0 and `Restart=always` (`deploy/fleetd-systemd.service`) starts the binary behind `/var/lib/fleet/bin/current/fleetd`. `Updater::apply` refuses a version listed in `bad_versions`. After it raises the restart signal the driver refuses every later offer (`restart pending`), so a second apply cannot overwrite `previous` with an unproven version. The accepted `seq` is written to `update_seq` after the swap, so a failed attempt does not burn it.

Retries: the driver acts once per distinct manifest. A failure leaves `current` as it was and logs a closed reason with no URL and no path: a swap failure logs a fixed phrase per error kind (`SwapError::reason`), never the path or archive entry name. It retries only when a new manifest arrives, at most `MAX_ATTEMPTS_PER_VERSION` (3) times for one version until the daemon restarts. The version `HealthGate` marks healthy is the one `current` named at daemon startup, read once before the poll loop starts, so a swap in this process never marks the new version healthy.

#### Rollback

- Guard: `ExecStartPre=-/usr/local/bin/fleetd update-guard` in the unit runs the baked, root-owned binary, never `current`. It always exits 0. The `-` prefix lets the daemon start even if the guard cannot run. Its state files are in `/var/lib/fleet/bin`: `health`, `starts`, `bad_versions` (`crates/fleetd/src/update/guard.rs`).
- Count: each start of an unproven `current` raises `starts`. `MAX_UNHEALTHY_STARTS = 3`: starts 1 to 3 are counted and the 4th start of that version rolls back.
- Health marker: the new daemon writes `health` with its version after it sent `READY=1` and one heartbeat the server accepted (`HealthGate` in `crates/fleetd/src/update/restart.rs`). A daemon with no `FLEET_SERVER_URL` never marks itself healthy.
- Rollback action: the guard appends the failed version to `bad_versions` (kept to the last 64), moves `current` back to `previous` and removes the `previous` link (`Swapper::rollback`), writes `health` for the restored version without any heartbeat proof from it, and clears `starts`. It does nothing when `previous` is missing, equals `current`, or is itself in `bad_versions`, and it does nothing when `current` is the `/usr/local/bin` seed. The first update off the seed therefore has no rollback target.
- Check state: `sudo -u fleetd /usr/local/bin/fleetd update-guard` prints one outcome line, but it also counts a start, so prefer `ls -l /var/lib/fleet/bin` and `cat /var/lib/fleet/bin/{health,starts,bad_versions}`.
- Manual rollback: on the Box, as the owner of `/var/lib/fleet/bin` (`fleetd`), flip the link the same way `Swapper` does: `ln -s <previous version> /var/lib/fleet/bin/.current.tmp && mv -T /var/lib/fleet/bin/.current.tmp /var/lib/fleet/bin/current`, where `<previous version>` is the target shown by `readlink /var/lib/fleet/bin/previous`, run `rm /var/lib/fleet/bin/previous` (`Swapper::rollback` removes that link too), then `sudo systemctl restart fleetd`. Add the bad version to `bad_versions` (one version per line) so `Updater::apply` refuses it, and write that version to `health` only if it should count as proven. The `mv -T` form is an assumption about GNU coreutils on the Box and is unverified.
- Server side stop: unpublish the release (delete it or return it to draft) or supersede it with a release whose manifest carries a higher `seq`. The server gate never serves a lower `seq` than it holds, so a rollback manifest needs a higher `seq`, not a lower one. The cache is in memory and a server restart clears it, after which the server serves whatever the latest published release holds. Known limit: a manifest with a high `seq` that was never signed by the release key still enters the cache (the server does not verify signatures) and blocks every lower `seq` until the server restarts; fleetd rejects it, so no Box is harmed, but real releases do not reach Boxes until the restart. For break-glass, replace `FLEET_UPDATE_REPO` with `FLEET_UPDATE_MANIFEST` and deliver the pair yourself. Boxes already on the new version do not downgrade: the `seq` and version checks refuse an older manifest.

#### Release key custody

- Location: the private key lives offline (an encrypted removable drive or a hardware token held by the release owner) or as a secret of a protected CI environment that only the release workflow can read. It never lives on the fleet server, on a Box, or in this repository. ADR-0047 fixes this rule. The CI route exists (see CI signing route), with the key as the repository secret `FLEET_UPDATE_SIGNING_KEY`. Treat repository secrets as readable by anyone who can push a workflow to a tag; protect tag creation or move the secret into a protected environment before the first release.
- Who may sign: the release owner named by the repository owner, and one backup holder. Signing needs a passphrase for the key. Keep the passphrase apart from the key file.
- Storage: two copies of the encrypted key on separate offline media in separate places. Keep the public key in the repository at `crates/fleetd/trust/update.pub`, where fleetd embeds it.
- Rotation: generate a new key pair and follow the four rotate steps under Trust root: release signed with the old key that bakes the new one, wait for every Box, switch the secret and `FLEET_UPDATE_PUBLIC_KEY`, then sign with the new key and destroy the old key. Remove any `/etc/fleetd/update.pub` override first. A Template rebuild resets the Box to the baked binary and its embedded key.
- Compromise response: a leaked key lets an attacker ship a binary to every Box that fetches a manifest signed by it, and this is the one failure ADR-0047 names as fleet-wide. Steps: unpublish or delete the release that carries the leaked-key manifest, then restart the server so the in-memory cache drops the pair (or unset `FLEET_UPDATE_REPO` and restart to stop the feed entirely); generate a new key; push the new key as `/etc/fleetd/update.pub` on each Box as root, or rebuild the Template and replace Boxes; publish a manifest signed by the new key with a higher `seq`. A Box that already took a malicious binary runs it as `fleetd`, so treat the Box and its credentials as lost. A Box still on the old embedded key or an old override file will accept any manifest signed by the leaked key until the file is replaced, and a higher `seq` signed with the leaked key outranks yours. Do not trust the old key again.

Unverified, no live run: the rollback and key-rotation parts of the runbook; `minisign -S -H` output against `minisign_verify` 0.3 prehash handling on a real manifest; the manual rollback commands; the CI signing route for a rotated key.

### Enable self-update on an existing box

A box on `fleetd-systemd.service` from before the self-update layout has no `/var/lib/fleet/bin` and a unit that keeps it read-only. The server then relays a manifest and fleetd logs `update failed reason="staging write failed"` on each offer. Seen on the dev box on 2026-11-08, where the unit had `ReadWritePaths=/var/lib/fleet/jobs /run/fleet` and `ExecStart=/usr/local/bin/fleetd serve`. fleetd does not log the errno, so the missing directory and the read-only sandbox are the inferred cause, and the fix below cleared it.

This is for a box already on the systemd-launcher layout (`User=fleetd`). A box on the legacy `fleetd.service` (`User=agent`) must follow [Install order](#install-order) instead, because the swap to the `fleetd` user also needs the sysusers, secrets ownership and `fleet-agent@.service` steps.

Run as root on the box, from a checkout of the release you run:

```sh
sudo install -o root -g root -m 0644 deploy/tmpfiles.d/fleet.conf /etc/tmpfiles.d/fleet.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/fleet.conf
sudo cp -p /etc/systemd/system/fleetd.service /root/fleetd.service.bak
diff /etc/systemd/system/fleetd.service deploy/fleetd-systemd.service
sudo install -o root -g root -m 0644 deploy/fleetd-systemd.service /etc/systemd/system/fleetd.service
sudo systemd-analyze verify /etc/systemd/system/fleetd.service
sudo systemctl daemon-reload
sudo systemctl restart fleetd
```

Read the `diff` before the `install`. The expected difference is the `ExecStartPre=-` update-guard line, `ExecStart=/var/lib/fleet/bin/current/fleetd serve` and `-/var/lib/fleet/bin` in `ReadWritePaths=`. Any other difference is a local setting to carry over by hand. `--create` also makes `/var/lib/fleet/tools`, `seed` and `/run/fleet/hook`. The restart ends a running job.

Check:

```sh
ls -la /var/lib/fleet/bin
/var/lib/fleet/bin/current/fleetd --version
journalctl -u fleetd --since -10min | grep -E 'update|guard'
```

On the dev box the first offer after the restart was applied: `update applied, exiting for restart`, then `update-guard: start 1 of the current version`, then `update offer ignored reason="seq not newer"`. `current` pointed at `0.3.8`, and `health`, `starts` and `update_seq` were present. The swap off the `/usr/local/bin` seed records no `previous`, so this first update has no rollback target. To go back, restore the backup unit, then run `daemon-reload` and `restart`. The unit then runs `/usr/local/bin/fleetd` directly. This rollback has not been run.

Requirements outside the box: `FLEET_UPDATE_REPO` set on the server, server egress to the release hosts on 443 (on the dev box's cluster the fetch failed with `release host unavailable` until the egress policy admitted them), and box egress to the hosts in `update_hosts`.

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

Set these in `/etc/fleetd/config.toml`, which must be root-owned, mode 0644, not writable by `fleetd` or `fleet-job`, because the hook client trusts `hook_socket_uid` from this file. The hook client loads the same config as the daemon (`Config::load`), so it and the daemon both accept the environment variable in the second column, and the variable wins. Keep the file as the source of truth and do not pass these variables into the job environment.

| Key | Variable | Value for this mode |
| --- | --- | --- |
| `agent_launcher` | `FLEETD_AGENT_LAUNCHER` | `"systemd"` (default `"direct"`) |
| `systemctl_path` | `FLEETD_SYSTEMCTL_PATH` | absolute path, default `/usr/bin/systemctl` |
| `hook_socket` | `FLEETD_HOOK_SOCKET` | `"/run/fleet/hook/hook.sock"` |
| `hook_socket_uid` | `FLEETD_HOOK_SOCKET_UID` | the numeric uid of `fleetd` (`id -u fleetd`) |
| `hook_socket_group` | `FLEETD_HOOK_SOCKET_GROUP` | `"fleet-work"` |
| `job_group` | `FLEETD_JOB_GROUP` | `"fleet-work"` |
| `tool_cache_uid` | `FLEETD_TOOL_CACHE_UID` | the numeric uid of `fleet-job` (`id -u fleet-job`), required when `[mise]` is set |
| `jobs_dir` | `FLEETD_JOBS_DIR` | `"/var/lib/fleet/jobs"` |
| `claude_bin` | none | `"/usr/local/bin/claude-real"` |
| `model_allowlist` | none | optional array of exact, case-sensitive model ids, for example `["model-a", "model-b"]`. fleetd refuses a job whose model is outside it before any process starts. An empty array, an empty entry or a duplicate stops startup. Unset means fleetd trusts the server's `FLEET_MODEL_ALLOWLIST`. Set it on every Box (ADR-0054). |

```toml
agent_launcher = "systemd"
hook_socket = "/run/fleet/hook/hook.sock"
hook_socket_uid = 996
hook_socket_group = "fleet-work"
job_group = "fleet-work"
jobs_dir = "/var/lib/fleet/jobs"
claude_bin = "/usr/local/bin/claude-real"
```

The `996` is an example. Use the uid `id -u fleetd` prints. The socket group follows the fleetd egid unless the run dir is setgid, which affects only whether the job uid can connect. Without `job_group`, the run dir keeps no job group and the job uid cannot read `spec.json`, so set it in this mode.

A hook socket under `/run/fleetd` is unreachable by the job uid, because that directory is mode 0700. That is why `hook_socket` lives in `/run/fleet/hook`. The hook client accepts the socket when its owner and its `SO_PEERCRED` peer are `hook_socket_uid` and the parent directory has no group or other write bit. Mode 0750 satisfies that.

### Run dir and unit contract

For each job the launcher creates `/run/fleet/<job id>/` (the job id matches `[A-Za-z0-9_-]{1,64}`), mode 0750 with the job group, holding:

- `env`, mode 0600, the agent environment as an `EnvironmentFile`. systemd reads it as root, so the job uid never needs it.
- `spec.json`, `argv` and `cwd` only, written by the launcher and read by `fleetd agent-exec <job id>` as the job uid. Mode 0640 with the job group. It never holds the environment.
- `stdout`, a FIFO with mode 0660 and the job group. The unit's `StandardOutput=file:/run/fleet/%i/stdout` writes to it, and fleetd reads it.

The launcher runs `systemctl start --no-block fleet-agent@<job id>.service`, polls `systemctl show`, and when the unit ends (`inactive`, `failed`, or `active (exited)`) calls `stop` and `reset-failed` and removes the run dir. Cancel is `systemctl kill` and `stop`, which kill the whole cgroup. On the normal end path the launcher calls `stop` and `reset-failed` and removes the run dir, and `stop` runs the unit's `ExecStopPost=` command, the `chmod` described in [Job agent environment](#job-agent-environment). A launcher handle dropped before that cleanup (a cancelled or aborted job) sends `systemctl kill --kill-whom=all --signal=SIGKILL` and `reset-failed` and makes no `stop` call. The unit runs at most `RuntimeMaxSec=2h`.

At startup, after it holds its port and sockets and before it polls for work, fleetd removes every directory under `/run/fleet` whose name is a job id, since none belongs to a live job of the new process. A unit for that id is handled by state: a unit in any state other than `inactive` or `failed` (that includes `activating`, `deactivating` and `reloading`) is stopped, then reset-failed; a `failed` unit is reset-failed; an inactive unit gets no call. The sweep leaves symlinks, files, `hook` and other names alone. The job worktree under `/var/lib/fleet/jobs/<id>` and `.agent/<id>` are not swept: remove them by hand after a crash. The sweep runs only after the daemon holds its sockets, so a second instance cannot sweep a running one. fleetd reports ready only after the sweep, so `TimeoutStartSec` governs a long sweep; the unit leaves it at the systemd default. `fleetd-systemd.service` sets `TimeoutStopSec=15`, which equals the 15 second jobs grace in `runtime.rs`, so systemd can send `SIGKILL` before a draining job's final report is sent: there is no margin.

The unit sets `RemainAfterExit=yes` and no `CollectMode=`. systemd unloads a unit that exits cleanly, and with `CollectMode=inactive-or-failed` a failed one too, and `systemctl show` then reports `Result=success` and `ExecMainStatus=0` for every exit code, so the launcher would read a failure as no result. With `RemainAfterExit=yes` a clean exit stays `active (exited)` and a failed unit stays `failed`, both with the real status, until `systemctl stop` or `reset-failed`. The launcher must stop the unit after reading the status, because `reset-failed` leaves an `active (exited)` unit loaded. polkit allows `stop` for these units.

The unit sets `ProtectProc=invisible`, `ProcSubset=pid`, `PrivateTmp=yes`, `NoNewPrivileges=yes` and `MemoryMax=2300M` with `TasksMax=512`. `CPUQuota` is unset. `PrivateTmp=yes` is required: with `ProtectSystem=strict` and a shared `/tmp`, Claude Code fails at start with `EROFS: read-only file system, mkdir '/tmp/claude-<uid>'`. `PrivateTmp=yes` also fails a `ReadWritePaths=` entry under `/var/tmp` with status 226/NAMESPACE, which is why the jobs dir lives outside `/var/tmp`. `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` stays open because `AF_UNIX` alone blocks loopback. `InaccessiblePaths=/etc/swarm` hides the secrets directory from the job.

`fleetd-systemd.service` omits `RestrictSUIDSGID=yes`. fleetd chmods each shared job dir to mode 2770, and that filter makes the chmod fail with EPERM, so every job ends with `workspace could not be prepared`. The daemon has no capabilities and `NoNewPrivileges=yes`, and the agent unit keeps `RestrictSUIDSGID=yes`.

### Network

The template sets `PrivateNetwork=yes`, and no drop-in relaxes it. ADR-0031 P2 is done on the unit side: inside the namespace the job sees only its own loopback. `fleetd agent-exec` listens on an ephemeral `127.0.0.1` port there and forwards each connection to the egress proxy over `/run/fleet/<job id>/job.sock`. `HTTPS_PROXY` and `NODE_USE_ENV_PROXY=1` point at that port, so the model API is the only reachable host, and only through fleetd's `egress_allow` list. A unix socket on the filesystem crosses a network namespace, and the unit bind-mounts both paths the job needs: `BindPaths=/run/fleet/%i` for `job.sock` and `BindReadOnlyPaths=/run/fleet/hook` for the hook socket. Linux lets `connect()` reach a socket on a read-only mount, but this was not probed on a box.

Timing telemetry crosses the `PrivateNetwork=yes` boundary the same way (ADR-0055). fleetd runs one OTLP/HTTP receiver per job on the unix socket `/run/fleet/<job id>/otel.sock`, mode 0660 with the job group, so the job uid can connect. It accepts `POST /v1/logs` with `Content-Type: application/json` and a per-job bearer token. `fleetd agent-exec` binds a second forwarder on `127.0.0.1:<port>` inside the namespace, with a port fleetd chooses, and relays raw bytes to that socket. It serves at most 4 connections, closes a connection idle for 30 seconds and carries at most 16 MiB per connection. The forwarder starts only when `agent-exec` runs in a private network namespace. If it fails to start, the job runs and loses its timing. fleetd sets `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` to `http://127.0.0.1:<port>/v1/logs` on the Claude child, and a Profile or Job cannot override any `OTEL_*` name. The bind-mounted `/run/fleet/%i` already carries `otel.sock`, so the unit needs no extra path. Unverified: a full timing run through this path on a live box. The loopback probe covers transport only.

Loopback probe result: `deploy/probe-agent-loopback.sh` runs under `sudo` on a box and starts a unit from `fleet-agent@.service`. It has not been run on a live host (ADR-0055). Under `PrivateNetwork=yes` a TCP connect to the host loopback is expected to fail and a unix socket to work, which is why the receiver listens on a unix socket and a forwarder bridges the namespace loopback. The probe's transport lines report reachability and do not change its exit code, only its control checks do.

The unit needs the wiring: `PrivateNetwork=yes` leaves the job no route to the model API except through the egress proxy that fleetd serves on the job socket. A fleetd that runs `agent_launcher = "systemd"` with no services registered cuts the model API for every job, and logs `agent_launcher is systemd and no services are registered` at startup. Deploy the unit and a fleetd that registers the egress proxy together, never the unit alone.

The host hook port `127.0.0.1:7071` is unreachable from the namespace. All seven managed hooks are therefore `command` hooks, `fleetd hook <event>`, which reach fleetd over the hook socket. Set `hook_socket` in `/etc/fleetd/config.toml` to a socket under `/run/fleet/hook`.

To verify on a box:

1. `systemd-analyze verify /etc/systemd/system/fleet-agent@.service /etc/systemd/system/fleetd.service` exits 0.
2. `python3 -m json.tool /etc/claude-code/managed-settings.json` parses and `grep -c '"type": "http"'` prints 0.
3. Run one job. In its unit, `systemctl show fleet-agent@<job id>.service -p PrivateNetwork` prints `PrivateNetwork=yes`, and the hook events for the job arrive in the fleetd queue.
4. Upgrading a box that has the old `allow-network.conf` drop-in (keep this note until no box carries the old drop-in): delete `/etc/systemd/system/fleet-agent@.service.d/allow-network.conf` and run `sudo systemctl daemon-reload` only once the fleetd that registers the egress proxy is running, because `PrivateNetwork=yes` then leaves jobs no route to the model API. The startup warning `agent_launcher is systemd and no services are registered` is a guard: its absence does not prove egress works, so run a job and confirm it reaches the model API.

### Build-chain egress preset

`deploy/box/config.toml` is an example Box config. It sets only `egress_allow`, with exact hosts for cargo, npm, pip, GitHub and Docker Hub (ADR-0049). It holds no wildcard. `config.rs` rejects a wildcard over a bare TLD such as `*.org` and accepts `*.example.org`. Copy the list into `/etc/fleetd/config.toml` to enable build chains on a box.

The host list is unverified until observe mode (`egress_observe`) captures real build traffic on a box. Expect to add or drop hosts then. Only the Box owner edits this list; a Job only narrows it.

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

### Setup unit probe

Status: not run. No Box was available when the script was written, so `deploy/probe-env-setup.sh` is checked statically only (`bash -n`, `shellcheck`, and `crates/fleetd/tests/env_probe_script.rs`, which parses `fleet-env@.service` and the probe list). No live output exists. [ADR-0067](../docs/adr/0067-job-environments.md) stays unbuilt until the output of a run on a Box is recorded, since decision 6 claims each sandbox directive of the Setup unit and none is verified.

Run it on a Box with both units installed, as root, one command:

```sh
sudo bash deploy/probe-env-setup.sh
```

The first output line is `output: <path>`, a file under `/var/tmp` that gets one line per probe, `PASS|FAIL <name> <detail>`. The exit status is 0 only when every probe passes, 1 on a `FAIL` or a missing control, 2 on a missing precondition (not Linux, not root, a unit or user absent). `bash deploy/probe-env-setup.sh --list` prints the probe names and the directives each covers and touches nothing.

Each probe runs the properties of the installed `fleet-env@.service` (or `fleet-agent@.service` for the agent-side probes) in a transient unit and first runs a positive control: the same check with the one directive removed or overridden, or on the host, must show the thing the directive hides. A probe whose control does not show it reports `FAIL <name> control absent: ...`, never `PASS`. The only network targets are `1.1.1.1:443` and a unix socket the probe creates at `/run/fleet-env/<id>/job.sock`; `/etc/swarm` is stat-ed and access-checked, never read. Fixtures are created under the id `probe<pid>`, an existing name is refused and the cleanup trap removes them.

Limits of the probes, from reading the script:

- `proxy-path` proves `lo` and the unix socket path. It does not run the forwarder of `env-setup-exec`, so the TCP to unix relay stays untested.
- `env-out-writable-visible` copies the marker to `/run/fleet/<id>/envd/out` itself, because the launcher does not carry `out/` to the agent yet. It proves the agent unit sees that path, not the carry.
- Inferred, not part of the design: `env-dir-unreadable-from-agent` can report `FAIL`. `fleet-agent@.service` now sets `TemporaryFileSystem=/run/fleet-env:ro` (the agent reads its env from `/run/fleet/<id>/envd`, never `/run/fleet-env`), so a `FAIL` there is a regression in the unit, not a script fault.

### Credential isolation probe

Status: not run. Set `BOX` to the test box host name and `SERVER` to the fleet server URL. Run the steps as the operator over `ssh agent@$BOX`. Every command prints a status or a count, never a value. `JOBUID` is `fleet-job` and `FPID` is the fleetd main pid.

1. Job uid cannot read fleetd secrets. Expect `denied` twice. A control runs first: it reads `/etc/hostname` as `fleet-job` and must succeed, so a missing user, a failed `sudo` or an empty pid prints `control failed` and stops, never `denied`.

   ```sh
   ssh agent@$BOX 'FPID=$(systemctl show -p MainPID --value fleetd); { id -u fleet-job >/dev/null && [ "${FPID:-0}" -gt 0 ] && sudo -u fleet-job sh -c "head -c1 /etc/hostname >/dev/null"; } || { echo "control failed"; exit 1; }; for f in /proc/$FPID/environ /etc/swarm/secrets.env; do sudo -u fleet-job sh -c "head -c1 $f >/dev/null 2>&1 && echo readable || echo denied"; done'
   ```

2. Job env and argv hold no token. A job must be running. The loop runs under `sudo` so every `/proc/<pid>/environ` is readable, and errors stay visible. Expect `sampled` of at least 1 and `tokens=0`. `sampled=0` or any read error fails the step, so `tokens=0` means the environ files were read and were clean. A process that exits between `pgrep` and the read prints `unreadable environ` and fails the step, and a zombie `fleet-job` process has an empty environ and prints `empty environ`. Both fail safe: rerun the step while the job is still running.

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

5. Another job's socket is refused. Submit job B first and read its id from the submit output, then put that id in job A's prompt and submit A while B still runs (`sleep 120` holds it). In job A, connect to job B's socket path and print only the outcome. The path `/run/fleet/<job B id>/job.sock` assumes `run_dir=/run/fleet` and the per-job layout of ADR-0037, which this probe has not confirmed. A's mount namespace holds no B directory, so the connect most likely fails with `No such file or directory` from the mount layer before the cgroup check runs. That outcome passes this step and does not exercise the cgroup check. As a control, connect to `/run/fleet/$FLEET_JOB_ID/job.sock` from A: it must not fail with a mount error.

   ```sh
   fleet submit --server $SERVER --repo <test repo url> --prompt 'sleep 120'
   fleet status --server $SERVER <job B id>
   fleet submit --server $SERVER --repo <test repo url> --prompt 'python3 -c "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(\"/run/fleet/<job B id>/job.sock\")" 2>&1 | tail -1; echo done'
   ```

6. A push to another branch is impossible. `fleetd broker push` takes no branch argument, and the target is the bound `swarm/<job id>` branch. Expect the extra argument refused and the branch list unchanged.

   ```sh
   fleet submit --server $SERVER --repo <test repo url> --prompt 'run: fleetd broker push refs/heads/main; fleetd broker push --branch main'
   ssh agent@$BOX 'git ls-remote --heads <test repo url> refs/heads/main | cut -f1'
   ```

   Compare the `main` sha before and after the job. Expect no change. `git ls-remote` separates the sha and the ref with a tab, so a `grep -c " refs/heads/main$"` with a space always counts 0 and proves nothing.

Record each outcome in the run log. Do not mark this check passed until all six hold on the box.

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

`disposable = true` in `/etc/fleetd/config.toml` declares that the Box holds nothing worth protecting from its jobs. It defaults to false. On a disposable Box a Job with no Profile runs with `--dangerously-skip-permissions`. On any other Box fleetd passes `--permission-mode dontAsk`, so a job is not left waiting on a permission prompt. A kimi job starts only on a disposable Box: on any other Box fleetd never starts the binary. Set it only on a Box that holds nothing worth protecting. A Box that runs kimi must be such a Box, because kimi needs it and fleetd refuses the job otherwise. A Box shared between users, or one that holds data you care about, must leave it unset.

### egress_allow

`egress_allow` is the Box ceiling for outbound hosts. List exact hosts only: `config.rs` rejects a wildcard over a bare TLD and accepts `*.example.org`, and a Job can only narrow the list. `deploy/box/config.toml` is the preset for cargo, npm, pip, GitHub (`github.com`, `api.github.com`, `codeload.github.com`, `objects.githubusercontent.com`) and Docker Hub. The host list is unverified. It stays unverified until observe mode (`egress_observe`) has captured real traffic on a box. That key is not yet in running boxes, so do not rely on it. Expect to add or drop hosts after the capture.

### Credentials

A job uses a fine-grained PAT (`github_pat`) scoped to throwaway repos or, for a User with a `github_app` credential, a one-hour installation token and the bot identity the server sends (ADR-0058). fleetd refreshes the token under 10 minutes before expiry, before a push or `gh` child, a mirror fetch or a broker `gh` call, up to a per-Job mint cap and a per-User rate limit. fleetd revokes the replaced token and, when the job ends, the held one, best effort with a 10 second bound; a token it cannot revoke expires within the hour. See [Settings](#settings) for where fleetd reads and scrubs the token.

### Docker mode

Docker in a Job is refused until the spike in [ADR-0049](../docs/adr/0049-job-docker-and-build-egress.md) passes. A Job never gets a root docker socket: `fleet-job` is not in the `docker` group and the agent and install units list `/run/docker.sock` and `/var/run/docker.sock` under `InaccessiblePaths=` (with the `-` prefix, so an absent path is skipped). A docker socket at any other path, such as a rootless one, is not covered. Jobs run without docker meanwhile.

### Warm caches

Warm caches (BOX-7). `/var/lib/fleet/seed` (tmpfiles.d: `fleetd:fleet-work` 0750, with `cargo` and `npm` subdirectories) is a read-only seed that an operator or install step fills as the fleetd uid: `cargo` holds a `CARGO_HOME` (registry and git checkouts), `npm` holds an npm cache. A job never writes it, and no cache is shared writable. `warm_job_caches` in `crates/fleetd/src/tools.rs` byte-copies the seed into `cargo-home` and `npm-cache` inside the job's own directory (new inodes, `nlink` 1, mode 0600 or 0700 with an execute bit, 0700 directories; no hardlink or reflink, so a write or delete in the copy cannot reach the seed, which a test pins by hashing the tree before and after). Caps are `MAX_SEED_BYTES` (2 GiB), `MAX_SEED_FILE_BYTES` (256 MiB), `MAX_SEED_ENTRIES` (200000) and `MAX_SEED_DEPTH` (32), each tested at the limit and one over with a shrunk value through `SeedLimits`. A symlink (absolute, relative, out of tree, or as a root or subdirectory), a file with `nlink` above 1, a fifo, a socket or a device refuses the whole copy and removes the partial result; a missing seed gives empty cache directories. `cache_env` is the pure function for the job env: `CARGO_HOME` and `npm_config_cache` name the copy, require absolute paths and refuse NUL, CR and LF. The agent unit adds `ReadOnlyPaths=-/var/lib/fleet/seed` (the `-` prefix because the directory is created at runtime). The install unit is unchanged: `ProtectSystem=strict` already leaves the seed read-only there and its `ReadWritePaths=` lists only the tool cache, so no unit was widened. Nothing calls `warm_job_caches` or `cache_env` from the runner yet (TOOL-8 owns the runner). Unverified: the npm cache layout a seed needs (`npm_config_cache` pointing at a copied `_cacache`), how cargo behaves offline or with `net.offline` against a seeded `CARGO_HOME`, whether a copied registry index is fresh enough to avoid a full index fetch, whether the seed is large enough to repay the per-job copy time, `fleet-job` reading the 0750 seed through `fleet-work`, and the populate step itself, which no code performs.

### Bundled mise and the `[mise]` section

A box that installs job tools needs three things: a verified mise binary, the `[mise]` table in `/etc/fleetd/config.toml`, and `tool_cache_uid`.

```toml
tool_cache_uid = 995

[mise]
version = "<pinned mise version>"
sha256 = "<64 lowercase hex characters>"
signature_path = "/etc/fleetd/mise.minisig"
public_key_path = "/etc/fleetd/mise.pub"
```

The `995` is an example. Use the uid `id -u fleet-job` prints.

- All four `[mise]` keys are required. A missing key fails with a message naming it, `sha256` must be 64 lowercase hex characters, and unknown keys are refused. With `FLEET_SERVER_URL` set, an invalid table stops startup with an error naming `mise`. Without it nothing reads the table. The table is config-file only. Use absolute paths: the tests keep relative paths as written, and nothing resolves them against a base.
- `tool_cache_uid` is required whenever `[mise]` is set (also `FLEETD_TOOL_CACHE_UID`, which wins). Without it the job poller refuses to start with `invalid tool_cache_uid value`. Root (0) and 4294967295 are refused. A box without `[mise]` ignores the key.
- The binary is `/usr/local/libexec/fleet/mise` (`MISE_BINARY` in `crates/fleetd/src/agent_exec.rs`). Nothing in this repository installs it: the operator or the Template puts it there. `verify_mise` refuses it unless the file is a regular file and not a symlink, owned by root (`MISE_OWNER_UID` 0), without group or other write bits, with the same owner and mode on its directory, at most 256 MiB, and its sha256 and minisign signature match the pins. The install unit runs this check each time through `fleetd tool-install-exec`.
- The public key file at `public_key_path` goes through the same root-owned, not group or other writable check as `/etc/fleetd/update.pub`. It is a separate key and file. Keeping the mise key apart from the release key is a choice of this layout: nothing ties the two together.
- Unverified: that `signature_path` accepts a signature made with or without the minisign prehash flag, and every mise release asset layout. No box has run the check.

### Config file owner and mode

Any config file that selects a trusted principal must be owned by root, mode 0644, and not writable by `fleetd` or `fleet-job`. Install it with `sudo install -m 0644 -o root -g root <file> /etc/fleetd/config.toml`. The job uid must be able to read it. For `secrets.env` use `fleetd:fleetd` mode 0600 (see [Install order](#install-order)).

### Server variables

These are fleet-server settings. `infra/README.md` carries the same rows.

| Variable | Meaning |
| --- | --- |
| `FLEET_UPDATE_MANIFEST` | break-glass only: path of the signed update manifest. The signature is the file of the same name with `.minisig` appended. Unset or empty means no manifest. Setting it together with `FLEET_UPDATE_REPO` stops startup. |
| `FLEET_UPDATE_REPO` | `owner/repo` of the GitHub repository whose latest release carries the signed update manifest (ADR-0060). The owner is 1 to 39 bytes of letters, digits and `-`. The repository is 1 to 100 bytes of letters, digits, `.`, `_` and `-`, and not `.` or `..`. Anything else stops startup. Setting it together with `FLEET_UPDATE_MANIFEST` stops startup. Unset or empty means no feed, with no warning. When set, the server polls the latest release and relays the last good pair in `HeartbeatReply`. |
| `FLEET_UPDATE_POLL_SECS` | seconds between release feed polls. Default 900. A value below 60 or above 86400 stops startup. While a poll fails or the seq gate rejects its pair, the wait doubles up to one hour (or the interval, if that is longer), and returns to the interval after an accepted pair. |
| `FLEET_MODEL_ALLOWLIST` | comma-separated list of exact, case-sensitive model ids a Job may use. Unset means the server applies no model restriction. An empty list, an empty entry, a duplicate, an over-long entry or a disallowed character stops startup. The server checks it at Profile save, Job submit, batch submit and when it serves the Profile blob to a leased Box (ADR-0054). Set `model_allowlist` on each Box too, see [fleetd settings](#fleetd-settings). |

The ADR-0048 server switch for Profile `tools` is removed and stops startup if that variable is set, to any value. Profile `tools` need the `profile:tools` capability on the saving user (for `tools`, and for a selection that names a `tool` Catalog item), on the submitting user, and on the job owner when the server serves the blob to a leased Box. Tools are accepted only in TOML Profile content (`content_toml`). A Box still needs `[mise]`, see [Bundled mise](#bundled-mise-and-the-mise-section).
