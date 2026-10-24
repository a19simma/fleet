# Deploying fleetd

Two files configure a box: a systemd unit for the daemon and a Claude Code managed settings file that points the hooks at it. The paths and the user name `agent` are examples. Change them to match the box.

## Install

1. Put the `fleetd` binary at `/usr/local/bin/fleetd`. The [root README Install section](../README.md#install) says how to get it.
2. Copy `fleetd.service` to `/etc/systemd/system/`. Adjust `User=`, the uid in `user@1000.service` and `XDG_RUNTIME_DIR`, and the `ReadWritePaths=` home paths. workmux and pueue keep their sockets and state under the user runtime directory, so the unit orders after `user@1000.service` and sets `XDG_RUNTIME_DIR` (plan, systemd unit section; T9). The uid 1000 is an assumption: match it to `User=`. The `-` prefix on a `ReadWritePaths=` path makes systemd skip it when it does not exist. `ProtectHome=read-only` makes all of `/home` read-only, and `ReadWritePaths=` reopens only the listed paths: the workmux state, and `~/.claude`, `~/.config` and `~/.cache`, which `claude -p` writes because the agent child keeps the real `HOME`. `~/.claude.json` sits directly in the home directory and is not reopened, because a single-file entry breaks its atomic rename and reopening the home directory would undo `ProtectHome`. If Claude Code needs to write it on your box, start `claude` once as `agent` outside the unit, or add `-/home/agent` to `ReadWritePaths=` and accept the wider write scope. This path set is unverified on a live box and `systemd-analyze verify` was not run (not available where this was written).
3. Copy `managed-settings.json` to `/etc/claude-code/managed-settings.json`, or to `/etc/claude-code/managed-settings.d/10-fleetd.json` to keep it apart from other managed policy. If you change the port, change it in the URLs too.
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
| `FLEETD_SECRETS_FILE` | env file whose values are scrubbed from every event | `/etc/swarm/secrets.env`, optional |
| `FLEETD_JOBS_DIR` | job worktrees and git mirrors (the mirror cache lives under it) | `$STATE_DIRECTORY/jobs`, else `./jobs` |
| `FLEET_SERVER_URL` | server URL. While set, fleetd heartbeats and polls for jobs | unset, no server link |
| `FLEET_TOKEN` | box bearer token for the server. Required when `FLEET_SERVER_URL` is set | unset |
| `GH_TOKEN` | GitHub PAT for the job push and `gh pr create`, passed to `fleetd askpass` and `gh` only | unset |

The default jobs dir is `/var/lib/fleetd/jobs`, inside `StateDirectory=fleetd`, so the unit needs no extra path for it. If you set `FLEETD_JOBS_DIR` or `jobs_dir` elsewhere, add that path to `ReadWritePaths=` with a drop-in (`systemctl edit fleetd`), or the worktree and mirror writes fail under `ProtectSystem=strict`. `claude_bin` and `gh_bin` are config-file keys only, with no env variable. They default to `claude` and `gh`, resolved through `PATH`. Set absolute paths in `/etc/fleetd/config.toml` when the units `PATH` does not include them.

A missing secrets file disables redaction and fleetd logs a warning only. It does not refuse to start.

`EnvironmentFile=-/etc/swarm/box.env` in the unit loads variables from that file. Put non-secret settings there: `FLEETD_PORT`, `FLEET_BOX_NAME`, `FLEETD_DB`, `FLEETD_SOCKET`, `FLEETD_SECRETS_FILE`, `FLEETD_JOBS_DIR` and `FLEET_SERVER_URL`. Put `FLEET_TOKEN` and `GH_TOKEN` in `secrets.env` only, mode 0600 and owned by `agent`, because fleetd scrubs that file's values from events. The `-` prefix makes the file optional: a missing file is not an error. The unit also loads `/etc/swarm/secrets.env` into the environment, so `FLEET_TOKEN` and `GH_TOKEN` reach fleetd, and fleetd reads the same file by path through `FLEETD_SECRETS_FILE` for the redaction list. The agent child environment is stripped of `GH_TOKEN` and `FLEET_TOKEN`, but the agent runs as the same uid as fleetd and can read the fleetd process environment through `/proc` and any file fleetd reads, such as `/etc/swarm/secrets.env`. The PAT is therefore exposed to the agent on this box. Use a fine-grained PAT scoped to throwaway repos on disposable Boxes only. Per-job isolation (a separate uid or a credential broker) is not built. The unit sets `StateDirectory=fleetd` and `RuntimeDirectory=fleetd`, so systemd exports `STATE_DIRECTORY` and `RUNTIME_DIRECTORY` and the db and socket land in `/var/lib/fleetd` and `/run/fleetd`.

Config file keys: `http_port`, `socket_path`, `db_path`, `queue_max_bytes`, `queue_max_age_secs`, `hook_events`, `secrets_file`, `box_name`, `dedupe_window_secs`, `claude_bin`, `gh_bin`, `disposable`, `jobs_dir`. Unknown keys are an error. `hook_events` lists the hook names to record. Add a name there and a matching hook in the managed settings to record more events.

## Hooks

The managed settings hold one hook per default `hook_events` entry (`SessionStart`, `UserPromptSubmit`, `Stop`, `Notification`, `SessionEnd`), each with `"timeout": 5` seconds. Four are http hooks. `SessionStart` is a command hook, `fleetd hook SessionStart`, because Claude Code accepts only `command` and `mcp_tool` hooks for that event. Claude Code spawns that process, so it does not share the unit's environment or `STATE_DIRECTORY` and `RUNTIME_DIRECTORY`. It loads `/etc/fleetd/config.toml` and its own env. Set a non-default port or socket in `/etc/fleetd/config.toml`; without them it skips the relative `./fleetd.sock` and uses loopback port 7071. The subcommand reads the payload from stdin and POSTs it to `/hook/SessionStart` on the unix socket, else the loopback port. It uses the socket only when its path is absolute and the socket is owned by the current uid; otherwise it counts as a failed connect. It falls back to the loopback port only when the socket connect fails or the socket gives no status line within 1 second; any HTTP status from the socket is final and is not replayed. When `FLEET_JOB_ID` is set it sends it as an `X-Fleet-Job` header, cut to printable ASCII and 128 bytes. Config loading counts against the same budget. It caps input at 1 MiB and 2 seconds, prints errors to stderr only and always exits 0, so a down fleetd never blocks Claude Code. `fleetd` must be on the `PATH` of the Claude Code process. The hooks have no `onFailure`: on 2.1.289 it had no observable effect ([T8](../docs/phase0/T8.md)). A hook fired while fleetd is down was lost in the T8 runs, which saw no retry.

The `http` hook type in managed settings is untested on a live box. T3 and T4 covered http hooks and managed files separately.

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
