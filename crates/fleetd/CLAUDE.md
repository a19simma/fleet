# fleetd

## Spawn tests

- **Fake agent or git script.** Write it once in a `OnceLock<TempDir>` before any test spawns, so no thread forks while the file is open for write (Linux `ETXTBSY`). One script serves every test: the prompt carries `mode:path`.
- **Start races.** A freshly written script can take over 100 ms to start on macOS, so a report heartbeat proves nothing about the child. Gate a kill on a signal from the child: a fifo the child's descendant opens, read by a test task that sends on a oneshot once its `open` returns. Reading the same fifo to EOF proves the whole process group died.
- **Lease heartbeat.** The runner reports at least every 30 s. Tests shrink `report_interval` and `flush_interval`.
- **Escaped descendants.** A `setsid` descendant must finish `setsid` before the agent script exits, because the exit kills the process group. The script waits for the pid file the descendant writes, and the test kills that pid.
- **Surviving descendants hang the test binary.** A red kill test leaves `sleep 300` holding the runner fifo, and the runtime drop blocks on the fifo `open` in `tokio::fs`.

## Runner loop

- **List every exit arm of a loop with several, and test each one for the heartbeat and the group kill.** The arms are stdout EOF, child exit, deadline, shutdown and report error. A17 failed twice because each retry fixed the named arm and left a sibling: group disarmed after wait, report awaited inside `select`, no heartbeat arm after stdout EOF.
- **A change to the spawn path needs every test binary that spawns the fake agent.** `grep -l claude_bin crates/fleetd/tests/*.rs` lists them, and `daemon_jobs` and `e2e_jobs` are among them. TEL-A3 ran only `telemetry` and `runner::` tests and went red on both in the independent verify.

## Askpass test

- **Own test file.** `tests/askpass_process.rs` runs the `fleetd askpass` binary, so it stays alone in its binary.

## Daemon test

- **Own test file.** `tests/daemon_jobs.rs` runs the whole daemon against a fake `FleetWorker` on a real socket, with a fake agent and fake `gh` scripts and a `file://` origin, so it stays alone in its binary.
- **The fake agent must leave a mark the test checks.** `claude_bin` is config, but a wrong path falls back to the real `claude` on `PATH`. The test asserts the committed file holds the fake's output.
- **Env is injected.** `run_with_env` takes the `FLEET_SERVER_URL` and `FLEET_TOKEN` lookup, so a test sets no process env.

## Credentials

- **Name the attacker uid in every secrecy claim.** A token is hidden from a process under another uid than fleetd's, never from the agent, which shares fleetd's uid (ADR-0024 Known limit). Write docs and doc comments to match.
- **Never run credentialed git or gh in a repo the agent wrote.** Linked worktrees share the common-dir config, so the agent can plant `core.sshCommand`, `credential.helper` or `url.*.insteadOf`. Finish fetches into a throwaway bare repo with no tokens, then pushes and opens the PR from it.
- **Credentialed children get a scratch `HOME`, `XDG_*` and `GH_CONFIG_DIR` in a scratch dir beside the job worktree, and only the one credential they need.** The agent can write that dir, so isolation relies on the process-group kill. The agent shares fleetd's uid, so it can still read the tokens through `/proc/<pid>/environ` and `/etc/swarm/secrets.env` (ADR-0024 Known limit). The push gets `GIT_ASKPASS` (the current fleetd executable, run as `askpass`) and the `GH_TOKEN` that helper prints, `gh` gets `GH_TOKEN` (plus `GH_HOST`, `GH_ENTERPRISE_TOKEN`). Real `HOME`, `SSH_*`, `GIT_SSH*`, `GIT_EXEC_PATH`, `LD_*` and `DYLD_*` are never inherited. The push allows only `https` remotes on the `repo_hosts` list (`RepoPolicy`), so ssh, `git://` and `file://` remotes fail by design. Tests that serve a local bare repo build `RepoPolicy::new(Vec::<String>::new()).with_file_repos()` (or set `Config::allow_file_repos`) and never a config key.
- **Workspace git is cleared too.** `workspace.rs` runs every git call with `env_clear`, a scratch `HOME`, `GIT_CONFIG_GLOBAL=/dev/null` and `-c core.hooksPath=/dev/null -c core.fsmonitor=`. `tests/workspace_guards.rs` records each call with a fake git, so a new call path must go through `Workspace::git`.

## Agent config

- **`agent_config_dir` replaces the default `settings.json` allow list entirely.** An operator bundle that omits `Bash` leaves a `dontAsk` job unable to change files: `Edit`, `Write`, `NotebookEdit` and `MultiEdit` are denied by the argv floor, so edits go through Bash.

## Fallback commit tests

- **Hostile repo.** The fallback runs git in an agent-written tree. Tests plant hooks, `filter.<name>` config and `core.fsmonitor` and assert none ran. Read `git config --list --name-only` before the first git call that touches the tree, or a clean filter runs during `status`.
- **Fake `claude` modes.** The prompt carries `mode:path` as in the spawn tests; `write`, `commit`, `secret` and `trap` cover the fallback cases.

## Config keys

- **`Config::resolve` sits at the clippy `too_many_lines` cap.** Put a new key's env, file and validation logic in a helper fn and call it once, or clippy fails the build.
- **Binding a `tokio::net::UnixListener` needs a runtime.** A plain `#[test]` that calls `bind_socket` or `bind_hook_socket` panics with "no reactor running"; use `#[tokio::test]`.

## Named pipes and modes

- **No `mknodat` on macOS, no `unsafe` allowed.** `jobenv::create_stdout_fifo` runs the `mkfifo` program. A nonblocking FIFO reader reads 0 until a writer opens, then `WouldBlock`, so a test opens the writer before it asserts idle.
- **Mode asserts need the umask in mind.** `create_dir_all` and git leave 0755 dirs, so assert group-write and setgid bits (`& 0o2020`), not group-read.

## Systemd launcher test

- **Own test file.** `tests/systemd_launcher.rs` runs a fake `systemctl` script and the `fleetd agent-exec` binary, so it stays alone in its binary. The script is written once in a `OnceLock<TempDir>`, and its per-job state lives in a directory named after the job id, so every test uses a unique id.
- **Startup sweep.** `sweep_stale_runs(config, run_dir)` takes the run root as a parameter and only acts for the systemd launcher. `run_with_hub` calls it only after `bind_all` succeeds, so a second instance that fails to bind sweeps nothing. It removes real directories with a job-id name through `RunDir` and skips `hook`, symlinks and files. Unit states: an active-like unit is stopped, then reset-failed; a `failed` unit is reset-failed; an inactive unit gets no call. Tests plant dirs in a temp run root.
- **Run dir contract.** With `agent_launcher = "systemd"`, `systemd.rs` makes `<run_dir>/<job id>/` (default `/run/fleet`), mode 0750 with `job_group`, holding `env` (0600, the `EnvironmentFile`), `spec.json` (`argv` and `cwd` only, 0640 with the job group) and `stdout` (a FIFO, 0660). It runs `systemctl start --no-block fleet-agent@<id>.service`, polls `show`, and at the end calls `stop` and `reset-failed` and removes the dir. `deploy/README.md` holds the operator view.
- **The fake is injected as `systemctl_path`.** No env var selects it. `show.N` files give the Nth `show` reply and `show.last` the rest.
