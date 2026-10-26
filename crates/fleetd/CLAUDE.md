# fleetd

## Spawn tests

- **Fake agent or git script.** Write it once in a `OnceLock<TempDir>` before any test spawns, so no thread forks while the file is open for write (Linux `ETXTBSY`). One script serves every test: the prompt carries `mode:path`.
- **Start races.** A freshly written script can take over 100 ms to start on macOS, so a report heartbeat proves nothing about the child. Gate a kill on a signal from the child: a fifo the child's descendant opens, read by a test task that sends on a oneshot once its `open` returns. Reading the same fifo to EOF proves the whole process group died.
- **Lease heartbeat.** The runner reports at least every 30 s. Tests shrink `report_interval` and `flush_interval`.
- **Escaped descendants.** A `setsid` descendant must finish `setsid` before the agent script exits, because the exit kills the process group. The script waits for the pid file the descendant writes, and the test kills that pid.
- **Surviving descendants hang the test binary.** A red kill test leaves `sleep 300` holding the runner fifo, and the runtime drop blocks on the fifo `open` in `tokio::fs`.

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

- **`agent_config_dir` replaces the default `settings.json` allow list entirely.** An operator bundle that omits `Edit`, `Write` or `Bash` leaves a `dontAsk` job unable to change files.

## Fallback commit tests

- **Hostile repo.** The fallback runs git in an agent-written tree. Tests plant hooks, `filter.<name>` config and `core.fsmonitor` and assert none ran. Read `git config --list --name-only` before the first git call that touches the tree, or a clean filter runs during `status`.
- **Fake `claude` modes.** The prompt carries `mode:path` as in the spawn tests; `write`, `commit`, `secret` and `trap` cover the fallback cases.

## Config keys

- **`Config::resolve` sits at the clippy `too_many_lines` cap.** Put a new key's env, file and validation logic in a helper fn and call it once, or clippy fails the build.
- **Binding a `tokio::net::UnixListener` needs a runtime.** A plain `#[test]` that calls `bind_socket` or `bind_hook_socket` panics with "no reactor running"; use `#[tokio::test]`.
