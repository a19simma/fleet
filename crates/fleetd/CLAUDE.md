# fleetd

## Spawn tests

- **Fake agent or git script.** Write it once in a `OnceLock<TempDir>` before any test spawns, so no thread forks while the file is open for write (Linux `ETXTBSY`). One script serves every test: the prompt carries `mode:path`.
- **Start races.** A freshly written script can take over 100 ms to start on macOS, so a report heartbeat proves nothing about the child. Gate a kill on a signal from the child: a fifo the child's descendant opens, read by a test task that sends on a oneshot once its `open` returns. Reading the same fifo to EOF proves the whole process group died.
- **Lease heartbeat.** The runner reports at least every 30 s. Tests shrink `report_interval` and `flush_interval`.
- **Escaped descendants (`setsid` test only).** A `setsid` descendant must finish `setsid` before the agent script exits, because the exit kills the process group. The script waits for the pid file the descendant writes, and the test kills that pid.
- **Surviving descendants can hang the test binary.** A red kill test leaves `sleep 300` holding the runner fifo. The test `Reader` avoids the blocking `tokio::fs` fifo `open`, but a blocking-pool read of a pid fifo can still stall the runtime drop. Kill leftovers by pid, never by name pattern.

## Runner loop

- **List every exit arm of a loop with several, and test each one for the heartbeat and the group kill.** The arms are stdout EOF, child exit, deadline, shutdown and report error. A17 failed twice because each retry fixed the named arm and left a sibling: group disarmed after wait, report awaited inside `select`, no heartbeat arm after stdout EOF.
- **A change to the spawn path, or to a default that changes what a job does after the agent exits, needs every test binary that spawns the fake agent.** `grep -l 'claude_bin\|fake_gh\|"gh"' crates/fleetd/tests/*.rs` lists them, and `daemon_jobs` and `e2e_jobs` are among them. TEL-A3 ran only `telemetry` and `runner::` tests, and TEL-J2 added a 900 s CI wait after the PR that a fake `gh` answering every call alike turned into four red integration tests; both went red only in the independent verify.

## Profile jobs

- **`Reporter::profile_blob` defaults to `UNIMPLEMENTED`.** A test reporter that omits it makes any Job with a `profile` fail closed with `profile invalid: profile could not be fetched`. A test that needs a blob implements it, as `Served` in `runner.rs` and `Blob` in `jobs.rs` do.
- **`GetProfileBlobReply.catalog` is applied as sent, never re-resolved.** `load_stamped` drops items that are not `admin_enabled` or that the Profile selection names, refuses the snapshot when it exceeds `MAX_BLOB_CATALOG_ITEMS` items or `MAX_BLOB_CATALOG_BYTES` content bytes (`CatalogTooLarge`), repeats an id (`CatalogDuplicate`), carries an item digest that differs from the digest of its fields (`CatalogDigest`), or holds an item the core rules refuse (`CatalogName`, `CatalogBody`, else `Catalog`), and writes skills to `skills/<name>/SKILL.md`, subagents to `agents/<name>.md` and context items to `.claude/ctx/<name>.md`. A catalog tool needs the tools stamp. Only the claude runner reads the bundle; codex and kimi take the tool pins and the prompt only. The subagent frontmatter check is a strict allowlist, not a scan: `---\n`, then only `name|description|color|tools: <one-line printable-ASCII plain scalar>` lines (no repeat, no indent, no CR or tab), then `---\n`, with `tools` names checked against the Floor deny set and `model` refused, since only the Profile model is checked against the box allowlist; anything else is refused, as is a BOM or a leading `---` that is not that fence.
- **A new `FleetWorker` stub needs `get_profile_blob`.** `daemon_jobs` serves a real blob through `Worker::blob`; the other stubs return `unimplemented`.

## Askpass test

- **Own test file.** `tests/askpass_process.rs` runs the `fleetd askpass` binary, so it stays alone in its binary.

## Daemon test

- **Own test file.** `tests/daemon_jobs.rs` runs the whole daemon against a fake `FleetWorker` on a real socket, with a fake agent and fake `gh` scripts and a `file://` origin, so it stays alone in its binary.
- **The fake agent must leave a mark the test checks.** `claude_bin` is config, but a wrong path falls back to the real `claude` on `PATH`. The test asserts the committed file holds the fake's output.
- **Env is injected.** `run_with_env` takes the `FLEET_SERVER_URL` and `FLEET_TOKEN` lookup, so a test sets no process env.

## Credentials

- **The job path takes the GitHub token from the credential holder only.** With a `CredentialBook` attached, `GH_TOKEN` and `GH_ENTERPRISE_TOKEN` in `base_env` are dropped, a missing `github_pat` fails the job with `no github credential`, and the `gh` child env is the fixed set plus the holder token. The wiring refuses a plain `http` `FLEET_SERVER_URL` unless the host is loopback or `FLEETD_ALLOW_PLAINTEXT_CREDENTIALS=1`. Workspaces and the publish mirror are keyed by the Job `user_id` (ADR-0046).
- **The claude agent env takes its model secret from the holder too.** With a `CredentialBook` attached, `agent_spec` drops `CLAUDE_CODE_OAUTH_TOKEN` and `ANTHROPIC_API_KEY` from the base env and sets one from the held `anthropic_api_key` or `claude_subscription_token`; a claude job whose holder has neither fails with `no agent credential`. Judge jobs fetch no credentials and keep the base env. The value reaches the 0600 `env` file only, never `spec.json`.
- **A codex job's env is `codex::env` only.** `agent_spec` branches on `resolve(job.agent)`: a codex job gets the Codex argv, a per-job `CODEX_HOME` kept in the runner until `end_job`, and `CODEX_API_KEY` from the held `codex_api_key` as its one secret; with no held key the variable is absent, never a box value. An unknown agent fails with `agent is not supported` in `run_stream`.
- **A kimi job mirrors the codex job, and runs only on a disposable box.** `agent_spec` dispatches to `kimi_spec`: the argv `kimi -p <prompt> --output-format stream-json [-m <model>]` with `kimi_bin` from config, `kimi::env` only, an empty per-job `KIMI_CODE_HOME` kept until `end_job`, and `KIMI_MODEL_API_KEY` from the held `kimi_membership_key` or `kimi_platform_key`. A Profile model outside `kimi::resolve_model` fails with `kimi model is not valid`. `-p` runs under the auto policy with no approval (ADR-0043), so a kimi job on a box that is not disposable fails with `kimi needs a disposable box` before anything is built.
- **A codex or kimi job's summary is empty by design.** `Feed::set_unparsed` runs in `Stream::new` for every job whose runner is not claude (judge jobs count as claude): the feed reads no line, and `finish` returns `complete = false`, `missing = ["parser"]` and no figure. Stats read those figures as `NULL` too (`fleet-server/src/stats.rs`). Remove both together when a parser lands: `has_output_parser` in `runner.rs` and the `NULL` handling in the stats `CASE` list.
- **Name the attacker uid in every secrecy claim.** A token is hidden from a process under another uid than fleetd's, never from the agent, which shares fleetd's uid (ADR-0024 Known limit). Write docs and doc comments to match.
- **Never run credentialed git or gh in a repo the agent wrote.** Linked worktrees share the common-dir config, so the agent can plant `core.sshCommand`, `credential.helper` or `url.*.insteadOf`. Finish fetches into a throwaway bare repo with no tokens, then pushes and opens the PR from it.
- **Credentialed children get a scratch `HOME`, `XDG_*` and `GH_CONFIG_DIR` in a scratch dir beside the job worktree, and only the one credential they need.** The agent can write that dir, so isolation relies on the process-group kill. The agent shares fleetd's uid, so it can still read the tokens through `/proc/<pid>/environ` and `/etc/swarm/secrets.env` (ADR-0024 Known limit). The push gets `GIT_ASKPASS` (the current fleetd executable), the `FLEETD_ASKPASS` marker that makes it answer as the helper, `FLEETD_ASKPASS_HOST` and the `GH_TOKEN` the helper prints. `gh` gets `GH_HOST` only when `token_host` is set. Without a credential holder the base env supplies `GH_TOKEN` only when `token_host` is set, and `GH_ENTERPRISE_TOKEN` only when that host is not `github.com`. Real `HOME`, `SSH_*`, `GIT_SSH*`, `GIT_EXEC_PATH`, `LD_*` and `DYLD_*` are never inherited. The push allows only `https` remotes on the `repo_hosts` list (`RepoPolicy`), so ssh, `git://` and `file://` remotes fail by design. Tests that serve a local bare repo build `RepoPolicy::new(Vec::<String>::new()).with_file_repos()` (or set `Config::allow_file_repos`) and never a config key.
- **Workspace git is cleared too.** `workspace.rs` runs every git call with `env_clear`, a scratch `HOME`, `GIT_CONFIG_GLOBAL=/dev/null` and `-c core.hooksPath=/dev/null -c core.fsmonitor=`. `tests/workspace_guards.rs` records each call with a fake git, so a new call path must go through `Workspace::git`.

## Agent config

- **`agent_config_dir` replaces the default `settings.json` allow list entirely.** An operator bundle that omits `Bash` leaves a `dontAsk` job unable to change files: `Edit`, `Write`, `NotebookEdit` and `MultiEdit` are denied by the argv floor, so edits go through Bash. An operator bundle can also drop the `Bash(curl *)` deny, because the bundle's `settings.json` replaces the default one.

## Fallback commit tests

- **Hostile repo.** The fallback runs git in an agent-written tree. Tests plant hooks, `filter.<name>` config and `core.fsmonitor` and assert none ran. Read `git config --list --name-only` before the first git call that touches the tree, or a clean filter runs during `status`.
- **Fake `claude` modes.** The prompt carries `mode:path` as in the spawn tests; `write`, `commit`, `secret` and `trap` cover the fallback cases.

## Config keys

- **`Config::resolve` sits at the clippy `too_many_lines` cap.** Put a new key's env, file and validation logic in a helper fn and call it once, or clippy fails the build.
- **Binding a `tokio::net::UnixListener` needs a runtime.** A plain `#[test]` that calls `bind_socket` or `bind_hook_socket` panics with "no reactor running"; use `#[tokio::test]`.

## Named pipes and modes

- **No `mknodat` on macOS, no `unsafe` allowed.** `jobenv::create_stdout_fifo` runs the `mkfifo` program. A nonblocking FIFO reader reads 0 until a writer opens, then `WouldBlock`, so a test opens the writer before it asserts idle. A read after the writer opened can still return `WouldBlock` under load: `the_fifo_is_0660_carries_the_group_and_streams_to_a_reader` failed with Os code 35 in two full verifies (PF-2, P3-2) and passed in 5 and 6 isolated reruns. Retry on `WouldBlock` with a bounded wait in the test helper.
- **Mode asserts need the umask in mind.** `create_dir_all` and git leave 0755 dirs, so assert group-write and setgid bits (`& 0o2020`), not group-read.

## Systemd launcher test

- **Own test file.** `tests/systemd_launcher.rs` runs a fake `systemctl` script and the `fleetd agent-exec` binary, so it stays alone in its binary. The script is written once in a `OnceLock<TempDir>`, and its per-job state lives in a directory named after the job id, so every test uses a unique id.
- **Startup sweep.** `sweep_stale_runs(config, run_dir)` takes the run root as a parameter and only acts for the systemd launcher. `run_with_hub` calls it only after `bind_all` succeeds, so a second instance that fails to bind sweeps nothing. It removes real directories with a job-id name through `RunDir` and skips `hook`, symlinks and files. Unit states: a unit in any state except `inactive` and `failed` (`is_live`, so `activating` and `deactivating` too) is stopped, then reset-failed; a `failed` unit is reset-failed; an inactive unit gets no call. Tests plant dirs in a temp run root.
- **Run dir contract.** With `agent_launcher = "systemd"`, `systemd.rs` makes `<run_dir>/<job id>/` (default `/run/fleet`), mode 0750 with `job_group`, holding `env` (0600, the `EnvironmentFile`), `spec.json` (`id`, `argv` and `cwd`, 0640 with the job group) and `stdout` (a FIFO, 0660). It runs `systemctl start --no-block fleet-agent@<id>.service`, polls `show`, and at the end calls `stop` and `reset-failed` and removes the dir. `deploy/README.md` holds the operator view.
- **Telemetry env.** `select_launcher` calls `with_telemetry` only after `config.require_host_netns()` succeeds. `launch` starts capture first, calls `TelemetryEnv::apply` on the spec env, then renders the env file, so the bearer reaches only the 0600 env file. Only a spec with `otel` set (claude, not judge) gets capture. A token byte outside `[A-Za-z0-9_-]` starts none.
- **Job socket.** `select_launcher(config, gid, services)` gives the systemd launcher a `JobSocketSetup`, and `launch` binds `<run_dir>/<id>/job.sock` after the FIFO and before `start`. The poller closes it right after the unit ends, before `stop`, and `Drop` closes it first, so it is unlinked before the dir is removed on every path. The direct launcher makes none and logs `JOB_SOCKET_REFUSED` once when services are given. The fake `systemctl` appends `<verb> sock|nosock` to `seen` when the case wrote a `rundir` file, so a test can assert the socket state at each call.
- **The fake is injected as `systemctl_path`.** No env var selects it. `show.N` files give the Nth `show` reply and `show.last` the rest.

## Linux uid test

- **Own test file, opt-in.** `tests/linux_uid.rs` builds an image (`tests/linux_uid/Dockerfile`) with `fleetd` (986, in `fleet-work` 987) and `fleet-job` (985), compiles itself and `fleetd` inside it, and runs the container tests as uid 986. The real `AgentRunner` and `SystemdLauncher` start a fake agent through `tests/linux_uid/systemctl`, which drops to 985:987 with `sudo -n setpriv` and runs `fleetd agent-exec`. Run it with `mise run it:linux`; it needs docker or colima, and the in-container build needs network access to crates.io.
- **`container_suite_passes` is `#[ignore]`.** It needs docker, so nextest and `cargo test` skip it and `clippy --all-targets` still compiles it. With no usable `docker info` it prints `SKIP: docker not available, run mise run it:linux with docker or colima` and passes.
- **Marker guard.** The container tests return early with a skip message unless `/etc/fleet-it` exists, so a plain `cargo test` on a laptop runs none of them.
- **The shim's env parse is a shell loop, not systemd's.** It strips one pair of quotes per line and does not undo the `\\` and `\"` escapes of `render_env_file`; a test value holding either needs the agent to record the variable itself.
- **The caches are the named volumes `fleet-it-target` and `fleet-it-cargo`.** Remove them to force a cold build.
