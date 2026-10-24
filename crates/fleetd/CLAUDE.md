# fleetd

## Spawn tests

- **Fake agent or git script.** Write it once in a `OnceLock<TempDir>` before any test spawns, so no thread forks while the file is open for write (Linux `ETXTBSY`). One script serves every test: the prompt carries `mode:path`.
- **Start races.** A freshly written script can take over 100 ms to start on macOS, so a report heartbeat proves nothing about the child. Gate a kill on a signal from the child: a fifo the child's descendant opens, read by a test task that sends on a oneshot once its `open` returns. Reading the same fifo to EOF proves the whole process group died.
- **Lease heartbeat.** The runner reports at least every 30 s. Tests shrink `report_interval` and `flush_interval`.
- **Surviving descendants hang the test binary.** A red kill test leaves `sleep 300` holding the runner fifo, and the runtime drop blocks on the fifo `open` in `tokio::fs`. When a mutation run hangs, `pkill -f "sleep 300"` once the test reports FAILED. Send mutation-run output to a file, not a pipe.

## Credentials

- **Never run credentialed git or gh in a repo the agent wrote.** Linked worktrees share the common-dir config, so the agent can plant `core.sshCommand`, `credential.helper` or `url.*.insteadOf`. Finish fetches into a throwaway bare repo with no tokens, then pushes and opens the PR from it.
- **Credentialed children get a scratch `HOME`, `XDG_*` and `GH_CONFIG_DIR` in a scratch dir beside the job worktree, and only the one credential they need.** The agent can write that dir, so isolation relies on the process-group kill. The push gets `GIT_ASKPASS`, `gh` gets `GH_TOKEN` (plus `GH_HOST`, `GH_ENTERPRISE_TOKEN`). Real `HOME`, `SSH_*`, `GIT_SSH*`, `GIT_EXEC_PATH`, `LD_*` and `DYLD_*` are never inherited. The push allows only `file` and `https` remotes, so ssh and `git://` remotes fail by design.
