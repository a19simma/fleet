# Phase 0 results

Ten throwaway tests for the fleetd plan (`docs/plan.md`), run on 2026-10-24. The plan and ADRs 0011, 0012, 0014 and 0016 are updated with the results. ADRs 0011 to 0017 are Accepted.

## Environment

| Item | Value |
|---|---|
| Box | <box> |
| Claude Code | 2.1.289, subscription auth, `ANTHROPIC_API_KEY` unset |
| workmux | 0.1.276 |
| pueue and pueued | 4.0.4 |
| Model in transcripts | claude-sonnet-5-5 |
| Test user | `agent` (uid 1000) |

The tests ran one at a time against <box>'s live pueue daemon and workmux state, so some runs queued behind others in the default pueue group.

## Results

| Test | Result | Impact on the plan |
|---|---|---|
| [T1](T1.md) `Stop` at the end of `claude -p` | Pass | `Stop` fires once per run, `SessionEnd` about 16 ms later. `stream-json` needs `--verbose`. A subagent hand-back fires a synthetic `UserPromptSubmit` |
| [T2](T2.md) Raw hook JSON field names | Pass | Normalizer field list fixed. `prompt_id` correlates a turn. `Notification` is late and best-effort |
| [T3](T3.md) http hook with a unix-socket URL | Fail for sockets, Pass for loopback | Hooks use `http://127.0.0.1:<port>/hook/<Event>`. Drop `onFailure` |
| [T4](T4.md) Managed settings on Linux | Pass | Loopback hook goes in managed settings. Hooks merge across sources, so fleetd tolerates one event per source |
| [T5](T5.md) workmux state and crash exit code | Partial | Start `workmux wait` on `working`. Exit 3 is a crash, exit 1 is gone. Watch DELETE. Drop `prompt`. Add a liveness check |
| [T6](T6.md) pueue callback | Pass for firing, Partial for safe use | Callback passes only `id` and `group`. Poll stays as reconcile |
| [T7](T7.md) Bearer token over gRPC | Pass | Auth interceptor works, including for reflection. A tonic client is untested |
| [T8](T8.md) Hook failure latency with fleetd down | Pass | About 2 ms per refused hook, no run impact. Events during the gap are lost. Set a hook `timeout` |
| [T9](T9.md) System unit reaching pueue | Pass | Needs `After=` and `Wants=user@1000.service`. Add `ProtectHome=read-only` and `ReadWritePaths` |
| [T10](T10.md) Transcript contents and drift | Partial | The file lacks the final entry at `Stop`. Read in fleetd after a delay. De-duplicate on `message.id`. Cost from `result` only |

## Remaining unknowns

These become Phase 1 pre-checks in the plan.

1. A stalled http listener (accepts, never answers) with a hook `timeout`. T3 and T8 only covered a refused connection.
2. The `http` hook type inside a managed settings file. T4 used command hooks.
3. `managed-settings.json` and `managed-settings.d/*.json` together, and their order.
4. Interactive session hook behaviour with http hooks from managed settings: `Stop` per turn, `Notification` timing, `idle_prompt`.
5. A tonic client sending `authorization: Bearer <token>`, ideally over a real VPN path with and without TLS.
6. The workmux `waiting` status. No test made an agent ask for input.
7. Repeated T10 lag samples. One sample per mode showed the final entry missing at `Stop` and present at 2 s. Also test long turns, many tool calls, `--resume` and disk load, and read at `SessionEnd` without a sleeping `Stop` hook. The T10 `SessionEnd` read came about 2 s after `Stop` only because its `Stop` hook slept.
8. The `X-Fleet-Job` header with `allowedEnvVars`. No test covered it, and the route was never built: only the `SessionStart` command hook sends the header (ADR-0012).
9. Whether the user's own `workmux set-window-status done` `Stop` hook still fires beside a managed file. T4 did not observe it.
10. The `Notification` delay. T2 records one at 7.5 s by file timestamps, yet it was absent from a listing made about 25 s after the prompt. Unexplained.

## Leftovers on <box>

Nothing here is part of the product. Clean up when convenient.

- `~/phase0/`: artifacts of all ten tests, including hook logs, debug logs, throwaway scripts and the T5 inotify logs.
- `~/phase0/T7/venv`: python venv with `grpcio`, `grpcio-tools` and `grpcio-reflection` 1.84.1.
- `~/.config/mise/config.toml`: `github:fullstorydev/grpcurl` (1.9.4) added by `mise use -g` in T7.
- `inotify-tools`, installed with apt in T5.
- `~/.claude.json`: a trust entry for `/home/agent/phase0/T1/wd` from the interactive session in T2. T10 also accepted the trust dialog in an interactive session for `/home/agent/phase0/T10/work`, so check for a second entry.
- `~/.claude/projects/-home-agent-phase0-*`: transcripts written by the test sessions.
- Finished entries in the shared pueue daemon from the T5, T7 and T10 runners. Not verified, check `pueue status`.
- `/swapfile-e2e`, 4 GB, from the earlier Cilium work. It is not part of Phase 0.

Already reverted by the tests: `/etc/claude-code` (T4, with `~/.claude/settings.json` restored to its original hash), the throwaway `fleetd-t9.service` unit, `/tmp/phase0-t7`, the separate pueued instance from T6, the T5 worktrees and watcher job.
