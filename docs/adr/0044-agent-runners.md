# Agent runners

Status: Proposed 2026-10-29. Built in fleetd: the `AgentRunner` trait with the `claude`, `codex` and `kimi` runners and per-runner egress hosts under the Box ceiling. The Codex runner is wired: a job whose `agent` is `codex` runs the Codex argv and environment with a per-job `CODEX_HOME` dropped at job end, and needs a held `codex_api_key`. The Kimi runner is wired the same way: the argv `kimi -p <prompt> --output-format stream-json [-m <model>]` run in the job workdir with the binary from the `kimi_bin` config key, a cleared environment holding only `KIMI_MODEL_API_KEY` from a held `kimi_membership_key` or `kimi_platform_key` plus `KIMI_MODEL_NAME` (default `kimi-for-coding`), `KIMI_MODEL_PROVIDER_TYPE`, `KIMI_MODEL_BASE_URL`, `KIMI_DISABLE_TELEMETRY` and `KIMI_CODE_NO_AUTO_UPDATE`, an empty per-job `KIMI_CODE_HOME` dropped at job end, a fixed failure for a model name outside a plain-identifier allowlist, and a fixed failure on a box that is not disposable because `-p` runs under the auto policy with no approval (verified in ADR-0043). The argv, variables and the host `api.kimi.ai` were checked against a live run of Kimi Code 2.4.1. An unknown agent fails with `agent is not supported`. The Kimi model host `api.kimi.ai` reaches the child through the Box `egress_allow` ceiling and the per-job narrowing in `model_hosts()`. Other hosts the CLI may contact are unverified (ADR-0043). Not built: runner-owned command lines for claude (argv still comes from `claude_bin` in the runner config) and the Codex and Kimi output parsers. Builds on ADR-0043 (credential kinds) and ADR-0033 (delivery). Amends ADR-0021, ADR-0029 and ADR-0034.

fleetd runs Claude Code today. Users hold credentials for other agent CLIs (ADR-0043). This ADR makes the agent a choice per Job.

## Decision

### Trait

fleetd gets an `AgentRunner` trait. It owns what differs between agent CLIs: the command line, the environment it needs, which credential kinds it accepts and how it reads the CLI's output.

### Runners

| Runner | Status | Accepted kinds |
|---|---|---|
| `claude` | Exists | `anthropic_api_key`, `claude_subscription_token` |
| `codex` | New | `codex_api_key` |
| `kimi` | New | `kimi_membership_key`, `kimi_platform_key` |

### Job field

`Job.agent` names the runner. It lives on the Job. A Profile stays closed over its field list (ADR-0034), and one Profile can run under any runner.

### Summaries

The output parsers for Codex and Kimi do not exist yet. fleetd reads none of a non-claude job's lines, so its Job Summary has `complete = false`, `missing = ["parser"]` and every runner figure `NULL`, never 0. Phase timings fleetd measures itself (`clone_ms`, `push_ms`, `pr_ms`, `queue_wait_ms`) stay. The server stats query also reads a runner figure as `NULL` for a job whose agent is not `claude` and whose summary is incomplete, so an older fleetd that sent zeros cannot enter a percentile, sum or `n`. Claude summaries are unaffected, complete or not.

### Credentials

v1 takes static secrets only. `refreshing_file` credentials, the Codex `auth.json` and Kimi OAuth, are out of v1 (ADR-0043). fleetd receives the credential through ADR-0033 and passes it to the runner as that CLI expects.

Residual risk: `CODEX_API_KEY` sits in the child environment, so the agent shell can read it from `/proc`, and it could be written into the worktree. `CLAUDE_CODE_OAUTH_TOKEN` has the same exposure. The Codex config sets `features.hooks=false` and no live Codex run has confirmed that CLI honours the key. Tests check the config and argv structure only.

## Consequences

- Adding a runner means one trait implementation and its kind list.
- A Job whose owner holds no credential of an accepted kind fails with a fixed error before the agent starts.
- Stuck detection and cost figures for Codex and Kimi stay absent until their parsers land.
- The model API hosts of a new runner must be in the Box `egress_allow` (ADR-0038).
- The runner calls `set_job_hosts(job_id, runner.model_hosts())` on the egress proxy just before the agent starts, and the job end hook forgets it on every exit path. A job gets its own runner's hosts and nothing else, so the Anthropic host is not reachable from a codex or kimi job. The narrowed hosts are the runner's declared hosts that the Box `egress_allow` also lists.

## Considered and rejected

- **Agent on the Profile.** It would widen the closed Profile field list and tie a Profile to one vendor.
- **One generic runner with a command template.** It cannot express per-CLI credential handling or output parsing.
