# Metrics and the improvement loop

Status: Accepted. Built: `GetStats`, `fleet stats`, the turn and budget caps and the stuck detector in shadow mode. Stuck enforcement is not built. Builds on ADR-0029.

ADR-0029 stores one summary per Job. Comparing a prompt, agent config or model change needs aggregates, a hard stop for a runaway Job and a way to learn which Jobs got stuck before any rule acts on it.

## Decision

- **Stats.** `FleetJobs.GetStats` aggregates over `jobs` left-joined to `job_summary`, with `since` and `until` as unix seconds on `jobs.created_at`. The window defaults to 7 days and clamps to 90, and the reply sets `clamped`. `repo` and `box` filter. `group_by` is `none`, `repo`, `box`, `state`, `day`, `bundle_sha`, `claude_version` or `model`. The server maps the enum onto a fixed column list, so no client text reaches the SQL or an error. Jobs with a `NULL` stamp field, including jobs without a summary, form one group with `unknown` set. The CLI prints it as `unknown`, and the label is never stored or merged with a real value. A reply holds at most 200 groups and sets `truncated` past that. Each metric returns its own `n`, the count of Jobs that observed it, beside the sum and the p50 and p95, so an average never hides a `NULL` (ADR-0029). It also returns jobs per outcome (`FAILED` with the error `agent timed out` counts as timed out), `with_summary`, `complete` and `stuck_jobs`.
- **CLI.** `fleet stats [--since 7d] [--repo R] [--box B] [--by repo|box|state|day|bundle-sha|claude-version|model]`.
- **Hard caps.** fleetd always passes `--max-turns` and `--max-budget-usd`. Defaults are 100 turns and 5.0 USD. Config keys `max_turns` (1 to 1000) and `max_budget_usd` (above 0, up to 1000, finite) override them, and fleetd refuses to start on a value outside the range.
- **Cap outcome.** A final `result` line with subtype `error_max_turns` ends the Job `FAILED` with error `max turns reached`. Subtype `error_max_budget_usd` ends it `FAILED` with `budget exceeded`. A cap hit wins over the exit status and publishes no branch.
- **Stuck detector, shadow mode.** The parser watches the event stream for four rules: `repeat_action_observation` (same tool, input and output 4 times in a row), `repeat_error` (same failing call and output 3 times), `alternating` (two distinct calls, 3 full cycles) and `monologue` (3 assistant turns in a row without a tool call). It keys on hashes of the redacted tool and command and stores no text. It records only the first rule that fires, as `stuck_rule`, `stuck_at_seq` and `stuck_at_ms` on `job_summary`, and never changes the Job's behaviour. A Job that hits a rule still runs to its normal end.
- **Enforcement waits.** No rule cancels, warns or retries until about two weeks of shadow data show how often each fires on Jobs that went on to succeed.
- **Version stamp.** The terminal summary carries `bundle_sha` (SHA-256 of the agent config bundle), `claude_version` (from `claude --version`, once per runner) and `model` (from the `init` line). `fleet status` prints the three fields in the telemetry block, `-` when unset. A field fleetd does not know is unset on the wire and stored as `NULL`, never as a placeholder such as the string `unknown`. The server validates each field again: non-empty, no control character, at most 64 characters for the sha and the version and 128 bytes for the model. A bad value rejects the report with the fixed error `invalid job telemetry`, and migration 0009 adds the same checks as `CHECK` constraints.
- **Out of scope for now.** An OTLP receiver, a bundle canary, fixtures with `fleet eval run`, a judge Job and a pull-request-merged signal.

## Unverified

- The process exit code of `claude` on a cap hit and the `is_error` value of those result lines were not observed. The budget subtype strings come from the installed binary (Claude Code 2.1.289), and the runner's doc comment records that reading. The budget path was not run live.
- Whether the budget check fires before or after the call that crosses it.
- The `permission_denied` system message shape the parser reads is an assumption, as the parser's module doc says.
- Inferred, not part of the design: the rule thresholds are initial values. The shadow period tests them.

## Consequences

- A runaway Job costs at most the cap before it ends `FAILED`.
- A Job that hit a cap is a failure in `fleet stats` and carries a summary with the result subtype.
- Rules that never fire in shadow mode cost nothing, and rules that fire often on good Jobs get changed before they enforce.
- A stuck Job whose hook exit code arrives later is judged on the stream alone, so `repeat_error` can miss a failing Bash call that reported `ok`.
- Grouping by `day` returns oldest first. Other groupings return the largest group first.

## Considered and rejected

- **Enforce stuck rules at once.** Thresholds adapted from another project have no local data behind them.
- **Return averages only.** A `NULL` figure would read as zero.
- **A wall-clock limit as the only cap.** It does not bound spend.
