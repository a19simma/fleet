# Agent runners

Status: Proposed 2026-10-29. Not built. Builds on ADR-0043 (credential kinds) and ADR-0033 (delivery). Amends ADR-0021, ADR-0029 and ADR-0034.

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

`Job.agent` names the runner. It is a field on the Job and not on the Profile. A Profile stays closed over its field list (ADR-0034), and one Profile can run under any runner.

### Summaries

The output parsers for Codex and Kimi do not exist yet. A Job Summary from a non-claude runner is marked Incomplete until its parser is built. Figures the runner cannot supply are `NULL` under the rules of ADR-0029.

### Credentials

v1 takes static secrets only. `refreshing_file` credentials, the Codex `auth.json` and Kimi OAuth, are out of v1 (ADR-0043). fleetd receives the credential through ADR-0033 and passes it to the runner as that CLI expects.

## Consequences

- Adding a runner means one trait implementation and its kind list.
- A Job whose owner holds no credential of an accepted kind fails with a fixed error before the agent starts.
- Stuck detection and cost figures for Codex and Kimi stay absent until their parsers land.
- The model API hosts of a new runner must be in the Box `egress_allow` (ADR-0038).

## Considered and rejected

- **Agent on the Profile.** It would widen the closed Profile field list and tie a Profile to one vendor.
- **One generic runner with a command template.** It cannot express per-CLI credential handling or output parsing.
