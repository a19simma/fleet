# Agent credential kinds and shapes

Status: Proposed 2026-10-29. Built in fleet-server and fleet-core: the kind and shape checks, the sealed store, the GitHub verify call and the credentials page. The page shows no last-used time, because `CredentialSummary` carries none. Builds on ADR-0040 for storage and sealing. Supersedes the standing decision "PAT in `/etc/swarm/secrets.env`" for user Jobs only. Leaves the Gitea and Forgejo path to ADR-0045.

A user stores the credentials their agent and their forge need. This ADR lists the kinds the store accepts, the shapes they take and the risks the user takes on.

## Decision

### Kinds

| Kind | Source | Notes |
|---|---|---|
| `anthropic_api_key` | Anthropic Console | Static key, sealed by ADR-0040. No prefix check. |
| `claude_subscription_token` | `claude setup-token` | Valid one year. Passed to the agent as `CLAUDE_CODE_OAUTH_TOKEN`. |
| `github_pat` | GitHub | Fine-grained `github_pat_` tokens only. |
| `kimi_membership_key` | Kimi Code Console | `sk-kimi-` prefix, checked on save. Prefix unverified. |
| `kimi_platform_key` | Kimi platform | Static key, sealed by ADR-0040. No prefix check. |
| `codex_api_key` | OpenAI | Static key, sealed by ADR-0040. No prefix check. |

### Shapes

- `static_secret`: one value that does not change until the user replaces it. Accepted in v1.
- `refreshing_file`: a file the agent rewrites as it refreshes tokens. Reserved and rejected in v1. It covers the Codex `auth.json` and Kimi OAuth, whose refresh tokens are single use. Two Jobs sharing one file would invalidate each other, and the server would need to take back the rewritten file.

### GitHub

- Only fine-grained `github_pat_` tokens are accepted.
- Classic `ghp_` tokens are rejected. They carry account-wide scope and cannot be limited to a repository.
- On save, the UI shows the `login`, the `fingerprint` and the expiry, so the user sees which identity and how long the token lives.
- A GitHub App route is later work.

### Standing decision

"PAT in `/etc/swarm/secrets.env`" is superseded for user Jobs: their credentials come from the store of ADR-0040. The Box PAT is temporary and will be removed.

### Gitea and Forgejo

Forgejo has no GitHub App equivalent (https://forgejo.org/docs/latest/user/oauth2-provider/), so a PAT is the common path across forges. ADR-0045 decides the rest.

## Accepted risk: Anthropic terms

ACCEPTED AND OWNED BY THE USER, for personal use.

The Anthropic legal page says developers "may not collect, store, or intermediate Claude.ai credentials or session tokens" (https://code.claude.com/docs/en/legal-and-compliance). Storing a `claude_subscription_token` in Fleet falls under that wording. Anthropic can change its policy or enforce it, and that can end this use with no code change. The user owns this risk. Fleet does not mitigate it.

## Research facts

- Codex PATs (`at-`) exist only for Business and Enterprise plans, with 7 to 90 day windows (https://learn.chatgpt.com/docs/enterprise/access-tokens.md). They do not help a personal plan, so Codex on a personal plan needs `codex_api_key` or the rejected `refreshing_file`.
- The Codex `auth.json` refreshes after 8 days (source: openai/codex `codex-rs/login/src/auth/manager.rs`).
- Kimi OAuth access tokens live about 900 s and refresh tokens are single use. The source is a blog and this is unverified.
- Kimi membership keys are created in the Kimi Code Console (https://www.kimi.com/en/help/kimi-code/membership-guide).

## Unverified

- The `sk-kimi-` prefix of `kimi_membership_key`.
- The 900 s lifetime and single-use refresh of Kimi OAuth tokens.
- Whether Anthropic enforces the quoted terms against a `claude setup-token` token stored by a self-hosted service.

## Consequences

- v1 needs no file write-back from the Box to the server.
- A user on a plan with only OAuth sign-in has no Codex or Kimi path until `refreshing_file` is designed.
- The terms risk can end the subscription route at any time. The `anthropic_api_key` kind stays available.
