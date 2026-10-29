# Forge trait

Status: Proposed 2026-10-29. Not built. Builds on ADR-0043 and ADR-0033. Amends ADR-0037 and ADR-0024.

Fleet pushes a branch, opens a pull request and reads CI state on GitHub through the broker (ADR-0037). This ADR puts those operations behind one interface so another forge can fit later.

## Decision

### Trait

A `Forge` trait with three operations:

- `push`: publish the Job branch.
- `create_pr`: open a pull request.
- `ci_result`: read the CI outcome of the pull request.

`ci_result` returns a normalised `CiResult`, so the CI follow-up of ADR-0028 reads one shape whatever the forge reports.

### Implementations

- GitHub is the only implementation in v1. It wraps the existing `gh` broker path (ADR-0024, ADR-0037) and uses the Job owner's `github_pat` delivered by ADR-0033.
- A Gitea-family slot is specified as `Unsupported`. It is not built and not verified. This ADR fixes the shared interface only.

### Credentials and identity

Gitea and Forgejo have no GitHub App equivalent (https://forgejo.org/docs/latest/user/oauth2-provider/), so a PAT is the common path. Pull requests are posted as the authenticated user, with that user's token.

## Consequences

- The broker calls the trait and not `gh` directly.
- A Job whose repo host maps to `Unsupported` fails with a fixed error.
- Gitea behaviour is unknown until someone builds and tests it.

## Considered and rejected

- **Build Gitea now.** The user chose the shared interface only.
- **No trait, GitHub calls inline.** A second forge would rewrite the broker.
