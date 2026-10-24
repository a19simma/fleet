# Job git credentials and permission policy

Status: Accepted. The runner, push and pull request step and reporter are built as library code. Daemon wiring is pending, so no runtime path calls them yet. Amends ADR-0011.

Pushing a branch and opening a pull request need write access to the repo, and ADR-0011 says fleetd holds no git credential. A headless `claude -p` run stalls on any permission prompt, and the agent can run arbitrary shell.

## Decision

- **Credential.** A fine-grained personal access token with contents and pull-requests write, scoped to named repos. It lives in `/etc/swarm/secrets.env` beside the other secrets, as `GH_TOKEN`. The first test scopes it to one throwaway repo.
- **Who sees it.** fleetd's own `git` and `gh` child processes get it through `GIT_ASKPASS` and `GH_TOKEN`. The agent child environment strips `GH_TOKEN`, so the agent cannot read it. The redactor also masks the value in events and transcripts.
- **Pull request.** `gh pr create --fill --head swarm/<id> --base <base>`, run by fleetd after the push (ADR-0020). The agent never pushes.
- **Branch.** The result branch is `swarm/<job_id>`, the only branch namespace a Box may push (ADR-0016).
- **Permissions.** fleetd config marks a Box disposable or not. Only a disposable Box runs Jobs with `--dangerously-skip-permissions`. Other Boxes get a configurable permission mode and tool allowlist. Not built: only `disposable` exists.
- **Targets.** Each Job names its own `repo` and `base_ref`. An allowlist on fleetd (`FLEET_JOB_REPO_ALLOWLIST`) is planned for later and does not exist yet.

## Consequences

- Once the runner is wired into the daemon, fleetd holds the job PAT. It is a new credential, separate from the baked git credential, and sits beside the four credentials already on a Box: the Claude subscription token, the baked git credential, the VPN auth key and the Box bearer token. A leaked PAT can write to its scoped repos only.
- With skip-permissions the agent has a full shell, so the Box is the sandbox. Its blast radius is the Box plus its Claude token, since the git token never enters the agent environment.
- A leaked client token (ADR-0023) can make a Box clone any repo the PAT reads and push to any it writes, until the allowlist exists.
- Inferred, not part of the design: a Job prompt can still make the agent print files it can read, so redaction of exact values is the only masking.

## Considered and rejected

- **A GitHub App installation token per Job.** Safer and short lived, but needs an App and a minting step. A later upgrade.
- **An SSH deploy key.** Cannot open a pull request.
- **Always skip permissions.** Ties safety entirely to the environment, including on a Box that is not disposable.
- **A permission allowlist only.** Stalls on any tool outside the list.
- **One repo set in fleetd config.** Blocks multi-repo use.
