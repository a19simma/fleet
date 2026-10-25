# Job git credentials and permission policy

Status: Accepted. The runner, push and pull request step and reporter are built and run by the daemon. Amends ADR-0011.

Pushing a branch and opening a pull request need write access to the repo, and ADR-0011 says fleetd holds no git credential. A headless `claude -p` run stalls on any permission prompt, and the agent can run arbitrary shell.

## Decision

- **Credential.** A fine-grained personal access token with contents and pull-requests write, scoped to named repos. It lives in `/etc/swarm/secrets.env` beside the other secrets, as `GH_TOKEN`. The first test scopes it to one throwaway repo.
- **Who sees it.** Only fleetd's `git push` and `gh` children get the token. The `git push` child gets `GIT_ASKPASS`, set to `fleetd askpass`, and `GH_TOKEN`, so `GH_TOKEN` reaches both the push process and the askpass helper it runs. The helper prints `GH_TOKEN` from its environment for a password prompt and `x-access-token` for a username prompt, so an https push needs no operator-supplied helper. The `gh` child gets `GH_TOKEN`, plus `GH_HOST` and `GH_ENTERPRISE_TOKEN` when set. The fetch from the agent's worktree and every other helper get no token. The agent child environment strips `GH_TOKEN` and `FLEET_TOKEN`, but that only cleans the child's own env block (see Known limit). The redactor also masks the value in events and transcripts. Any claim here that the token stays secret holds against a process under a uid other than fleetd's. It does not hold against the agent, which runs as fleetd's uid.
- **Pull request.** `gh pr create --repo <repo> --head <branch> --base <base> --title <tip commit subject, capped> --body "Fleet job <id>"`, run by fleetd after the push (ADR-0020). The agent never pushes.
- **Branch.** The result branch is `swarm/<job_id>`, the only branch namespace a Box may push (ADR-0016).
- **Permissions.** fleetd config marks a Box disposable or not. Only a disposable Box runs Jobs with `--dangerously-skip-permissions`. Other Boxes get a configurable permission mode and tool allowlist. Not built: only `disposable` exists.
- **Targets.** Each Job names its own `repo` and `base_ref`. The `repo_hosts` allowlist limits the host, not the repo path (see Which repos).

- **Which repos.** A job repo must be `https://` on a host listed in the `repo_hosts` config key, `github.com` by default. A port, userinfo, a backslash and every other scheme are rejected, so ssh, `git://`, `file://` and scp-style urls fail. `workspace::validate_repo` enforces this before any git process starts, and the runner repeats it before the push. `fleetd askpass` answers a username or password prompt only when the quoted url in the prompt is `https` on a listed host, taken after the last `@`, so `https://github.com@other.example` gets nothing. The push passes the list to the helper in `FLEETD_ASKPASS_HOSTS`, and a missing or empty list answers nothing. Mirror fetch and push run with `GIT_ALLOW_PROTOCOL=https`.
- **Test-only local repos.** `RepoPolicy::with_file_repos` (and `Config::allow_file_repos`) also admit `file://` urls and absolute paths and add `file` to `GIT_ALLOW_PROTOCOL`. Only Rust code can set it. The config file has no key for it and no environment variable reads it, so a production daemon never takes a local repo. Tests pair it with an empty `repo_hosts`.
- **Workspace git.** Every git call in `workspace.rs` runs with `env_clear` plus `PATH`, a scratch `HOME` and `XDG_CONFIG_HOME` under `<jobs_dir>/.git-home`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0` and `-c core.hooksPath=/dev/null -c core.fsmonitor=`. No token is in that environment, because the mirror is writable by the agent. Each sync runs `git remote set-url origin` and falls back to `git remote add origin`, so a mirror whose init succeeded and whose remote add did not recovers on the next sync.
- **Job id.** The server mints every job id as a ULID, which is `[A-Za-z0-9]`. The server accepts printable ASCII up to 64 bytes only to look up or cancel an id, and no submit path takes a client id. The daemon accepts 1 to 64 bytes of `[A-Za-z0-9_]`, so every id the server issues passes and the path and branch `swarm/<job_id>` stay safe. Inferred, not part of the design: this leaves the server's lookup rule looser than the daemon rule, and a row inserted by hand with another id fails at the daemon with a fixed error. The server rule was left alone to keep this change inside fleetd. A test asserts that generated ids pass the daemon rule.

## Consequences

- fleetd holds the job PAT. It is a new credential, separate from the baked git credential, and sits beside the four credentials already on a Box: the Claude subscription token, the baked git credential, the VPN auth key and the Box bearer token. A leaked PAT can write to its scoped repos only.
- With skip-permissions the agent has a full shell, so the Box is the sandbox. Its blast radius is the Box plus its Claude token plus the git PAT, which the agent can read (see Known limit).
- A leaked client token (ADR-0023) can make a Box clone any repo the PAT reads and push to any it writes, until the allowlist exists.
- A Job prompt can make the agent print files it can read. The redactor masks exact values only.

## Known limit

- The agent runs as the same uid as fleetd and can read the fleetd process environment through `/proc/<pid>/environ` and any file fleetd reads, so `GH_TOKEN` and `FLEET_TOKEN` are exposed to the agent on this box. The same uid also reads `/etc/swarm/secrets.env`. Use a fine-grained PAT scoped to throwaway repos on disposable Boxes only. Per-job isolation (a separate uid or a credential broker) is not built.

## Considered and rejected

- **A GitHub App installation token per Job.** Safer and short lived, but needs an App and a minting step. A later upgrade.
- **An SSH deploy key.** Cannot open a pull request.
- **Always skip permissions.** Ties safety entirely to the environment, including on a Box that is not disposable.
- **A permission allowlist only.** Stalls on any tool outside the list.
- **One repo set in fleetd config.** Blocks multi-repo use.
