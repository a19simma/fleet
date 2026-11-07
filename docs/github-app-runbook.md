# GitHub App runbook

Operations runbook for the GitHub App lane. Design: [ADR-0058](adr/0058-github-app-lane.md). Deployment: [infra/README.md](../infra/README.md), section Server variables. Master key custody is separate: [credential-key-runbook.md](credential-key-runbook.md).

Every id, key, host and email below is a placeholder. Replace `<app-id>`, `<slug>`, `<bot-id>`, `<installation-id>` and `<fleet-host>` with your own values.

Unverified claims: three things in this runbook about GitHub are not checked against GitHub documentation or a live response: GitHub adds `metadata: read` to every installation token, a push that changes `.github/workflows` needs the `workflows` permission, and the pull request shows the bot as author. Two more are flagged where they appear: the shape of the `GET /app/installations/{id}` reply, and how an older fleetd answers the `github_installation_token` wire kind. Sourced: the one-hour token life comes from GitHub's REST reference for creating an installation access token (official docs, linked in ADR-0058). The server requires status 204 from `DELETE /installation/token` and treats any other answer as a failed revoke (source code, `crates/fleet-server/src/cred/app_mint.rs`); ADR-0058 does not cite a GitHub page for that status.

## What the lane does

A User who holds a `github_app` credential and the `forge:github_app` capability gets an installation token for the Job repository, which lasts one hour (official docs, see Unverified claims) instead of a PAT. The Job commits, pushes and opens its pull request as the App's bot. A PAT Job is unchanged and keeps the fixed identity `Fleet Job <fleet-job@fleet.invalid>`. When a User holds both credentials, the App wins. A mint failure never falls back to the PAT (ADR-0058, SEC-008). The server answers `FAILED_PRECONDITION` with the status text `github app token unavailable`, which fleetd discards. A mint failure at the first fetch reports `credentials could not be fetched`; a refresh whose mint fails keeps the last good token until it expires. Search the server log for `github app token mint failed`, which the server logs when the call to GitHub fails or its response fails validation (refusal, timeout, transport error, malformed or invalid body). The server logs `github app token revoke failed` when its own revoke of a token does not get a 204 answer (a `fleet credential verify` probe, a failed post-mint recheck or a cancelled call); that token then lives until it expires, at most one hour, and a `revoke_failed` row records it. If the mint line is absent, check the lane config: App id or key unset, a malformed installation id, or a signing failure, none of which log.

The end-to-end check is in `crates/fleetd/tests/daemon_jobs.rs`: `an_app_job_commits_as_the_bot_and_the_token_reaches_only_the_forge_call` and `a_pat_job_in_the_same_harness_keeps_the_fixed_identity`. They run the real daemon against a local bare git remote and a local fake REST endpoint for the pull request.

## Create and install the App

1. Create a GitHub App under the operator account. Make it private, so it installs only on that account (ADR-0058, SEC-001).
2. Grant these repository permissions: `contents: write`, `pull_requests: write`, `checks: read`, `statuses: read`. GitHub adds `metadata: read` to every installation token (see Unverified claims). The server accepts `metadata: read` in the token response and refuses any other key or higher level (SEC-016). Without `checks: read` and `statuses: read` the CI steps fail for App Jobs, and GitHub refuses the token request while the App lacks a requested permission (inferred, ADR-0058).
3. A push that changes `.github/workflows` needs the `workflows` permission (see Unverified claims), which the server does not request. Such pushes fail.
4. Install the App on the account and select the repositories Jobs may touch. Note the installation id from the installation URL.
5. Generate a private key in the App settings. GitHub lets an App hold several keys at once, which the rotation below uses.
6. Look up the bot id: `gh api '/users/<slug>[bot]' --jq .id`. The bot email is `<bot-id>+<slug>[bot]@users.noreply.github.com`.

Not yet built, so do not rely on them: the per-credential repository list, a revoke that survives a daemon exit (ADR-0058, Status; see Refresh, limits and audit). Until the per-credential repository list exists, the operator list is the only repository ceiling, so any holder of `forge:github_app` can mint a write token for any repository the operator list allows. Grant the capability with that in mind.

## Server variables

Set the id, the key file, the name and the email on the fleet-server Deployment, together with `FLEET_MASTER_KEY_FILE`. Unset, the lane is off and startup is unchanged.

| Variable | Rule | Startup failure |
| --- | --- | --- |
| `FLEET_GITHUB_APP_ID` | 1 to 20 ASCII digits, no leading zero, within `u64`. | An invalid value, or `FLEET_GITHUB_APP_KEY_FILE` set without it, stops startup naming `FLEET_GITHUB_APP_ID`. |
| `FLEET_GITHUB_APP_KEY_FILE` | Path to the PEM key. | `FLEET_GITHUB_APP_ID` set without it stops startup naming `FLEET_GITHUB_APP_KEY_FILE`. A bad file stops startup with `FLEET_GITHUB_APP_KEY_FILE:` and a fixed message, see below. |
| `FLEET_MASTER_KEY_FILE` | Path to the credential master key file, see the credential key runbook. | Required when `FLEET_GITHUB_APP_ID` is set: without it startup stops naming `FLEET_MASTER_KEY_FILE` with `required when FLEET_GITHUB_APP_ID is set`. |
| `FLEET_GITHUB_APP_BOT_NAME` | 1 to 64 characters from letters, digits, space, `.`, `_`, `-`, `[` and `]`. Starts alphanumeric, ends alphanumeric or `]`. | Missing or outside the grammar stops startup naming this variable. |
| `FLEET_GITHUB_APP_BOT_EMAIL` | `<bot-id>+<slug>[bot]@users.noreply.github.com`: digits, `+`, lowercase letters, digits and `-`, `[bot]`, that domain. At most 128 bytes. | Missing or outside the grammar stops startup naming this variable. |
| `FLEET_GITHUB_APP_ACCOUNT` | The GitHub login of the operator account that owns the installation: 1 to 39 ASCII letters, digits and hyphens, not starting or ending with a hyphen. Compared after ASCII lowercasing. | Required once the App is set. Missing or outside the grammar stops startup naming this variable. |
| `FLEET_GITHUB_APP_INSTALLATIONS` | Comma separated installation ids, each a `u64` with no leading zero, at most 64 entries. | Unset or empty allows no installation, so every put, verify and release is refused. An empty entry or a bad id stops startup naming this variable. |
| `FLEET_GITHUB_APP_REPOS` | Comma separated `owner/name` or `owner/*` entries, at most 1024. Each owner must be `FLEET_GITHUB_APP_ACCOUNT`. | Unset or empty allows no repository, so every verify and release is refused. A bad entry, another owner or any other glob stops startup naming this variable. |

The id and the key file go together: one without the other stops startup, and an empty value counts as unset. The server makes both key paths absolute against its working directory at startup. After it loads the key it asks GitHub which App the key belongs to. A key for another App stops startup with `FLEET_GITHUB_APP_KEY_FILE: the key does not belong to FLEET_GITHUB_APP_ID`. When GitHub cannot be reached, the server logs a warning that the id check was skipped and starts. The name, the email and the account are required once the id and key file are set. The name and the email are read only then, so a name or email set alone is ignored, not rejected. The server checks both against the identity grammar (SEC-006). fleetd checks them again before the clone and fails the Job on a bad identity, so a server bug cannot inject a hostile name.

## Mount the private key

The key is a file, never an environment variable and never in the sealed store (ADR-0058). Keep it in a Kubernetes Secret apart from `fleet-master-key`, and mount it read-only at a path of its own, for example `/etc/fleet/github-app/private-key.pem`, with `FLEET_GITHUB_APP_KEY_FILE` set to that path. The Deployment in this repo mounts only the master key, so the operator adds the volume, the mount and the variables in its own patch, including the three allowlist variables.

The server loads the file once at startup and refuses it when:

| Check | Message after `FLEET_GITHUB_APP_KEY_FILE:` |
| --- | --- |
| The file cannot be opened or read. | `github app key file unreadable` |
| The path is not a regular file. | `github app key path is not a regular file` |
| The file is owned by another uid than the server's effective uid. | `github app key file must be owned by the server user` |
| `mode & 0o077` is not zero. | `github app key file must not be group or other accessible` |
| The file is over 16 KiB, or is not a PEM RSA private key of 2048 to 8192 bits. | `github app key is not a PEM RSA private key of at least 2048 bits` |

Why the mode check exists: the key mints tokens that write to every installed repository. A group or other readable file lets any other uid in the pod or on the node read it. Mode `0400` or `0600` passes. `0440` fails, because the group bit is inside `0o077`. The server also refuses a file owned by another uid than its own effective uid, so a stolen copy placed by another user does not load. No other user may write the file.

Symlinks are followed, because Kubernetes Secret mounts are symlinks. The server checks the file the link points at. It accepts PKCS#1 (`RSA PRIVATE KEY`) and PKCS#8 (`PRIVATE KEY`) PEM.

The mode check and the owner check must both pass. A Secret file is owned by root, so a server running as uid 65532 (see `infra/deployment.yaml`, which also sets `fsGroup: 65532`) fails the owner check on a root-owned mount, whatever the mode. With mode `0400` and root as owner it also cannot read the file. Kubernetes can add group read for `fsGroup`, which the mode check refuses. The operator must make the file's owner the server uid, through the pod security context or the mount, and keep the mode at `0400` or `0600`. Unverified: no setting in this repo does this, and whether a Secret volume can satisfy both rules is untested. Test it on a live cluster before you rely on it. The startup messages above tell the cases apart: `unreadable` means the uid cannot read it, `must be owned by the server user` means the owner is wrong, `must not be group or other accessible` means the mode is too wide. If the mount cannot pass, a copy step into an `emptyDir` that sets the file to `0400` for uid 65532 is a candidate. It is not part of this repo and no image shell is available in the distroless server image, so that step would need its own container.

## Rotate the key

The server holds one parsed key for the life of the process and reads the file only at startup. A new key takes effect after a restart.

1. In the App settings, generate a second private key. GitHub keeps the old one valid.
2. Update the key Secret with the new key. Keep the same file name and mode.
3. Restart the server pods. A bad file stops the new pod at startup and the old pod keeps serving, so a rolling restart does not take the lane down. Pods that have not restarted still sign with the old key.
4. Check the pod logs for `github app key loaded` on every pod.
5. Delete the old key in the App settings only after every pod runs the new one. Deleting it earlier makes the old pods fail their mints. A Job in its first fetch reports `credentials could not be fetched`; a refresh whose mint fails keeps the last good token until it expires. The server log shows `github app token mint failed`.

Running Jobs are not lost. The server never stores the token, so a restart does not touch a token a Box already holds. That token lasts one hour (official docs, see Unverified claims). fleetd refreshes it before a push or `gh` child, and a refresh uses whichever key the server signs with at that time, so keep the old key until every pod runs the new one.

## Grant the capability and store the credential

1. An admin grants `forge:github_app` to the User on the capabilities page, `https://<fleet-host>/users/<user-id>/capabilities`. The server checks the capability when the credential is saved and again at each release. A revoke refuses a leased Job that has not yet fetched its credentials.
2. The User stores the installation id. The value is the id and nothing else, and the id must parse as `u64`:

   ```
   printf '%s' '<installation-id>' | fleet credential put github_app
   ```

   The secret is read from stdin and never from an argument. The command prints the stored row with its id.

The server refuses the installation before any GitHub call when the id is not in `FLEET_GITHUB_APP_INSTALLATIONS`. It then calls `GET /app/installations/{id}` with the App JWT, at put and at every mint, and refuses an installation that is suspended, that belongs to another App id, whose `account.login` is not `FLEET_GITHUB_APP_ACCOUNT` or whose reply carries another id. The shape of that reply is unverified against a live GitHub response: check it with `fleet credential verify` before you rely on it. The Job repository is compared in full as lowercase `owner/name` against `FLEET_GITHUB_APP_REPOS`; a repository with a CR, LF, backslash, `@`, an empty segment, a non-ASCII character or an over-long name never matches. The per-credential repository list an admin sets is not built, so the operator list is the only repository check. A refusal that arrives on a refresh mid-Job is sticky for that Job: fleetd does not reuse the held token and does not ask the server again.

| Refusal | Cause | Server status and message | CLI and web notice | Audit row |
| --- | --- | --- | --- | --- |
| Installation not allowed | Id off the list, empty list, suspended, other App id, other account or id mismatch. | `FAILED_PRECONDITION`, `github app installation is not allowed` | `installation_refused` | `denied`: `installation not on allowlist` or `installation binding refused` |
| Repository not allowed | Job repository off the list, owned by another account or malformed. | `FAILED_PRECONDITION`, `repository is not allowed for the github app` | `repo_refused` | `denied`: `repository not allowed` |
| Installation lookup failed | GitHub unreachable, non-200 or an incomplete reply. | `FAILED_PRECONDITION`, `github app token unavailable` at release, `UNAVAILABLE` at put | invalid token notice | `failed`: `mint failed` |

## Verify

1. Submit one Job as that User against a repository the installation covers. `fleet credential verify` mints against the repository of the User's latest Job and counts toward the per-User rate limit but never toward the per-Job cap (its audit rows have scope `probe`), so a User with no Job gets `FAILED_PRECONDITION` and the CLI notice for no job.
2. Run `fleet credential list` to read the credential id, then `fleet credential verify <id>`.
3. The server mints once and revokes the token, and returns no token text. A revoke GitHub refuses answers `valid: false`, so the CLI prints the refused notice. The call writes `attempt`, `minted` and `revoked` rows to `github_app_mint`. Success prints `GitHub accepted the stored credential.`, and a refused token prints `GitHub refused the stored credential.`. Any mint failure prints the invalid token notice, with no detail. For the cause, read the server log and check, in order: the App id, the key, the installation id, the granted permissions and the repository.
4. Run an App Job to the end. The pull request shows the bot as author (see Unverified claims). `git log` on the pushed branch shows `<name>` and `<email>` from the server variables for author and committer.

## Refresh, limits and audit

Built (ADR-0058):

- fleetd refreshes the installation token before a push or `gh` child, a mirror fetch or a broker `gh` call when under 10 minutes of it remain. Each of them holds the token it started with until it exits, so a refresh never revokes a token under a running child.
- The server allows `MAX_APP_MINTS_PER_JOB` (34) mint attempts per Job and `MAX_APP_MINTS_PER_USER_PER_MINUTE` (20) per User. Past the Job cap, the release answers `FAILED_PRECONDITION` with `github app token limit reached` (`PRECONDITION_APP_MINT_CAP`), which is terminal. Past the User limit, which counts every scope, it answers `github app token rate limited` (`PRECONDITION_APP_MINT_RATE`), which is retryable: the first fetch of a Job waits up to 70 seconds in 10 second steps and a refresh keeps the held token and retries after 30 seconds. A Job fails with `github app token rate limited` only when the limit holds through every wait. There is no PAT fallback.
- fleetd revokes the token a refresh replaced, and the held token when the Job ends, with `DELETE /installation/token`. A replaced token is revoked after the push or `gh` children that started with it have exited, at most 15 minutes later. The revoke is best effort with a 10 second bound. A failed revoke logs a fixed string and never fails the Job, so that token lives until its expiry.
- Every mint writes rows to `github_app_mint`: `attempt`, then `minted`, `failed` or `denied`, and `revoked` or `revoke_failed` when the server revokes after a failed recheck. The installation lookup and the mint share a 7 second budget, so the server answers inside fleetd's 10 second call limit. A `failed` row with reason `mint cancelled` means the call was dropped before the mint returned; that attempt still counts toward the cap, and a token GitHub may have created for it cannot be revoked. A `failed` row with reason `mint failed` can also mean the 7 second budget ran out; the same slot and revoke caveat apply.
- fleetd also revokes an installation token that came in a reply it rejected: a missing or invalid identity, a malformed reply, or a refresh that cannot swap in or finds its entry replaced by a re-fetch.

- Deleting a credential that has mint history sets a tombstone on the `credentials` row instead of removing it, because `github_app_mint` rows reference it and are insert-only. A tombstoned credential is never released, never verified and never overwritten: `PutCredential` on it answers `PRECONDITION_CREDENTIAL_TOMBSTONED`. A credential with no mint history is removed.

Not built: the per-credential repository list, the audit of revokes inside the mint client, a fleetd revoke that survives a daemon exit, and a revoke of a token GitHub created while the mint call was cut off (its value was never read, so it lives until its expiry, at most one hour).

When the Job cap is hit, the step fails with the Job reason `github app token limit reached`. A plain mint failure reports `credentials could not be fetched` instead. A refresh whose mint fails keeps the last good token until it expires. A box whose clock runs ahead of the server's refreshes every 45 minutes, keeps the token for 50 minutes after the fetch and then fails the step with `credential expired` if the refresh still fails. A box clock that runs behind cannot be detected: its steps fail at GitHub once the token has expired. To see the cause, list the denied rows. The table has no user column, so join through the credential:

```
SELECT m.at, m.job_id, m.reason
FROM github_app_mint m
JOIN credentials c ON c.id = m.credential_id
WHERE c.user_id = <user-id> AND m.outcome = 'denied'
ORDER BY m.at DESC;
```

Reason `job mint cap` means the Job used its 34 attempts. Reason `user mint rate` means the User started 20 mints in the last minute. A `denied` row is not repeated for one Job and scope while one with the same reason is under 60 seconds old. Rows with outcome `failed` carry the mint failure reason.

## Upgrade note

Applies when you move to a server and fleetd that carry the GitHub App lane (ADR-0058).

- Server variables: none are required to upgrade. To turn the lane on, set `FLEET_GITHUB_APP_ID`, `FLEET_GITHUB_APP_KEY_FILE`, `FLEET_GITHUB_APP_BOT_NAME`, `FLEET_GITHUB_APP_BOT_EMAIL` and `FLEET_GITHUB_APP_ACCOUNT` together, with `FLEET_GITHUB_APP_INSTALLATIONS` and `FLEET_GITHUB_APP_REPOS` to allow anything. The first two go as a pair, and the rest are required once they are set, except the two lists, which default to deny-all. A partial or invalid set stops startup with the variable named.
- Mount the key file first. A key file that is group or other accessible, not a regular file, over 16 KiB or not RSA stops startup.
- Database: the server migrations add the `github_app_mint` audit table and the `credentials.tombstoned_at` column (0033) and the `forge:github_app` capability CHECK (0034). They run with the server.
- fleetd: upgrade every Box before you grant `forge:github_app`. The Box needs the code that accepts the `github_installation_token` wire kind and the `GitIdentity`. How an older fleetd answers that kind is unverified.
- Behaviour change for a User who holds `github_app` and `forge:github_app`: Jobs use the App token, not the PAT, even when a PAT is stored. Commits, pushes and pull requests carry the bot identity. There is no PAT fallback: a mint failure at the first fetch fails the Job, and a refresh whose mint fails keeps the last good token until it expires. A failed first fetch reports `credentials could not be fetched`. A failed call to GitHub, or a response that fails validation, logs `github app token mint failed`; a lane config fault logs nothing.
- A User who holds `github_app` without `forge:github_app` fails the Job. The server answers `PERMISSION_DENIED`, fleetd maps every such answer to a lease mismatch, and the Job reports `credentials refused: lease does not match`. The server does not fall back to the PAT.
- No change for a User with only a PAT. Those Jobs keep `Fleet Job <fleet-job@fleet.invalid>` and the PAT.
- The token lasts one hour (official docs, see Unverified claims). fleetd refreshes it before a push or `gh` child, a mirror fetch or a broker `gh` call when under 10 minutes remain, within the per-Job and per-User mint limits (see Refresh, limits and audit). Each holds the token it started with until it exits.
