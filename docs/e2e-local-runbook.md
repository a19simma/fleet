# Local end-to-end test runbook

Facts for running real end-to-end tests of fleet from the maintainer's Mac. Every line below was observed on 2026-11-07 unless marked as an assumption.

## Setup on this machine

- The CLI is `fleet`, installed at `~/.local/bin/fleet`.
- The live server is `https://fleet.simonmalm.com`.
- `FLEET_SERVER_URL` is not set in the shell. Pass `--server https://fleet.simonmalm.com` on every command, or export the variable for the session.
- The CLI finds its own credentials. Authentication succeeded with `fleet list` and `fleet jobs` and no extra flags. Never read, print or copy the token or any CLI config file while testing.
- One box is registered, state `LIVE`.
- Jobs run as kind `agent` on that box, on branches named `swarm/<job-id>`.

## Repos

- `a19simma/ana` and `a19simma/radiant` are the repos the maintainer added to their user for testing. This comes from the maintainer, and the CLI cannot confirm it.
- `a19simma/ana` has job history. `a19simma/radiant` had none on 2026-11-07 and one on 2026-11-08 (see Run record), so it is the safer first target.
- `fleet submit --repo` takes a string, and the server accepts or refuses it at submit time. The server requires an `https://` URL, for example `https://github.com/a19simma/radiant`. On 2026-11-08 the form `a19simma/radiant` was refused with `InvalidArgument: invalid job request`, and the URL form was accepted. The source has a `fleet repo` command (`add`, `list`, `remove`); whether the installed `fleet` binary has it is unchecked. A job history entry `a19simma/ana.git` exists and looks like the same repo under a second spelling. The submit form that produced it is unknown.

## Commands

| Goal | Command |
| --- | --- |
| Check the box is live | `fleet --server <url> list` |
| List recent jobs (50 by default) | `fleet --server <url> jobs` |
| Submit without opening a pull request | `fleet --server <url> submit --repo <https-url> --base <ref> --no-pr "<prompt>"` |
| Make a repeated submit return the same job | add `--idempotency-key <key>` |
| Show one job | `fleet --server <url> status <id>` |
| Follow a job, exit 0 only on success | `fleet --server <url> watch <id>` |
| Print the transcript | `fleet --server <url> logs <id>` |
| Follow the transcript, exits nonzero unless the job succeeded | `fleet --server <url> logs --follow <id>` |
| Cancel a job | `fleet --server <url> cancel <id>` |

## A safe first test

1. Run `fleet list` and confirm the box is `LIVE` with a recent last-seen time.
2. Submit a small read-only prompt against `https://github.com/a19simma/radiant` with `--no-pr` and a unique `--idempotency-key`.
3. Run `fleet watch <id>`. Exit code 0 means the job succeeded.
4. Run `fleet logs <id>` and read the transcript.
5. If the job hangs, run `fleet cancel <id>`.

## What this tests

- A test run on the deployed server exercises the version that server runs, which was 0.3.3 in `infra/` on 2026-11-07 and 0.3.8 on 2026-11-08. Deploy the release you want to test first, then submit.
- A GitHub App job commits as the App only when the user holds `forge:github_app` and the repo is on the server allowlist (`FLEET_GITHUB_APP_REPOS`). The CLI cannot show either. See `docs/github-app-runbook.md`.

## Rules for the agent running these tests

- Do not read credential, token or env files.
- Never run `create-user`, `reset-passkeys`, `grant-admin` or `revoke-admin` against the live database or config. They are `fleet-server` admin commands (see `docs/adr/0056-admin-is-a-user-flag.md`), not `fleet` subcommands.
- Submit only when the maintainer has asked for a test, and always pass `--no-pr` unless a pull request is the point of the test.
- Record the job id of every job you submit.

## Run record

- 2026-11-08, server and box on 0.3.8: `fleet submit --repo https://github.com/a19simma/radiant --base main --no-pr --idempotency-key e2e-0.3.8-20261108-1` returned job `01M6YBHJ2JV7PW3R3XD7YVDXHJ`. It ended `SUCCEEDED` in 2 turns. `fleet status` named the branch `swarm/01M6YBHJ2JV7PW3R3XD7YVDXHJ`, but the job made no commits, so none was pushed. The transcript ended with `fleet: no_changes` and no pull request. The pull request path was not exercised. The repo holds only `.gitignore`, `LICENSE`, `README.md` and `SPEC.md`.
