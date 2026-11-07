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
- `a19simma/ana` has job history. `a19simma/radiant` had none on 2026-11-07, so it is the safer first target.
- The CLI has no `repo` command yet. `fleet submit --repo` takes a free string, and the server accepts or refuses it at submit time. Use the `owner/name` form. A job history entry `a19simma/ana.git` exists and looks like the same repo under a second spelling.

## Commands

| Goal | Command |
| --- | --- |
| Check the box is live | `fleet --server <url> list` |
| List recent jobs (50 by default) | `fleet --server <url> jobs` |
| Submit without opening a pull request | `fleet --server <url> submit --repo <owner/name> --base <ref> --no-pr "<prompt>"` |
| Make a repeated submit return the same job | add `--idempotency-key <key>` |
| Show one job | `fleet --server <url> status <id>` |
| Follow a job, exit 0 only on success | `fleet --server <url> watch <id>` |
| Print the transcript | `fleet --server <url> logs <id>` |
| Follow the transcript, exits nonzero unless the job succeeded | `fleet --server <url> logs --follow <id>` |
| Cancel a job | `fleet --server <url> cancel <id>` |

## A safe first test

1. Run `fleet list` and confirm the box is `LIVE` with a recent last-seen time.
2. Submit a small read-only prompt against `a19simma/radiant` with `--no-pr` and a unique `--idempotency-key`.
3. Run `fleet watch <id>`. Exit code 0 means the job succeeded.
4. Run `fleet logs <id>` and read the transcript.
5. If the job hangs, run `fleet cancel <id>`.

## What this tests

- A test run on the deployed server exercises the version that server runs, which was 0.3.3 in `infra/` on 2026-11-07. Deploy the release you want to test first, then submit.
- A GitHub App job commits as the App only when the user holds `forge:github_app` and the repo is on the server allowlist (`FLEET_GITHUB_APP_REPOS`). The CLI cannot show either. See `docs/github-app-runbook.md`.

## Rules for the agent running these tests

- Do not read credential, token or env files.
- Never run `create-user`, `reset-passkeys`, `grant-admin` or `revoke-admin` against the live database or config. They are `fleet-server` admin commands (see `docs/adr/0056-admin-is-a-user-flag.md`), not `fleet` subcommands.
- Submit only when the maintainer has asked for a test, and always pass `--no-pr` unless a pull request is the point of the test.
- Record the job id of every job you submit.
