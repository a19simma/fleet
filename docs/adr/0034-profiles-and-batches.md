# Profiles and batches

Status: Accepted 2026-10-27. Profile storage, the `FleetProfiles` client RPCs, `fleet profile create`, `list` and `show`, migration 0012, the `FleetBatches.SubmitBatch` client RPC and `Job.profile` and `Job.batch_id` are built; the rest is not built. Amends ADR-0021, ADR-0023, ADR-0029 and ADR-0030. ADR-0035 covers storage and distribution.

A future UI will dispatch the same prompt with several named configurations and compare outcomes. No UI exists yet. This ADR records the structure that comparison needs: a Profile that fixes the agent config of one Job, a Batch that groups Jobs by Profile, and a per-profile view in the CLI.

## Decision

### Profile

A **Profile** is typed JSON with `deny_unknown_fields`. Its content fields are:

- `claude_md`
- `context_files`: a list of `{path, text}`
- `prompt_prefix`
- `prompt_template`: only the `{prompt}` placeholder is allowed
- `skills`: a list of `{name, files[{path, text}]}`, inline
- `allow` and `deny`: permission rule lists
- `model`, `max_turns` and `max_budget_usd`
- `env_flags`: a map from name to `"0"` or `"1"`
- `settings`: permissions, model and attribution

A Profile holds no MCP servers, no hooks and no secrets. `claude_version` is never part of the content: ADR-0029 records it per Job in the stamp.

### Identity

The canonical form is JSON with sorted keys and no whitespace. The **Profile hash** is `sha256("fleet-profile-v1\0" + canonical bytes)`. A Profile is immutable and content-addressed. A named Profile has **Profile versions**, each pointing at one blob hash. A Job records the profile name, version and hash.

### Floor and clamp

The **Floor** is fixed in fleetd. It sets the permission mode to `dontAsk` and carries a fixed deny set. A Profile can only tighten it:

- The effective deny list is the Floor deny set united with the Profile `deny`.
- An `allow` entry that matches a Floor deny is dropped.

The Box ceilings for max turns, budget and timeout win over the Profile values (clamp). fleetd applies the Floor and the ceilings last.

### Floor

`fleetd::floor::FLOOR_DENY` holds the Floor deny set:

- `Bash(git push *)`, `Bash(git push*)`, `Bash(gh *)`: the daemon publishes the branch (ADR-0024).
- `Bash(curl *)`: denied in the default agent settings.
- `WebFetch`: fetches go through the egress proxy (ADR-0031), not the tool. This is a documented choice.
- `Edit`, `Write`, `NotebookEdit`, `MultiEdit`: edits go through Bash (ADR-0024).

An `allow` entry matches a Floor deny, and is dropped, when `covers(deny, allow)` holds. Identical strings cover. A bare tool name covers that name and that name followed by `(`. `Tool(prefix*)` covers `Tool(arg)` when `arg` starts with `prefix`, and `Tool(prefix2*)` when `prefix2` starts with `prefix`. Tool names are matched exactly, with case and whitespace significant. `Bash(git push*)` therefore also covers `Bash(git pushd*)`: when in doubt the allow is dropped. fleetd reports each dropped allow. The effective deny list is the Floor set, then the Profile extras in sorted order, with no repeats. Max turns and budget use the Box default when the Profile sets none, then the lower of that value and the Box ceiling.

Whether deny beats allow in the real claude is unverified: the probe on the dev box (claude 2.1.289) stopped at "Not logged in", so neither the allow-and-deny run nor the allow-only control ran. Dropping the allow is correct either way.

### Validation

`fleet-core` checks these rules on every Floor. Each failure is a fixed error that never echoes the input.

- Caps: at most 64 files (context files plus skill files), 4 MiB of text in total, 256 KiB per file.
- Paths: relative, `/` separated, no empty, `.` or `..` component, no component starting with `.`, at most 256 bytes. Skill names are one component of `[A-Za-z0-9_-]`. No duplicate paths or skill names. Symlinks are refused when fleetd writes the files.
- `prompt_template` holds `{prompt}` once and no other brace.
- `settings.model` equals `model` when set. Settings hold no `defaultMode`, hooks or MCP, and permission rules name no MCP tool.
- `env_flags` names come from a fixed allowlist in `fleet-core`.
- Paths and allow rules naming credential locations are rejected, and text that looks like a secret is rejected. Both checks are best-effort lints.
- `max_budget_usd` is whole US cents.

### Overlay

`fleetd::profile_apply::apply_profile` lays a validated Profile over the box bundle. `fleetd::profile_apply::load` checks the blob against the Job's `ProfileRef` first, and the runner calls it before the clone (ADR-0035). Inferred, not part of the design: the rules below.

- `CLAUDE.md` is replaced by the Profile `claude_md` when set. Each context file is written at `.claude/ctx/<path>` inside the bundle root and imported by an `@.claude/ctx/<path>` line appended to `CLAUDE.md`, so the import resolves from the file that holds it. A context path with whitespace is refused, because an import line cannot carry it.
- Skill files are written at `skills/<name>/<path>`.
- `settings.json` is generated: permissions from the Floor, the Profile model and attribution. Rules in `settings.permissions` join `allow` and `deny` before the Floor. A Profile with no allow rules keeps the default allow list; any allow rule replaces that list.
- Overlay paths that collide when compared without case are refused, because the box may hold a case-insensitive filesystem.
- The argv pieces are `--model`, `--allowedTools`, `--disallowedTools`, `--max-turns` and `--max-budget-usd` (cents written as dollars with two decimals). The prompt is the prefix followed by the template with `{prompt}` replaced once.
- Unverified: whether claude discovers `skills/<name>/` under `CLAUDE_CONFIG_DIR` and resolves the import. The probe on the dev box stopped at "Not logged in".

### Batch

A **Batch** is one prompt dispatched once per Profile. `repeats` is 1 for now, enforced by a CHECK; a request may send 0, which means 1, and 2 or more is refused. `SubmitBatch` takes a prompt, a repo, a `base_sha` of 40 lowercase hex characters, 1 to 16 distinct Profile names and an idempotency key. One transaction pins the latest version and hash of each Profile and inserts one Job per Profile, so a failure leaves no Batch and no Job. The same key with the same parameters returns the stored Batch; other parameters give `ALREADY_EXISTS`. Batch Jobs use `base_sha` as the base ref and do not open a pull request. `fleet batch show` prints one column per Profile. A missing value prints `-`. The rows carry the command run breakdown and the time taken, both read from the existing telemetry (ADR-0029).

### Scope

This task set builds structure only: Profile storage and application, a batch table and the CLI view.

## Deferred

- Stats grouped by Profile.
- Scheduler and fairness between Batches.
- Budget caps per Batch.
- The judge.
- Repeats above 1.
- A/A runs.
- MCP in Profiles.
- Assigning `claude_version` per Profile.
- A UI and a Profile editor.
- Per-Profile secrets.

## Consequences

- A comparison reads figures that already exist. No new metric is defined.
- Keeping secrets, hooks and MCP out of a Profile means a Profile is safe to store and show.
- The Floor stays out of reach of a Profile, so a hostile or mistaken Profile cannot loosen permissions.

## Considered and rejected

- **Mutable named Profiles.** A Job could not tell which content it ran.
- **`claude_version` inside the Profile.** The stamp already records the version that ran, and a Profile that pins it duplicates that record.
- **Letting a Profile loosen the Floor.** Removes the one guarantee that holds for every Job.
