# Profiles and batches

Status: Accepted 2026-10-27. Not built. Amends ADR-0021, ADR-0023, ADR-0029 and ADR-0030. ADR-0035 covers storage and distribution.

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

### Validation

`fleet-core` checks these rules on every Floor. Each failure is a fixed error that never echoes the input.

- Caps: at most 64 files (context files plus skill files), 4 MiB of text in total, 256 KiB per file.
- Paths: relative, `/` separated, no empty, `.` or `..` component, no component starting with `.`, at most 256 bytes. Skill names are one component of `[A-Za-z0-9_-]`. No duplicate paths or skill names. Symlinks are refused when fleetd writes the files.
- `prompt_template` holds `{prompt}` once and no other brace.
- `settings.model` equals `model` when set. Settings hold no `defaultMode`, hooks or MCP, and permission rules name no MCP tool.
- `env_flags` names come from a fixed allowlist in `fleet-core`.
- Paths and allow rules naming credential locations are rejected, and text that looks like a secret is rejected. Both checks are best-effort lints.
- `max_budget_usd` is whole US cents.

### Batch

A **Batch** is one prompt dispatched once per Profile. `repeats` is 1 for now, enforced by a CHECK. `fleet batch show` prints one column per Profile. A missing value prints `-`. The rows carry the command run breakdown and the time taken, both read from the existing telemetry (ADR-0029).

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
