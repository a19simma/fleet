# Profile version streams are keyed by profile id

Status: Proposed 2026-11-04. Built: migration 0027 and the profile store, which keys create, read, share and the Job pin by profile id. Amends ADR-0035. Builds on ADR-0052.

Migration 0023 added the `profile.id` surrogate key with `UNIQUE (owner_user_id, name)`, so two owners can each hold a Profile with the same name. `profile_version` and the job pin stayed keyed by name. A review of the profile store found that two owners of one name shared a single version stream: the second owner's create landed in the first owner's version numbers. This ADR keys every version stream by the Profile id.

## Decision

### Identity

- A Profile is identified by `profile.id`.
- A name is a label that belongs to one owner. Resolving a name to an id is an owner-scoped lookup on `(owner_user_id, name)` and takes the caller's user id.
- Create, lock, read, share and pin take the id from that caller-scoped lookup, never from the name alone.

### Storage

- Migration 0027 builds `profile_version` keyed by `(profile_id, version)` with `UNIQUE (profile_id, hash)`. `hash` references `profile_blob (hash)`. A create whose content equals an existing version of the same profile returns that version and makes it the latest. It adds no row.
- The job pin moves to foreign keys on `(profile_id, profile_version)` and `(profile_id, profile_hash)` into `profile_version`.
- `jobs.profile_id` is new. The `jobs_batch_columns_together` CHECK requires `profile_id` together with the other batch and profile columns.
- `jobs.profile_name` stays as a display copy and is not a key.
- The migration backfills `profile_version` and `jobs.profile_id` from the system-owned profile row of each name. It raises an exception when a name has no system-owned row, when the new row count differs from the old one, or when a pinned job is left without `profile_id`.
- The per-profile advisory lock key is `profile_id`.
- Migration notes: every pre-existing `profile_version` row and pinned job moves to a shared profile named after it and owned by the `system` user, so history that earlier releases kept per name belongs to that shared profile, whose owner is the `system` user. `system_user_id()` finds the `system` user by case-insensitive username, so a human who registered as `System` before migration 0023 owns those profiles. Registration does not reserve the name; check the `users` table before upgrading a deployment.

### Blobs

- A blob stays keyed by hash and is shared by content across owners.
- A create reply must not reveal whether a blob or a hash exists for another owner. Requirement: a create of a blob that already exists returns the same status and the same body fields as a create of a new blob. Test: create the same content twice from two owners and compare the two replies field by field. Timing parity is a goal that no test measures.

## Amends

- ADR-0035, Storage: `profile_version` and the Job pin key on `(profile_id, version)` and `(profile_id, hash)`. ADR-0035 gets an "Amended by ADR-0057" pointer and keeps its text.

## Consequences

- Two owners of the same name get two version streams that start at version 1 each.
- The migration aborts on a database that holds a version row whose name has no system-owned profile.
- Store code binds `profile_id` and no longer inserts or selects by name alone.
- Content-addressed blob sharing stays, so storage use does not grow with owners.

## Considered and rejected

- **Keying versions by `(owner_user_id, name)`.** It repeats the owner and name in every row and in the Job pin foreign keys, and a rename would rewrite them.
- **Per-owner blob tables.** It breaks content sharing and still needs a hash lookup that can leak existence.
