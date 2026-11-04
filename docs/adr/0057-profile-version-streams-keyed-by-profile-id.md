# Profile version streams are keyed by profile id

Status: Proposed 2026-11-04. Migration 0027 is written on the PRF-S0 branch. The RPC and store changes are not built. Amends ADR-0035. Builds on ADR-0052.

Migration 0023 added the `profile.id` surrogate key with `UNIQUE (owner_user_id, name)`, so two owners can each hold a Profile with the same name. `profile_version` and the job pin stayed keyed by name. PRF-S1 found that two owners of one name shared a single version stream: the second owner's create landed in the first owner's version numbers. This ADR keys every version stream by the Profile id.

## Decision

### Identity

- A Profile is identified by `profile.id`.
- A name is a label that belongs to one owner. Resolving a name to an id is an owner-scoped lookup on `(owner_user_id, name)` and takes the caller's user id.
- Create, lock, read, share and pin take the id from that caller-scoped lookup, never from the name alone.

### Storage

- Migration 0027 builds `profile_version` keyed by `(profile_id, version)` with `UNIQUE (profile_id, hash)`. `hash` references `profile_blob (hash)`.
- The job pin moves to foreign keys on `(profile_id, profile_version)` and `(profile_id, profile_hash)` into `profile_version`.
- `jobs.profile_id` is new. The `jobs_batch_columns_together` CHECK requires `profile_id` together with the other batch and profile columns.
- `jobs.profile_name` stays as a display copy and is not a key.
- The migration backfills `profile_version` and `jobs.profile_id` from the system-owned profile row of each name. It raises an exception when a name has no system-owned row or when the new row count differs from the old one.
- The per-profile advisory lock key is `profile_id`.

### Blobs

- A blob stays keyed by hash and is shared by content across owners.
- A create reply must not reveal whether a blob or a hash exists for another owner. A create that matches an existing blob returns the same reply shape and timing class as one that stores a new blob.

## Amends

- ADR-0035, Storage: `profile_version` and the Job pin key on `(profile_id, version)` and `(profile_id, hash)`, not on the name. ADR-0035 gets an "Amended by ADR-0057" pointer and keeps its text.

## Consequences

- Two owners of the same name get two version streams that start at version 1 each.
- The migration aborts on a database that holds a version row whose name has no system-owned profile.
- Store code that inserts or selects by name needs a rewrite to bind `profile_id` (PRF-S0B).
- Content-addressed blob sharing stays, so storage use does not grow with owners.

## Considered and rejected

- **Keying versions by `(owner_user_id, name)`.** It repeats the owner and name in every row and in the Job pin foreign keys, and a rename would rewrite them.
- **Per-owner blob tables.** It breaks content sharing and still needs a hash lookup that can leak existence.
