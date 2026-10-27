# Profile blob distribution

Status: Accepted 2026-10-27. Migration 0011, migration 0012 and the `FleetProfiles` and `FleetBatches.SubmitBatch` client RPCs are built; `GetProfileBlob` and fleetd materialisation are not built. Amends ADR-0021 and ADR-0023. Implements the storage and delivery of ADR-0034.

ADR-0034 defines the Profile. The server holds Profiles and fleetd applies them, so a Box needs the Profile content for a leased Job without holding a client credential.

## Decision

### Storage

- Migration 0011 adds insert-only blobs and versions. Migration 0010 belongs to phase durations.
- Migration 0011 stores the hash as `bytea`, so the stored content is the exact canonical bytes. A trigger on both tables rejects UPDATE, DELETE and TRUNCATE.
- Inferred, not part of the design: a profile name is 1 to 64 bytes of `[A-Za-z0-9_-]`. `CreateProfile{name, content_json}` validates with `Profile::from_json` and `validate`, stores the canonical bytes and returns the existing version when the name already holds that content, so a name can never hold one hash under two versions. `GetProfile{name, version?}` returns the latest version when `version` is unset. `ListProfiles{limit, after_name}` returns each name with its latest version and hash, 50 by default and 200 at most.
- Migration 0012 adds the batch table with `repeats` CHECK = 1, and adds `batch_id`, `repeat_idx`, `batch_pos`, `profile_name`, `profile_version` and `profile_hash` to `jobs`, with foreign keys that pin a Job to a stored version and hash.

### Protocol

- `Job.profile = 22` and `Job.batch_id = 23`.
- Client scope gains `FleetProfiles` and `FleetBatches`.
- Worker scope gains `FleetWorker.GetProfileBlob{job_id, attempt, box}`, authorised against the lease like the other worker calls.

### Materialisation

Per Job, fleetd:

1. Fetches the blob with `GetProfileBlob`.
2. Verifies the hash.
3. Re-validates it with the shared validator in `fleet-core`.
4. Overlays a `Bundle` with `Bundle::from_files`.
5. Applies the fixed Floor and the Box ceilings last.

fleetd fails closed with `profile invalid: <reason>`. A **Bundle** is the on-disk file set fleetd installs for the agent; the Profile overlays it for one Job.

## Consequences

- fleetd does not trust the server: a bad blob, hash or content stops the Job before the agent starts.
- The lease authorises the blob read, so a Box reads only the Profile of a Job it holds.
- ADR-0033 stays reserved for `GetJobCredential` and bundle distribution of Phase E. This ADR does not use it.

## Considered and rejected

- **Inline Profile in `Job`.** It grows every claim and repeats the content per Job.
- **Box fetches with the client token.** It would hand a Box the client scope (ADR-0023).
- **Trusting the server validation.** A second check in fleetd costs little and keeps the Floor local.
