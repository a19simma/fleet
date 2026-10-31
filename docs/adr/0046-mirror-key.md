# Mirror key

Status: Proposed 2026-10-29. Built in the fleetd workspace (`mirror_dir_for` hashes the owner and the repo, tested). Not wired: no caller sets the owner from the Job, so every mirror still uses the empty owner. Amends ADR-0024 and ADR-0031.

fleetd keeps a git mirror per repository (ADR-0024) and clones Jobs from it (ADR-0031 P3). The mirror is fetched with a user's credential. A mirror shared across users would let one user's token pull content that another user's token could not.

## Decision

The mirror is keyed by `(user, repo)` from the start. The directory name derives from both the Job owner and the repo url, in place of the sha256 of the repo url alone (ADR-0024).

Cross-user separation is enforced once a second user exists. There is one user now, so the key has one value in practice.

## Consequences

- A second user's Jobs get a separate mirror, fetched with that user's credential.
- Disk use grows with the number of users per repo.
- Adding the key later would force a mirror rebuild. Doing it now costs nothing.

## Considered and rejected

- **Key by repo url only.** It leaks private content across users the day a second user arrives.
- **Defer the key until a second user exists.** It forces a rename and rebuild of every mirror at that point.
