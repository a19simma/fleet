# Suggested edits

Status: Proposed 2026-11-09, decide and apply path built in WRK-9 (Web session in WRK-11). Builds on ADR-0064 and ADR-0065. Amends ADR-0042 (which credential kinds may decide).

An Attempt or a Retro often ends with a proposed change: split a Slice, add a path to a Slice, record a Pitfall, patch a file in the repository. A worker agent must not apply these on its own authority, because an edit to the graph or to repository instructions steers every later worker. This ADR makes each proposal a record a person decides.

## Decision

1. **Suggested edit.** A **Suggested edit** is a stored proposal with a kind, a payload, a target, a `base_hash` and a state: `pending`, `accepted`, `rejected` or `stale`. Kinds: `slice_op` (add, remove or move a path in a Slice, or create or delete a Slice), `pitfall` (create or change a Pitfall) and `file_patch` (a unified diff against the repository).
2. **Who decides.** `DecideEdit` accepts a signed-in User's Web session or API token (ADR-0042). Both resolve to one named User: the session is a server-side row for a passkey login, and the API token is created by that User in the UI and stored as a SHA-256 hash. The Client token is refused: it acts as the Bootstrap user, which has no passkey and stands for any holder of the shared secret, so it names no person. The Box token is refused: it is box scope and carries no user. A Job agent holds only Job credentials, which are third-party secrets released to a Box and never a server credential, so it has nothing `DecideEdit` accepts. An agent can only file an edit. Inferred, not part of the design: ADR-0042 does not say which kinds may take a decision that steers later workers, so this may need an ADR-0042 amendment naming Web session and API token as the deciding kinds and the Client token as refused. WRK-9 checks the auth code first and amends ADR-0042 only if that split is not already enforced.
3. **Accept applies in the same transaction.** Accepting a `slice_op` or `pitfall` edit applies it inside the decide transaction. The transaction takes `FOR UPDATE` on the Work project row (ADR-0064), re-runs the overlap and cycle check on the changed graph and rolls back with a fixed reason if it fails. An accepted edit is therefore either fully applied or not accepted.
4. **A `file_patch` is never applied by the server.** The server stores the diff and marks it accepted. `fleet edit apply` on a person's machine runs `git apply --3way` into the working tree, leaves the change uncommitted and does not stage it. The person reviews and commits.
5. **Stale marking.** `base_hash` is the hash of the target when the edit was filed: the Slice's path set, the Pitfall text or the file blob id. Each decide and each list recomputes it. A mismatch moves a `pending` edit to `stale`, and `DecideEdit` refuses to accept a `stale` edit. The filer can re-file against the new base.
6. **Bounds.** A payload is at most 64 KiB. A diff is checked as hostile-text clean with the reject set (ADR-0063), apart from the newline and tab a diff needs. A project holds at most a fixed number of `pending` edits, one shared constant, and refuses new ones past it.
7. **Surfaces.** CLI `fleet edit list`, `show`, `accept`, `reject`, `apply` (WRK-10). Web diff review with accept and reject (WRK-11).

## Consequences

- No agent can change the graph or a file by itself. A person is in the path of every structural change.
- Accept can fail on overlap long after the edit was filed. The reason is fixed and the edit stays `pending` for a fresh look.
- Stale marking costs a hash per pending edit per read. The pending cap bounds it.
- `fleet edit apply` runs only on a machine with a checkout. A reviewer on the web accepts, and the filer or a maintainer applies.

## Considered and rejected

- **Agents apply their own edits.** One bad Attempt then rewrites the rules the next worker reads.
- **Server pushes the patch to the repository.** It needs a write credential on the server for a branch no person has read, and it skips the uncommitted review step.
- **No `base_hash`, rebase at accept.** A silent rebase of a Slice change can pass a graph check and still mean something else than the reviewer saw.
- **Auto-accept low-risk kinds.** Pitfalls are read by every later Attempt, so even a small one steers the loop.
