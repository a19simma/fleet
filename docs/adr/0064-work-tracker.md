# Server-side work tracker

Status: Proposed 2026-11-09, partly built (store, graph RPCs, claim with slice leases, lease TTL and renew, report with derived counts and a redacted 8 KiB evidence tail, notes, defers, lease reaper; not built: WRK-5, WRK-6, WRK-12, WRK-13). Builds on ADR-0042 (users, owner scope), ADR-0059 (repository registry) and ADR-0063 (hostile text). Extended by ADR-0065 and ADR-0066.

A ralph loop keeps its work graph in `.ralph/tasks.json`, `.ralph/slices.json` and `.ralph/progress.md` on one machine. One conductor reads them, so a second operator, a second machine or the web UI cannot see the graph, and a crashed worker leaves a stale line nobody reaps. Fleet already stores Jobs, Users and a repository registry. This ADR moves the graph into the server so agents and people claim and report work through one API.

## Decision

1. **Vocabulary.** A **Work project** binds one registered repository to an owner. A **Work item** is one unit of change with a key unique in its project. A **Slice** is a named set of repository paths. An **Attempt** is one claim of a Work item and ends in a **Verdict**. See `CONTEXT.md`.
2. **Graph model.** Tables: `work_project`, `work_slice`, `work_slice_path`, `work_mergeable_path`, `work_item`, `work_item_slice` (membership), `work_dep` (one row per edge, with a `why` text), `work_slice_lease`, `work_attempt`, `work_event` and `work_defer`. Every row hangs off a project, and a project has one owner. All reads and writes check the owner (ADR-0042).
3. **Graph writes serialise on the project row.** Each write that changes items, slices or edges takes `FOR UPDATE` on the `work_project` row, then runs the cycle check and the slice-overlap check from `fleet_core::graph` (WRK-1) inside the same transaction. Two slices overlap when any two of their paths are equal or one is a parent of the other, compared segment by segment. A path in the mergeable set belongs to no slice and never blocks a claim.
4. **Ready is computed, never stored.** A Work item is **Ready** when it is not cancelled or blocked, every dependency has a passing Attempt, no Attempt holds it, and every Slice it belongs to is free of leases. A slice-less Work item owns no Slice and is always free of leases.
5. **Claim takes every Slice lease in one transaction.** `ClaimWork` locks the project row, recomputes Ready for the named item and inserts one `work_slice_lease` row per Slice of the item. The primary key is the Slice, so a second claim on any shared Slice fails on the key even if the Ready check raced. The claim inserts the Attempt in the same transaction. A claim that finds the item not Ready is refused with a fixed reason.
6. **A lease has a TTL.** The holder renews it with `RenewLease`. A reaper sweep, run by the server on a timer, closes the Attempt as `lost` and deletes the leases of any lease past its expiry. Time comes from the database clock.
7. **Attempt report and derived counts.** `ReportAttempt` records a Verdict, `pass` or `fail`, with a note and an evidence tail. The server cuts the evidence to 8 KiB after redaction and hostile-text stripping, using `sanitise_text` (ADR-0063), so a secret straddling the cap leaves no prefix. `passes` and `fails` of a Work item are counts over Attempts. No column stores them. A Verdict closes the Attempt and deletes the leases in the same transaction.
8. **Defer.** A **Defer** records work found during an Attempt and left out of scope: a title, a reason and the vertical it belongs to. A Defer is not a Work item and is never Ready. A person promotes it to a Work item, or drops it.
9. **Idempotency.** Every mutating RPC takes a client key. A repeat with the same `(project, key)` returns the first result. Hostile text in any title, note or reason is refused at the proto boundary with the reject set (ADR-0063) and escaped in the web UI.
10. **Repo binding.** `Work project.repo` is a foreign key to a registry row of the same owner (WRK-13, ADR-0059). Setting it validates the row.
11. **Import and export.** `ImportWork` reads a `.ralph` directory, dry-run by default, idempotent on `(project, key)`, and prints every line it could not parse. Export regenerates `tasks.json` and `slices.json` so a loop can still run from files (WRK-12).
12. **Surfaces.** CLI `fleet work` (WRK-5): `project`, `slices`, `add`, `list`, `show`, `dep`, `cancel`, `unblock`, `next`, `claim`, `pass`, `fail`, `note`, `defers`. Web pages (WRK-6): board, dependency graph, Slice-lock view, item timeline, Defers by vertical.

## Consequences

- One transaction guards the whole claim, so two workers cannot hold overlapping Slices. The cost is that every graph write and every claim in a project serialises on one row. Inferred, not part of the design: a project with a few dozen Work items and a handful of workers does not feel it.
- A worker that dies keeps its Slices locked until the TTL passes. The reaper bounds the wait, and `unblock` lets a person clear it sooner.
- Derived counts cost a scan of a Work item's Attempts. Attempts per item stay small.
- The `.ralph` files stay a valid interchange format. The server is the source of truth once a project is imported.
- The Work project owner scope is the only access rule in v1. Teams and shared projects are later work.

## Considered and rejected

- **Keep the graph in git files only.** One machine reads it, nothing reaps a dead worker and the web UI cannot show lock state.
- **Store `passes` and `fails` as columns.** They drift from the Attempt rows after a retried write or a reaper close.
- **Optimistic claims with a version column.** Two overlapping claims on different Slices need a check across rows. A row lock on the project is simpler to reason about than a version per Slice.
- **A lease per Work item instead of per Slice.** It does not stop two items that touch the same paths.
- **Reuse `job` rows as Work items.** A Job is one run on one Box. A Work item has many Attempts, dependencies and Slices, and exists before any Box runs it.
- **An external tracker (GitHub issues, Linear).** The loop needs lease and Slice semantics no tracker offers, and a hard dependency on a third party for a private-network tool.
