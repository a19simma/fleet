# Retros, improvements and pitfalls

Status: Proposed 2026-11-09, CLI built in WRK-10, web pages built in WRK-11. Not built: decision 4 creates no Pitfall from an accepted Improvement of kind `pitfall`. Builds on ADR-0064 and ADR-0063. Extended by ADR-0066.

A ralph loop learns from `progress.md` lines and `CLAUDE.md` notes that a person copies by hand. A lesson found in one Attempt is lost to the next worker unless someone files it. This ADR gives the server a place for what a loop learns and a way to hand it back to the next Attempt.

## Decision

1. **Retro.** A **Retro** is a review of a span of finished Work items in one Work project. `OpenRetro` takes the span. Tables: `retro`, `improvement`, `improvement_occurrence`, `pitfall`.
2. **Improvement.** An **Improvement** is one proposed change to how the loop works, found in a Retro or filed during an Attempt: a title, a body, a kind and a count of occurrences. Filing the same title again adds an `improvement_occurrence` row and raises the count; it does not add an Improvement. An existing title filed into a Retro keeps its first `retro_id`, so it does not count in that Retro's undecided check. The count ranks Improvements.
3. **Disposition is required to close.** Each Improvement ends as `accepted`, `rejected`, `deferred` or `applied`, with a reason. `CloseRetro` is refused while any Improvement of the Retro has no disposition. The refusal names the count and no client text.
4. **Pitfall.** A **Pitfall** is a known trap with a symptom, a cause and a fix, kept as short text. Pitfalls are user-level: they belong to a User and apply to every Work project of that User, because a trap in a tool or a language follows the person, not the repository. A Work project can list project-level Pitfalls too, with the same fields and a project key. An accepted Improvement of kind `pitfall` creates a Pitfall.
5. **Brief.** `GetWorkBrief` returns the text a worker reads before an Attempt: the Work item, its Slices, the Pitfalls ranked by how often they were hit and how recent they are, and Improvements that are open or accepted and not yet applied, filed against that Work item or whose vertical names one of its Slices. The brief is capped at a fixed token budget set by one shared constant. It drops the lowest-ranked entries first and says how many it dropped. The server renders the brief from stored rows through the strip path (ADR-0063), never from raw client text.
6. **Hostile text.** Every title, body, symptom, cause and fix is checked with the reject set at the proto boundary and stripped with the strip set before it enters a brief.
7. **Surfaces.** CLI: `fleet retro`, `fleet improvement`, `fleet pitfall` (WRK-10). Web: Retro, Improvement and Pitfall pages and a verify review, a page that lists the undecided Improvements that block closing a Retro and says whether it is blocked, ready or closed (WRK-11).

## Consequences

- A lesson filed once reaches every later Attempt through the brief, with no person copying lines.
- A Retro cannot close with open questions, so a backlog of undecided Improvements cannot hide. A slow reviewer blocks closing a Retro; `deferred` is the release valve.
- User-level Pitfalls cross Work projects of one User and never cross Users.
- The token cap loses low-ranked Pitfalls. The brief reports the drop, so a worker knows the list is partial.

## Considered and rejected

- **Free-form notes in `progress.md` only.** No ranking, no disposition and no way to cap what a worker reads.
- **Pitfalls per repository only.** The same trap in a tool recurs across repositories and would be filed again each time.
- **Close a Retro with open Improvements.** Open items rot. A forced disposition keeps the list short.
- **Rank by recency alone.** A rare, costly trap drops out of the brief once a few cheap ones are newer.
- **Embeddings for matching duplicate Improvements.** A dependency and a model call for a table with an exact-title key that already works. Revisit when titles drift in practice.
