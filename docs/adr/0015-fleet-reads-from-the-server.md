# Fleet reads from the server

Status: Accepted

The existing picker has `fleet` ssh into each Box and poll tmux and pueue, so the picker needs the laptop awake, on the VPN, and willing to run one ssh round trip per Box per refresh and per preview move. fleetd (ADR-0011) and the server (ADR-0013) now hold that state.

## Decision

`fleet list`, `fleet preview` and a new `fleet watch` read from the Fleet server. Attach stays on ssh. `fleet` is a Rust binary sharing the `fleet.v1` proto crate with the server (ADR-0013). It reads the server address from config, `FLEET_SERVER_URL`, and uses no Tailscale call or identity.

- **Replaces the existing ssh polling in part.** The polling, the ssh sources of List and Preview, and the cost of one ssh round trip per refresh. The picker, the line formats (`box-N`, `box-N/<session>`, `box-N#<id>`), Connect and the sesh integration stay.
- **List.** One `FleetQuery.ListFleet` call. Each line shows the age of its data. A silent Box shows `stale` or `lost` from its heartbeat age.
- **Preview.** Event-derived: status, prompt, last assistant message, last notification, task state, cost, result tail, and the best-effort transcript summary and session timeline (ADR-0011). A live pane capture stays an explicit ssh action, `fleet preview --live`.
- **Watch.** v1: the client polls `ListFleet` and prints transitions (a session going idle, a Box going stale). Later: `FleetQuery.Watch` streams transitions, including a Job finishing with cost, and a reconnect replays from `ListEvents --since`.
- **Drain.** `fleet drain box-N` sets the drain flag and shows readiness: pueue idle, fleetd queue empty, no unpushed commits. Scale-down stays a manual Box count edit.
- **Fallback.** For one release `fleet list` falls back to the existing ssh poll when the server is unreachable. That poll is ssh access, outside fleet traffic, and still uses the VPN peer list.

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- `fleet watch` is a client poll of `ListFleet` in v1. There is no `Watch` rpc in v1.
- `fleet preview` and `fleet drain` are out of v1.

## Consequences

- The picker works while the laptop was asleep, and shows what happened meanwhile.
- No ssh fan-out for listing. ControlMaster matters only for attach.
- Freshness equals the 30 s heartbeat and the event stream, not the instant of the call.
- The preview loses live screen text by default.
- The CLI is a Rust binary with a compile step on the laptop. The nushell script stays only as the ssh fallback.
- The server is a new dependency of the daily workflow.

## Amendments

- **Job commands (ADR-0021), built.** The CLI adds `fleet submit`, `jobs`, `status`, `logs [-f]` and `cancel`, through `FleetJobs` with the client token (ADR-0023). `list` and `watch` are unchanged.

## Considered and rejected

- **Keep polling, add caching.** Still needs a live laptop to fill the cache.
- **Ship pane text to the server on a timer.** Puts screen contents, including printed secrets, in the database.
- **Drop the ssh fallback at once.** Leaves the picker blank during a server outage.
