# Ingest protocol

Status: Accepted

ADR-0012 and the plan sketched `PushEvents` as one long-lived bidirectional stream, a `Hello` handshake and a cumulative high-water mark per box and boot. The server built in step 3 uses something simpler. This ADR records what runs.

## Decision

`FleetIngest.PushEvents` is a unary call. fleetd sends a batch, the server stores it in one transaction and replies once.

- **Request.** `PushEventsRequest` holds `QueuedEvent { seq, envelope }` entries. `seq` is the fleetd queue sequence number and travels beside the envelope, not inside it.
- **Ack.** The reply carries `acked_through_seq`, the highest `seq` in the request, plus `stored`, `duplicate` and a list of `Rejection { seq, reason }`. A successful reply acks the whole batch: every event in it was stored, was already stored, or was rejected. fleetd deletes queued events through `acked_through_seq`. A failed call acks nothing and fleetd resends the batch.
- **Dedupe key.** `(box, id)`. The insert is `ON CONFLICT (box, id) DO NOTHING`. A resent batch yields `duplicate` counts and projects nothing a second time. `(box, boot_id, seq)` has a non-unique index and is not a constraint.
- **No `Hello`, no high-water mark.** The server keeps no per-box ingest cursor and has no `box_boots` table. After a gap fleetd resends from its queue and the dedupe key absorbs the overlap.
- **Box check.** The box name must match `box-<digits>`. Every event in a request must carry the same box. An invalid name or a mixed batch fails the whole request with `InvalidArgument`. fleetd does not retry that code.
- **Per-event rejects.** An event whose envelope is missing, whose `id` or `source` does not parse, whose `payload_json` is not JSON or exceeds 256 KiB, whose timestamps pass the end of year 9999, whose numbers exceed the column range, or that holds a NUL character in a field, payload key or payload string goes into `rejected` and is acked. Retrying it would never succeed. An event whose `schema_version` is not 1 is also listed in `rejected` but is not acked: `acked_through_seq` stops one below the lowest such `seq`, so a newer fleetd keeps those events and resends them after the server upgrades. The rule a client can rely on: every event at or below `acked_through_seq` may be deleted, and every event above it stays queued and is resent. A permanent rejection (a NUL character, an out-of-range value) whose `seq` lies above the lowest unsupported-version `seq` is therefore not acked either, and the server rejects it again on each resend until the server is upgraded. `Rejection` carries only `seq` and a free-text `reason`, so the reply does not mark a rejection as permanent or retryable; the reason text for an unsupported version starts with `unsupported schema_version`. An unsupported-version event that is also over 256 KiB or lacks an envelope is rejected before ingest, never reaches the schema check, and is acked. The forwarder (a later task) deletes only through `acked_through_seq`.
- **Storage failure.** A database error returns `Unavailable` and stores nothing.
- **Wire shape.** The envelope travels as flat fields with `ts_ms` (capture time) and `payload_json` (the payload as a JSON string), not as a protobuf `Struct`. `session_id`, `prompt_id`, `workdir` and `occurred_at_ms` are proto3 `optional`, so absent and empty differ.
- **Heartbeat.** `Heartbeat` is a separate unary call. The server stamps `last_heartbeat_at` with its own clock and stores the queue figures from the request. It replies with `next_in_s`, 30 in this build.
- **Ids.** `id` is a dedupe key, not a security boundary. A box can only collide with its own ids, because the key includes `box`. The FNV-1a derived ids of ADR-0012 stay: a collision drops one event of one box and no one gains anything from forcing it.

Supersedes the stream and ack parts of ADR-0012 (one stream, cumulative high-water mark per box and boot, unique `(box, boot_id, seq)`) and the forwarder section of the plan (bidirectional stream, `Hello`, keepalive).

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- A request carries at most 500 events, or the call fails with `InvalidArgument`. The server decodes messages up to 1 MiB, applies a 30 second request timeout, 8 concurrent requests and 32 streams per connection, and pings every 30 seconds. Postgres statements time out after 10 seconds. The forwarder limits of 100 events, 256 KiB or 500 ms stay a fleetd choice.
- The server accepts `schema_version` 1 only. ADR-0012 asks for the current and previous version, and no earlier version has shipped. The window opens when version 2 is defined.
- A `Notification` for a session with no row stores the event and creates no row, since it sets `last_notification` only (ADR-0019). Box identity (`hostname`, `machine_id`, `boot_id`) follows the newest new event by capture time, so a late batch from an older boot does not overwrite it. A heartbeat stamps the same identity with the server clock under the same guard, so an event captured before the heartbeat cannot rewind it.

## Consequences

- Retry logic lives in one place: the call either succeeded or fleetd sends the batch again.
- Gaps and server restarts need no handshake. A reconnect is a new call.
- Every batch costs one request and one transaction. At tens of events per second per fleet that is acceptable.
- The server cannot tell fleetd which events it already holds. fleetd learns only from the reply, so a long outage ends with a resend of the whole queue.
- A malformed event is lost with a reason in the reply, and fleetd can log it.
- A mixed-box batch is a client bug, so it fails loudly.
- The local queue has no per-row delivery state. fleetd peeks the head of the queue in `seq` order, sends it, and deletes through `acked_through_seq` after a reply. There is no `inflight` state, no attempt counter and no retry time column, and a restart needs no reset. Backoff is the forwarder's local state. An overflow marker is a single row: the drop count merged into a marker after it was peeked is lost when its ack deletes the row, and the next drops create a new marker.

## Considered and rejected

- **Bidirectional stream with `Hello` and a high-water mark.** More state on both sides and a resync protocol, for no gain at this rate.
- **Client streaming with one ack at the end.** The same batch semantics as unary with a harder error model.
- **Unique `(box, boot_id, seq)`.** A fleetd queue rebuild would turn a valid event into a constraint error. The event id already decides identity.
- **A hash of the whole envelope as the key.** The derived id already encodes the natural key.
