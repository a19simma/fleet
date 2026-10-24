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
- **Per-event rejects.** An event whose envelope is missing, whose `id` or `source` does not parse, whose `payload_json` is not JSON, whose numbers exceed the column range, or that holds a NUL character goes into `rejected` and is acked. Retrying it would never succeed.
- **Storage failure.** A database error returns `Unavailable` and stores nothing.
- **Wire shape.** The envelope travels as flat fields with `ts_ms` (capture time) and `payload_json` (the payload as a JSON string), not as a protobuf `Struct`. `session_id`, `prompt_id`, `workdir` and `occurred_at_ms` are proto3 `optional`, so absent and empty differ.
- **Heartbeat.** `Heartbeat` is a separate unary call. The server stamps `last_heartbeat_at` with its own clock and stores the queue figures from the request. It replies with `next_in_s`, 30 in this build.
- **Ids.** `id` is a dedupe key, not a security boundary. A box can only collide with its own ids, because the key includes `box`. The FNV-1a derived ids of ADR-0012 stay: a collision drops one event of one box and no one gains anything from forcing it.

Supersedes the stream and ack parts of ADR-0012 (one stream, cumulative high-water mark per box and boot, unique `(box, boot_id, seq)`) and the forwarder section of the plan (bidirectional stream, `Hello`, keepalive).

## Decisions (2026-10-24)

- Accepted 2026-10-24.
- The server does not enforce a batch size. The tonic default message limit of 4 MiB applies. The forwarder limits of 100 events, 256 KiB or 500 ms stay a fleetd choice.

## Consequences

- Retry logic lives in one place: the call either succeeded or fleetd sends the batch again.
- Gaps and server restarts need no handshake. A reconnect is a new call.
- Every batch costs one request and one transaction. At tens of events per second per fleet that is acceptable.
- The server cannot tell fleetd which events it already holds. fleetd learns only from the reply, so a long outage ends with a resend of the whole queue.
- A malformed event is lost with a reason in the reply, and fleetd can log it.
- A mixed-box batch is a client bug, so it fails loudly.

## Considered and rejected

- **Bidirectional stream with `Hello` and a high-water mark.** More state on both sides and a resync protocol, for no gain at this rate.
- **Client streaming with one ack at the end.** The same batch semantics as unary with a harder error model.
- **Unique `(box, boot_id, seq)`.** A fleetd queue rebuild would turn a valid event into a constraint error. The event id already decides identity.
- **A hash of the whole envelope as the key.** The derived id already encodes the natural key.
