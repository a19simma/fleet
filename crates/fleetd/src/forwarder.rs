//! Forwards queued events to the server through unary `PushEvents` calls.
//!
//! Each call carries the head of the queue: at most 100 events and 256 KiB of stored
//! envelopes, sent once 500 ms have passed since the last drain. The server dedupes on
//! `(box, id)`, so a resend after a lost reply is safe. Queue rows are deleted only through
//! the `acked_through_seq` the server returns.

use std::future::Future;
use std::time::Duration;

use fleet_proto::queued_event;
use fleet_proto::v1::PushEventsRequest;
use fleet_proto::v1::fleet_ingest_client::FleetIngestClient;
use prost::Message;
use tonic::transport::Channel;

use crate::{Error, Store};

/// Largest request message the server decodes, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// The ingest client the forwarder drives.
pub type Ingest = FleetIngestClient<Channel>;

/// When a batch is cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Batching {
    /// Most events in one call.
    pub max_events: u32,
    /// Most stored envelope bytes in one call. One event larger than this still goes alone.
    pub max_bytes: u64,
    /// Pause between drains of the queue.
    pub max_wait: Duration,
}

impl Default for Batching {
    fn default() -> Self {
        Self {
            max_events: 100,
            max_bytes: 256 * 1024,
            max_wait: Duration::from_millis(500),
        }
    }
}

/// The result of one successful `PushEvents` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sent {
    /// Events in the request.
    pub events: usize,
    /// The `acked_through_seq` the server returned, clamped to the highest `seq` sent.
    pub acked_through: u64,
    /// Queue rows deleted because of it.
    pub deleted: u64,
}

fn shrink_to_cap(request: &mut PushEventsRequest) {
    while request.encoded_len() > MAX_MESSAGE_BYTES && request.events.len() > 1 {
        request.events.truncate(request.events.len().div_ceil(2));
    }
}

/// Sends the head of the queue once and deletes what the server acknowledged.
///
/// Returns `None` when the queue is empty. The request is halved until it fits the
/// server's decode limit. A single event over that limit stays in the request alone and
/// the server rejects it, which surfaces as [`Error::Rpc`]. [`drain`] propagates the
/// error, [`run`] logs it and sleeps `max_wait`, and the event stays queued, so it blocks
/// the events behind it. Rows that are not envelopes are deleted without a call when no
/// row in the batch decodes, and are skipped otherwise.
/// The acknowledgement is clamped to the highest `seq` actually sent.
///
/// # Errors
///
/// Fails when the queue read or delete fails, the server answers with an error, or the
/// server acknowledges no sent event ([`Error::AckIgnored`]). The queue is left as it was
/// in the last two cases.
pub async fn send_batch(
    store: &Store,
    client: &mut Ingest,
    batching: &Batching,
) -> Result<Option<Sent>, Error> {
    let rows = store.peek(batching.max_events, batching.max_bytes).await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut request = PushEventsRequest::default();
    for row in &rows {
        if let (Ok(envelope), Ok(seq)) = (row.envelope(), u64::try_from(row.seq)) {
            request.events.push(queued_event(seq, &envelope));
        } else {
            tracing::warn!(seq = row.seq, "queued event is not an envelope, skipped");
        }
    }
    shrink_to_cap(&mut request);
    let events = request.events.len();
    let Some(highest) = request.events.iter().map(|event| event.seq).max() else {
        let top = rows.last().map_or(0, |row| row.seq);
        let deleted = store.ack_through(top).await?;
        return Ok(Some(Sent {
            events: 0,
            acked_through: 0,
            deleted,
        }));
    };
    let reply = client
        .push_events(request)
        .await
        .map_err(|status| Error::Rpc(Box::new(status)))?
        .into_inner();
    let acked_through = reply.acked_through_seq.min(highest);
    let through = i64::try_from(acked_through).unwrap_or(i64::MAX);
    let deleted = store.ack_through(through).await?;
    if deleted == 0 {
        return Err(Error::AckIgnored {
            acked_through: reply.acked_through_seq,
        });
    }
    Ok(Some(Sent {
        events,
        acked_through,
        deleted,
    }))
}

/// Sends batches until the queue is empty.
///
/// # Errors
///
/// Fails on the first error from [`send_batch`], including an acknowledgement that
/// deletes nothing, so the loop always ends.
pub async fn drain(store: &Store, client: &mut Ingest, batching: &Batching) -> Result<u64, Error> {
    let mut total = 0;
    while let Some(sent) = send_batch(store, client, batching).await? {
        total += sent.deleted;
    }
    Ok(total)
}

/// Drains the queue every `max_wait` until `shutdown` completes.
///
/// A failed drain is logged by its code only and retried on the next round. Shutdown
/// cancels a drain in flight, so a hung call cannot block it; the cancelled batch stays
/// queued and is resent later.
pub async fn run(
    store: &Store,
    client: &mut Ingest,
    batching: &Batching,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => return,
            result = drain(store, client, batching) => {
                if let Err(err) = result {
                    tracing::warn!(%err, "forwarding failed");
                }
            }
        }
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(batching.max_wait) => {}
        }
    }
}
