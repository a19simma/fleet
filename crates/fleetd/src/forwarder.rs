//! Forwards queued events to the server through unary `PushEvents` calls.
//!
//! Each call carries the head of the queue: at most 100 events and 256 KiB of stored
//! envelopes, sent once 500 ms have passed since the last clean drain. A failed drain waits
//! on a full-jitter backoff instead, one second doubling to five minutes, reset only by a
//! drain that finishes without error. The server dedupes on `(box, id)`, so a resend after a
//! lost reply is safe. Queue rows are deleted only through the `acked_through_seq` the
//! server returns, so an error status such as `InvalidArgument` leaves every row queued and
//! the batch is retried on the backoff schedule.

use std::future::Future;
use std::time::Duration;

use fleet_proto::queued_event;
use fleet_proto::v1::PushEventsRequest;
use fleet_proto::v1::fleet_ingest_client::FleetIngestClient;
use prost::Message;
use tokio::sync::watch;
use tonic::transport::Channel;

use crate::backoff::{Backoff, Random, SystemRandom};
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
/// error, [`run`] logs it and backs off, and the event stays queued, so it blocks the
/// events behind it. Rows that are not envelopes are deleted without a call when no
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

/// Drains the queue until `shutdown` completes, with system randomness for the backoff.
///
/// See [`run_with`].
pub async fn run(
    store: &Store,
    client: &mut Ingest,
    batching: &Batching,
    shutdown: impl Future<Output = ()>,
) {
    run_with(store, client, batching, SystemRandom::new(), shutdown).await;
}

/// Drains the queue until `shutdown` completes, drawing backoff jitter from `random`.
///
/// A drain that ends without error, including one over an empty queue, resets the backoff
/// and waits `max_wait`. A failed drain is logged by its code only and waits a full-jitter
/// delay that doubles from one second to a five minute ceiling on each consecutive
/// failure. Shutdown cancels a drain in flight, so a hung call cannot block it; the
/// cancelled batch stays queued and is resent later.
pub async fn run_with<G: Random>(
    store: &Store,
    client: &mut Ingest,
    batching: &Batching,
    random: G,
    shutdown: impl Future<Output = ()>,
) {
    let (drained, _) = watch::channel(0);
    run_observed(store, client, batching, random, &drained, shutdown).await;
}

/// Like [`run_with`], and counts each drain that ends without error on `drained`.
///
/// The count starts wherever the caller's sender holds it and rises by one after every
/// clean drain, including one over an empty queue, before the loop waits `max_wait`.
pub async fn run_observed<G: Random>(
    store: &Store,
    client: &mut Ingest,
    batching: &Batching,
    random: G,
    drained: &watch::Sender<u64>,
    shutdown: impl Future<Output = ()>,
) {
    let queue = Queue {
        store,
        client,
        batching,
    };
    run_loop(
        queue,
        batching.max_wait,
        Backoff::standard(random),
        drained,
        shutdown,
    )
    .await;
}

trait Drain {
    async fn drain(&mut self) -> Result<u64, Error>;
}

struct Queue<'a> {
    store: &'a Store,
    client: &'a mut Ingest,
    batching: &'a Batching,
}

impl Drain for Queue<'_> {
    async fn drain(&mut self) -> Result<u64, Error> {
        drain(self.store, self.client, self.batching).await
    }
}

async fn run_loop<D: Drain, G: Random>(
    mut queue: D,
    max_wait: Duration,
    mut backoff: Backoff<G>,
    drained: &watch::Sender<u64>,
    shutdown: impl Future<Output = ()>,
) {
    tokio::pin!(shutdown);
    loop {
        let wait = tokio::select! {
            () = &mut shutdown => return,
            result = queue.drain() => match result {
                Ok(_) => {
                    backoff.reset();
                    drained.send_modify(|count| *count += 1);
                    max_wait
                }
                Err(err) => {
                    tracing::warn!(%err, "forwarding failed");
                    backoff.next_delay()
                }
            }
        };
        tokio::select! {
            () = &mut shutdown => return,
            () = tokio::time::sleep(wait) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex, PoisonError};

    use tokio::sync::Notify;
    use tokio::time::Instant;

    use super::*;

    const NEAR_ONE: f64 = 0.999;

    struct Fixed(f64);

    impl Random for Fixed {
        fn next_unit(&mut self) -> f64 {
            self.0
        }
    }

    struct Script {
        results: VecDeque<bool>,
        calls: Arc<Mutex<Vec<Instant>>>,
        stop: Arc<Notify>,
    }

    impl Drain for Script {
        fn drain(&mut self) -> impl Future<Output = Result<u64, Error>> {
            self.calls
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Instant::now());
            let ok = self.results.pop_front().unwrap_or(true);
            if self.results.is_empty() {
                self.stop.notify_one();
            }
            std::future::ready(if ok { Ok(0) } else { Err(Error::ReadOnly) })
        }
    }

    const MAX_WAIT: Duration = Duration::from_secs(7);

    async fn gaps(results: &[bool], unit: f64) -> Vec<Duration> {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(Notify::new());
        let script = Script {
            results: results.iter().copied().collect(),
            calls: Arc::clone(&calls),
            stop: Arc::clone(&stop),
        };
        let backoff = Backoff::standard(Fixed(unit));
        let finished = tokio::time::timeout(
            Duration::from_secs(3600),
            run_loop(
                script,
                MAX_WAIT,
                backoff,
                &watch::channel(0).0,
                stop.notified(),
            ),
        )
        .await;
        assert!(finished.is_ok(), "loop did not stop");
        let times = calls.lock().unwrap_or_else(PoisonError::into_inner).clone();
        times.windows(2).map(|pair| pair[1] - pair[0]).collect()
    }

    fn secs(values: &[u64]) -> Vec<Duration> {
        values.iter().map(|s| Duration::from_secs(*s)).collect()
    }

    fn near_one(values: &[u64]) -> Vec<Duration> {
        values
            .iter()
            .map(|s| Duration::from_secs(*s).mul_f64(NEAR_ONE))
            .collect()
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_grows_across_consecutive_failures() {
        let observed = gaps(&[false; 6], NEAR_ONE).await;

        assert_eq!(observed, near_one(&[1, 2, 4, 8, 16]));
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_is_capped() {
        let observed = gaps(&[false; 13], NEAR_ONE).await;

        assert_eq!(
            observed,
            near_one(&[1, 2, 4, 8, 16, 32, 64, 128, 256, 300, 300, 300])
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_delay_is_jittered_below_the_ceiling() {
        let observed = gaps(&[false; 4], 0.5).await;

        assert_eq!(
            observed,
            vec![
                Duration::from_millis(500),
                Duration::from_secs(1),
                Duration::from_secs(2)
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn backoff_resets_after_success() {
        let observed = gaps(&[false, false, false, true, false, false], NEAR_ONE).await;

        let mut expected = near_one(&[1, 2, 4]);
        expected.push(MAX_WAIT);
        expected.extend(near_one(&[1]));
        assert_eq!(observed, expected);
    }

    #[tokio::test(start_paused = true)]
    async fn a_clean_drain_waits_max_wait_not_backoff() {
        let observed = gaps(&[true; 4], NEAR_ONE).await;

        assert_eq!(observed, secs(&[7, 7, 7]));
    }
}
