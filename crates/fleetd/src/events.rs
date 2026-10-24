//! Event operations on the `events` table.
//!
//! Every function takes a connection, so a caller composes them inside one transaction.

use std::time::Duration;

use fleet_core::{Envelope, Identity, Source};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row, SqliteConnection};

use crate::Error;
use crate::system::fresh_id;

/// Kind of the event that reports dropped events.
pub const OVERFLOW_KIND: &str = "fleetd.queue_overflow";

/// Queue caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Cap on the summed byte length of stored envelopes.
    pub max_bytes: u64,
    /// Events whose `ts` is older than this are dropped.
    pub max_age: Duration,
}

/// Result of [`crate::Store::enqueue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueued {
    /// The event is committed under `seq`.
    Stored {
        /// Assigned sequence number.
        seq: i64,
    },
    /// An event with this id already existed under `seq`.
    Duplicate {
        /// Sequence number of the earlier copy.
        seq: i64,
    },
    /// The event was not kept: it exceeds the byte cap on its own, or cap enforcement
    /// removed it because every stored event ranks higher. Other drops caused by this
    /// call are counted in the `fleetd.queue_overflow` event.
    Dropped,
}

/// One stored row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueuedEvent {
    /// Commit order.
    pub seq: i64,
    /// Event id.
    pub id: String,
    /// Event time, milliseconds since the epoch.
    pub ts: i64,
    /// Event kind.
    pub kind: String,
    /// The stored envelope.
    #[serde(rename = "envelope")]
    pub payload: Value,
}

impl QueuedEvent {
    /// Rebuilds the stored envelope.
    ///
    /// The envelope carries no `seq`: send [`QueuedEvent::seq`] beside it.
    ///
    /// # Errors
    ///
    /// Fails when the stored JSON is not an envelope.
    pub fn envelope(&self) -> Result<Envelope, Error> {
        Ok(serde_json::from_value(self.payload.clone())?)
    }
}

/// Running count of events removed by cap enforcement.
#[derive(Debug, Default)]
pub struct Tally {
    dropped: u64,
    self_dropped: bool,
}

impl Tally {
    fn add(&mut self, seq: i64, keep: i64, weight: i64) {
        self.dropped = self
            .dropped
            .saturating_add(u64::try_from(weight).unwrap_or(1));
        if seq == keep {
            self.self_dropped = true;
        }
    }
}

fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Removes events older than `limits.max_age`, then the lowest priority and oldest
/// events until the stored bytes fit `limits.max_bytes`.
///
/// `keep` is the seq of the event being inserted: removing it sets the tally's
/// self-drop flag. Overflow events weigh by the count they carry.
///
/// # Errors
///
/// Fails when a statement fails.
pub async fn enforce_caps(
    conn: &mut SqliteConnection,
    limits: Limits,
    now_ms: u64,
    keep: i64,
    tally: &mut Tally,
) -> Result<(), Error> {
    let age_ms = u64::try_from(limits.max_age.as_millis()).unwrap_or(u64::MAX);
    let cutoff = signed(now_ms).saturating_sub(signed(age_ms));
    let aged = sqlx::query(
        "DELETE FROM events WHERE ts < ?
         RETURNING seq,
           CASE WHEN kind = ? THEN MAX(COALESCE(json_extract(payload, '$.payload.dropped'), 1), 1) ELSE 1 END AS weight",
    )
    .bind(cutoff)
    .bind(OVERFLOW_KIND)
    .fetch_all(&mut *conn)
    .await?;
    for row in &aged {
        tally.add(row.try_get("seq")?, keep, row.try_get("weight")?);
    }

    let mut total: i64 =
        sqlx::query_scalar("SELECT COALESCE(SUM(LENGTH(CAST(payload AS BLOB))), 0) FROM events")
            .fetch_one(&mut *conn)
            .await?;
    while total > signed(limits.max_bytes) {
        let victim = sqlx::query(
            "DELETE FROM events WHERE seq = (SELECT seq FROM events ORDER BY priority ASC, seq ASC LIMIT 1)
             RETURNING seq, LENGTH(CAST(payload AS BLOB)) AS bytes,
               CASE WHEN kind = ? THEN MAX(COALESCE(json_extract(payload, '$.payload.dropped'), 1), 1) ELSE 1 END AS weight",
        )
        .bind(OVERFLOW_KIND)
        .fetch_optional(&mut *conn)
        .await?;
        let Some(victim) = victim else { break };
        total -= victim.try_get::<i64, _>("bytes")?;
        tally.add(victim.try_get("seq")?, keep, victim.try_get("weight")?);
    }
    Ok(())
}

/// Adds `count` dropped events to the overflow marker.
///
/// The newest `fleetd.queue_overflow` row is updated in place while it has not been
/// peeked, so the queue holds at most one unpeeked marker. A marker at or below the
/// highest peeked `seq` may be in flight and is never changed: the next drops create a new
/// row with a higher `seq`, so their count survives the ack of the old one.
async fn record_overflow(
    conn: &mut SqliteConnection,
    template: &Envelope,
    now_ms: u64,
    count: u64,
) -> Result<(), Error> {
    let merged = sqlx::query(
        "UPDATE events SET payload = json_set(payload, '$.payload.dropped',
             COALESCE(json_extract(payload, '$.payload.dropped'), 0) + ?)
         WHERE seq = (SELECT MAX(seq) FROM events WHERE kind = ?)
           AND seq > (SELECT peeked_seq FROM queue_state WHERE id = 1)",
    )
    .bind(signed(count))
    .bind(OVERFLOW_KIND)
    .execute(&mut *conn)
    .await?;
    if merged.rows_affected() > 0 {
        return Ok(());
    }
    let identity = Identity {
        box_name: template.box_name.clone(),
        hostname: template.hostname.clone(),
        machine_id: template.machine_id.clone(),
        boot_id: template.boot_id.clone(),
    };
    let mut marker = Envelope::new(
        &identity,
        fresh_id(now_ms),
        Source::Fleetd,
        OVERFLOW_KIND,
        now_ms,
    );
    marker.payload = json!({ "dropped": count });
    sqlx::query(
        "INSERT OR IGNORE INTO events (id, ts, kind, priority, payload) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(marker.id.to_string())
    .bind(signed(marker.ts))
    .bind(&marker.kind)
    .bind(marker.priority() as i64)
    .bind(serde_json::to_string(&marker)?)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Inserts an event, ignoring a repeat of the same id, then enforces the caps.
///
/// An event larger than `limits.max_bytes` is dropped before the table is touched.
/// Everything cap enforcement removes is added to the single `fleetd.queue_overflow`
/// event, and the caps are enforced again after that event is written. When that second
/// pass evicts more events, including the marker itself because it cannot fit, their
/// count is logged and not recorded. The caller owns the transaction.
///
/// # Errors
///
/// Fails when a statement fails or the envelope cannot be serialized.
pub async fn insert(
    conn: &mut SqliteConnection,
    envelope: &Envelope,
    limits: Limits,
    now_ms: u64,
) -> Result<Enqueued, Error> {
    let body = serde_json::to_string(envelope)?;
    let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
    if size > limits.max_bytes {
        tracing::warn!(kind = %envelope.kind, size, max = limits.max_bytes, "event exceeds queue cap, dropped");
        return Ok(Enqueued::Dropped);
    }
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO events (id, ts, kind, priority, payload) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(envelope.id.to_string())
    .bind(signed(envelope.ts))
    .bind(&envelope.kind)
    .bind(envelope.priority() as i64)
    .bind(&body)
    .execute(&mut *conn)
    .await?;
    if inserted.rows_affected() == 0 {
        let seq: i64 = sqlx::query_scalar("SELECT seq FROM events WHERE id = ?")
            .bind(envelope.id.to_string())
            .fetch_one(&mut *conn)
            .await?;
        return Ok(Enqueued::Duplicate { seq });
    }
    let seq = inserted.last_insert_rowid();

    let mut tally = Tally::default();
    enforce_caps(conn, limits, now_ms, seq, &mut tally).await?;
    if tally.dropped > 0 {
        record_overflow(conn, envelope, now_ms, tally.dropped).await?;
        let before = tally.dropped;
        enforce_caps(conn, limits, now_ms, seq, &mut tally).await?;
        let unrecorded = tally.dropped - before;
        if unrecorded > 0 {
            tracing::warn!(unrecorded, "queue overflow count could not be recorded");
        }
    }
    if tally.self_dropped {
        return Ok(Enqueued::Dropped);
    }
    Ok(Enqueued::Stored { seq })
}

fn queued(row: &SqliteRow) -> Result<QueuedEvent, Error> {
    let text: String = row.try_get("payload")?;
    Ok(QueuedEvent {
        seq: row.try_get("seq")?,
        id: row.try_get("id")?,
        ts: row.try_get("ts")?,
        kind: row.try_get("kind")?,
        payload: serde_json::from_str(&text)?,
    })
}

/// Lists stored rows in `seq` order.
///
/// # Errors
///
/// Fails when the read fails or a stored envelope is not JSON.
pub async fn list(
    conn: &mut SqliteConnection,
    limit: Option<u32>,
) -> Result<Vec<QueuedEvent>, Error> {
    let rows =
        sqlx::query("SELECT seq, id, ts, kind, payload FROM events ORDER BY seq ASC LIMIT ?")
            .bind(limit.map_or(-1, i64::from))
            .fetch_all(&mut *conn)
            .await?;
    rows.iter().map(queued).collect()
}

/// Number of stored events.
///
/// # Errors
///
/// Fails when the read fails.
pub async fn count(conn: &mut SqliteConnection) -> Result<u64, Error> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
        .fetch_one(&mut *conn)
        .await?;
    Ok(u64::try_from(count).unwrap_or(0))
}

/// Reads the head of the queue and persists the highest returned `seq` as the peeked head.
///
/// Returns up to `limit_count` rows in `seq` order and at most `limit_bytes` of stored
/// envelope bytes. The batch stops at the first row that would cross the byte limit, which
/// keeps `seq` order, but holds one row whenever the queue is not empty, so an event larger
/// than the limit still gets sent alone. The highest returned `seq` is recorded as the
/// peeked head. The caller sends the batch and then calls [`ack_through`] with the highest
/// `seq` the server acknowledged.
///
/// A row whose envelope is not JSON is deleted and logged with its `seq` and the decode
/// error, never the payload, so it cannot block the rows behind it.
///
/// # Errors
///
/// Fails when a statement fails.
pub async fn peek(
    conn: &mut SqliteConnection,
    limit_count: u32,
    limit_bytes: u64,
) -> Result<Vec<QueuedEvent>, Error> {
    let mut batch = Vec::new();
    while batch.is_empty() {
        let rows = sqlx::query(
            "SELECT seq, id, ts, kind, payload, LENGTH(CAST(payload AS BLOB)) AS bytes
             FROM events ORDER BY seq ASC LIMIT ?",
        )
        .bind(i64::from(limit_count))
        .fetch_all(&mut *conn)
        .await?;
        if rows.is_empty() {
            break;
        }
        let mut total: u64 = 0;
        let mut quarantined = false;
        for row in &rows {
            let bytes = u64::try_from(row.try_get::<i64, _>("bytes")?).unwrap_or(u64::MAX);
            if !batch.is_empty() && total.saturating_add(bytes) > limit_bytes {
                break;
            }
            match queued(row) {
                Ok(event) => {
                    total = total.saturating_add(bytes);
                    batch.push(event);
                }
                Err(Error::Json(err)) => {
                    let seq: i64 = row.try_get("seq")?;
                    tracing::warn!(seq, error = %err, "dropping undecodable queued event");
                    sqlx::query("DELETE FROM events WHERE seq = ?")
                        .bind(seq)
                        .execute(&mut *conn)
                        .await?;
                    quarantined = true;
                }
                Err(err) => return Err(err),
            }
        }
        if !quarantined {
            break;
        }
    }
    if let Some(top) = batch.last() {
        sqlx::query("UPDATE queue_state SET peeked_seq = MAX(peeked_seq, ?) WHERE id = 1")
            .bind(top.seq)
            .execute(&mut *conn)
            .await?;
    }
    Ok(batch)
}

/// Deletes every row with `seq <= min(seq, highest peeked seq)`.
///
/// An ack above the peeked head never reaches rows that were not sent. Rows that cap
/// enforcement already evicted are simply absent, so a stale ack does nothing. Returns the
/// number of rows deleted.
///
/// # Errors
///
/// Fails when the statement fails.
pub async fn ack_through(conn: &mut SqliteConnection, seq: i64) -> Result<u64, Error> {
    let done = sqlx::query(
        "DELETE FROM events
         WHERE seq <= MIN(?, (SELECT peeked_seq FROM queue_state WHERE id = 1))",
    )
    .bind(seq)
    .execute(&mut *conn)
    .await?;
    Ok(done.rows_affected())
}
