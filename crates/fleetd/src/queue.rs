use std::path::{Path, PathBuf};
use std::time::Duration;

use fleet_core::{Envelope, Identity, Source};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::{Connection, Row, SqliteConnection};

use crate::Error;
use crate::system::{fresh_id, now_ms as clock_ms};

/// Kind of the event that reports dropped events.
pub const OVERFLOW_KIND: &str = "fleetd.queue_overflow";

const MARKER_PASSES: usize = 3;
const SQLITE_CORRUPT: i32 = 11;
const SQLITE_NOTADB: i32 = 26;

const SCHEMA: [&str; 3] = [
    "CREATE TABLE IF NOT EXISTS events (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        id TEXT NOT NULL UNIQUE,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        priority INTEGER NOT NULL,
        payload TEXT NOT NULL,
        state TEXT NOT NULL DEFAULT 'pending',
        attempts INTEGER NOT NULL DEFAULT 0,
        next_try_at INTEGER NOT NULL DEFAULT 0
    )",
    "CREATE INDEX IF NOT EXISTS events_drop_order ON events (priority, seq)",
    "CREATE INDEX IF NOT EXISTS events_ts ON events (ts)",
];

/// Queue caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Cap on the summed byte length of stored envelopes.
    pub max_bytes: u64,
    /// Events whose `ts` is older than this are dropped.
    pub max_age: Duration,
}

/// Result of [`Queue::enqueue`].
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
    /// Delivery state, `pending` until the forwarder lands.
    pub state: String,
    /// Delivery attempts so far.
    pub attempts: i64,
    /// Earliest next delivery attempt, milliseconds since the epoch.
    pub next_try_at: i64,
    /// The stored envelope.
    #[serde(rename = "envelope")]
    pub payload: Value,
}

/// The SQLite disk queue.
///
/// WAL mode, `synchronous=FULL`, one pooled connection so writers serialize. The commit
/// is the durability point: callers answer HTTP only after [`Queue::enqueue`] returns.
/// Byte caps count `LENGTH(CAST(payload AS BLOB))`, the UTF-8 size of each stored envelope.
#[derive(Debug, Clone)]
pub struct Queue {
    pool: SqlitePool,
    limits: Option<Limits>,
}

#[derive(Default)]
struct Tally {
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

fn options(path: &Path, create: bool) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5))
}

fn signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn is_corrupt(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .and_then(|code| code.parse::<i32>().ok())
        .is_some_and(|code| matches!(code & 0xff, SQLITE_CORRUPT | SQLITE_NOTADB))
}

fn move_aside(path: &Path) -> Result<(), Error> {
    let stamp = clock_ms();
    for suffix in ["", "-wal", "-shm"] {
        let mut from = path.as_os_str().to_owned();
        from.push(suffix);
        let mut to = path.as_os_str().to_owned();
        to.push(format!(".corrupt-{stamp}{suffix}"));
        match std::fs::rename(PathBuf::from(&from), PathBuf::from(&to)) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(Error::Io {
                    path: PathBuf::from(from),
                    source,
                });
            }
        }
    }
    Ok(())
}

async fn enforce_caps(
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

async fn record_overflow(
    conn: &mut SqliteConnection,
    template: &Envelope,
    now_ms: u64,
    count: u64,
) -> Result<(), Error> {
    let merged = sqlx::query(
        "UPDATE events SET payload = json_set(payload, '$.payload.dropped',
             COALESCE(json_extract(payload, '$.payload.dropped'), 0) + ?)
         WHERE seq = (SELECT MAX(seq) FROM events WHERE kind = ? AND state = 'pending')",
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

impl Queue {
    /// Opens or creates the queue at `path` and applies the schema.
    ///
    /// A file that SQLite reports as corrupt or not a database is moved to
    /// `<name>.corrupt-<ms>`, with its `-wal` and `-shm` files, and a fresh queue is
    /// created in its place.
    ///
    /// # Errors
    ///
    /// Fails when the database cannot be opened or migrated, or the corrupt file cannot
    /// be moved.
    pub async fn open(path: &Path, limits: Limits) -> Result<Self, Error> {
        match Self::try_open(path, limits).await {
            Err(Error::Db(err)) if is_corrupt(&err) => {
                tracing::error!(path = %path.display(), %err, "queue file is corrupt, moving it aside");
                move_aside(path)?;
                Self::try_open(path, limits).await
            }
            other => other,
        }
    }

    async fn try_open(path: &Path, limits: Limits) -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options(path, true))
            .await?;
        for statement in SCHEMA {
            if let Err(err) = sqlx::query(statement).execute(&pool).await {
                pool.close().await;
                return Err(err.into());
            }
        }
        Ok(Self {
            pool,
            limits: Some(limits),
        })
    }

    /// Opens an existing queue for inspection without creating it. The returned queue
    /// has no caps and rejects [`Queue::enqueue`].
    ///
    /// # Errors
    ///
    /// Fails when the file is missing or not a database.
    pub async fn open_existing(path: &Path) -> Result<Self, Error> {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options(path, false))
            .await?;
        Ok(Self { pool, limits: None })
    }

    /// Commits an event, ignoring a repeat of the same id, then enforces the caps.
    ///
    /// An event larger than `max_bytes` is dropped before the queue is touched. Cap
    /// enforcement drops events older than `max_age`, then removes the lowest priority
    /// and oldest events until the bytes fit `max_bytes`. Everything dropped is added to
    /// one pending `fleetd.queue_overflow` event in the same transaction, and the caps
    /// are enforced again after that event is written. Evicting an overflow event
    /// carries its count into the next one.
    ///
    /// # Errors
    ///
    /// Fails when the database write fails or the queue was opened with
    /// [`Queue::open_existing`].
    pub async fn enqueue(&self, envelope: &Envelope, now_ms: u64) -> Result<Enqueued, Error> {
        let limits = self.limits.ok_or(Error::ReadOnly)?;
        let body = serde_json::to_string(envelope)?;
        let size = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if size > limits.max_bytes {
            tracing::warn!(kind = %envelope.kind, size, max = limits.max_bytes, "event exceeds queue cap, dropped");
            return Ok(Enqueued::Dropped);
        }
        let mut conn = self.pool.acquire().await?;
        let mut tx = conn.begin().await?;
        let inserted = sqlx::query(
            "INSERT OR IGNORE INTO events (id, ts, kind, priority, payload) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(envelope.id.to_string())
        .bind(signed(envelope.ts))
        .bind(&envelope.kind)
        .bind(envelope.priority() as i64)
        .bind(&body)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() == 0 {
            let seq: i64 = sqlx::query_scalar("SELECT seq FROM events WHERE id = ?")
                .bind(envelope.id.to_string())
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(Enqueued::Duplicate { seq });
        }
        let seq = inserted.last_insert_rowid();

        let mut tally = Tally::default();
        enforce_caps(&mut tx, limits, now_ms, seq, &mut tally).await?;
        let mut pending = tally.dropped;
        for _ in 0..MARKER_PASSES {
            if pending == 0 {
                break;
            }
            record_overflow(&mut tx, envelope, now_ms, pending).await?;
            let before = tally.dropped;
            enforce_caps(&mut tx, limits, now_ms, seq, &mut tally).await?;
            pending = tally.dropped - before;
        }
        tx.commit().await?;
        if pending > 0 {
            tracing::warn!(pending, "queue overflow count could not be recorded");
        }
        if tally.self_dropped {
            return Ok(Enqueued::Dropped);
        }
        Ok(Enqueued::Stored { seq })
    }

    /// Lists stored rows in `seq` order.
    ///
    /// # Errors
    ///
    /// Fails when the database read fails or a stored envelope is not JSON.
    pub async fn list(&self, limit: Option<u32>) -> Result<Vec<QueuedEvent>, Error> {
        let rows = sqlx::query(
            "SELECT seq, id, ts, kind, payload, state, attempts, next_try_at
             FROM events ORDER BY seq ASC LIMIT ?",
        )
        .bind(limit.map_or(-1, i64::from))
        .fetch_all(&self.pool)
        .await?;
        let mut events = Vec::with_capacity(rows.len());
        for row in &rows {
            let text: String = row.try_get("payload")?;
            events.push(QueuedEvent {
                seq: row.try_get("seq")?,
                id: row.try_get("id")?,
                ts: row.try_get("ts")?,
                kind: row.try_get("kind")?,
                state: row.try_get("state")?,
                attempts: row.try_get("attempts")?,
                next_try_at: row.try_get("next_try_at")?,
                payload: serde_json::from_str(&text)?,
            });
        }
        Ok(events)
    }

    /// Number of stored events.
    ///
    /// # Errors
    ///
    /// Fails when the database read fails.
    pub async fn count(&self) -> Result<u64, Error> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events")
            .fetch_one(&self.pool)
            .await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Checkpoints the WAL and closes the pool.
    ///
    /// # Errors
    ///
    /// Fails when the checkpoint fails.
    pub async fn close(self) -> Result<(), Error> {
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await?;
        self.pool.close().await;
        Ok(())
    }
}
