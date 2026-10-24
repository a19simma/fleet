use std::path::{Path, PathBuf};
use std::time::Duration;

use fleet_core::Envelope;
use sqlx::Transaction;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};

use crate::Error;
use crate::events::{self, Enqueued, Limits, QueuedEvent};
use crate::system::now_ms as clock_ms;

const SQLITE_CORRUPT: i32 = 11;
const SQLITE_NOTADB: i32 = 26;

/// The SQLite disk store.
///
/// WAL mode, `synchronous=FULL`, one pooled connection so writers serialize. The commit
/// is the durability point: callers answer HTTP only after [`Store::enqueue`] returns.
/// Byte caps count `LENGTH(CAST(payload AS BLOB))`, the UTF-8 size of each stored envelope.
/// The schema comes from the migrations in `migrations/`. Event operations live in the
/// `events` module and take a connection, so [`Store::begin`] composes them in one
/// transaction.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    limits: Option<Limits>,
}

fn options(path: &Path, create: bool) -> SqliteConnectOptions {
    SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(create)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full)
        .busy_timeout(Duration::from_secs(5))
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

impl Store {
    /// Opens or creates the store at `path` and applies the migrations.
    ///
    /// The first migration is idempotent, so a database created before migrations
    /// existed opens and is then recorded as migrated. A file that SQLite reports as
    /// corrupt or not a database is moved to `<name>.corrupt-<ms>`, with its `-wal` and
    /// `-shm` files, and a fresh store is created in its place.
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
        if let Err(err) = sqlx::migrate!("./migrations").run(&pool).await {
            pool.close().await;
            return Err(err.into());
        }
        Ok(Self {
            pool,
            limits: Some(limits),
        })
    }

    /// Opens an existing store for inspection without creating it. The returned store
    /// has no caps and rejects [`Store::enqueue`].
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

    /// Starts a transaction on the pooled connection. Use it to compose several
    /// event operations atomically.
    ///
    /// # Errors
    ///
    /// Fails when no connection is available or `BEGIN` fails.
    pub async fn begin(&self) -> Result<Transaction<'static, sqlx::Sqlite>, Error> {
        Ok(self.pool.begin().await?)
    }

    /// Commits an event, ignoring a repeat of the same id, then enforces the caps.
    ///
    /// The oldest, lowest priority events are dropped first when a cap is hit, and the drops are counted in a `fleetd.queue_overflow` event.
    ///
    /// # Errors
    ///
    /// Fails when the database write fails or the store was opened with
    /// [`Store::open_existing`].
    pub async fn enqueue(&self, envelope: &Envelope, now_ms: u64) -> Result<Enqueued, Error> {
        let limits = self.limits.ok_or(Error::ReadOnly)?;
        let mut tx = self.begin().await?;
        let outcome = events::insert(&mut tx, envelope, limits, now_ms).await?;
        tx.commit().await?;
        Ok(outcome)
    }

    /// Lists stored rows in `seq` order.
    ///
    /// # Errors
    ///
    /// Fails when the database read fails or a stored envelope is not JSON.
    pub async fn list(&self, limit: Option<u32>) -> Result<Vec<QueuedEvent>, Error> {
        let mut conn = self.pool.acquire().await?;
        events::list(&mut conn, limit).await
    }

    /// Number of stored events.
    ///
    /// # Errors
    ///
    /// Fails when the database read fails.
    pub async fn count(&self) -> Result<u64, Error> {
        let mut conn = self.pool.acquire().await?;
        events::count(&mut conn).await
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
