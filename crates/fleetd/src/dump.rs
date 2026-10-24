use std::io::Write;
use std::path::Path;

use crate::Error;
use crate::queue::Queue;

/// Prints queued events as JSON lines in `seq` order, up to `limit` of them.
///
/// Each line holds `seq`, `id`, `ts`, `kind`, `state`, `attempts`, `next_try_at` and the
/// stored envelope under `envelope`. Lines go straight to `out`.
///
/// # Errors
///
/// Fails when the queue cannot be read or the output cannot be written.
pub async fn dump(db_path: &Path, limit: Option<u32>, out: &mut impl Write) -> Result<(), Error> {
    let queue = Queue::open_existing(db_path).await?;
    for row in queue.list(limit).await? {
        serde_json::to_writer(&mut *out, &row)?;
        out.write_all(b"\n").map_err(Error::Runtime)?;
    }
    Ok(())
}
