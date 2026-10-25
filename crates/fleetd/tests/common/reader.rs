//! A fifo reader that proves a spawned writer died, and cannot hang the test binary.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use std::io::Read;
use tokio::sync::oneshot;

const WAIT: Duration = Duration::from_secs(20);

/// Reads a fifo to end of file. The end arrives only once every writer is gone.
///
/// The read runs on a detached thread, not the runtime's blocking pool, because a read
/// that never ends would otherwise keep the runtime from shutting down. Opening a fifo
/// blocks until a writer opens it, so dropping the reader opens the fifo for writing once
/// to release a thread whose writer never started.
pub(crate) struct Reader {
    path: PathBuf,
    opened: oneshot::Receiver<()>,
    started: bool,
    eof: Option<oneshot::Receiver<std::io::Result<usize>>>,
}

/// Starts reading the fifo at `path` in the background.
pub(crate) fn hold_reader(path: &Path) -> Reader {
    let owned = path.to_owned();
    let (tx, opened) = oneshot::channel();
    let (done, eof) = oneshot::channel();
    std::thread::spawn(move || {
        let read = std::fs::File::open(owned).and_then(|mut file| {
            let _ = tx.send(());
            let mut sink = Vec::new();
            file.read_to_end(&mut sink)
        });
        let _ = done.send(read);
    });
    Reader {
        path: path.to_owned(),
        opened,
        started: false,
        eof: Some(eof),
    }
}

impl Reader {
    /// Waits until a writer has opened the fifo.
    ///
    /// # Errors
    ///
    /// Fails when no writer opens it in time.
    pub(crate) async fn wait_opened(&mut self) -> Result<(), String> {
        tokio::time::timeout(WAIT, &mut self.opened)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        self.started = true;
        Ok(())
    }

    /// Waits until every writer has closed the fifo.
    ///
    /// # Errors
    ///
    /// Fails when no writer ever opened the fifo, a writer is still alive after the wait,
    /// or the read failed.
    pub(crate) async fn wait_eof(mut self) -> Result<(), String> {
        if !self.started && self.opened.try_recv().is_err() {
            return Err("no writer opened the fifo".to_owned());
        }
        let eof = self.eof.take().ok_or("eof already taken")?;
        tokio::time::timeout(WAIT, eof)
            .await
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        let _ = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.path);
    }
}
