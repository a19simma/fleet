//! Captures `tracing` output for the current test thread.
//!
//! One global subscriber is installed for the whole test binary, so every callsite stays enabled
//! whatever the other test threads do. Its writer sends each line to the buffer of the calling
//! thread, or drops it when the thread captures nothing.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::cell::RefCell;
use std::sync::{Arc, Mutex, Once, PoisonError};

/// A shared buffer that is a `tracing` writer.
#[derive(Clone, Default)]
pub(crate) struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

thread_local! {
    static CURRENT: RefCell<Option<LogBuf>> = const { RefCell::new(None) };
}

static INSTALL: Once = Once::new();

/// Writer that appends to the buffer the calling thread captures into.
pub(crate) struct Router;

impl std::io::Write for Router {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        CURRENT.with(|current| {
            if let Some(target) = current.borrow_mut().as_mut() {
                target.write(buf)?;
            }
            Ok(buf.len())
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Router {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        Self
    }
}

/// Stops the capture of the current thread when dropped.
pub(crate) struct LogGuard;

impl Drop for LogGuard {
    fn drop(&mut self) {
        CURRENT.with(|current| *current.borrow_mut() = None);
    }
}

impl LogBuf {
    /// Everything logged so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

/// Routes this thread's `tracing` events into the returned buffer until the guard drops.
pub(crate) fn capture_logs() -> (LogBuf, LogGuard) {
    INSTALL.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_writer(Router)
            .with_ansi(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
    let buf = LogBuf::default();
    CURRENT.with(|current| *current.borrow_mut() = Some(buf.clone()));
    (buf, LogGuard)
}
