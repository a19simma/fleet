//! Shutdown sequencing for the server binary: servers, the lease reaper and the stop flag.

use std::error::Error;
use std::fmt;
use std::future::Future;

use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Boxed error the server binary returns.
pub type BoxError = Box<dyn Error + Send + Sync>;

/// The lease reaper ended while the servers were still running.
#[derive(Debug)]
pub struct ReaperDied;

impl fmt::Display for ReaperDied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("lease reaper stopped unexpectedly")
    }
}

impl Error for ReaperDied {}

/// Drives `served` and `reaper` to a joint end and returns the result.
///
/// The stop flag is set when `served` finishes on `Ok` or `Err`, and when the reaper ends
/// first, so no task outlives the call. The reaper is always joined. A `served` error wins
/// over [`ReaperDied`]. A reaper that ends before the servers and before any stop request
/// is logged at error level and returns [`ReaperDied`] once the servers have drained.
///
/// # Errors
///
/// Returns the error of `served`, or [`ReaperDied`] when the reaper ended early.
pub async fn supervise<S>(
    served: S,
    mut reaper: JoinHandle<()>,
    stop: &watch::Sender<bool>,
) -> Result<(), BoxError>
where
    S: Future<Output = Result<(), BoxError>>,
{
    tokio::pin!(served);
    let mut early = None;
    let result = tokio::select! {
        result = &mut served => result,
        joined = &mut reaper => {
            let stopping = stop.send_replace(true);
            early = Some((joined, !stopping));
            served.await
        }
    };
    stop.send_replace(true);
    let (joined, died) = match early {
        Some(early) => early,
        None => (reaper.await, false),
    };
    if let Err(err) = joined {
        tracing::error!(panicked = err.is_panic(), "lease reaper task died");
        if result.is_ok() {
            return Err(Box::new(ReaperDied));
        }
    } else if died {
        tracing::error!("lease reaper task ended before shutdown");
        if result.is_ok() {
            return Err(Box::new(ReaperDied));
        }
    }
    result
}
