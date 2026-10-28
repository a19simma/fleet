//! Runs one short helper command with a deadline and bounded captured output.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;

use crate::group::GroupGuard;

pub(crate) const CAPTURE_BYTES: u64 = 64 * 1024;

/// What a finished command left behind. Output is cut at the capture limit.
#[derive(Debug)]
pub(crate) struct Captured {
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) truncated: bool,
}

/// Why a command produced no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureError {
    Start,
    Timeout,
}

/// Runs `command` in its own process group with no stdin, then kills the group. Each stream
/// is cut at `limit` bytes, and `truncated` is set when either held more.
pub(crate) async fn capture(
    command: Command,
    timeout: Duration,
    limit: u64,
) -> Result<Captured, CaptureError> {
    capture_keeping(command, timeout, limit, Keep::Head).await
}

/// Which end of a stream survives the capture limit.
#[derive(Clone, Copy)]
pub(crate) enum Keep {
    Head,
    Tail,
}

/// Like [`capture`], but `keep` picks the first or the last `limit` bytes of each stream.
pub(crate) async fn capture_keeping(
    mut command: Command,
    timeout: Duration,
    limit: u64,
    keep: Keep,
) -> Result<Captured, CaptureError> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|_| CaptureError::Start)?;
    let mut guard = GroupGuard::new(child.id());
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let work = async {
        tokio::join!(
            read(stdout, limit, keep),
            read(stderr, limit, keep),
            child.wait()
        )
    };
    let result = tokio::time::timeout(timeout, work).await;
    guard.kill();
    match result {
        Ok(((stdout, cut_out), (stderr, cut_err), Ok(status))) => Ok(Captured {
            success: status.success(),
            stdout,
            stderr,
            truncated: cut_out || cut_err,
        }),
        Ok(_) => Err(CaptureError::Start),
        Err(_) => {
            let _ = child.wait().await;
            Err(CaptureError::Timeout)
        }
    }
}

async fn read(pipe: Option<impl AsyncRead + Unpin>, limit: u64, keep: Keep) -> (String, bool) {
    let Some(mut pipe) = pipe else {
        return (String::new(), false);
    };
    if matches!(keep, Keep::Tail) {
        return read_tail(pipe, limit).await;
    }
    let mut buf = Vec::new();
    let _ = (&mut pipe).take(limit).read_to_end(&mut buf).await;
    let dropped = tokio::io::copy(&mut pipe, &mut tokio::io::sink())
        .await
        .unwrap_or(0);
    (String::from_utf8_lossy(&buf).into_owned(), dropped > 0)
}

async fn read_tail(mut pipe: impl AsyncRead + Unpin, limit: u64) -> (String, bool) {
    let cap = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut buf: Vec<u8> = Vec::new();
    let mut dropped = false;
    while let Ok(n) = pipe.read_buf(&mut buf).await {
        if n == 0 {
            break;
        }
        if buf.len() > cap.saturating_mul(2) {
            buf.drain(..buf.len() - cap);
            dropped = true;
        }
    }
    if buf.len() > cap {
        buf.drain(..buf.len() - cap);
        dropped = true;
    }
    (String::from_utf8_lossy(&buf).into_owned(), dropped)
}
