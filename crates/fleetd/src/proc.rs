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

const CAPTURE_BYTES: u64 = 64 * 1024;

/// What a finished command left behind. Output is cut at 64 KiB.
#[derive(Debug)]
pub(crate) struct Captured {
    pub(crate) success: bool,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Why a command produced no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CaptureError {
    Start,
    Timeout,
}

/// Runs `command` in its own process group with no stdin, then kills the group.
pub(crate) async fn capture(
    mut command: Command,
    timeout: Duration,
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
    let work = async { tokio::join!(read(stdout), read(stderr), child.wait()) };
    let result = tokio::time::timeout(timeout, work).await;
    guard.kill();
    match result {
        Ok((stdout, stderr, Ok(status))) => Ok(Captured {
            success: status.success(),
            stdout,
            stderr,
        }),
        Ok(_) => Err(CaptureError::Start),
        Err(_) => {
            let _ = child.wait().await;
            Err(CaptureError::Timeout)
        }
    }
}

async fn read(pipe: Option<impl AsyncRead + Unpin>) -> String {
    let Some(mut pipe) = pipe else {
        return String::new();
    };
    let mut buf = Vec::new();
    let _ = (&mut pipe).take(CAPTURE_BYTES).read_to_end(&mut buf).await;
    let _ = tokio::io::copy(&mut pipe, &mut tokio::io::sink()).await;
    String::from_utf8_lossy(&buf).into_owned()
}
