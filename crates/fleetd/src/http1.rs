//! One HTTP/1 round trip over any byte stream, shared by the hook and the watchdog probe.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// A parsed HTTP/1 response: the status code and whatever body arrived.
pub struct Response {
    /// The numeric status code.
    pub status: u16,
    /// The body bytes read, decoded lossily.
    pub body: String,
}

/// Why a round trip produced no response.
pub enum Failure {
    /// The request could not be written, so the peer saw nothing usable.
    NotSent,
    /// The request was written but no valid response came back; the outcome is unknown.
    Unanswered(io::Error),
}

fn header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|at| at + 4)
}

fn content_length(head: &str) -> Option<usize> {
    head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse().ok())
            .flatten()
    })
}

fn complete(raw: &[u8]) -> bool {
    let Some(end) = header_end(raw) else {
        return false;
    };
    let head = String::from_utf8_lossy(raw.get(..end).unwrap_or_default());
    content_length(&head).is_some_and(|len| raw.len() - end >= len)
}

/// Writes `request` to `stream` and reads one HTTP/1 response.
///
/// Reads until the declared `Content-Length` body is complete, the peer closes, or 64 KiB
/// arrive. The request should carry `Connection: close`.
///
/// # Errors
///
/// Fails with [`Failure::NotSent`] when the write fails and with [`Failure::Unanswered`]
/// on a read error or a response without a status line.
pub async fn roundtrip(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &[u8],
) -> Result<Response, Failure> {
    if stream.write_all(request).await.is_err() || stream.flush().await.is_err() {
        return Err(Failure::NotSent);
    }
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];
    while raw.len() < MAX_RESPONSE_BYTES && !complete(&raw) {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(err) => return Err(Failure::Unanswered(err)),
        }
    }
    let end = header_end(&raw).unwrap_or(raw.len());
    let text = String::from_utf8_lossy(&raw);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            Failure::Unanswered(io::Error::new(
                io::ErrorKind::InvalidData,
                "no status line from fleetd",
            ))
        })?;
    let body = String::from_utf8_lossy(raw.get(end..).unwrap_or_default()).into_owned();
    Ok(Response { status, body })
}
