use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::{Config, Error};

const MAX_STDIN_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(2);

/// Forwards one Claude Code hook payload to the local fleetd.
///
/// Reads `input` up to 1 MiB, then POSTs it to `/hook/<event>`. It uses the unix
/// socket in `config` when that path exists and falls back to the loopback port when
/// the socket cannot be reached. The whole call has a 2 second budget. Callers that
/// must never block Claude Code should print the error to stderr and exit 0.
///
/// # Errors
///
/// Fails when `event` is empty or not alphanumeric, the input exceeds 1 MiB, the
/// budget runs out, no listener accepts the connection, or fleetd answers with a
/// status other than 2xx.
pub async fn forward_hook(
    config: &Config,
    event: &str,
    input: impl AsyncRead + Unpin,
) -> Result<(), Error> {
    if event.is_empty() || !event.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::InvalidValue {
            name: "hook event",
            value: event.to_owned(),
        });
    }
    tokio::time::timeout(TOTAL_TIMEOUT, forward(config, event, input))
        .await
        .map_err(|_| Error::Runtime(io::Error::new(io::ErrorKind::TimedOut, "hook timed out")))?
        .map_err(Error::Runtime)
}

async fn forward(config: &Config, event: &str, input: impl AsyncRead + Unpin) -> io::Result<()> {
    let mut body = Vec::new();
    input
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut body)
        .await?;
    if body.len() as u64 > MAX_STDIN_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hook input exceeds 1 MiB",
        ));
    }
    let request = request_bytes(event, &body);
    if config.socket_path.exists()
        && let Ok(stream) = UnixStream::connect(&config.socket_path).await
    {
        return exchange(stream, &request).await;
    }
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.http_port));
    exchange(TcpStream::connect(addr).await?, &request).await
}

fn request_bytes(event: &str, body: &[u8]) -> Vec<u8> {
    let mut request = format!(
        "POST /hook/{event} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

async fn exchange(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &[u8],
) -> io::Result<()> {
    stream.write_all(request).await?;
    stream.flush().await?;
    let mut response = Vec::new();
    stream
        .take(MAX_RESPONSE_BYTES)
        .read_to_end(&mut response)
        .await?;
    let text = String::from_utf8_lossy(&response);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed response"))?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!("fleetd answered {status}")))
    }
}
