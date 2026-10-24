use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

use crate::{Config, Error};

const MAX_STDIN_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(2);
const UNIX_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_JOB_ID_BYTES: usize = 128;
const JOB_ENV: &str = "FLEET_JOB_ID";

fn job_header_value(raw: &str) -> Option<String> {
    let clean: String = raw
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(MAX_JOB_ID_BYTES)
        .collect();
    let trimmed = clean.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Loads config and forwards one hook payload inside a single 2 second budget.
///
/// Reads `config_path` (or the default config file) and then behaves like
/// [`forward_hook`], so a slow config read cannot extend the budget. Sends the
/// `FLEET_JOB_ID` env var as `X-Fleet-Job` when it is set.
///
/// # Errors
///
/// Fails when the config cannot be loaded, or for any reason [`forward_hook`] fails.
pub async fn run_hook(
    config_path: Option<&Path>,
    event: &str,
    input: impl AsyncRead + Unpin,
) -> Result<(), Error> {
    let path = config_path.map(Path::to_path_buf);
    let work = async {
        let config = tokio::task::spawn_blocking(move || Config::load(path.as_deref()))
            .await
            .map_err(|err| Error::Runtime(io::Error::other(err)))??;
        forward_hook(&config, event, input).await
    };
    tokio::time::timeout(TOTAL_TIMEOUT, work)
        .await
        .map_err(|_| Error::Runtime(io::Error::new(io::ErrorKind::TimedOut, "hook timed out")))?
}

/// Forwards one Claude Code hook payload to the local fleetd.
///
/// Reads `input` up to 1 MiB, then POSTs it to `/hook/<event>`. It uses the unix
/// socket in `config` when that path exists and falls back to the loopback port when
/// the socket cannot be reached or the exchange over it fails. It sends the
/// `FLEET_JOB_ID` env var as `X-Fleet-Job` when set. The whole call has a 2 second
/// budget. Callers that must never block Claude Code should print the error to
/// stderr and exit 0.
///
/// The unix attempt gets its own 1 second sub-budget and TCP gets the rest. TCP is
/// tried only when the unix connect fails, a write fails, or the sub-budget ends
/// before any HTTP status line arrives. Any status line from the socket is final,
/// whatever its code. When the request was fully written and the socket then closes
/// or errors without a status line, the outcome is unknown: the daemon may already
/// have enqueued the event, so the hook is not replayed over TCP and fails.
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
    let job = std::env::var(JOB_ENV).ok();
    forward_hook_as(config, event, input, job.as_deref()).await
}

/// Like [`forward_hook`], with the job id given instead of read from the environment.
///
/// `job` is sanitised to printable ASCII and capped at 128 bytes; an empty result sends
/// no header.
///
/// # Errors
///
/// Fails for the same reasons as [`forward_hook`].
pub async fn forward_hook_as(
    config: &Config,
    event: &str,
    input: impl AsyncRead + Unpin,
    job: Option<&str>,
) -> Result<(), Error> {
    if event.is_empty() || !event.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::InvalidValue {
            name: "hook event",
            value: event.to_owned(),
        });
    }
    let job = job.and_then(job_header_value);
    tokio::time::timeout(TOTAL_TIMEOUT, forward(config, event, input, job.as_deref()))
        .await
        .map_err(|_| Error::Runtime(io::Error::new(io::ErrorKind::TimedOut, "hook timed out")))?
        .map_err(Error::Runtime)
}

async fn forward(
    config: &Config,
    event: &str,
    input: impl AsyncRead + Unpin,
    job: Option<&str>,
) -> io::Result<()> {
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
    let request = request_bytes(event, &body, job);
    if config.socket_path.exists() {
        let attempt = tokio::time::timeout(UNIX_TIMEOUT, async {
            match UnixStream::connect(&config.socket_path).await {
                Ok(stream) => exchange(stream, &request).await,
                Err(_) => Err(Attempt::NotDelivered),
            }
        })
        .await;
        match attempt {
            Ok(Ok(())) => return Ok(()),
            Ok(Err(Attempt::Final(err))) => return Err(err),
            Ok(Err(Attempt::NotDelivered)) | Err(_) => {}
        }
    }
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.http_port));
    match exchange(TcpStream::connect(addr).await?, &request).await {
        Ok(()) => Ok(()),
        Err(Attempt::Final(err)) => Err(err),
        Err(Attempt::NotDelivered) => Err(io::Error::other("hook request was not delivered")),
    }
}

enum Attempt {
    NotDelivered,
    Final(io::Error),
}

fn request_bytes(event: &str, body: &[u8], job: Option<&str>) -> Vec<u8> {
    let job_line = job.map_or_else(String::new, |id| format!("X-Fleet-Job: {id}\r\n"));
    let mut request = format!(
        "POST /hook/{event} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n{job_line}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    request.extend_from_slice(body);
    request
}

async fn exchange(
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &[u8],
) -> Result<(), Attempt> {
    if stream.write_all(request).await.is_err() || stream.flush().await.is_err() {
        return Err(Attempt::NotDelivered);
    }
    let mut response = Vec::new();
    let mut buf = [0u8; 1024];
    while !response.contains(&b'\n') && (response.len() as u64) < MAX_RESPONSE_BYTES {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(buf.get(..n).unwrap_or_default()),
            Err(err) => return Err(Attempt::Final(err)),
        }
    }
    let text = String::from_utf8_lossy(&response);
    let status = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            Attempt::Final(io::Error::new(
                io::ErrorKind::InvalidData,
                "no status line from fleetd",
            ))
        })?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(Attempt::Final(io::Error::other(format!(
            "fleetd answered {status}"
        ))))
    }
}
