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
    let work = async {
        let config = Config::load(config_path)?;
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
    if config.socket_path.exists()
        && let Ok(stream) = UnixStream::connect(&config.socket_path).await
        && matches!(exchange(stream, &request).await, Ok(()))
    {
        return Ok(());
    }
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, config.http_port));
    exchange(TcpStream::connect(addr).await?, &request).await
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
