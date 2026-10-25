use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

use crate::http1::{Failure, roundtrip};
use crate::toolhook::{is_tool_event, reduce};
use crate::{Config, Error};

const MAX_STDIN_BYTES: u64 = 1024 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(2);
const UNIX_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_JOB_ID_BYTES: usize = 128;
const JOB_ENV: &str = "FLEET_JOB_ID";
const EMPTY_REPORT: &[u8] = b"{}";

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
        let job = std::env::var(JOB_ENV).ok();
        forward_hook(&config, event, input, job.as_deref()).await
    };
    tokio::time::timeout(TOTAL_TIMEOUT, work)
        .await
        .map_err(|_| Error::Runtime(io::Error::new(io::ErrorKind::TimedOut, "hook timed out")))?
}

/// Forwards one Claude Code hook payload to the local fleetd.
///
/// Reads `input` up to 1 MiB, then POSTs it to `/hook/<event>`. It uses the unix
/// socket in `config` when that path exists, else the loopback port. `job` is sent as
/// `X-Fleet-Job` after it is sanitised to printable ASCII and capped at 128 bytes; an
/// empty result sends no header. For `PostToolUse` and `PostToolUseFailure` the body is
/// reduced to the tool use id, tool name, exit code and duration before it is sent, so no
/// tool output or file content leaves the process; oversize or unusable input sends `{}`,
/// which the daemon counts as dropped. The call has no overall deadline: [`run_hook`] owns
/// the 2 second budget, and callers that must never block Claude Code should use it.
///
/// The unix attempt gets a 1 second sub-budget. TCP is tried only when the unix
/// connect fails, a write fails, or the sub-budget ends before any HTTP status line
/// arrives. Any status line from the socket is final, whatever its code. When the
/// request was fully written and the socket then closes or errors without a status
/// line, the outcome is unknown: the daemon may already have enqueued the event, so
/// the hook is not replayed over TCP and fails.
///
/// # Errors
///
/// Fails when `event` is empty or not alphanumeric, the input exceeds 1 MiB, no
/// listener accepts the connection, or fleetd answers with a status other than 2xx.
pub async fn forward_hook(
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
    forward(config, event, input, job.as_deref())
        .await
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
    let oversize = body.len() as u64 > MAX_STDIN_BYTES;
    if is_tool_event(event) {
        body = if oversize {
            EMPTY_REPORT.to_vec()
        } else {
            reduce(event, &body).map_or_else(|| EMPTY_REPORT.to_vec(), |report| report.to_body())
        };
    } else if oversize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hook input exceeds 1 MiB",
        ));
    }
    let request = request_bytes(event, &body, job);
    if socket_usable(&config.socket_path) {
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

/// Decides whether a socket at `path` owned by `socket_uid` may be trusted.
///
/// The path must be absolute and the owner must be `current_uid`, so a planted
/// socket from another user is never sent a hook payload.
fn socket_acceptable(path: &Path, socket_uid: u32, current_uid: u32) -> bool {
    path.is_absolute() && socket_uid == current_uid
}

fn socket_usable(path: &Path) -> bool {
    std::fs::metadata(path)
        .is_ok_and(|meta| socket_acceptable(path, meta.uid(), rustix::process::geteuid().as_raw()))
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
    stream: impl AsyncRead + AsyncWrite + Unpin,
    request: &[u8],
) -> Result<(), Attempt> {
    match roundtrip(stream, request).await {
        Err(Failure::NotSent) => Err(Attempt::NotDelivered),
        Err(Failure::Unanswered(err)) => Err(Attempt::Final(err)),
        Ok(response) if (200..300).contains(&response.status) => Ok(()),
        Ok(response) => Err(Attempt::Final(io::Error::other(format!(
            "fleetd answered {}",
            response.status
        )))),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::socket_acceptable;

    #[test]
    fn accepts_an_absolute_path_owned_by_the_current_uid() {
        assert!(socket_acceptable(Path::new("/run/fleetd.sock"), 1000, 1000));
    }

    #[test]
    fn refuses_a_relative_path() {
        assert!(!socket_acceptable(Path::new("fleetd.sock"), 1000, 1000));
    }

    #[test]
    fn refuses_a_socket_owned_by_another_uid() {
        assert!(!socket_acceptable(Path::new("/run/fleetd.sock"), 0, 1000));
    }
}
