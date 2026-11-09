//! Per-Job OTLP/HTTP receiver on a unix socket in the Job directory.
//!
//! The receiver accepts `POST /v1/logs` with a per-Job bearer token and
//! `Content-Type: application/json`, and hands each body to a bounded channel. It speaks
//! HTTP/1 by hand so that every read is bounded and every framing quirk is refused.
//!
//! Peer identity is the socket's file mode and group, not a credential check: the token is
//! the only authentication, and a Job that reads its own environment can post for itself
//! (ADR-0055).

use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, mpsc, watch};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::Instant;

/// File name of the receiver socket inside the Job directory.
pub const SOCKET_NAME: &str = "otel.sock";
/// The only accepted request path.
pub const LOGS_PATH: &str = "/v1/logs";
/// Shortest accepted bearer token, in bytes.
pub const MIN_TOKEN_BYTES: usize = 16;
/// Longest accepted bearer token, in bytes.
pub const MAX_TOKEN_BYTES: usize = 256;
/// Largest request line plus header block, in bytes.
pub const MAX_HEAD_BYTES: usize = 8 * 1024;
/// Most header lines accepted in one request.
pub const MAX_HEADERS: usize = 64;

/// How long no body may arrive before a flush counts the stream as drained.
pub const QUIET_PERIOD: Duration = Duration::from_millis(1500);
/// Longest wait a flush honours, whatever deadline the caller passes.
pub const MAX_FLUSH_DEADLINE: Duration = Duration::from_secs(10);

/// Result of a flush.
///
/// `flush` returns once no connection is in flight and no body has been queued for the quiet
/// period, counted from the call at the earliest. The caller's deadline is capped at
/// [`MAX_FLUSH_DEADLINE`]. Dropping the future mutates nothing. A connection still in the
/// accept backlog is not yet counted as in flight, so a flush can return before its body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Flush {
    /// The deadline fired before the stream went quiet.
    pub incomplete: bool,
}

const MAX_CHUNK_LINE_BYTES: usize = 32;
const READ_BUF_BYTES: usize = 4096;
const ACCEPT_BACKOFF: Duration = Duration::from_millis(50);
const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Why a bearer token was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenError {
    /// Shorter than [`MIN_TOKEN_BYTES`].
    TooShort,
    /// Longer than [`MAX_TOKEN_BYTES`].
    TooLong,
    /// A byte outside visible ASCII (`!` to `~`).
    BadByte,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::TooShort => "otel token is too short",
            Self::TooLong => "otel token is too long",
            Self::BadByte => "otel token holds a byte outside visible ascii",
        })
    }
}

impl std::error::Error for TokenError {}

/// A per-Job bearer token, kept only as a SHA-256 digest.
///
/// The digest makes the comparison independent of the length and content of the presented
/// value, and keeps the secret out of `Debug` output.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken([u8; 32]);

impl std::fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BearerToken(..)")
    }
}

impl BearerToken {
    /// Validates `token` and keeps its digest.
    ///
    /// # Errors
    ///
    /// Fails when the token is shorter than [`MIN_TOKEN_BYTES`], longer than
    /// [`MAX_TOKEN_BYTES`] or holds a byte outside visible ASCII.
    pub fn new(token: &str) -> Result<Self, TokenError> {
        let bytes = token.as_bytes();
        if bytes.len() < MIN_TOKEN_BYTES {
            return Err(TokenError::TooShort);
        }
        if bytes.len() > MAX_TOKEN_BYTES {
            return Err(TokenError::TooLong);
        }
        if !bytes.iter().all(u8::is_ascii_graphic) {
            return Err(TokenError::BadByte);
        }
        Ok(Self(Sha256::digest(bytes).into()))
    }

    /// Whether `presented` hashes to the stored digest, compared without early exit.
    #[must_use]
    pub fn matches(&self, presented: &[u8]) -> bool {
        let other: [u8; 32] = Sha256::digest(presented).into();
        let mut diff = 0u8;
        for (a, b) in self.0.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        std::hint::black_box(diff) == 0
    }
}

/// Bounds on the receiver.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Largest accepted body, in bytes.
    pub max_body: usize,
    /// Most connections served at once; the next is answered 503 and closed.
    pub max_connections: usize,
    /// Bodies the channel holds before the receiver answers 429.
    pub queue: usize,
    /// Whole-request read deadline, so a stalled peer frees its slot.
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body: 1024 * 1024,
            max_connections: 8,
            queue: 64,
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// A bound receiver and its accept loop.
///
/// Dropping it stops the loop, aborts every connection and unlinks the socket.
#[derive(Debug)]
pub struct OtelReceiver {
    path: PathBuf,
    identity: (u64, u64),
    task: JoinHandle<()>,
    activity: Arc<watch::Sender<Activity>>,
}

#[derive(Clone, Copy, Debug)]
struct Activity {
    in_flight: usize,
    last_body: Option<Instant>,
}

struct InFlight(Arc<watch::Sender<Activity>>);

impl InFlight {
    fn enter(activity: &Arc<watch::Sender<Activity>>) -> Self {
        activity.send_modify(|a| a.in_flight += 1);
        Self(Arc::clone(activity))
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0
            .send_modify(|a| a.in_flight = a.in_flight.saturating_sub(1));
    }
}

struct Shared {
    activity: Arc<watch::Sender<Activity>>,
    token: BearerToken,
    tx: mpsc::Sender<Vec<u8>>,
    permits: Arc<Semaphore>,
    max_body: usize,
    request_timeout: Duration,
}

impl OtelReceiver {
    /// Binds `path` and starts serving; returns the receiver and the body channel.
    ///
    /// The socket is bound in a private 0700 staging dir beside `path`, given its final mode
    /// and renamed onto `path`, so it is never reachable under a wider mode. With no `group`
    /// the mode is 0600. With a `group` the socket is chowned to that group and the mode is
    /// 0660, because a peer under another uid needs write permission to connect. A dead
    /// socket at `path` is replaced. A live one, a symlink or any other file is refused
    /// untouched. Needs a Tokio runtime.
    ///
    /// The check for an existing socket and the rename onto `path`, and the removal in `Drop`,
    /// are separate steps and leave small races. The directory holding `path` must not be
    /// writable by any other user. A crash can leave a `.ot<pid>-<n>` staging dir behind; no
    /// sweep removes it.
    ///
    /// # Errors
    ///
    /// Fails with `InvalidInput` for a zero limit or a path with no parent, `AddrInUse` when
    /// a listener answers at `path`, `AlreadyExists` when `path` holds something other than
    /// a socket, and with the underlying error when the staging dir, the bind, the chown, the
    /// mode change or the rename fails.
    pub fn bind(
        path: &Path,
        token: BearerToken,
        group: Option<u32>,
        limits: Limits,
    ) -> io::Result<(Self, mpsc::Receiver<Vec<u8>>)> {
        if limits.max_body == 0
            || limits.max_connections == 0
            || limits.queue == 0
            || limits.request_timeout.is_zero()
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let (listener, identity) = publish(path, group)?;
        let (tx, rx) = mpsc::channel(limits.queue);
        let activity = Arc::new(watch::Sender::new(Activity {
            in_flight: 0,
            last_body: None,
        }));
        let shared = Arc::new(Shared {
            activity: Arc::clone(&activity),
            token,
            tx,
            permits: Arc::new(Semaphore::new(limits.max_connections)),
            max_body: limits.max_body,
            request_timeout: limits.request_timeout,
        });
        let task = tokio::spawn(accept_loop(listener, shared));
        Ok((
            Self {
                path: path.to_path_buf(),
                identity,
                task,
                activity,
            },
            rx,
        ))
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Waits for in-flight bodies and a quiet period; see [`Flush`].
    pub async fn flush(&self, deadline: Duration) -> Flush {
        self.flush_with(deadline, QUIET_PERIOD).await
    }

    /// [`flush`](Self::flush) with the quiet period as a parameter, for tests.
    pub async fn flush_with(&self, deadline: Duration, quiet: Duration) -> Flush {
        let start = Instant::now();
        let end = start + deadline.min(MAX_FLUSH_DEADLINE);
        let mut rx = self.activity.subscribe();
        loop {
            let snapshot = *rx.borrow_and_update();
            let now = Instant::now();
            let wake = if snapshot.in_flight == 0 {
                let quiet_from = snapshot.last_body.map_or(start, |at| at.max(start));
                let quiet_at = quiet_from + quiet;
                if now >= quiet_at {
                    return Flush { incomplete: false };
                }
                quiet_at.min(end)
            } else {
                end
            };
            if now >= end {
                return Flush { incomplete: true };
            }
            tokio::select! {
                () = tokio::time::sleep_until(wake) => {}
                _ = rx.changed() => {}
            }
        }
    }
}

impl Drop for OtelReceiver {
    fn drop(&mut self) {
        self.task.abort();
        let ours = std::fs::symlink_metadata(&self.path).is_ok_and(|meta| {
            meta.file_type().is_socket() && (meta.dev(), meta.ino()) == self.identity
        });
        if ours {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

fn publish(path: &Path, group: Option<u32>) -> io::Result<(UnixListener, (u64, u64))> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    "a listener already answers at the otel socket path",
                ));
            }
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "otel socket path holds something other than a socket",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let stage = parent.join(format!(
        ".ot{}-{}",
        std::process::id(),
        STAGE_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&stage)?;
    let staged = stage.join(SOCKET_NAME);
    let result = bind_staged(&staged, path, group);
    let _ = std::fs::remove_file(&staged);
    let _ = std::fs::remove_dir(&stage);
    result
}

fn bind_staged(
    staged: &Path,
    path: &Path,
    group: Option<u32>,
) -> io::Result<(UnixListener, (u64, u64))> {
    let listener = UnixListener::bind(staged)?;
    let mode = if let Some(gid) = group {
        std::os::unix::fs::chown(staged, None, Some(gid))?;
        0o660
    } else {
        0o600
    };
    std::fs::set_permissions(staged, std::fs::Permissions::from_mode(mode))?;
    let meta = std::fs::symlink_metadata(staged)?;
    std::fs::rename(staged, path)?;
    Ok((listener, (meta.dev(), meta.ino())))
}

async fn accept_loop(listener: UnixListener, shared: Arc<Shared>) {
    let mut set: JoinSet<()> = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    tokio::time::sleep(ACCEPT_BACKOFF).await;
                    continue;
                };
                let Ok(permit) = Arc::clone(&shared.permits).try_acquire_owned() else {
                    let _ = stream.try_write(&render(Reply::BUSY));
                    continue;
                };
                let guard = InFlight::enter(&shared.activity);
                let shared = Arc::clone(&shared);
                set.spawn(async move {
                    serve(&shared, stream).await;
                    drop(permit);
                    drop(guard);
                });
            }
            Some(_) = set.join_next(), if !set.is_empty() => {}
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Reply {
    code: u16,
    reason: &'static str,
}

impl Reply {
    const OK: Self = Self::new(200, "OK");
    const BAD_REQUEST: Self = Self::new(400, "Bad Request");
    const UNAUTHORIZED: Self = Self::new(401, "Unauthorized");
    const NOT_FOUND: Self = Self::new(404, "Not Found");
    const METHOD: Self = Self::new(405, "Method Not Allowed");
    const LENGTH_REQUIRED: Self = Self::new(411, "Length Required");
    const TOO_LARGE: Self = Self::new(413, "Payload Too Large");
    const MEDIA: Self = Self::new(415, "Unsupported Media Type");
    const EXPECT: Self = Self::new(417, "Expectation Failed");
    const HEADERS_LARGE: Self = Self::new(431, "Request Header Fields Too Large");
    const FULL: Self = Self::new(429, "Too Many Requests");
    const NOT_IMPLEMENTED: Self = Self::new(501, "Not Implemented");
    const BUSY: Self = Self::new(503, "Service Unavailable");

    const fn new(code: u16, reason: &'static str) -> Self {
        Self { code, reason }
    }
}

fn render(reply: Reply) -> Vec<u8> {
    let body = if reply.code == 200 { "{}" } else { "" };
    format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reply.code,
        reply.reason,
        body.len(),
        body
    )
    .into_bytes()
}

enum Fail {
    Reply(Reply),
    Closed,
}

impl From<Reply> for Fail {
    fn from(reply: Reply) -> Self {
        Self::Reply(reply)
    }
}

async fn serve(shared: &Shared, mut stream: UnixStream) {
    let outcome = tokio::time::timeout(
        shared.request_timeout,
        handle(shared, BufferedReader::new(&mut stream)),
    )
    .await;
    let reply = match outcome {
        Ok(Ok(())) => Reply::OK,
        Ok(Err(Fail::Reply(reply))) => reply,
        Ok(Err(Fail::Closed)) | Err(_) => return,
    };
    let _ = tokio::time::timeout(WRITE_TIMEOUT, async {
        stream.write_all(&render(reply)).await?;
        stream.shutdown().await
    })
    .await;
}

struct BufferedReader<R> {
    inner: R,
    buf: Vec<u8>,
    pos: usize,
}

impl<R: AsyncRead + Unpin> BufferedReader<R> {
    const fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::new(),
            pos: 0,
        }
    }

    async fn fill(&mut self) -> Result<(), Fail> {
        if self.pos < self.buf.len() {
            return Ok(());
        }
        self.buf.clear();
        self.buf.resize(READ_BUF_BYTES, 0);
        self.pos = 0;
        let n = self
            .inner
            .read(&mut self.buf)
            .await
            .map_err(|_| Fail::Closed)?;
        self.buf.truncate(n);
        if n == 0 { Err(Fail::Closed) } else { Ok(()) }
    }

    async fn byte(&mut self) -> Result<u8, Fail> {
        self.fill().await?;
        let b = self.buf.get(self.pos).copied().ok_or(Fail::Closed)?;
        self.pos += 1;
        Ok(b)
    }

    async fn line(&mut self, budget: &mut usize, over: Reply) -> Result<Vec<u8>, Fail> {
        let mut out = Vec::new();
        loop {
            let b = self.byte().await?;
            if *budget == 0 {
                return Err(over.into());
            }
            *budget -= 1;
            match b {
                b'\n' => {
                    return if out.pop() == Some(b'\r') {
                        Ok(out)
                    } else {
                        Err(Reply::BAD_REQUEST.into())
                    };
                }
                b'\r' => out.push(b),
                0x00..=0x08 | 0x0a..=0x1f | 0x7f..=0xff => {
                    return Err(Reply::BAD_REQUEST.into());
                }
                _ => out.push(b),
            }
        }
    }

    async fn take_into(&mut self, out: &mut Vec<u8>, mut want: usize) -> Result<(), Fail> {
        while want > 0 {
            self.fill().await?;
            let avail = self.buf.get(self.pos..).unwrap_or_default();
            let n = avail.len().min(want);
            out.extend_from_slice(avail.get(..n).unwrap_or_default());
            self.pos += n;
            want -= n;
        }
        Ok(())
    }
}

#[derive(Default)]
struct Head<'a> {
    authorization: Option<&'a [u8]>,
    content_type: Option<&'a [u8]>,
    content_length: Option<&'a [u8]>,
    transfer_encoding: Option<&'a [u8]>,
    content_encoding: Option<&'a [u8]>,
    expect: Option<&'a [u8]>,
}

fn token_name(name: &[u8]) -> bool {
    !name.is_empty()
        && name
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map_or(start, |at| at + 1);
    value.get(start..end).unwrap_or_default()
}

fn parse_headers(lines: &[Vec<u8>]) -> Result<Head<'_>, Reply> {
    let mut head = Head::default();
    for line in lines {
        let (name, value) = line
            .iter()
            .position(|b| *b == b':')
            .and_then(|at| Some((line.get(..at)?, line.get(at + 1..)?)))
            .ok_or(Reply::BAD_REQUEST)?;
        if !token_name(name) {
            return Err(Reply::BAD_REQUEST);
        }
        if value.contains(&b'\r') {
            return Err(Reply::BAD_REQUEST);
        }
        let value = trim_ows(value);
        let slot = match name.to_ascii_lowercase().as_slice() {
            b"authorization" => &mut head.authorization,
            b"content-type" => &mut head.content_type,
            b"content-length" => &mut head.content_length,
            b"transfer-encoding" => &mut head.transfer_encoding,
            b"content-encoding" => &mut head.content_encoding,
            b"expect" => &mut head.expect,
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(Reply::BAD_REQUEST);
        }
    }
    Ok(head)
}

fn bearer(value: &[u8]) -> Option<&[u8]> {
    let (scheme, rest) = value.split_at_checked(7)?;
    (scheme.eq_ignore_ascii_case(b"bearer ")).then_some(rest)
}

fn json_media_type(value: &[u8]) -> bool {
    let lower = value.to_ascii_lowercase();
    lower == b"application/json"
        || lower == b"application/json; charset=utf-8"
        || lower == b"application/json;charset=utf-8"
}

async fn handle<R: AsyncRead + Unpin>(
    shared: &Shared,
    mut src: BufferedReader<R>,
) -> Result<(), Fail> {
    let mut budget = MAX_HEAD_BYTES;
    let request_line = src.line(&mut budget, Reply::HEADERS_LARGE).await?;
    let mut parts = request_line.split(|b| *b == b' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Reply::BAD_REQUEST.into());
    };
    if version != b"HTTP/1.1" && version != b"HTTP/1.0" {
        return Err(Reply::BAD_REQUEST.into());
    }
    let mut lines = Vec::new();
    loop {
        let line = src.line(&mut budget, Reply::HEADERS_LARGE).await?;
        if line.is_empty() {
            break;
        }
        if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
            return Err(Reply::BAD_REQUEST.into());
        }
        if lines.len() == MAX_HEADERS {
            return Err(Reply::HEADERS_LARGE.into());
        }
        lines.push(line);
    }
    if target != LOGS_PATH.as_bytes() {
        return Err(Reply::NOT_FOUND.into());
    }
    if method != b"POST" {
        return Err(Reply::METHOD.into());
    }
    let head = parse_headers(&lines)?;
    let authorized = head
        .authorization
        .and_then(bearer)
        .is_some_and(|presented| shared.token.matches(presented));
    if !authorized {
        return Err(Reply::UNAUTHORIZED.into());
    }
    if !head.content_type.is_some_and(json_media_type) {
        return Err(Reply::MEDIA.into());
    }
    if head
        .content_encoding
        .is_some_and(|v| !v.eq_ignore_ascii_case(b"identity"))
    {
        return Err(Reply::MEDIA.into());
    }
    if head.expect.is_some() {
        return Err(Reply::EXPECT.into());
    }
    let body = read_body(shared, &mut src, &head).await?;
    if body.is_empty() {
        return Err(Reply::BAD_REQUEST.into());
    }
    match shared.tx.try_send(body) {
        Ok(()) => {
            shared
                .activity
                .send_modify(|a| a.last_body = Some(Instant::now()));
            Ok(())
        }
        Err(mpsc::error::TrySendError::Full(_)) => Err(Reply::FULL.into()),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(Reply::BUSY.into()),
    }
}

async fn read_body<R: AsyncRead + Unpin>(
    shared: &Shared,
    src: &mut BufferedReader<R>,
    head: &Head<'_>,
) -> Result<Vec<u8>, Fail> {
    match (head.content_length, head.transfer_encoding) {
        (Some(_), Some(_)) => Err(Reply::BAD_REQUEST.into()),
        (None, None) => Err(Reply::LENGTH_REQUIRED.into()),
        (Some(raw), None) => {
            let canonical = raw.first().is_some_and(|b| *b != b'0') || raw == b"0";
            if !canonical || !raw.iter().all(u8::is_ascii_digit) {
                return Err(Reply::BAD_REQUEST.into());
            }
            let len: u64 = std::str::from_utf8(raw)
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or(Reply::TOO_LARGE)?;
            let len = usize::try_from(len)
                .ok()
                .filter(|len| *len <= shared.max_body)
                .ok_or(Reply::TOO_LARGE)?;
            let mut out = Vec::with_capacity(len);
            src.take_into(&mut out, len).await?;
            Ok(out)
        }
        (None, Some(te)) => {
            if !te.eq_ignore_ascii_case(b"chunked") {
                return Err(Reply::NOT_IMPLEMENTED.into());
            }
            read_chunked(shared.max_body, src).await
        }
    }
}

async fn read_chunked<R: AsyncRead + Unpin>(
    max_body: usize,
    src: &mut BufferedReader<R>,
) -> Result<Vec<u8>, Fail> {
    let mut out = Vec::new();
    loop {
        let mut budget = MAX_CHUNK_LINE_BYTES;
        let line = src.line(&mut budget, Reply::BAD_REQUEST).await?;
        if line.is_empty() || line.len() > 16 || !line.iter().all(u8::is_ascii_hexdigit) {
            return Err(Reply::BAD_REQUEST.into());
        }
        let size = std::str::from_utf8(&line)
            .ok()
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or(Reply::BAD_REQUEST)?;
        if size == 0 {
            let mut budget = 2;
            return if src.line(&mut budget, Reply::BAD_REQUEST).await?.is_empty() {
                Ok(out)
            } else {
                Err(Reply::BAD_REQUEST.into())
            };
        }
        let size = usize::try_from(size).map_err(|_| Reply::TOO_LARGE)?;
        if size > max_body.saturating_sub(out.len()) {
            return Err(Reply::TOO_LARGE.into());
        }
        src.take_into(&mut out, size).await?;
        let mut budget = 2;
        if !src.line(&mut budget, Reply::BAD_REQUEST).await?.is_empty() {
            return Err(Reply::BAD_REQUEST.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_rules() {
        assert_eq!(BearerToken::new("short"), Err(TokenError::TooShort));
        assert_eq!(
            BearerToken::new(&"a".repeat(MAX_TOKEN_BYTES + 1)),
            Err(TokenError::TooLong)
        );
        assert_eq!(
            BearerToken::new("aaaaaaaa aaaaaaaaa"),
            Err(TokenError::BadByte)
        );
        assert_eq!(
            BearerToken::new("aaaaaaaa\r\naaaaaaaaa"),
            Err(TokenError::BadByte)
        );
        assert_eq!(
            BearerToken::new("aaaaaaaaaaaaaaaé"),
            Err(TokenError::BadByte)
        );
        assert!(BearerToken::new(&"a".repeat(MAX_TOKEN_BYTES)).is_ok());
    }

    #[test]
    fn matches_exact_only() {
        let token = BearerToken::new("0123456789abcdef").unwrap_or_else(|_| unreachable!());
        assert!(token.matches(b"0123456789abcdef"));
        assert!(!token.matches(b"0123456789abcdeF"));
        assert!(!token.matches(b"0123456789abcde"));
        assert!(!token.matches(b"0123456789abcdef "));
        assert!(!token.matches(b""));
        assert_eq!(format!("{token:?}"), "BearerToken(..)");
    }

    #[test]
    fn bearer_scheme_parse() {
        assert_eq!(bearer(b"Bearer abc"), Some(&b"abc"[..]));
        assert_eq!(bearer(b"bEaReR abc"), Some(&b"abc"[..]));
        assert_eq!(bearer(b"Basic abc"), None);
        assert_eq!(bearer(b"Bearer"), None);
        assert_eq!(bearer(b"Bearerabc"), None);
    }
}
