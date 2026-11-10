use std::fmt;
use std::future::Future;
use std::time::Duration;

use fleet_core::host::HostName;

use crate::{Credential, RepoRef};

/// The cap on one reply body: 256 KiB. A [`Http`] seam enforces it and an adapter checks it
/// again.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// The total time one [`Http`] call may take: 7 s.
pub const REPO_CHECK_BUDGET: Duration = Duration::from_secs(7);

/// An HTTP method the forges need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`.
    Get,
    /// `POST`.
    Post,
}

/// One request to `https://{host}{path}` on port 443. Its `Debug` text redacts every header value
/// and the body, because `Authorization` carries the token.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method.
    pub method: Method,
    /// The host to dial. It decides SNI and certificate verification.
    pub host: HostName,
    /// The path and query, starting with `/`.
    pub path: String,
    /// Header names and values.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

fn header_names(headers: &[(String, String)]) -> Vec<&str> {
    headers.iter().map(|(name, _)| name.as_str()).collect()
}

impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("host", &self.host)
            .field("path", &self.path)
            .field("headers", &header_names(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl HttpRequest {
    /// The first header named `name`, ignoring case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// One reply. A 3xx status is returned as is: no seam follows a redirect. Its `Debug` text
/// redacts header values and the body.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// Header names and values.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

/// Why the seam returned no reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// The call went past [`REPO_CHECK_BUDGET`].
    Timeout,
    /// The connection reset or failed.
    Reset,
    /// The body went over [`MAX_BODY_BYTES`].
    BodyTooLarge,
    /// The host failed address vetting. Nothing was dialled.
    HostRefused,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Timeout => "http call timed out",
            Self::Reset => "http connection failed",
            Self::BodyTooLarge => "http body too large",
            Self::HostRefused => "http host refused",
        })
    }
}

impl std::error::Error for HttpError {}

/// The HTTP seam, injected by the caller.
///
/// The server injects `cred::pinned` and fleetd its own pinned client. An implementation dials
/// the vetted address only, follows no redirect, caps the body at [`MAX_BODY_BYTES`] and the
/// call at [`REPO_CHECK_BUDGET`]. It reads no environment.
pub trait Http: Send + Sync {
    /// Sends one request.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send;
}

/// A git operation over HTTPS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitOp {
    /// Fetch the repository.
    Fetch,
    /// Push the Job branch.
    Push,
}

/// One git command. The token travels to the runner for its askpass and goes nowhere else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCommand {
    /// The operation.
    pub op: GitOp,
    /// The repository.
    pub repo: RepoRef,
    /// The branch to push. `None` fetches every branch the adapter needs.
    pub branch: Option<String>,
    /// The credential for the repository host.
    pub credential: Credential,
}

/// What a git command produced. Its `Debug` text redacts the stderr.
#[derive(Clone, PartialEq, Eq)]
pub struct GitOutput {
    /// The exit code.
    pub code: i32,
    /// The stderr text. It is untrusted and may hold the token.
    pub stderr: String,
}

/// Why the git seam returned no output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GitError {
    /// The process did not start.
    Spawn,
    /// The command ran past its deadline and was killed.
    Timeout,
}

impl fmt::Display for GitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Spawn => "git did not start",
            Self::Timeout => "git timed out",
        })
    }
}

impl std::error::Error for GitError {}

/// The git seam: an injected command runner. Tests use a fake. It reads no environment.
pub trait Git: Send + Sync {
    /// Runs one command to completion.
    fn run(&self, command: GitCommand) -> impl Future<Output = Result<GitOutput, GitError>> + Send;
}

impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("headers", &header_names(&self.headers))
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl fmt::Debug for GitOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitOutput")
            .field("code", &self.code)
            .field("stderr_len", &self.stderr.len())
            .finish()
    }
}
