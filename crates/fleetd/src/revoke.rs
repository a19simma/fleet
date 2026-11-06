//! Revokes a GitHub App installation token (ADR-0058, SEC-010).
//!
//! `DELETE /installation/token` with the token as the bearer ends it at once. fleetd calls it
//! for the token a refresh replaced and for the held token when a Job ends. The caller treats a
//! failure as best effort: the one-hour expiry bounds the token that stays live. One timeout,
//! [`REVOKE_TIMEOUT`], covers the connect, the TLS handshake and the response head. The token
//! goes into one header marked sensitive, and no error holds it or any text from the network.

use std::fmt;
#[cfg(any(test, feature = "testing"))]
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Empty;
use hyper::body::Bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, CONNECTION, HOST, USER_AGENT};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

/// The longest a revoke may take, from the first connect to the response head.
pub const REVOKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The fixed log text for a revoke that failed. It never holds the token.
pub const REVOKE_FAILED: &str = "installation token revoke failed";

const GITHUB_HOST: &str = "api.github.com";
const GITHUB_PORT: u16 = 443;
const REVOKE_PATH: &str = "/installation/token";
const API_VERSION: &str = "2022-11-28";

/// Why a revoke did not complete. Display text is fixed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeError {
    /// The call took longer than [`REVOKE_TIMEOUT`].
    Timeout,
    /// The connect, the TLS handshake or the HTTP exchange failed.
    Transport,
    /// The server answered with a status outside 2xx.
    Status(u16),
    /// The token cannot be put in a header.
    BadToken,
}

impl fmt::Display for RevokeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Timeout => "revoke timed out",
            Self::Transport => "revoke transport failed",
            Self::Status(_) => "revoke refused",
            Self::BadToken => "revoke token is not a header value",
        })
    }
}

impl std::error::Error for RevokeError {}

#[derive(Clone)]
enum Target {
    Tls {
        config: Arc<ClientConfig>,
    },
    #[cfg(any(test, feature = "testing"))]
    Plain {
        addr: SocketAddr,
    },
}

/// The client that revokes installation tokens.
#[derive(Clone)]
pub struct Revoker {
    target: Target,
    limit: Duration,
}

impl fmt::Debug for Revoker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Revoker").finish_non_exhaustive()
    }
}

impl Revoker {
    /// The production client: `https://api.github.com` over the webpki roots, no redirects.
    #[must_use]
    pub fn github() -> Self {
        Self {
            target: Target::Tls {
                config: crate::fetch::webpki_tls_config(),
            },
            limit: REVOKE_TIMEOUT,
        }
    }

    /// A client that talks plain HTTP to `addr`. A seam for tests that stand in for GitHub with
    /// a loopback server. It exists only in test builds and under the `testing` feature, so
    /// the shipped binary cannot be pointed at a plain endpoint.
    #[cfg(any(test, feature = "testing"))]
    #[must_use]
    pub const fn plain(addr: SocketAddr) -> Self {
        Self {
            target: Target::Plain { addr },
            limit: REVOKE_TIMEOUT,
        }
    }

    /// Replaces the time limit, [`REVOKE_TIMEOUT`] by default. A seam for tests.
    #[must_use]
    pub const fn with_timeout(mut self, limit: Duration) -> Self {
        self.limit = limit;
        self
    }

    /// Sends `DELETE /installation/token` with `token` as the bearer.
    ///
    /// # Errors
    ///
    /// [`RevokeError::Timeout`] after the time limit, [`RevokeError::Transport`] when the
    /// exchange fails, [`RevokeError::Status`] for a status outside 2xx and
    /// [`RevokeError::BadToken`] when the token is not a valid header value. None of them holds
    /// the token.
    pub async fn revoke(&self, token: &str) -> Result<(), RevokeError> {
        let bearer = Zeroizing::new(format!("Bearer {token}"));
        let mut auth =
            hyper::header::HeaderValue::from_str(&bearer).map_err(|_| RevokeError::BadToken)?;
        auth.set_sensitive(true);
        timeout(self.limit, self.exchange(auth))
            .await
            .map_err(|_| RevokeError::Timeout)?
    }

    async fn exchange(&self, auth: hyper::header::HeaderValue) -> Result<(), RevokeError> {
        match &self.target {
            #[cfg(any(test, feature = "testing"))]
            Target::Plain { addr } => {
                let tcp = TcpStream::connect(addr)
                    .await
                    .map_err(|_| RevokeError::Transport)?;
                send(tcp, &addr.to_string(), auth).await
            }
            Target::Tls { config } => {
                let tcp = TcpStream::connect((GITHUB_HOST, GITHUB_PORT))
                    .await
                    .map_err(|_| RevokeError::Transport)?;
                let name = ServerName::try_from(GITHUB_HOST).map_err(|_| RevokeError::Transport)?;
                let tls = TlsConnector::from(Arc::clone(config))
                    .connect(name, tcp)
                    .await
                    .map_err(|_| RevokeError::Transport)?;
                send(tls, GITHUB_HOST, auth).await
            }
        }
    }
}

async fn send<T>(io: T, host: &str, auth: hyper::header::HeaderValue) -> Result<(), RevokeError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .handshake::<_, Empty<Bytes>>(TokioIo::new(io))
        .await
        .map_err(|_| RevokeError::Transport)?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(REVOKE_PATH)
        .header(HOST, host)
        .header(USER_AGENT, "fleetd-revoke")
        .header(ACCEPT, "application/vnd.github+json")
        .header("x-github-api-version", API_VERSION)
        .header(CONNECTION, "close")
        .header(AUTHORIZATION, auth)
        .body(Empty::<Bytes>::new())
        .map_err(|_| RevokeError::Transport);
    let sent = match request {
        Ok(request) => sender
            .send_request(request)
            .await
            .map_err(|_| RevokeError::Transport),
        Err(err) => Err(err),
    };
    driver.abort();
    let status = sent?.status();
    if status.is_success() {
        Ok(())
    } else {
        Err(RevokeError::Status(status.as_u16()))
    }
}
