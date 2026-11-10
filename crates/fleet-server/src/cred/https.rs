//! Request plumbing shared by every outbound HTTPS call of the credential code.
//!
//! It serves ADR-0043, ADR-0058 and ADR-0059: the TLS client config, one HTTP/1.1 exchange
//! over any stream, a capped body read, the bearer header and the transport seam of the
//! repository verifier.
//!
//! No error here carries a token or any text from the network.

use std::net::IpAddr;
use std::sync::Arc;

use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::{Body, Bytes, Incoming};
use hyper::header::HeaderValue;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

/// Why the TLS stack could not be set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsError;

impl std::fmt::Display for TlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("tls setup failed")
    }
}

impl std::error::Error for TlsError {}

/// Builds the TLS client config: ring, the bundled webpki roots, TLS 1.2 as the minimum and
/// HTTP/1.1 only. There is no option to skip certificate verification.
///
/// # Errors
///
/// Returns [`TlsError`] when ring does not support the protocol versions.
pub fn tls_config() -> Result<Arc<ClientConfig>, TlsError> {
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    tls_config_with_roots(roots)
}

/// A TLS client config over the given trust roots.
pub(super) fn tls_config_with_roots(roots: RootCertStore) -> Result<Arc<ClientConfig>, TlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| TlsError)?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Aborts the connection driver task when dropped.
pub(super) struct AbortOnDrop(pub(super) JoinHandle<Result<(), hyper::Error>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the HTTP/1.1 handshake on `io`, sends `request` and returns the response head with the
/// body still unread. The driver task lives as long as the returned guard.
pub(super) async fn send<Io>(
    io: Io,
    request: Request<Empty<Bytes>>,
) -> Result<(Response<Incoming>, AbortOnDrop), hyper::Error>
where
    Io: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    let guard = AbortOnDrop(tokio::spawn(connection));
    let response = sender.send_request(request).await?;
    Ok((response, guard))
}

/// A body read stopped before the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// The body is longer than the cap.
    TooLarge,
    /// The stream failed.
    Stream,
}

/// Reads `body` up to `cap` bytes. A longer body is [`BodyError::TooLarge`], never a prefix.
///
/// # Errors
///
/// Returns [`BodyError`] when the body exceeds `cap` or the stream fails.
pub async fn read_capped<B>(body: B, cap: usize) -> Result<Bytes, BodyError>
where
    B: Body,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    Limited::new(body, cap)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|err| {
            if err
                .downcast_ref::<http_body_util::LengthLimitError>()
                .is_some()
            {
                BodyError::TooLarge
            } else {
                BodyError::Stream
            }
        })
}

/// The sensitive `Authorization: Bearer` value for `token`, or `None` when the token is not a
/// valid header value.
pub fn bearer_header(token: &[u8]) -> Option<HeaderValue> {
    let text = Zeroizing::new(String::from_utf8(token.to_vec()).ok()?);
    let mut header =
        HeaderValue::from_str(&Zeroizing::new(format!("Bearer {}", text.as_str()))).ok()?;
    header.set_sensitive(true);
    Some(header)
}

/// One `GET` the repository verifier asks of a forge.
#[derive(Debug)]
pub struct ForgeGet<'a> {
    /// The API host: lowercase ASCII DNS name, used for DNS, SNI, certificate checks and `Host`.
    pub host: &'a str,
    /// The request path with its query, starting with `/`.
    pub path: &'a str,
    /// Whether RFC 1918 and unique-local addresses are acceptable for this host.
    pub allow_private: bool,
    /// The private addresses an admin approved for this host. With `allow_private`, a private
    /// address outside this list refuses the call. Empty admits no private address.
    pub approved_ips: &'a [IpAddr],
    /// The `Authorization` value, marked sensitive, or `None` to send no such header.
    pub authorization: Option<&'a HeaderValue>,
    /// The `Accept` header value.
    pub accept: &'a str,
}

/// Longest `Location` value kept on a [`ForgeReply`], in bytes. A longer value fails the call.
pub const MAX_LOCATION_BYTES: usize = 2048;

/// What a forge answered. The body of a 3xx is never read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeReply {
    /// The status code.
    pub status: StatusCode,
    /// The body, at most the transport cap, empty for a 3xx.
    pub body: Vec<u8>,
    /// The `Location` value of a 3xx reply: exactly one header, UTF-8, at most
    /// [`MAX_LOCATION_BYTES`]. `None` on any other status or a 3xx without the header.
    pub location: Option<String>,
}

/// Why a forge call gave no reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The host or one of its addresses failed vetting. Nothing was dialled.
    Blocked,
    /// The forge could not be reached or answered unusably.
    Unavailable,
    /// The body is over the cap.
    TooLarge,
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Blocked => "forge address refused",
            Self::Unavailable => "forge unavailable",
            Self::TooLarge => "forge body over the cap",
        })
    }
}

impl std::error::Error for FetchError {}

/// Performs one forge `GET`. The real implementation is `PinnedHttps`; tests inject a fake.
#[tonic::async_trait]
pub trait ForgeTransport: Send + Sync {
    /// Sends `request` and returns the reply without following redirects.
    ///
    /// # Errors
    ///
    /// Returns [`FetchError`] when the address is refused, the forge is unreachable or the body
    /// is over the cap.
    async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Full;

    #[tokio::test]
    async fn a_body_at_the_cap_reads_and_one_byte_over_fails() {
        let at = read_capped(Full::new(Bytes::from_static(b"abcd")), 4).await;
        assert_eq!(at.unwrap().as_ref(), b"abcd");
        let over = read_capped(Full::new(Bytes::from_static(b"abcde")), 4).await;
        assert_eq!(over, Err(BodyError::TooLarge));
    }

    #[test]
    fn the_bearer_header_is_sensitive_and_rejects_bad_bytes() {
        let header = bearer_header(b"tok").unwrap();
        assert!(header.is_sensitive());
        assert_eq!(header.as_bytes(), b"Bearer tok");
        assert!(!format!("{header:?}").contains("tok"));
        assert!(bearer_header(b"a\nb").is_none());
        assert!(bearer_header(&[0xff, 0xfe]).is_none());
    }

    #[test]
    fn tls_builds_with_the_bundled_roots() {
        let config = tls_config().unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
