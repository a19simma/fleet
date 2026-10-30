//! GitHub token verification behind the [`GithubApi`] seam (ADR-0043).
//!
//! The server asks `GET /user` with the token. The response names the `login` and a response
//! header names the expiry of a fine-grained token. No error here carries the token or any
//! text from the network.

use std::sync::Arc;
use std::time::Duration;

use fleet_core::credential::Secret;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, HOST, HeaderValue, USER_AGENT};
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const API_HOST: &str = "api.github.com";
const EXPIRY_HEADER: &str = "github-authentication-token-expiration";
/// Latest expiry in milliseconds since the Unix epoch that is accepted, 9999-12-31 23:59:59 UTC.
pub const MAX_EXPIRY_MS: i64 = 253_402_300_799_000;
const MAX_BODY_BYTES: usize = 64 * 1024;
const TOTAL_TIMEOUT: Duration = Duration::from_secs(10);

/// What GitHub says about a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubUser {
    /// The account the token belongs to.
    pub login: String,
    /// Expiry in milliseconds since the Unix epoch, when the response carried one.
    pub expires_at_ms: Option<i64>,
}

/// Why a verification gave no answer about the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubError {
    /// GitHub refused the token.
    Rejected,
    /// GitHub could not be reached or answered something unusable.
    Unavailable,
}

impl std::fmt::Display for GithubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rejected => "github rejected the token",
            Self::Unavailable => "github is unavailable",
        })
    }
}

impl std::error::Error for GithubError {}

/// Looks a GitHub token up. Tests replace it with a fake.
#[tonic::async_trait]
pub trait GithubApi: Send + Sync {
    /// Identifies the owner of `token`.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError::Rejected`] when GitHub refuses the token and
    /// [`GithubError::Unavailable`] for any other failure.
    async fn user(&self, token: &Secret) -> Result<GithubUser, GithubError>;
}

/// The real client: HTTPS to `api.github.com` with the bundled web roots.
pub struct HttpsGithub {
    tls: Arc<ClientConfig>,
}

impl std::fmt::Debug for HttpsGithub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HttpsGithub(..)")
    }
}

impl HttpsGithub {
    /// Builds a client that trusts the bundled web roots.
    ///
    /// # Errors
    ///
    /// Returns [`GithubError::Unavailable`] when the TLS stack cannot be set up.
    pub fn new() -> Result<Self, GithubError> {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| GithubError::Unavailable)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            tls: Arc::new(config),
        })
    }

    async fn request(&self, token: &Secret) -> Result<GithubUser, GithubError> {
        let bearer =
            Zeroizing::new(String::from_utf8(token.expose().to_vec()).map_err(unavailable)?);
        let tcp = TcpStream::connect((API_HOST, 443))
            .await
            .map_err(unavailable)?;
        let name = ServerName::try_from(API_HOST).map_err(unavailable)?;
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, tcp)
            .await
            .map_err(unavailable)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .map_err(unavailable)?;
        let _guard = AbortOnDrop(tokio::spawn(connection));
        let mut header =
            HeaderValue::from_str(&Zeroizing::new(format!("Bearer {}", bearer.as_str())))
                .map_err(unavailable)?;
        header.set_sensitive(true);
        let request = Request::builder()
            .uri("/user")
            .header(HOST, API_HOST)
            .header(USER_AGENT, "fleet-server")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, header)
            .body(Empty::<Bytes>::new())
            .map_err(unavailable)?;
        let response = sender.send_request(request).await.map_err(unavailable)?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED => return Err(GithubError::Rejected),
            _ => return Err(GithubError::Unavailable),
        }
        let expires_at_ms = response
            .headers()
            .get(EXPIRY_HEADER)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_expiry);
        let body = Limited::new(response.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
            .map_err(|_| GithubError::Unavailable)?
            .to_bytes();
        let login = login_of(&body).ok_or(GithubError::Unavailable)?;
        Ok(GithubUser {
            login,
            expires_at_ms,
        })
    }
}

#[tonic::async_trait]
impl GithubApi for HttpsGithub {
    async fn user(&self, token: &Secret) -> Result<GithubUser, GithubError> {
        timeout(TOTAL_TIMEOUT, self.request(token))
            .await
            .unwrap_or(Err(GithubError::Unavailable))
    }
}

struct AbortOnDrop(JoinHandle<Result<(), hyper::Error>>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn unavailable<E>(_: E) -> GithubError {
    GithubError::Unavailable
}

fn login_of(body: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let login = value.get("login")?.as_str()?;
    let valid = !login.is_empty()
        && login.len() <= fleet_proto::MAX_CREDENTIAL_LOGIN_BYTES
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'[' || b == b']');
    valid.then(|| login.to_owned())
}

/// Parses the expiry header, `YYYY-MM-DD HH:MM:SS UTC`, into milliseconds since the Unix epoch.
///
/// The header name and format come from GitHub's documentation and have not been checked
/// against a live response.
pub fn parse_expiry(text: &str) -> Option<i64> {
    let (date, time) = text.trim().strip_suffix(" UTC")?.split_once(' ')?;
    let [year, month, day] = fields::<3>(date, '-')?;
    let [hour, minute, second] = fields::<3>(time, ':')?;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => return None,
    };
    if !(1970..=9999).contains(&year)
        || !(1..=days_in_month).contains(&day)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year / 400;
    let year_of_era = shifted_year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146_097 + day_of_era - 719_468;
    Some(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000)
}

fn fields<const N: usize>(text: &str, separator: char) -> Option<[i64; N]> {
    let mut out = [0_i64; N];
    let mut parts = text.split(separator);
    for slot in &mut out {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 4 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_parses_the_documented_format() {
        assert_eq!(parse_expiry("1970-01-01 00:00:00 UTC"), Some(0));
        assert_eq!(
            parse_expiry("2030-03-17 17:46:40 UTC"),
            Some(1_900_000_000_000)
        );
        assert_eq!(
            parse_expiry("2000-02-29 00:00:01 UTC"),
            Some(951_782_401_000)
        );
    }

    #[test]
    fn expiry_rejects_other_shapes() {
        for bad in [
            "",
            "2030-03-17 17:46:40",
            "2030-03-17T17:46:40Z",
            "2030-13-17 17:46:40 UTC",
            "2030-02-30 17:46:40 UTC",
            "2100-02-29 00:00:00 UTC",
            "2030-03-17 24:00:00 UTC",
            "2030-03-17 17:46 UTC",
            "2030-03-17 17:46:40:1 UTC",
            "-2030-03-17 17:46:40 UTC",
            "1969-12-31 23:59:59 UTC",
        ] {
            assert_eq!(parse_expiry(bad), None, "{bad}");
        }
    }

    #[test]
    fn login_comes_from_the_json_body() {
        assert_eq!(
            login_of(br#"{"login":"octo-cat","id":1}"#).as_deref(),
            Some("octo-cat")
        );
        assert_eq!(login_of(br#"{"login":""}"#), None);
        assert_eq!(login_of(br#"{"login":"a b"}"#), None);
        assert_eq!(login_of(br#"{"id":1}"#), None);
        assert_eq!(login_of(b"nope"), None);
    }
}
