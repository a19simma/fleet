//! GitHub App installation token mint and revoke with fail-closed response checks (ADR-0058).
//!
//! The client talks to the fixed `https://api.github.com` (SEC-020). Redirects are never
//! followed: hyper does not follow them and any status other than the expected one is an error.
//! The request body is built with `serde_json` from server constants and the Job repository
//! name (SEC-019). The URL is built from the `u64` installation id.
//!
//! Every response is validated before the token is returned (SEC-016): the permissions must be
//! a subset of [`ACCEPTED_PERMISSIONS`], `repositories` must be exactly the one requested and
//! `expires_at` must lie in the future and at most [`MAX_TOKEN_TTL_SECS`] ahead. A failed
//! validation revokes the token before it is discarded (SEC-010), also when the 201 body does
//! not parse but its `token` field reads. No error carries text from the network.
//!
//! The release path in `cred::store` calls the client after the capability check and the
//! transaction commit (SEC-011).
//!
//! Not zeroized: the `HeaderValue` copy of the bearer value inside hyper and the TLS buffers.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue, USER_AGENT};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde::de::{Deserializer, MapAccess, Visitor};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

use super::app_jwt::AppJwt;
use super::github::{AbortOnDrop, parse_expiry, tls_config};

const API_HOST: &str = "api.github.com";
const API_VERSION: &str = "2022-11-28";

/// Longest accepted distance from now to the token `expires_at`: 65 minutes. GitHub issues
/// one-hour tokens, so the margin covers clock skew.
pub const MAX_TOKEN_TTL_SECS: u64 = 65 * 60;

/// Time allowed to open the TCP connection and finish the TLS handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Time allowed for one whole call, connect to last body byte.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Largest accepted response body. A longer body fails closed.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;

const MAX_REPOSITORY_BYTES: usize = 100;
const MAX_TOKEN_BYTES: usize = 512;
const RFC3339_LEN: usize = 20;

/// The permissions the server requests, as `(name, level)`. The request body is built from this
/// table and nothing the client sent.
pub const REQUESTED_PERMISSIONS: [(&str, &str); 4] = [
    ("contents", "write"),
    ("pull_requests", "write"),
    ("checks", "read"),
    ("statuses", "read"),
];

/// The permissions a response may carry, each at most at the stated level. It is the requested
/// set plus [`METADATA_PERMISSION`].
pub const ACCEPTED_PERMISSIONS: [(&str, &str); 5] = [
    ("contents", "write"),
    ("pull_requests", "write"),
    ("checks", "read"),
    ("statuses", "read"),
    (METADATA_PERMISSION, "read"),
];

/// Inferred, not part of the design: GitHub adds `metadata:read` to every installation token.
/// Unverified against a live token: confirm before relying on it (ADR-0058, SEC-016).
pub const METADATA_PERMISSION: &str = "metadata";

/// Whether a revoke ran after a failed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeOutcome {
    /// GitHub confirmed the revoke.
    Revoked,
    /// The revoke call failed.
    Failed,
    /// No token could be read from the response, so there was nothing to revoke.
    NotAttempted,
}

/// Which validation rule refused the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invalid {
    /// A field is missing, has the wrong type or is duplicated.
    Shape,
    /// The permissions are not a subset of the accepted set.
    Permissions,
    /// `repositories` is not exactly the one requested.
    Repositories,
    /// `expires_at` is malformed, in the past or over [`MAX_TOKEN_TTL_SECS`] ahead.
    Expiry,
}

/// Why a mint or revoke failed. Messages are fixed and never carry network text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintError {
    /// The client or a request could not be built.
    Setup,
    /// The repository name is outside the accepted grammar.
    Repository,
    /// Connect, TLS or transport failure.
    Transport,
    /// A timeout elapsed.
    Timeout,
    /// GitHub answered with an unexpected status code.
    Status(u16),
    /// The response body is over [`MAX_RESPONSE_BYTES`].
    TooLarge,
    /// The response body is not usable JSON and holds no readable token.
    Malformed,
    /// The response failed validation. `revoke` says what happened to the token.
    Invalid {
        /// The rule that failed.
        reason: Invalid,
        /// The revoke that followed.
        revoke: RevokeOutcome,
    },
}

impl fmt::Display for MintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Setup => "github app client setup failed",
            Self::Repository => "repository name is not accepted",
            Self::Transport => "github app request failed",
            Self::Timeout => "github app request timed out",
            Self::Status(_) => "github app request refused",
            Self::TooLarge => "github app response too large",
            Self::Malformed => "github app response malformed",
            Self::Invalid { .. } => "github app response failed validation",
        })
    }
}

impl std::error::Error for MintError {}

/// A minted installation token and its expiry. `Debug` is redacted and the value is wiped on
/// drop.
pub struct InstallationToken {
    value: Zeroizing<String>,
    expires_at: u64,
}

impl InstallationToken {
    /// The token text. Pass it only to GitHub or to the Box that needs it.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Expiry in seconds since the Unix epoch, checked against [`MAX_TOKEN_TTL_SECS`].
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for InstallationToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InstallationToken(..)")
    }
}

/// Timeouts and the response cap. The shipped client uses [`Limits::default`].
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// See [`CONNECT_TIMEOUT`].
    pub connect_timeout: Duration,
    /// See [`TOTAL_TIMEOUT`].
    pub total_timeout: Duration,
    /// See [`MAX_RESPONSE_BYTES`].
    pub max_body_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect_timeout: CONNECT_TIMEOUT,
            total_timeout: TOTAL_TIMEOUT,
            max_body_bytes: MAX_RESPONSE_BYTES,
        }
    }
}

enum Endpoint {
    Github(Arc<ClientConfig>),
    #[cfg(test)]
    Plain(std::net::SocketAddr),
}

/// The GitHub App installation token client.
pub struct AppClient {
    endpoint: Endpoint,
    limits: Limits,
}

impl fmt::Debug for AppClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppClient(..)")
    }
}

#[cfg(test)]
impl InstallationToken {
    pub(crate) fn for_test(value: &str, expires_at: u64) -> Self {
        Self {
            value: Zeroizing::new(value.to_owned()),
            expires_at,
        }
    }
}

impl AppClient {
    /// Builds the client for `https://api.github.com` with the bundled web roots.
    ///
    /// # Errors
    ///
    /// Returns [`MintError::Setup`] when the TLS stack cannot be set up.
    pub fn new() -> Result<Self, MintError> {
        Ok(Self {
            endpoint: Endpoint::Github(tls_config().map_err(|_| MintError::Setup)?),
            limits: Limits::default(),
        })
    }

    #[cfg(test)]
    pub(crate) fn plain(addr: std::net::SocketAddr, limits: Limits) -> Self {
        Self {
            endpoint: Endpoint::Plain(addr),
            limits,
        }
    }

    /// Mints an installation token for `repository` (the bare name, no owner) and validates the
    /// response against `now`, seconds since the Unix epoch.
    ///
    /// A response that fails validation has its token revoked when one can be read. A 201 body
    /// that does not parse, but whose `token` field alone reads, counts as `Invalid` with reason
    /// `Shape` and is revoked. A body over the cap is not revoked: the token may lie past it.
    ///
    /// # Errors
    ///
    /// Returns [`MintError`]: `Setup` when a request cannot be built, `Repository` for a name
    /// outside the grammar, `Status`, `Timeout`, `Transport`, `TooLarge` or `Malformed` for a
    /// failed call, and `Invalid` when the response breaks a validation rule.
    pub async fn mint(
        &self,
        jwt: &AppJwt,
        installation_id: u64,
        repository: &str,
        now: u64,
    ) -> Result<InstallationToken, MintError> {
        if !valid_repository(repository) {
            return Err(MintError::Repository);
        }
        let body = serde_json::to_vec(&request_body(repository)).map_err(|_| MintError::Setup)?;
        let request = self.request(
            Method::POST,
            &format!("/app/installations/{installation_id}/access_tokens"),
            jwt.expose(),
            body,
        )?;
        let bytes = self.send(request, StatusCode::CREATED).await?;
        let (token, outcome) = if let Ok(raw) = serde_json::from_slice::<Raw>(&bytes) {
            let token = raw.token.clone().map(Zeroizing::new);
            (token, validate(raw, repository, now))
        } else {
            let token = serde_json::from_slice::<TokenOnly>(&bytes)
                .ok()
                .and_then(|only| only.token)
                .map(Zeroizing::new)
                .filter(|t| valid_token(t));
            if token.is_none() {
                return Err(MintError::Malformed);
            }
            (token, Err(Invalid::Shape))
        };
        drop(bytes);
        match outcome {
            Ok(token) => Ok(token),
            Err(reason) => {
                let revoke = match token.filter(|t| valid_token(t)) {
                    None => RevokeOutcome::NotAttempted,
                    Some(value) => {
                        let doomed = InstallationToken {
                            value,
                            expires_at: 0,
                        };
                        match self.revoke(&doomed).await {
                            Ok(()) => RevokeOutcome::Revoked,
                            Err(_) => RevokeOutcome::Failed,
                        }
                    }
                };
                Err(MintError::Invalid { reason, revoke })
            }
        }
    }

    /// Reads the App id GitHub reports for the key behind `jwt`.
    ///
    /// # Errors
    ///
    /// Returns [`MintError`]: `Setup` when the request cannot be built, `Status`, `Timeout`,
    /// `Transport` or `TooLarge` for a failed call, and `Malformed` when the reply holds no
    /// numeric `id`.
    pub async fn app_id(&self, jwt: &AppJwt) -> Result<u64, MintError> {
        let request = self.request(Method::GET, "/app", jwt.expose(), Vec::new())?;
        let bytes = self.send(request, StatusCode::OK).await?;
        serde_json::from_slice::<AppIdOnly>(&bytes)
            .map(|reply| reply.id)
            .map_err(|_| MintError::Malformed)
    }

    /// Revokes `token` with `DELETE /installation/token`.
    ///
    /// # Errors
    ///
    /// Returns [`MintError`] when the call fails or GitHub does not answer 204.
    pub async fn revoke(&self, token: &InstallationToken) -> Result<(), MintError> {
        let request = self.request(
            Method::DELETE,
            "/installation/token",
            token.expose(),
            Vec::new(),
        )?;
        self.send(request, StatusCode::NO_CONTENT).await.map(drop)
    }

    fn request(
        &self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Vec<u8>,
    ) -> Result<Request<Full<Bytes>>, MintError> {
        let mut auth = HeaderValue::from_str(&Zeroizing::new(format!("Bearer {bearer}")))
            .map_err(|_| MintError::Setup)?;
        auth.set_sensitive(true);
        let host = match &self.endpoint {
            Endpoint::Github(_) => API_HOST.to_owned(),
            #[cfg(test)]
            Endpoint::Plain(addr) => addr.to_string(),
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, host)
            .header(USER_AGENT, "fleet-server")
            .header(ACCEPT, "application/vnd.github+json")
            .header("x-github-api-version", API_VERSION)
            .header(AUTHORIZATION, auth);
        if !body.is_empty() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| MintError::Setup)
    }

    async fn send(
        &self,
        request: Request<Full<Bytes>>,
        expect: StatusCode,
    ) -> Result<Zeroizing<Vec<u8>>, MintError> {
        let limits = self.limits;
        let call = async {
            match &self.endpoint {
                Endpoint::Github(tls) => {
                    let tcp = timeout(limits.connect_timeout, TcpStream::connect((API_HOST, 443)))
                        .await
                        .map_err(|_| MintError::Timeout)?
                        .map_err(|_| MintError::Transport)?;
                    let name = ServerName::try_from(API_HOST).map_err(|_| MintError::Setup)?;
                    let tls = timeout(
                        limits.connect_timeout,
                        TlsConnector::from(Arc::clone(tls)).connect(name, tcp),
                    )
                    .await
                    .map_err(|_| MintError::Timeout)?
                    .map_err(|_| MintError::Transport)?;
                    exchange(tls, request, expect, limits.max_body_bytes).await
                }
                #[cfg(test)]
                Endpoint::Plain(addr) => {
                    let tcp = timeout(limits.connect_timeout, TcpStream::connect(addr))
                        .await
                        .map_err(|_| MintError::Timeout)?
                        .map_err(|_| MintError::Transport)?;
                    exchange(tcp, request, expect, limits.max_body_bytes).await
                }
            }
        };
        timeout(limits.total_timeout, call)
            .await
            .map_err(|_| MintError::Timeout)?
    }
}

async fn exchange<T>(
    io: T,
    request: Request<Full<Bytes>>,
    expect: StatusCode,
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, MintError>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io))
        .await
        .map_err(|_| MintError::Transport)?;
    let _guard = AbortOnDrop(tokio::spawn(connection));
    let response = sender
        .send_request(request)
        .await
        .map_err(|_| MintError::Transport)?;
    let status = response.status();
    if status != expect {
        return Err(MintError::Status(status.as_u16()));
    }
    let mut incoming = response.into_body();
    let mut body = Zeroizing::new(Vec::with_capacity(cap.saturating_add(1)));
    while let Some(frame) = incoming.frame().await {
        let frame = frame.map_err(|_| MintError::Transport)?;
        if let Some(data) = frame.data_ref() {
            let room = cap.saturating_add(1) - body.len();
            body.extend_from_slice(data.get(..data.len().min(room)).unwrap_or_default());
            if body.len() > cap {
                return Err(MintError::TooLarge);
            }
        }
    }
    Ok(body)
}

fn request_body(repository: &str) -> serde_json::Value {
    let permissions: serde_json::Map<String, serde_json::Value> = REQUESTED_PERMISSIONS
        .iter()
        .map(|(name, level)| ((*name).to_owned(), serde_json::Value::from(*level)))
        .collect();
    serde_json::json!({ "repositories": [repository], "permissions": permissions })
}

fn valid_repository(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_REPOSITORY_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token.bytes().all(|b| b.is_ascii_graphic())
}

#[derive(Debug)]
struct Permissions(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for Permissions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Permissions;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a permission map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut out = BTreeMap::new();
                while let Some((key, value)) = map.next_entry::<String, String>()? {
                    if out.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate key"));
                    }
                }
                Ok(Permissions(out))
            }
        }
        deserializer.deserialize_map(V)
    }
}

#[derive(Deserialize)]
struct RawRepository {
    name: Option<String>,
}

#[derive(Deserialize)]
struct AppIdOnly {
    id: u64,
}

#[derive(Deserialize)]
struct TokenOnly {
    token: Option<String>,
}

#[derive(Deserialize)]
struct Raw {
    token: Option<String>,
    expires_at: Option<String>,
    permissions: Option<Permissions>,
    repositories: Option<Vec<RawRepository>>,
}

fn level_rank(level: &str) -> Option<u8> {
    match level {
        "read" => Some(1),
        "write" => Some(2),
        "admin" => Some(3),
        _ => None,
    }
}

fn permissions_ok(permissions: &BTreeMap<String, String>) -> bool {
    permissions.iter().all(|(name, level)| {
        let granted = level_rank(level);
        let accepted = ACCEPTED_PERMISSIONS
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, l)| level_rank(l));
        matches!((granted, accepted), (Some(g), Some(a)) if g <= a)
    })
}

fn parse_rfc3339_utc(text: &str) -> Option<u64> {
    let b = text.as_bytes();
    let shape_ok = b.len() == RFC3339_LEN
        && b.get(10) == Some(&b'T')
        && b.get(19) == Some(&b'Z')
        && text.is_ascii();
    if !shape_ok {
        return None;
    }
    let spaced = format!("{} {} UTC", text.get(..10)?, text.get(11..19)?);
    u64::try_from(parse_expiry(&spaced)? / 1000).ok()
}

fn validate(raw: Raw, repository: &str, now: u64) -> Result<InstallationToken, Invalid> {
    let token = raw.token.map(Zeroizing::new).ok_or(Invalid::Shape)?;
    let (Some(expires_at), Some(permissions), Some(repositories)) =
        (raw.expires_at, raw.permissions, raw.repositories)
    else {
        return Err(Invalid::Shape);
    };
    if !valid_token(&token) {
        return Err(Invalid::Shape);
    }
    if !permissions_ok(&permissions.0) {
        return Err(Invalid::Permissions);
    }
    let one_requested = matches!(
        repositories.as_slice(),
        [RawRepository { name: Some(name) }] if name.eq_ignore_ascii_case(repository)
    );
    if !one_requested {
        return Err(Invalid::Repositories);
    }
    let expires_at = parse_rfc3339_utc(&expires_at).ok_or(Invalid::Expiry)?;
    if expires_at <= now || expires_at - now > MAX_TOKEN_TTL_SECS {
        return Err(Invalid::Expiry);
    }
    Ok(InstallationToken {
        value: token,
        expires_at,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use std::time::Instant;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    const NOW: u64 = 1_700_000_000;
    const IN_ONE_HOUR: &str = "2023-11-14T23:13:20Z";
    const AT_CEILING: &str = "2023-11-14T23:18:20Z";
    const OVER_CEILING: &str = "2023-11-14T23:18:21Z";
    const TOKEN: &str = "ghs_testtoken0123456789";
    const JWT: &str = "jwt.header.sig";
    const REPO: &str = "widget";
    const ID: u64 = 4242;

    enum Script {
        Reply(String),
        Hang,
    }

    struct Fake {
        addr: SocketAddr,
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl Fake {
        fn requests(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    fn http(status: &str, extra: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n{body}",
            body.len()
        )
    }

    fn created(body: &str) -> Script {
        Script::Reply(http("201 Created", "", body))
    }

    fn no_content() -> Script {
        Script::Reply(http("204 No Content", "", ""))
    }

    async fn read_request(stream: &mut TcpStream) -> String {
        let mut buf = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let n = stream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            let text = String::from_utf8_lossy(&buf).into_owned();
            if let Some((head, body)) = text.split_once("\r\n\r\n") {
                let want = head
                    .lines()
                    .find_map(|l| {
                        l.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if body.len() >= want {
                    break;
                }
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    async fn fake(script: Vec<Script>) -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let queue = Arc::new(Mutex::new(VecDeque::from(script)));
        let seen_task = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let seen = Arc::clone(&seen_task);
                let queue = Arc::clone(&queue);
                tokio::spawn(async move {
                    let request = read_request(&mut stream).await;
                    seen.lock().unwrap().push(request);
                    let next = queue.lock().unwrap().pop_front();
                    match next {
                        Some(Script::Reply(text)) => {
                            let _ = stream.write_all(text.as_bytes()).await;
                            let _ = stream.shutdown().await;
                        }
                        Some(Script::Hang) => tokio::time::sleep(Duration::from_secs(60)).await,
                        None => {}
                    }
                });
            }
        });
        Fake { addr, seen }
    }

    fn client(fake: &Fake) -> AppClient {
        AppClient::plain(fake.addr, Limits::default())
    }

    fn body_with(token: &str, expires: &str, permissions: &str, repositories: &str) -> String {
        format!(
            r#"{{"token":"{token}","expires_at":"{expires}","permissions":{permissions},"repositories":{repositories}}}"#
        )
    }

    const GOOD_PERMS: &str = r#"{"contents":"write","pull_requests":"write","checks":"read","statuses":"read","metadata":"read"}"#;
    const GOOD_REPOS: &str = r#"[{"id":1,"name":"widget","full_name":"o/widget"}]"#;

    fn good() -> String {
        body_with(TOKEN, IN_ONE_HOUR, GOOD_PERMS, GOOD_REPOS)
    }

    async fn fake_status(body: &str) -> Fake {
        fake(vec![
            created(body),
            Script::Reply(http("500 Internal Server Error", "", "")),
        ])
        .await
    }

    async fn mint(fake: &Fake) -> Result<InstallationToken, MintError> {
        client(fake)
            .mint(&AppJwt::from_text(JWT), ID, REPO, NOW)
            .await
    }

    #[tokio::test]
    async fn good_response_mints_and_request_is_built_from_constants() {
        let fake = fake(vec![created(&good())]).await;
        let token = mint(&fake).await.unwrap();
        assert_eq!(token.expose(), TOKEN);
        assert_eq!(token.expires_at(), NOW + 3600);
        let seen = fake.requests();
        assert_eq!(seen.len(), 1);
        let (head, body) = seen[0].split_once("\r\n\r\n").unwrap();
        let head = head.to_ascii_lowercase();
        assert!(head.starts_with("post /app/installations/4242/access_tokens http/1.1"));
        assert!(head.contains(&format!("authorization: bearer {JWT}")));
        assert!(head.contains("x-github-api-version: 2022-11-28"));
        assert!(head.contains("content-type: application/json"));
        let sent: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(
            sent,
            serde_json::json!({
                "repositories": ["widget"],
                "permissions": {
                    "contents": "write",
                    "pull_requests": "write",
                    "checks": "read",
                    "statuses": "read"
                }
            })
        );
    }

    #[tokio::test]
    async fn installation_url_is_built_from_the_integer() {
        let fake = fake(vec![created(&good())]).await;
        let _ = client(&fake)
            .mint(&AppJwt::from_text(JWT), u64::MAX, REPO, NOW)
            .await;
        assert!(
            fake.requests()[0]
                .starts_with("POST /app/installations/18446744073709551615/access_tokens HTTP/1.1")
        );
    }

    #[tokio::test]
    async fn subset_permissions_are_accepted() {
        for perms in [
            "{}",
            r#"{"contents":"read"}"#,
            r#"{"contents":"write","metadata":"read"}"#,
            r#"{"pull_requests":"read","checks":"read"}"#,
        ] {
            let fake = fake(vec![created(&body_with(
                TOKEN,
                IN_ONE_HOUR,
                perms,
                GOOD_REPOS,
            ))])
            .await;
            assert!(mint(&fake).await.is_ok(), "{perms}");
        }
    }

    #[tokio::test]
    async fn permissions_outside_the_accepted_set_are_refused_and_revoked() {
        for perms in [
            r#"{"contents":"admin"}"#,
            r#"{"checks":"write"}"#,
            r#"{"statuses":"write"}"#,
            r#"{"metadata":"write"}"#,
            r#"{"workflows":"write"}"#,
            r#"{"administration":"read"}"#,
            r#"{"contents":"write","issues":"read"}"#,
            r#"{"contents":"superuser"}"#,
            r#"{"contents":""}"#,
            r#"{"Contents":"write"}"#,
        ] {
            let fake = fake(vec![
                created(&body_with(TOKEN, IN_ONE_HOUR, perms, GOOD_REPOS)),
                no_content(),
            ])
            .await;
            assert_eq!(
                mint(&fake).await.unwrap_err(),
                MintError::Invalid {
                    reason: Invalid::Permissions,
                    revoke: RevokeOutcome::Revoked
                },
                "{perms}"
            );
            assert_eq!(fake.requests().len(), 2, "{perms}");
        }
    }

    #[tokio::test]
    async fn repositories_must_be_exactly_the_one_requested() {
        for repos in [
            "[]",
            r#"[{"name":"other"}]"#,
            r#"[{"name":"widget"},{"name":"other"}]"#,
            r#"[{"name":"widget"},{"name":"widget"}]"#,
            r#"[{"id":1}]"#,
            r#"[{"name":"widget2"}]"#,
            r#"[{"name":"widge"}]"#,
        ] {
            let fake = fake(vec![
                created(&body_with(TOKEN, IN_ONE_HOUR, GOOD_PERMS, repos)),
                no_content(),
            ])
            .await;
            assert_eq!(
                mint(&fake).await.unwrap_err(),
                MintError::Invalid {
                    reason: Invalid::Repositories,
                    revoke: RevokeOutcome::Revoked
                },
                "{repos}"
            );
        }
    }

    #[tokio::test]
    async fn repository_name_compares_ascii_case_insensitively() {
        let fake = fake(vec![created(&body_with(
            TOKEN,
            IN_ONE_HOUR,
            GOOD_PERMS,
            r#"[{"name":"Widget"}]"#,
        ))])
        .await;
        assert!(mint(&fake).await.is_ok());
    }

    #[tokio::test]
    async fn expiry_is_pinned_to_the_ceiling() {
        let fake_ok = fake(vec![created(&body_with(
            TOKEN, AT_CEILING, GOOD_PERMS, GOOD_REPOS,
        ))])
        .await;
        assert_eq!(
            mint(&fake_ok).await.unwrap().expires_at(),
            NOW + MAX_TOKEN_TTL_SECS
        );
        for expires in [
            OVER_CEILING,
            "2023-11-14T22:13:20Z",
            "2023-11-14T22:13:19Z",
            "2023-11-14T23:13:20Z\\u0000",
            "2023-11-14T23:13:20+00:00",
            "2023-11-14t23:13:20z",
            "2023-11-14 23:13:20Z",
            "2023-11-14T23:13:20.000Z",
            "2023-11-14T23:13:20",
            "2023-13-14T23:13:20Z",
            "tomorrow",
            "",
            "2023-11-14T23:13:2\u{e9}Z",
        ] {
            let fake = fake(vec![
                created(&body_with(TOKEN, expires, GOOD_PERMS, GOOD_REPOS)),
                no_content(),
            ])
            .await;
            let err = mint(&fake).await.unwrap_err();
            assert!(
                matches!(
                    err,
                    MintError::Invalid {
                        reason: Invalid::Expiry,
                        revoke: RevokeOutcome::Revoked
                    }
                ),
                "{expires:?} {err:?}"
            );
        }
    }

    #[test]
    fn rfc3339_parses_one_known_instant() {
        assert_eq!(parse_rfc3339_utc("2023-11-14T22:13:20Z"), Some(NOW));
        assert_eq!(parse_rfc3339_utc("1970-01-01T00:00:00Z"), Some(0));
    }

    #[tokio::test]
    async fn each_missing_field_is_refused_and_revoked() {
        let fields = [
            (
                "expires_at",
                r#"{"token":"ghs_t","permissions":{},"repositories":[{"name":"widget"}]}"#,
            ),
            (
                "permissions",
                r#"{"token":"ghs_t","expires_at":"2023-11-14T23:13:20Z","repositories":[{"name":"widget"}]}"#,
            ),
            (
                "repositories",
                r#"{"token":"ghs_t","expires_at":"2023-11-14T23:13:20Z","permissions":{}}"#,
            ),
        ];
        for (name, body) in fields {
            let fake = fake(vec![created(body), no_content()]).await;
            assert_eq!(
                mint(&fake).await.unwrap_err(),
                MintError::Invalid {
                    reason: Invalid::Shape,
                    revoke: RevokeOutcome::Revoked
                },
                "{name}"
            );
        }
        let fake = fake(vec![created(
            r#"{"expires_at":"2023-11-14T23:13:20Z","permissions":{},"repositories":[{"name":"widget"}]}"#,
        )])
        .await;
        assert_eq!(
            mint(&fake).await.unwrap_err(),
            MintError::Invalid {
                reason: Invalid::Shape,
                revoke: RevokeOutcome::NotAttempted
            }
        );
        assert_eq!(fake.requests().len(), 1);
    }

    #[tokio::test]
    async fn a_token_that_is_not_header_safe_is_not_sent_back() {
        for token in ["", "has space", "tab\\t", "new\\nline", "caf\u{e9}"] {
            let fake = fake(vec![created(&body_with(
                token,
                IN_ONE_HOUR,
                GOOD_PERMS,
                GOOD_REPOS,
            ))])
            .await;
            assert_eq!(
                mint(&fake).await.unwrap_err(),
                MintError::Invalid {
                    reason: Invalid::Shape,
                    revoke: RevokeOutcome::NotAttempted
                },
                "{token:?}"
            );
            assert_eq!(fake.requests().len(), 1);
        }
    }

    #[tokio::test]
    async fn revoke_after_failed_validation_deletes_the_installation_token() {
        let bad = body_with(TOKEN, IN_ONE_HOUR, r#"{"contents":"admin"}"#, GOOD_REPOS);
        let fake = fake(vec![created(&bad), no_content()]).await;
        let _ = mint(&fake).await;
        let seen = fake.requests();
        let head = seen[1].to_ascii_lowercase();
        assert!(head.starts_with("delete /installation/token http/1.1"));
        assert!(head.contains(&format!("authorization: bearer {TOKEN}")));
    }

    #[tokio::test]
    async fn a_failed_revoke_is_reported() {
        let bad = body_with(TOKEN, IN_ONE_HOUR, r#"{"contents":"admin"}"#, GOOD_REPOS);
        let fake = fake(vec![
            created(&bad),
            Script::Reply(http("500 Internal Server Error", "", "")),
        ])
        .await;
        assert_eq!(
            mint(&fake).await.unwrap_err(),
            MintError::Invalid {
                reason: Invalid::Permissions,
                revoke: RevokeOutcome::Failed
            }
        );
    }

    #[tokio::test]
    async fn revoke_wants_204() {
        let fake = fake(vec![no_content(), created("{}")]).await;
        let token = InstallationToken {
            value: Zeroizing::new(TOKEN.to_owned()),
            expires_at: 0,
        };
        let c = client(&fake);
        assert!(c.revoke(&token).await.is_ok());
        assert_eq!(c.revoke(&token).await.unwrap_err(), MintError::Status(201));
    }

    #[tokio::test]
    async fn redirects_are_not_followed() {
        let fake = fake(vec![Script::Reply(http(
            "302 Found",
            "location: http://127.0.0.1:1/elsewhere\r\n",
            "",
        ))])
        .await;
        assert_eq!(mint(&fake).await.unwrap_err(), MintError::Status(302));
        assert_eq!(fake.requests().len(), 1);
    }

    #[tokio::test]
    async fn non_201_statuses_fail_without_network_text() {
        for status in [
            "200 OK",
            "401 Unauthorized",
            "403 Forbidden",
            "404 Not Found",
            "422 Unprocessable Entity",
            "500 Internal Server Error",
        ] {
            let fake = fake(vec![Script::Reply(http(status, "", "NETTEXT-SECRET"))]).await;
            let err = mint(&fake).await.unwrap_err();
            assert!(matches!(err, MintError::Status(_)), "{status}");
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains("NETTEXT") && !shown.contains(TOKEN));
        }
    }

    #[tokio::test]
    async fn malformed_and_invalid_errors_carry_no_network_text() {
        let evil = body_with(
            "ghs_NETTEXT",
            IN_ONE_HOUR,
            GOOD_PERMS,
            r#"[{"name":"NETTEXT-repo"}]"#,
        );
        let bodies = [
            created("NETTEXT not json"),
            created(r#"{"token":"ghs_NETTEXT","expires_at":5}"#),
            created(&evil),
        ];
        for script in bodies {
            let fake = fake(vec![script, no_content()]).await;
            let err = mint(&fake).await.unwrap_err();
            let shown = format!("{err} {err:?}");
            assert!(!shown.contains("NETTEXT"), "{shown}");
        }
    }

    #[tokio::test]
    async fn duplicate_keys_are_refused() {
        let dup_top = format!(
            r#"{{"token":"a","token":"b","expires_at":"{IN_ONE_HOUR}","permissions":{{}},"repositories":[]}}"#
        );
        let dup_perm = format!(
            r#"{{"token":"{TOKEN}","expires_at":"{IN_ONE_HOUR}","permissions":{{"contents":"admin","contents":"write"}},"repositories":{GOOD_REPOS}}}"#
        );
        let dup_repo = format!(
            r#"{{"token":"{TOKEN}","expires_at":"{IN_ONE_HOUR}","permissions":{{}},"repositories":[{{"name":"other","name":"widget"}}]}}"#
        );
        let fake_top = fake(vec![created(&dup_top), no_content()]).await;
        assert_eq!(mint(&fake_top).await.unwrap_err(), MintError::Malformed);
        assert_eq!(fake_top.requests().len(), 1);
        for body in [dup_perm, dup_repo] {
            let fake = fake(vec![created(&body), no_content()]).await;
            assert_eq!(
                mint(&fake).await.unwrap_err(),
                MintError::Invalid {
                    reason: Invalid::Shape,
                    revoke: RevokeOutcome::Revoked
                },
                "{body}"
            );
            let seen = fake.requests();
            assert_eq!(seen.len(), 2, "{body}");
            assert!(seen[1].starts_with("DELETE /installation/token"), "{body}");
        }
    }

    #[tokio::test]
    async fn malformed_201_with_readable_token_is_revoked() {
        let bad_type = format!(
            r#"{{"token":"{TOKEN}","expires_at":"{IN_ONE_HOUR}","permissions":{{"contents":5}},"repositories":{GOOD_REPOS}}}"#
        );
        let fake = fake(vec![created(&bad_type), no_content()]).await;
        assert_eq!(
            mint(&fake).await.unwrap_err(),
            MintError::Invalid {
                reason: Invalid::Shape,
                revoke: RevokeOutcome::Revoked
            }
        );
        let seen = fake.requests();
        assert_eq!(seen.len(), 2);
        assert!(seen[1].starts_with("DELETE /installation/token"));
        assert!(
            seen[1]
                .to_ascii_lowercase()
                .contains(&format!("authorization: bearer {TOKEN}"))
        );
    }

    #[tokio::test]
    async fn malformed_201_revoke_failure_is_recorded() {
        let broken = format!(r#"{{"token":"{TOKEN}","permissions":5}}"#);
        let fake = fake_status(&broken).await;
        assert_eq!(
            mint(&fake).await.unwrap_err(),
            MintError::Invalid {
                reason: Invalid::Shape,
                revoke: RevokeOutcome::Failed
            }
        );
    }

    #[tokio::test]
    async fn non_json_201_body_is_malformed_without_revoke() {
        let truncated = format!(r#"{{"token":"{TOKEN}","permissions":"x"#);
        let unusable = r#"{"token":"bad token","permissions":5}"#;
        for body in ["not json", truncated.as_str(), unusable] {
            let fake = fake(vec![created(body), no_content()]).await;
            assert_eq!(mint(&fake).await.unwrap_err(), MintError::Malformed);
            assert_eq!(fake.requests().len(), 1);
        }
    }

    #[tokio::test]
    async fn response_cap_is_exact_and_fails_closed_one_over() {
        let body = good();
        let fake_ok = fake(vec![created(&body)]).await;
        let limits = Limits {
            max_body_bytes: body.len(),
            ..Limits::default()
        };
        let ok = AppClient::plain(fake_ok.addr, limits)
            .mint(&AppJwt::from_text(JWT), ID, REPO, NOW)
            .await;
        assert!(ok.is_ok());
        let fake_over = fake(vec![created(&body)]).await;
        let limits = Limits {
            max_body_bytes: body.len() - 1,
            ..Limits::default()
        };
        let over = AppClient::plain(fake_over.addr, limits)
            .mint(&AppJwt::from_text(JWT), ID, REPO, NOW)
            .await;
        assert_eq!(over.unwrap_err(), MintError::TooLarge);
    }

    #[tokio::test]
    async fn huge_body_is_refused_at_the_default_cap() {
        let huge = format!(r#"{{"pad":"{}"}}"#, "x".repeat(MAX_RESPONSE_BYTES));
        let fake = fake(vec![created(&huge)]).await;
        assert_eq!(mint(&fake).await.unwrap_err(), MintError::TooLarge);
    }

    #[tokio::test]
    async fn a_truncated_body_fails_closed() {
        let body = good();
        let cut = &body[..body.len() / 2];
        let reply = format!(
            "HTTP/1.1 201 Created\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{cut}",
            body.len()
        );
        let fake = fake(vec![Script::Reply(reply)]).await;
        assert_eq!(mint(&fake).await.unwrap_err(), MintError::Transport);
    }

    #[tokio::test]
    async fn a_slow_server_times_out() {
        let fake = fake(vec![Script::Hang]).await;
        let limits = Limits {
            total_timeout: Duration::from_secs(1),
            ..Limits::default()
        };
        let started = Instant::now();
        let result = timeout(
            Duration::from_secs(30),
            AppClient::plain(fake.addr, limits).mint(&AppJwt::from_text(JWT), ID, REPO, NOW),
        )
        .await
        .unwrap();
        assert_eq!(result.unwrap_err(), MintError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn refused_connection_is_a_transport_error() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let result = AppClient::plain(addr, Limits::default())
            .mint(&AppJwt::from_text(JWT), ID, REPO, NOW)
            .await;
        assert_eq!(result.unwrap_err(), MintError::Transport);
    }

    #[tokio::test]
    async fn hostile_repository_names_never_reach_the_network() {
        let long = "a".repeat(101);
        for name in [
            "",
            ".",
            "..",
            "a/b",
            "a b",
            "a\r\nb",
            "a?b",
            "a#b",
            "%2f",
            "a%2fb",
            "caf\u{e9}",
            "a\\b",
            "a\u{2028}b",
            long.as_str(),
        ] {
            let fake = fake(vec![created(&good())]).await;
            let result = client(&fake)
                .mint(&AppJwt::from_text(JWT), ID, name, NOW)
                .await;
            assert_eq!(result.unwrap_err(), MintError::Repository, "{name:?}");
            assert!(fake.requests().is_empty(), "{name:?}");
        }
        for name in [".github", "a.b_c-d", "A1", &"a".repeat(100)] {
            assert!(valid_repository(name), "{name}");
        }
    }

    #[test]
    fn request_body_is_json_built_from_constants() {
        assert_eq!(
            request_body("r\"x"),
            serde_json::json!({
                "repositories": ["r\"x"],
                "permissions": {
                    "contents": "write",
                    "pull_requests": "write",
                    "checks": "read",
                    "statuses": "read"
                }
            })
        );
    }

    #[test]
    fn every_requested_permission_is_accepted_and_metadata_is_extra() {
        for (name, level) in REQUESTED_PERMISSIONS {
            assert!(ACCEPTED_PERMISSIONS.contains(&(name, level)));
        }
        assert_eq!(ACCEPTED_PERMISSIONS.len(), REQUESTED_PERMISSIONS.len() + 1);
        assert!(ACCEPTED_PERMISSIONS.contains(&(METADATA_PERMISSION, "read")));
    }

    #[test]
    fn ttl_ceiling_is_65_minutes() {
        assert_eq!(MAX_TOKEN_TTL_SECS, 3900);
    }

    #[tokio::test]
    async fn token_and_client_debug_are_redacted() {
        let fake = fake(vec![created(&good())]).await;
        let token = mint(&fake).await.unwrap();
        assert_eq!(format!("{token:?}"), "InstallationToken(..)");
        assert!(!format!("{:?}", client(&fake)).contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn app_id_reads_the_id_from_get_app() {
        let fake = fake(vec![Script::Reply(http(
            "200 OK",
            "",
            r#"{"id":12345,"slug":"fleet"}"#,
        ))])
        .await;
        let id = client(&fake).app_id(&AppJwt::from_text(JWT)).await.unwrap();
        assert_eq!(id, 12345);
        let request = &fake.requests()[0];
        assert!(request.starts_with("GET /app "), "{request}");
        assert!(request.contains("Bearer jwt.header.sig"), "{request}");
    }

    #[tokio::test]
    async fn app_id_refuses_a_status_other_than_200() {
        let fake = fake(vec![Script::Reply(http("401 Unauthorized", "", ""))]).await;
        let err = client(&fake)
            .app_id(&AppJwt::from_text(JWT))
            .await
            .unwrap_err();
        assert_eq!(err, MintError::Status(401));
    }

    #[tokio::test]
    async fn app_id_refuses_a_body_without_a_numeric_id() {
        for body in [
            r#"{"slug":"fleet"}"#,
            r#"{"id":"12345"}"#,
            r#"{"id":-1}"#,
            "not json",
        ] {
            let fake = fake(vec![Script::Reply(http("200 OK", "", body))]).await;
            let err = client(&fake)
                .app_id(&AppJwt::from_text(JWT))
                .await
                .unwrap_err();
            assert_eq!(err, MintError::Malformed, "{body}");
        }
    }
}
