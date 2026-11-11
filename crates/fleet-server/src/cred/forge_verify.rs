//! Repository verification through [`fleet_forge::ForgeApi::verify`] (ADR-0068).
//!
//! [`ForgeHttp`] is the [`Http`] seam over a [`ForgeTransport`], so every request leaves through
//! the pinned connector: the vetted address only, no redirect, a capped body. A [`HostDirectory`]
//! answers from `git_hosts`, which decides the forge kind and the private-address flags of a
//! host. [`ForgejoVerifier`] calls the Gitea adapter only for a row of kind `forgejo`.
//!
//! No refusal carries an upstream body, a resolved address or a credential.

use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;

use fleet_core::host::HostName;
use fleet_core::repo::{ForgeKind, RepoRef, RepoVerdict};
use fleet_forge::{
    Credential, ForgeApi, ForgeError, GiteaForge, Http, HttpError, HttpRequest, HttpResponse,
    Method, Permission, RepoAccess, Token, Verified,
};
use hyper::header::HeaderValue;
use sqlx::{PgPool, Row};

use super::https::{FetchError, ForgeGet, ForgeTransport};
use super::repo_verify::{RepoCredential, RepoRefusal, RepoVerifier};
use crate::config::HostConfig;

const DEFAULT_ACCEPT: &str = "application/json";

const SELECT_HOST: &str = "\
SELECT kind, allow_private, \
ARRAY(SELECT host(a) FROM unnest(approved_ips) AS a)::text[] AS approved_ips \
FROM git_hosts WHERE host = $1";

/// What `git_hosts` holds about one host that a check needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHost {
    /// The forge kind of the row.
    pub kind: ForgeKind,
    /// Whether an admin approved private addresses for the host.
    pub allow_private: bool,
    /// The private addresses an admin approved.
    pub approved_ips: Vec<IpAddr>,
}

/// The source of host rows. Tests replace it with a fake.
#[tonic::async_trait]
pub trait HostDirectory: Send + Sync {
    /// The row of `host`, matched exactly, or `None` when the table has none.
    ///
    /// # Errors
    ///
    /// Returns [`RepoRefusal::UpstreamUnavailable`] when the table cannot be read.
    async fn find(&self, host: &str) -> Result<Option<GitHost>, RepoRefusal>;
}

/// The production [`HostDirectory`]: one `git_hosts` read per call, no cache.
#[derive(Clone)]
pub struct PgHostDirectory {
    pool: PgPool,
}

impl fmt::Debug for PgHostDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PgHostDirectory(..)")
    }
}

impl PgHostDirectory {
    /// A directory over `pool`.
    pub const fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

fn kind_of_row(name: &str) -> Option<ForgeKind> {
    match name {
        "github" => Some(ForgeKind::Github),
        "forgejo" => Some(ForgeKind::Forgejo),
        _ => None,
    }
}

#[tonic::async_trait]
impl HostDirectory for PgHostDirectory {
    async fn find(&self, host: &str) -> Result<Option<GitHost>, RepoRefusal> {
        let unavailable = |err: sqlx::Error| {
            tracing::warn!(error = %err, "git host lookup failed");
            RepoRefusal::UpstreamUnavailable
        };
        let Some(row) = sqlx::query(SELECT_HOST)
            .bind(host)
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?
        else {
            return Ok(None);
        };
        let name: String = row.try_get("kind").map_err(unavailable)?;
        let allow_private: bool = row.try_get("allow_private").map_err(unavailable)?;
        let addresses: Vec<String> = row.try_get("approved_ips").map_err(unavailable)?;
        let Some(kind) = kind_of_row(&name) else {
            return Ok(None);
        };
        let approved_ips = addresses
            .iter()
            .filter_map(|text| text.parse::<IpAddr>().ok())
            .collect();
        Ok(Some(GitHost {
            kind,
            allow_private,
            approved_ips,
        }))
    }
}

/// The [`Http`] seam over a [`ForgeTransport`] for one host's flags. It sends `GET` only and
/// refuses any other method, so nothing posts through the server's pinned connector.
pub struct ForgeHttp<'a> {
    transport: &'a dyn ForgeTransport,
    allow_private: bool,
    approved_ips: &'a [IpAddr],
}

impl fmt::Debug for ForgeHttp<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ForgeHttp(..)")
    }
}

impl<'a> ForgeHttp<'a> {
    /// A seam over `transport` with the host's private-address flags.
    pub const fn new(
        transport: &'a dyn ForgeTransport,
        allow_private: bool,
        approved_ips: &'a [IpAddr],
    ) -> Self {
        Self {
            transport,
            allow_private,
            approved_ips,
        }
    }
}

impl Http for ForgeHttp<'_> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        if request.method != Method::Get {
            return Err(HttpError::HostRefused);
        }
        let authorization = request
            .header("authorization")
            .map(|value| {
                HeaderValue::from_str(value).map(|mut header| {
                    header.set_sensitive(true);
                    header
                })
            })
            .transpose()
            .map_err(|_| HttpError::HostRefused)?;
        let reply = self
            .transport
            .get(&ForgeGet {
                host: request.host.as_str(),
                path: &request.path,
                allow_private: self.allow_private,
                approved_ips: self.approved_ips,
                authorization: authorization.as_ref(),
                accept: request.header("accept").unwrap_or(DEFAULT_ACCEPT),
            })
            .await
            .map_err(|error| match error {
                FetchError::Blocked => HttpError::HostRefused,
                FetchError::Unavailable => HttpError::Reset,
                FetchError::TooLarge => HttpError::BodyTooLarge,
            })?;
        Ok(HttpResponse {
            status: reply.status.as_u16(),
            headers: reply
                .location
                .map(|value| ("Location".to_owned(), value))
                .into_iter()
                .collect(),
            body: reply.body,
        })
    }
}

/// The refusal a [`ForgeError`] from `verify` maps to. The forge's answer to a hidden and to a
/// missing repository is one answer, and every other failure is an unusable forge.
pub(super) fn refusal_of(error: ForgeError) -> RepoRefusal {
    match error {
        ForgeError::NotFound | ForgeError::Unauthorized => RepoRefusal::NotFoundOrNoAccess,
        ForgeError::Timeout => RepoRefusal::Timeout,
        ForgeError::HostMismatch => RepoRefusal::NotAllowedHost,
        ForgeError::WrongKind
        | ForgeError::Unavailable
        | ForgeError::TooLarge
        | ForgeError::Redirected
        | ForgeError::Rejected
        | ForgeError::NonFastForward
        | ForgeError::Malformed => RepoRefusal::UpstreamUnavailable,
    }
}

fn forge_access(repo: &RepoRef, token: &[u8]) -> Result<RepoAccess, RepoRefusal> {
    let unusable = |_| RepoRefusal::UpstreamUnavailable;
    let host = HostName::normalise(repo.host()).map_err(unusable)?;
    let (owner, name) = repo
        .path()
        .split_once('/')
        .ok_or(RepoRefusal::UpstreamUnavailable)?;
    let forge_repo = fleet_forge::RepoRef::new(host.clone(), owner, name)
        .map_err(|_: ForgeError| RepoRefusal::UpstreamUnavailable)?;
    let text = String::from_utf8(token.to_vec()).map_err(|_| RepoRefusal::UpstreamUnavailable)?;
    let token = Token::new(text).map_err(|_: ForgeError| RepoRefusal::UpstreamUnavailable)?;
    Ok(RepoAccess::new(forge_repo, Credential::new(host, token)))
}

/// Runs `api.verify` for `repo` with `token` and maps the outcome to a verdict.
///
/// The canonical path is the requested one: the forge reports no other.
///
/// # Errors
///
/// Returns the [`RepoRefusal`] the failure maps to. The log line carries the host and the closed
/// error text only.
pub(super) async fn verify_with<A: ForgeApi>(
    api: &A,
    repo: &RepoRef,
    token: &[u8],
) -> Result<RepoVerdict, RepoRefusal> {
    let access = forge_access(repo, token)?;
    let Verified { push } = api.verify(&access).await.map_err(|error| {
        if error != ForgeError::NotFound && error != ForgeError::Unauthorized {
            tracing::warn!(host = %repo.host(), %error, "repository lookup refused");
        }
        refusal_of(error)
    })?;
    Ok(RepoVerdict {
        canonical_path: repo.path().to_owned(),
        read: true,
        push: match push {
            Permission::Granted => Some(true),
            Permission::Denied => Some(false),
            Permission::Unknown => None,
        },
        login: None,
    })
}

/// The Forgejo verifier: `GiteaForge::verify` over the pinned transport.
///
/// It uses the User's `forgejo_pat`. The host row decides: any host whose row is missing or not `forgejo` is
/// [`RepoRefusal::NotAllowedHost`] before a credential is read or a request leaves.
pub struct ForgejoVerifier {
    transport: Arc<dyn ForgeTransport>,
    hosts: Arc<dyn HostDirectory>,
}

impl fmt::Debug for ForgejoVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ForgejoVerifier(..)")
    }
}

impl ForgejoVerifier {
    /// A verifier that sends through `transport` and reads host rows from `hosts`.
    pub fn new(transport: Arc<dyn ForgeTransport>, hosts: Arc<dyn HostDirectory>) -> Self {
        Self { transport, hosts }
    }
}

#[tonic::async_trait]
impl RepoVerifier for ForgejoVerifier {
    async fn verify(
        &self,
        _host: &HostConfig,
        credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        let row = self
            .hosts
            .find(repo.host())
            .await?
            .ok_or(RepoRefusal::NotAllowedHost)?;
        if row.kind != ForgeKind::Forgejo {
            return Err(RepoRefusal::NotAllowedHost);
        }
        let Some(RepoCredential::Pat(secret)) = credential else {
            return Err(RepoRefusal::NoCredential);
        };
        let http = ForgeHttp::new(
            self.transport.as_ref(),
            row.allow_private,
            &row.approved_ips,
        );
        verify_with(&GiteaForge::new(http), repo, secret.expose()).await
    }
}
