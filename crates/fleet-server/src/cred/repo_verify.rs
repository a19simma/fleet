//! Repository verification (ADR-0059).
//!
//! The closed [`RepoRefusal`] set, the [`RepoVerifier`] seam, the GitHub verifier and the
//! [`RepoVerifiers`] registry that picks a verifier by the operator host list and applies
//! [`REPO_CHECK_BUDGET`].
//!
//! No log line or refusal carries an upstream body, a resolved address or a credential. A
//! credential prints as `[REDACTED]`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use fleet_core::credential::Secret;
use fleet_core::repo::{ForgeKind, RepoRef, RepoVerdict};
use fleet_proto::{
    CALL_BUDGET, PRECONDITION_REPO_NO_CREDENTIAL, PRECONDITION_REPO_NOT_ALLOWED_HOST,
    PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS, PRECONDITION_REPO_TIMEOUT,
    PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
};
use hyper::StatusCode;

use super::https::{ForgeGet, ForgeTransport, bearer_header};
use super::store::{CredentialStore, ProbeLease, ProbeTarget, StoreError};
use crate::config::{Forge, HostConfig, RepoHosts};

/// The whole repository check, from host lookup to verdict. It sits under
/// [`fleet_proto::CALL_BUDGET`] so the server answers before the client's deadline.
pub const REPO_CHECK_BUDGET: Duration = Duration::from_secs(7);

const _: () = assert!(REPO_CHECK_BUDGET.as_millis() < CALL_BUDGET.as_millis());

const GITHUB_API_HOST: &str = "api.github.com";

/// Why a repository check gave no verdict. The set is closed and maps one-to-one to the
/// `PRECONDITION_REPO_*` reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepoRefusal {
    /// The host is outside the operator list, or no verifier serves it.
    NotAllowedHost,
    /// The User holds no credential for the host.
    NoCredential,
    /// The forge answered 401, 403 or 404, or an allowlist refused the probe.
    NotFoundOrNoAccess,
    /// The forge could not be reached, was refused by address vetting, or answered unusably.
    UpstreamUnavailable,
    /// The check outlasted [`REPO_CHECK_BUDGET`].
    Timeout,
}

impl RepoRefusal {
    /// Every refusal, in wire order.
    pub const ALL: [Self; 5] = [
        Self::NotAllowedHost,
        Self::NoCredential,
        Self::NotFoundOrNoAccess,
        Self::UpstreamUnavailable,
        Self::Timeout,
    ];

    /// The fixed `FAILED_PRECONDITION` message for this refusal.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NotAllowedHost => PRECONDITION_REPO_NOT_ALLOWED_HOST,
            Self::NoCredential => PRECONDITION_REPO_NO_CREDENTIAL,
            Self::NotFoundOrNoAccess => PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS,
            Self::UpstreamUnavailable => PRECONDITION_REPO_UPSTREAM_UNAVAILABLE,
            Self::Timeout => PRECONDITION_REPO_TIMEOUT,
        }
    }
}

impl std::fmt::Display for RepoRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for RepoRefusal {}

/// The User's credential for one host, already chosen by the exact `(user, host)` pair.
pub enum RepoCredential {
    /// A personal access token.
    Pat(Secret),
    /// A GitHub App installation: each check mints a probe token and revokes it.
    App {
        /// The owning User.
        user_id: i64,
        /// The stored credential row.
        credential_id: i64,
        /// The unsealed installation id.
        installation: Secret,
    },
}

impl std::fmt::Debug for RepoCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pat(_) => f.write_str("RepoCredential::Pat([REDACTED])"),
            Self::App { .. } => f.write_str("RepoCredential::App([REDACTED])"),
        }
    }
}

/// Checks one repository against one forge.
#[tonic::async_trait]
pub trait RepoVerifier: Send + Sync {
    /// Asks the forge what `credential` can do with `repo`. `host` is the operator entry for
    /// `repo.host()`. A `None` credential is [`RepoRefusal::NoCredential`].
    ///
    /// # Errors
    ///
    /// Returns the [`RepoRefusal`] that names why no verdict exists.
    async fn verify(
        &self,
        host: &HostConfig,
        credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal>;
}

/// A probe-scope token held for one call. Dropping it revokes the token.
#[tonic::async_trait]
pub trait ProbeToken: Send {
    /// The token text.
    fn token(&self) -> Option<&str>;

    /// Revokes the token. A failed revoke is logged by the implementation.
    async fn finish(self: Box<Self>);
}

/// Mints probe-scope tokens for a `github_app` credential.
#[tonic::async_trait]
pub trait ProbeMint: Send + Sync {
    /// Mints a read-only token for `repo`.
    ///
    /// # Errors
    ///
    /// Returns the [`RepoRefusal`] that names why no token was minted.
    async fn mint(
        &self,
        user_id: i64,
        credential_id: i64,
        installation: &Secret,
        repo: &RepoRef,
    ) -> Result<Box<dyn ProbeToken>, RepoRefusal>;
}

#[tonic::async_trait]
impl ProbeToken for ProbeLease {
    fn token(&self) -> Option<&str> {
        Self::token(self)
    }

    async fn finish(self: Box<Self>) {
        if !Self::finish(*self).await {
            tracing::warn!("probe token revoke failed");
        }
    }
}

/// The refusal a failed probe mint maps to.
pub fn refusal_of(err: &StoreError) -> RepoRefusal {
    match err {
        StoreError::CapabilityDenied
        | StoreError::NotFound
        | StoreError::Tombstoned
        | StoreError::Expired => RepoRefusal::NoCredential,
        StoreError::InstallationDenied | StoreError::RepoDenied => RepoRefusal::NotFoundOrNoAccess,
        _ => RepoRefusal::UpstreamUnavailable,
    }
}

#[tonic::async_trait]
impl ProbeMint for CredentialStore {
    async fn mint(
        &self,
        user_id: i64,
        credential_id: i64,
        installation: &Secret,
        repo: &RepoRef,
    ) -> Result<Box<dyn ProbeToken>, RepoRefusal> {
        let target = format!("https://{}/{}", repo.host(), repo.display_path());
        let lease = self
            .probe_lease(
                user_id,
                credential_id,
                installation,
                ProbeTarget::Repo(&target),
            )
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "repository probe mint failed");
                refusal_of(&err)
            })?;
        Ok(Box::new(lease))
    }
}

fn api_parts(api_base: &str) -> Option<(&str, String)> {
    let rest = api_base.strip_prefix("https://")?;
    let (host, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = path.trim_end_matches('/');
    let prefix = if path.is_empty() {
        String::new()
    } else {
        format!("/{path}")
    };
    Some((host, prefix))
}

/// The GitHub verifier: `GET /repos/{owner}/{repo}`.
pub struct GithubVerifier {
    transport: Arc<dyn ForgeTransport>,
    minter: Option<Arc<dyn ProbeMint>>,
}

impl std::fmt::Debug for GithubVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GithubVerifier(..)")
    }
}

impl GithubVerifier {
    /// A verifier over `transport`. Without `minter`, a `github_app` credential is
    /// [`RepoRefusal::UpstreamUnavailable`].
    pub fn new(transport: Arc<dyn ForgeTransport>, minter: Option<Arc<dyn ProbeMint>>) -> Self {
        Self { transport, minter }
    }

    async fn lookup(
        &self,
        host: &HostConfig,
        token: &[u8],
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        let (api_host, prefix) =
            api_parts(&host.api_base).ok_or(RepoRefusal::UpstreamUnavailable)?;
        let authorization = bearer_header(token).ok_or(RepoRefusal::UpstreamUnavailable)?;
        let path = format!("{prefix}/repos/{}", repo.path());
        let reply = self
            .transport
            .get(&ForgeGet {
                host: api_host,
                path: &path,
                allow_private: host.allow_private,
                authorization: Some(&authorization),
                accept: "application/json",
            })
            .await
            .map_err(|err| {
                tracing::warn!(host = %repo.host(), error = %err, "repository lookup failed");
                RepoRefusal::UpstreamUnavailable
            })?;
        match reply.status {
            StatusCode::OK => verdict_of(&reply.body, repo.host()),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                Err(RepoRefusal::NotFoundOrNoAccess)
            }
            status => {
                tracing::warn!(host = %repo.host(), status = status.as_u16(), "repository lookup refused");
                Err(RepoRefusal::UpstreamUnavailable)
            }
        }
    }
}

fn verdict_of(body: &[u8], host: &str) -> Result<RepoVerdict, RepoRefusal> {
    let unusable = || {
        tracing::warn!("repository reply is unusable");
        RepoRefusal::UpstreamUnavailable
    };
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| unusable())?;
    let full_name = value
        .get("full_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(unusable)?;
    let canonical = RepoRef::parse_as(&format!("{host}/{full_name}"), ForgeKind::Github)
        .map_err(|_| unusable())?;
    let permissions = value.get("permissions");
    let flag = |name: &str| {
        permissions
            .and_then(|p| p.get(name))
            .and_then(serde_json::Value::as_bool)
    };
    Ok(RepoVerdict {
        canonical_path: canonical.path().to_owned(),
        read: flag("pull").unwrap_or(true),
        push: flag("push"),
        login: None,
    })
}

#[tonic::async_trait]
impl RepoVerifier for GithubVerifier {
    async fn verify(
        &self,
        host: &HostConfig,
        credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        match credential {
            None => Err(RepoRefusal::NoCredential),
            Some(RepoCredential::Pat(secret)) => self.lookup(host, secret.expose(), repo).await,
            Some(RepoCredential::App {
                user_id,
                credential_id,
                installation,
            }) => {
                if api_parts(&host.api_base).map(|(h, _)| h) != Some(GITHUB_API_HOST) {
                    return Err(RepoRefusal::NoCredential);
                }
                let minter = self
                    .minter
                    .as_ref()
                    .ok_or(RepoRefusal::UpstreamUnavailable)?;
                let lease = minter
                    .mint(*user_id, *credential_id, installation, repo)
                    .await?;
                let outcome = match lease.token() {
                    Some(token) => self.lookup(host, token.as_bytes(), repo).await,
                    None => Err(RepoRefusal::UpstreamUnavailable),
                };
                lease.finish().await;
                outcome
            }
        }
    }
}

/// Picks the verifier for a repository by the operator host list and applies the total budget.
pub struct RepoVerifiers {
    hosts: RepoHosts,
    by_forge: HashMap<ForgeId, Arc<dyn RepoVerifier>>,
    budget: Duration,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ForgeId {
    Github,
    Forgejo,
}

fn forge_id(forge: Forge) -> ForgeId {
    match forge {
        Forge::Github => ForgeId::Github,
        Forge::Forgejo => ForgeId::Forgejo,
    }
}

impl std::fmt::Debug for RepoVerifiers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepoVerifiers(..)")
    }
}

impl RepoVerifiers {
    /// A registry over `hosts` with no verifier and [`REPO_CHECK_BUDGET`].
    pub fn new(hosts: RepoHosts) -> Self {
        Self {
            hosts,
            by_forge: HashMap::new(),
            budget: REPO_CHECK_BUDGET,
        }
    }

    /// Serves hosts of `forge` with `verifier`.
    #[must_use]
    pub fn with(mut self, forge: Forge, verifier: Arc<dyn RepoVerifier>) -> Self {
        self.by_forge.insert(forge_id(forge), verifier);
        self
    }

    /// Replaces the total budget. Tests shrink it.
    #[must_use]
    pub fn with_budget(mut self, budget: Duration) -> Self {
        self.budget = budget;
        self
    }

    /// The grammar to parse a repository input of a configured host with, or `None` when the
    /// host is not listed. Callers use it with [`RepoRef::parse_as`].
    pub fn kind_of(&self, host: &str) -> Option<ForgeKind> {
        Some(match self.hosts.lookup(host)?.forge {
            Forge::Github => ForgeKind::Github,
            Forge::Forgejo => ForgeKind::Forgejo,
        })
    }

    /// Verifies `repo` for `credential`. The host is matched against the operator list before
    /// any lookup, and the whole call fits the budget.
    ///
    /// # Errors
    ///
    /// Returns [`RepoRefusal::NotAllowedHost`] for a host outside the list or with no verifier
    /// and [`RepoRefusal::Timeout`] when the budget runs out, else the verifier's refusal.
    pub async fn verify(
        &self,
        credential: Option<&RepoCredential>,
        repo: &RepoRef,
    ) -> Result<RepoVerdict, RepoRefusal> {
        let host = self
            .hosts
            .lookup(repo.host())
            .ok_or(RepoRefusal::NotAllowedHost)?;
        let verifier = self
            .by_forge
            .get(&forge_id(host.forge))
            .ok_or(RepoRefusal::NotAllowedHost)?;
        tokio::time::timeout(self.budget, verifier.verify(host, credential, repo))
            .await
            .unwrap_or(Err(RepoRefusal::Timeout))
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::Mutex;

    use fleet_proto::classify;
    use hyper::header::HeaderValue;
    use tonic::Code;

    use super::*;
    use crate::cred::https::{FetchError, ForgeReply};
    use crate::cred::repo_fake::FakeVerifier;

    const TOKEN: &str = "ghp_secretsecretsecret0123456789";
    const MINTED: &str = "ghs_minted0123456789abcdef";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Seen {
        host: String,
        path: String,
        allow_private: bool,
        authorization: String,
        sensitive: bool,
    }

    struct Script {
        reply: Result<ForgeReply, FetchError>,
        seen: Mutex<Vec<Seen>>,
    }

    impl Script {
        fn new(reply: Result<ForgeReply, FetchError>) -> Arc<Self> {
            Arc::new(Self {
                reply,
                seen: Mutex::new(Vec::new()),
            })
        }

        fn status(status: u16, body: &str) -> Arc<Self> {
            Self::new(Ok(ForgeReply {
                status: StatusCode::from_u16(status).unwrap(),
                body: body.as_bytes().to_vec(),
                location: None,
            }))
        }

        fn calls(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[tonic::async_trait]
    impl ForgeTransport for Script {
        async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
            self.seen.lock().unwrap().push(Seen {
                host: request.host.to_owned(),
                path: request.path.to_owned(),
                allow_private: request.allow_private,
                authorization: request.authorization.map_or_else(String::new, |value| {
                    String::from_utf8_lossy(value.as_bytes()).into_owned()
                }),
                sensitive: request.authorization.is_some_and(HeaderValue::is_sensitive),
            });
            self.reply.clone()
        }
    }

    struct Mint {
        outcome: Result<(), RepoRefusal>,
        minted: Mutex<Vec<(i64, i64, String)>>,
        finished: Arc<Mutex<usize>>,
    }

    struct Lease(Arc<Mutex<usize>>);

    #[tonic::async_trait]
    impl ProbeToken for Lease {
        fn token(&self) -> Option<&str> {
            Some(MINTED)
        }

        async fn finish(self: Box<Self>) {
            *self.0.lock().unwrap() += 1;
        }
    }

    #[tonic::async_trait]
    impl ProbeMint for Mint {
        async fn mint(
            &self,
            user_id: i64,
            credential_id: i64,
            _installation: &Secret,
            repo: &RepoRef,
        ) -> Result<Box<dyn ProbeToken>, RepoRefusal> {
            self.minted
                .lock()
                .unwrap()
                .push((user_id, credential_id, repo.path().to_owned()));
            self.outcome?;
            Ok(Box::new(Lease(Arc::clone(&self.finished))))
        }
    }

    fn mint(outcome: Result<(), RepoRefusal>) -> Arc<Mint> {
        Arc::new(Mint {
            outcome,
            minted: Mutex::new(Vec::new()),
            finished: Arc::new(Mutex::new(0)),
        })
    }

    fn github_host() -> HostConfig {
        RepoHosts::default().lookup("github.com").unwrap().clone()
    }

    fn repo(input: &str) -> RepoRef {
        RepoRef::parse_as(input, ForgeKind::Github).unwrap()
    }

    fn pat() -> RepoCredential {
        RepoCredential::Pat(Secret::new(TOKEN.to_owned()))
    }

    fn app() -> RepoCredential {
        RepoCredential::App {
            user_id: 7,
            credential_id: 9,
            installation: Secret::new("4242".to_owned()),
        }
    }

    async fn check(
        script: &Arc<Script>,
        credential: Option<&RepoCredential>,
    ) -> Result<RepoVerdict, RepoRefusal> {
        let verifier = GithubVerifier::new(script.clone(), None);
        verifier
            .verify(&github_host(), credential, &repo("github.com/Acme/Widget"))
            .await
    }

    #[test]
    fn refusals_map_one_to_one_to_the_five_wire_reasons() {
        let mut seen = std::collections::HashSet::new();
        for refusal in RepoRefusal::ALL {
            let reason = refusal.reason();
            assert!(seen.insert(reason), "{reason}");
            assert!(
                classify(Code::FailedPrecondition, reason).is_some(),
                "{reason}"
            );
            assert_eq!(refusal.to_string(), reason);
        }
        assert_eq!(seen.len(), 5);
        assert_eq!(
            RepoRefusal::NotAllowedHost.reason(),
            PRECONDITION_REPO_NOT_ALLOWED_HOST
        );
        assert_eq!(
            RepoRefusal::NoCredential.reason(),
            PRECONDITION_REPO_NO_CREDENTIAL
        );
        assert_eq!(
            RepoRefusal::NotFoundOrNoAccess.reason(),
            PRECONDITION_REPO_NOT_FOUND_OR_NO_ACCESS
        );
        assert_eq!(
            RepoRefusal::UpstreamUnavailable.reason(),
            PRECONDITION_REPO_UPSTREAM_UNAVAILABLE
        );
        assert_eq!(RepoRefusal::Timeout.reason(), PRECONDITION_REPO_TIMEOUT);
    }

    #[test]
    fn the_budget_is_seven_seconds_under_the_call_budget() {
        assert_eq!(REPO_CHECK_BUDGET, Duration::from_secs(7));
        assert!(REPO_CHECK_BUDGET < CALL_BUDGET);
    }

    #[test]
    fn api_bases_split_into_host_and_prefix() {
        assert_eq!(
            api_parts("https://api.github.com"),
            Some(("api.github.com", String::new()))
        );
        assert_eq!(
            api_parts("https://ghe.example/api/v3"),
            Some(("ghe.example", "/api/v3".to_owned()))
        );
        assert_eq!(
            api_parts("https://ghe.example/api/v3/"),
            Some(("ghe.example", "/api/v3".to_owned()))
        );
        assert_eq!(api_parts("http://ghe.example"), None);
        assert_eq!(api_parts("ghe.example"), None);
    }

    #[test]
    fn probe_mint_failures_map_to_closed_refusals() {
        for (err, want) in [
            (StoreError::CapabilityDenied, RepoRefusal::NoCredential),
            (StoreError::NotFound, RepoRefusal::NoCredential),
            (StoreError::Tombstoned, RepoRefusal::NoCredential),
            (StoreError::Expired, RepoRefusal::NoCredential),
            (
                StoreError::InstallationDenied,
                RepoRefusal::NotFoundOrNoAccess,
            ),
            (StoreError::RepoDenied, RepoRefusal::NotFoundOrNoAccess),
            (StoreError::MintFailed, RepoRefusal::UpstreamUnavailable),
            (
                StoreError::MintRateLimited,
                RepoRefusal::UpstreamUnavailable,
            ),
            (StoreError::MintCapReached, RepoRefusal::UpstreamUnavailable),
            (StoreError::NoJobRepo, RepoRefusal::UpstreamUnavailable),
            (
                StoreError::Db(sqlx::Error::PoolClosed),
                RepoRefusal::UpstreamUnavailable,
            ),
        ] {
            assert_eq!(refusal_of(&err), want, "{err}");
        }
    }

    #[tokio::test]
    async fn a_pat_check_sends_the_exact_request_and_reads_the_verdict() {
        let script = Script::status(
            200,
            r#"{"full_name":"Acme/Widget","permissions":{"admin":false,"push":true,"pull":true}}"#,
        );
        let verdict = check(&script, Some(&pat())).await.unwrap();
        assert_eq!(
            verdict,
            RepoVerdict {
                canonical_path: "acme/widget".to_owned(),
                read: true,
                push: Some(true),
                login: None,
            }
        );
        assert_eq!(
            script.calls(),
            [Seen {
                host: "api.github.com".to_owned(),
                path: "/repos/acme/widget".to_owned(),
                allow_private: false,
                authorization: format!("Bearer {TOKEN}"),
                sensitive: true,
            }]
        );
    }

    #[tokio::test]
    async fn push_comes_from_permissions_only_when_reported() {
        for (body, push, read) in [
            (
                r#"{"full_name":"a/b","permissions":{"push":false,"pull":true}}"#,
                Some(false),
                true,
            ),
            (
                r#"{"full_name":"a/b","permissions":{"push":true}}"#,
                Some(true),
                true,
            ),
            (
                r#"{"full_name":"a/b","permissions":{"pull":true}}"#,
                None,
                true,
            ),
            (r#"{"full_name":"a/b","permissions":{}}"#, None, true),
            (r#"{"full_name":"a/b"}"#, None, true),
            (r#"{"full_name":"a/b","permissions":null}"#, None, true),
            (
                r#"{"full_name":"a/b","permissions":{"push":"yes"}}"#,
                None,
                true,
            ),
            (
                r#"{"full_name":"a/b","permissions":{"push":false,"pull":false}}"#,
                Some(false),
                false,
            ),
        ] {
            let verdict = check(&Script::status(200, body), Some(&pat()))
                .await
                .unwrap();
            assert_eq!((verdict.push, verdict.read), (push, read), "{body}");
        }
    }

    #[tokio::test]
    async fn a_renamed_repository_reports_the_new_canonical_path() {
        let script = Script::status(
            200,
            r#"{"full_name":"Acme/Gadget","permissions":{"push":true}}"#,
        );
        let verdict = check(&script, Some(&pat())).await.unwrap();
        assert_eq!(verdict.canonical_path, "acme/gadget");
        assert_eq!(
            script.calls().first().map(|c| c.path.as_str()),
            Some("/repos/acme/widget")
        );
    }

    #[tokio::test]
    async fn an_unusable_200_body_is_unavailable() {
        for body in [
            "",
            "nope",
            "null",
            "[]",
            "{}",
            r#"{"full_name":1}"#,
            r#"{"full_name":""}"#,
            r#"{"full_name":"a"}"#,
            r#"{"full_name":"a/b/c"}"#,
            r#"{"full_name":"../etc"}"#,
            r#"{"full_name":"a/b?x=1"}"#,
            r#"{"full_name":"a/b\r\nX: y"}"#,
            r#"{"full_name":"a b/c"}"#,
            r#"{"full_name":"https://evil.test/a/b"}"#,
            r#"{"full_name":"acme/widget","permissions":{"push":true}"#,
        ] {
            assert_eq!(
                check(&Script::status(200, body), Some(&pat())).await,
                Err(RepoRefusal::UpstreamUnavailable),
                "{body}"
            );
        }
    }

    #[tokio::test]
    async fn statuses_collapse_to_the_closed_set() {
        let ok = r#"{"full_name":"acme/widget"}"#;
        for status in [401, 403, 404] {
            assert_eq!(
                check(&Script::status(status, ok), Some(&pat())).await,
                Err(RepoRefusal::NotFoundOrNoAccess),
                "{status}"
            );
        }
        for status in [
            201, 204, 301, 302, 303, 307, 308, 400, 410, 422, 429, 500, 502, 503,
        ] {
            assert_eq!(
                check(&Script::status(status, ok), Some(&pat())).await,
                Err(RepoRefusal::UpstreamUnavailable),
                "{status}"
            );
        }
    }

    #[tokio::test]
    async fn a_transport_failure_of_any_kind_is_unavailable() {
        for err in [
            FetchError::Blocked,
            FetchError::Unavailable,
            FetchError::TooLarge,
        ] {
            assert_eq!(
                check(&Script::new(Err(err)), Some(&pat())).await,
                Err(RepoRefusal::UpstreamUnavailable),
                "{err}"
            );
        }
    }

    #[tokio::test]
    async fn no_credential_asks_nothing() {
        let script = Script::status(200, r#"{"full_name":"acme/widget"}"#);
        assert_eq!(check(&script, None).await, Err(RepoRefusal::NoCredential));
        assert_eq!(script.calls().len(), 0);
    }

    #[tokio::test]
    async fn the_host_entry_decides_the_api_host_path_and_private_flag() {
        let hosts = RepoHosts::parse(
            "host=ghe.example,forge=github,api=https://ghe.example/api/v3,allow_private=true",
        )
        .unwrap();
        let host = hosts.lookup("ghe.example").unwrap();
        let script = Script::status(200, r#"{"full_name":"acme/widget"}"#);
        let verifier = GithubVerifier::new(script.clone(), None);
        verifier
            .verify(host, Some(&pat()), &repo("ghe.example/acme/widget"))
            .await
            .unwrap();
        let seen = script.calls();
        assert_eq!(seen.first().map(|c| c.host.as_str()), Some("ghe.example"));
        assert_eq!(
            seen.first().map(|c| c.path.as_str()),
            Some("/api/v3/repos/acme/widget")
        );
        assert_eq!(seen.first().map(|c| c.allow_private), Some(true));
    }

    #[tokio::test]
    async fn an_app_credential_mints_a_probe_token_uses_it_and_always_finishes() {
        let script = Script::status(
            200,
            r#"{"full_name":"acme/widget","permissions":{"push":false}}"#,
        );
        let minter = mint(Ok(()));
        let verifier = GithubVerifier::new(script.clone(), Some(minter.clone()));
        let verdict = verifier
            .verify(
                &github_host(),
                Some(&app()),
                &repo("github.com/acme/widget"),
            )
            .await
            .unwrap();
        assert_eq!(verdict.push, Some(false));
        assert_eq!(
            *minter.minted.lock().unwrap(),
            [(7, 9, "acme/widget".to_owned())]
        );
        assert_eq!(
            script.calls().first().map(|c| c.authorization.clone()),
            Some(format!("Bearer {MINTED}"))
        );
        assert_eq!(*minter.finished.lock().unwrap(), 1);

        let failing = Script::status(404, "{}");
        let minter = mint(Ok(()));
        let verifier = GithubVerifier::new(failing, Some(minter.clone()));
        let got = verifier
            .verify(
                &github_host(),
                Some(&app()),
                &repo("github.com/acme/widget"),
            )
            .await;
        assert_eq!(got, Err(RepoRefusal::NotFoundOrNoAccess));
        assert_eq!(*minter.finished.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn a_refused_mint_asks_the_forge_nothing() {
        for refusal in RepoRefusal::ALL {
            let script = Script::status(200, r#"{"full_name":"acme/widget"}"#);
            let verifier = GithubVerifier::new(script.clone(), Some(mint(Err(refusal))));
            let got = verifier
                .verify(
                    &github_host(),
                    Some(&app()),
                    &repo("github.com/acme/widget"),
                )
                .await;
            assert_eq!(got, Err(refusal));
            assert_eq!(script.calls().len(), 0);
        }
    }

    #[tokio::test]
    async fn an_app_credential_without_a_minter_or_off_github_com_never_mints() {
        let script = Script::status(200, r#"{"full_name":"acme/widget"}"#);
        let verifier = GithubVerifier::new(script.clone(), None);
        assert_eq!(
            verifier
                .verify(
                    &github_host(),
                    Some(&app()),
                    &repo("github.com/acme/widget")
                )
                .await,
            Err(RepoRefusal::UpstreamUnavailable)
        );
        let minter = mint(Ok(()));
        let verifier = GithubVerifier::new(script.clone(), Some(minter.clone()));
        let hosts =
            RepoHosts::parse("host=ghe.example,forge=github,api=https://ghe.example/api/v3")
                .unwrap();
        assert_eq!(
            verifier
                .verify(
                    hosts.lookup("ghe.example").unwrap(),
                    Some(&app()),
                    &repo("ghe.example/acme/widget"),
                )
                .await,
            Err(RepoRefusal::NoCredential)
        );
        assert!(minter.minted.lock().unwrap().is_empty());
        assert_eq!(script.calls().len(), 0);
    }

    #[test]
    fn credentials_print_redacted() {
        for credential in [pat(), app()] {
            let text = format!("{credential:?}");
            assert!(text.contains("REDACTED"), "{text}");
            assert!(!text.contains(TOKEN) && !text.contains("4242"), "{text}");
        }
        let header = HeaderValue::from_static("x");
        assert!(
            !format!(
                "{:?}",
                ForgeGet {
                    host: "h",
                    path: "/",
                    allow_private: false,
                    authorization: Some(&header),
                    accept: "application/json",
                }
            )
            .contains("Bearer")
        );
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Capture {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if let Ok(mut sink) = self.0.lock() {
                sink.extend_from_slice(buf);
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn neither_the_token_nor_the_upstream_body_reaches_the_logs_or_the_error() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_max_level(tracing::Level::TRACE)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let filler = "x".repeat(crate::cred::pinned::MAX_BODY_BYTES - TOKEN.len() / 2);
        let straddling = format!("{filler}{TOKEN}");
        let hostile = format!("{{\"message\":\"{TOKEN} {MINTED}\",\"full_name\":\"a\"}}");
        let mut results = Vec::new();
        for reply in [
            Script::status(500, &hostile),
            Script::status(200, &hostile),
            Script::status(200, &straddling),
            Script::status(404, &hostile),
            Script::new(Err(FetchError::TooLarge)),
        ] {
            results.push(format!("{:?}", check(&reply, Some(&pat())).await));
        }
        let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert_ne!(logs.len(), 0);
        for text in results.iter().chain(std::iter::once(&logs)) {
            assert!(!text.contains(TOKEN), "{text}");
            assert!(!text.contains(&TOKEN[..12]), "{text}");
            assert!(!text.contains(MINTED), "{text}");
        }
    }

    fn registry(fake: FakeVerifier) -> (RepoVerifiers, Arc<FakeVerifier>) {
        let fake = Arc::new(fake);
        let registry = RepoVerifiers::new(
            RepoHosts::parse(
                "host=github.com,forge=github,api=https://api.github.com;host=forge.example,forge=forgejo,api=https://forge.example",
            )
            .unwrap(),
        )
        .with(Forge::Github, fake.clone());
        (registry, fake)
    }

    #[tokio::test]
    async fn the_registry_refuses_unlisted_and_unserved_hosts_before_any_call() {
        let (registry, fake) = registry(FakeVerifier::ok("acme/widget", Some(true)));
        for input in [
            "evil.example/acme/widget",
            "api.github.com/acme/widget",
            "github.com.evil.example/acme/widget",
            "forge.example/acme/widget",
        ] {
            let parsed = RepoRef::parse_as(input, ForgeKind::Forgejo).unwrap();
            assert_eq!(
                registry.verify(Some(&pat()), &parsed).await,
                Err(RepoRefusal::NotAllowedHost),
                "{input}"
            );
        }
        assert_eq!(fake.calls(), 0);
        let none = RepoVerifiers::new(RepoHosts::none());
        assert_eq!(
            none.verify(Some(&pat()), &repo("github.com/acme/widget"))
                .await,
            Err(RepoRefusal::NotAllowedHost)
        );
    }

    #[tokio::test]
    async fn the_registry_reports_every_fake_state() {
        let target = repo("github.com/acme/widget");
        let cases: Vec<(FakeVerifier, Result<RepoVerdict, RepoRefusal>)> = vec![
            (
                FakeVerifier::ok("acme/widget", Some(true)),
                Ok(RepoVerdict {
                    canonical_path: "acme/widget".to_owned(),
                    read: true,
                    push: Some(true),
                    login: None,
                }),
            ),
            (
                FakeVerifier::ok("acme/widget", Some(false)),
                Ok(RepoVerdict {
                    canonical_path: "acme/widget".to_owned(),
                    read: true,
                    push: Some(false),
                    login: None,
                }),
            ),
            (
                FakeVerifier::ok("acme/widget", None),
                Ok(RepoVerdict {
                    canonical_path: "acme/widget".to_owned(),
                    read: true,
                    push: None,
                    login: None,
                }),
            ),
            (
                FakeVerifier::moved("acme/gadget"),
                Ok(RepoVerdict {
                    canonical_path: "acme/gadget".to_owned(),
                    read: true,
                    push: Some(true),
                    login: None,
                }),
            ),
            (
                FakeVerifier::not_allowed_host(),
                Err(RepoRefusal::NotAllowedHost),
            ),
            (
                FakeVerifier::no_credential(),
                Err(RepoRefusal::NoCredential),
            ),
            (
                FakeVerifier::not_found_or_no_access(),
                Err(RepoRefusal::NotFoundOrNoAccess),
            ),
            (
                FakeVerifier::upstream_unavailable(),
                Err(RepoRefusal::UpstreamUnavailable),
            ),
            (FakeVerifier::timed_out(), Err(RepoRefusal::Timeout)),
        ];
        for (fake, want) in cases {
            let (registry, _) = registry(fake);
            assert_eq!(registry.verify(Some(&pat()), &target).await, want);
        }
        let (registry, fake) = registry(FakeVerifier::ok("acme/widget", Some(true)));
        assert_eq!(
            registry.verify(None, &target).await,
            Err(RepoRefusal::NoCredential)
        );
        assert_eq!(fake.calls(), 1);
    }

    #[tokio::test]
    async fn a_hanging_verifier_ends_in_timeout_at_the_budget() {
        let (registry, _) = registry(FakeVerifier::hanging());
        let registry = registry.with_budget(Duration::from_millis(50));
        let started = std::time::Instant::now();
        let got = registry
            .verify(Some(&pat()), &repo("github.com/acme/widget"))
            .await;
        assert_eq!(got, Err(RepoRefusal::Timeout));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn a_verifier_inside_the_budget_is_not_cut_off() {
        let (registry, _) = registry(FakeVerifier::ok("acme/widget", None));
        let registry = registry.with_budget(Duration::from_secs(5));
        assert!(
            registry
                .verify(Some(&pat()), &repo("github.com/acme/widget"))
                .await
                .is_ok()
        );
    }

    #[test]
    fn the_registry_names_the_grammar_of_listed_hosts() {
        let (registry, _) = registry(FakeVerifier::hanging());
        assert_eq!(registry.kind_of("github.com"), Some(ForgeKind::Github));
        assert_eq!(registry.kind_of("forge.example"), Some(ForgeKind::Forgejo));
        assert_eq!(registry.kind_of("evil.example"), None);
        assert_eq!(registry.kind_of("api.github.com"), None);
    }
}
