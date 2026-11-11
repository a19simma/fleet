//! Host-kind dispatch for the broker: [`Forges::select`] picks the adapter of `fleet-forge` by
//! the kind the server sent for a host, and [`ApiChecks`] serves `pr_checks` through it.
//!
//! The adapters hold no token and no repo. A caller names the host and passes the credential
//! with every call, so a host without a [`HostPolicy`] has no adapter and gets
//! [`UnknownHost`]. [`Forges::for_host`] is the production form: it builds a [`PinnedHttp`] for
//! the host and refuses every git operation, because push, pull request creation and fetch of
//! the Job still run through `crate::publish` and the mirror.

use std::fmt;
use std::future::Future;
use std::net::IpAddr;

use fleet_core::forge::CiResult;
use fleet_core::host::{HostKind, HostName};
use fleet_forge::{
    CiCheck, ForgeApi, ForgeError, ForgeGit, Git, GitCommand, GitError, GitHubForge, GiteaForge,
    GiteaGit, Http, PushTarget, RepoAccess, RepoRef, Verified,
};

use crate::cred::HostEntry;

mod checks;
mod http;
mod job;
#[cfg(test)]
pub mod testing;

pub use checks::ApiChecks;
pub use http::PinnedHttp;
pub use job::JobForge;

/// The text of [`UnknownHost`]. It names no host and holds no client value.
pub const UNKNOWN_HOST: &str = "forge host not configured";

/// A host with no [`HostPolicy`], so no adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownHost;

impl fmt::Display for UnknownHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(UNKNOWN_HOST)
    }
}

impl std::error::Error for UnknownHost {}

/// What the server sent for one host: its kind and the private addresses an admin approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPolicy {
    host: HostName,
    kind: HostKind,
    approved: Vec<IpAddr>,
}

impl HostPolicy {
    /// A policy for `host` of `kind`, with `approved` as its allowed non-public addresses.
    #[must_use]
    pub const fn new(host: HostName, kind: HostKind, approved: Vec<IpAddr>) -> Self {
        Self {
            host,
            kind,
            approved,
        }
    }

    /// The policy of one credential-reply entry. `None` for the file-repo form, which has no host.
    #[must_use]
    pub fn from_entry(entry: &HostEntry) -> Option<Self> {
        let host = HostName::normalise(entry.host()?).ok()?;
        Some(Self::new(host, entry.kind(), entry.approved_ips().to_vec()))
    }
}

/// The repository a Job's `https://host/owner/repo[.git]` URL names. `None` for a file path, a
/// URL with userinfo, a port, a query or a fragment, or a name outside the grammar of
/// [`RepoRef::new`].
#[must_use]
pub fn repo_ref(url: &str) -> Option<RepoRef> {
    let rest = url.strip_prefix("https://")?;
    let mut parts = rest.split('/');
    let host = HostName::normalise(parts.next()?).ok()?;
    let owner = parts.next()?;
    let repo = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    RepoRef::new(host, owner, repo.strip_suffix(".git").unwrap_or(repo)).ok()
}

/// The git seam of the broker's adapters: it refuses every command.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoGit;

impl Git for NoGit {
    fn run(
        &self,
        _command: GitCommand,
    ) -> impl Future<Output = Result<fleet_forge::GitOutput, GitError>> + Send {
        std::future::ready(Err(GitError::Spawn))
    }
}

/// The adapter of one host, chosen by its kind.
pub enum HostApi<H, G> {
    /// `github.com`.
    Github(GitHubForge<H, G>),
    /// A Gitea or Forgejo host.
    Gitea(GiteaForge<H, GiteaGit<G>>),
}

impl<H, G> fmt::Debug for HostApi<H, G> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Github(_) => "HostApi::Github",
            Self::Gitea(_) => "HostApi::Gitea",
        })
    }
}

impl<H: Http, G: Send + Sync> ForgeApi for HostApi<H, G> {
    async fn identify(&self, host: &HostName) -> Result<HostKind, ForgeError> {
        match self {
            Self::Github(forge) => forge.identify(host).await,
            Self::Gitea(forge) => forge.identify(host).await,
        }
    }

    async fn verify(&self, access: &RepoAccess) -> Result<Verified, ForgeError> {
        match self {
            Self::Github(forge) => forge.verify(access).await,
            Self::Gitea(forge) => forge.verify(access).await,
        }
    }

    async fn create_pr(
        &self,
        target: &PushTarget,
        title: &str,
        body: &str,
    ) -> Result<String, ForgeError> {
        match self {
            Self::Github(forge) => forge.create_pr(target, title, body).await,
            Self::Gitea(forge) => forge.create_pr(target, title, body).await,
        }
    }

    async fn ci_result(&self, target: &PushTarget, pr_url: &str) -> Result<CiResult, ForgeError> {
        match self {
            Self::Github(forge) => forge.ci_result(target, pr_url).await,
            Self::Gitea(forge) => forge.ci_result(target, pr_url).await,
        }
    }

    async fn ci_checks(
        &self,
        target: &PushTarget,
        pr_url: &str,
    ) -> Result<Vec<CiCheck>, ForgeError> {
        match self {
            Self::Github(forge) => forge.ci_checks(target, pr_url).await,
            Self::Gitea(forge) => forge.ci_checks(target, pr_url).await,
        }
    }
}

impl<H: Send + Sync, G: Git> ForgeGit for HostApi<H, G> {
    async fn fetch(&self, access: &RepoAccess) -> Result<String, ForgeError> {
        match self {
            Self::Github(forge) => forge.fetch(access).await,
            Self::Gitea(forge) => forge.fetch(access).await,
        }
    }

    async fn push(&self, target: &PushTarget) -> Result<String, ForgeError> {
        match self {
            Self::Github(forge) => forge.push(target).await,
            Self::Gitea(forge) => forge.push(target).await,
        }
    }
}

/// The hosts one Job may reach and the adapter each one gets.
#[derive(Debug, Clone, Default)]
pub struct Forges {
    policies: Vec<HostPolicy>,
}

impl Forges {
    /// Forges over `policies`.
    #[must_use]
    pub const fn new(policies: Vec<HostPolicy>) -> Self {
        Self { policies }
    }

    /// The adapter for `host` over the given seams, chosen by the kind of its policy.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownHost`] when no policy names `host`. The match ignores ASCII case.
    pub fn select<H: Http, G: Git>(
        &self,
        host: &str,
        http: H,
        git: G,
    ) -> Result<HostApi<H, G>, UnknownHost> {
        let policy = self.policy(host).ok_or(UnknownHost)?;
        Ok(match policy.kind {
            HostKind::Github => HostApi::Github(GitHubForge::new(http, git)),
            HostKind::Forgejo => {
                HostApi::Gitea(GiteaForge::new(http).with_git(policy.host.clone(), git))
            }
        })
    }

    /// The production adapter for `host`: a [`PinnedHttp`] to it and [`NoGit`].
    ///
    /// # Errors
    ///
    /// Returns [`UnknownHost`] when no policy names `host`.
    pub fn for_host(&self, host: &str) -> Result<HostApi<PinnedHttp, NoGit>, UnknownHost> {
        let http = self.http_for(host)?;
        self.select(host, http, NoGit)
    }

    /// The production [`PinnedHttp`] for `host`, dialled to the addresses its policy approves.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownHost`] when no policy names `host`.
    pub fn http_for(&self, host: &str) -> Result<PinnedHttp, UnknownHost> {
        let policy = self.policy(host).ok_or(UnknownHost)?;
        Ok(PinnedHttp::system(
            policy.host.clone(),
            policy.approved.clone(),
        ))
    }

    fn policy(&self, host: &str) -> Option<&HostPolicy> {
        self.policies
            .iter()
            .find(|policy| policy.host.as_str().eq_ignore_ascii_case(host))
    }
}

#[cfg(test)]
mod tests {
    use fleet_forge::contract::Case;
    use fleet_forge::fake::{Fake, Shape};

    use super::*;

    fn name(text: &str) -> HostName {
        HostName::normalise(text).expect("test host is valid")
    }

    fn forges() -> Forges {
        Forges::new(vec![
            HostPolicy::new(name("github.com"), HostKind::Github, Vec::new()),
            HostPolicy::new(name("git.example.com"), HostKind::Forgejo, Vec::new()),
        ])
    }

    #[tokio::test]
    async fn a_github_host_gets_the_github_adapter() {
        let fake = Fake::new(Shape::GitHub);
        fake.arm(Case::IdentifyOk).expect("scenario");
        let api = forges()
            .select("github.com", fake.clone(), fake.clone())
            .expect("known host");
        assert!(matches!(api, HostApi::Github(_)));
        assert_eq!(api.identify(&fake.host()).await, Ok(HostKind::Github));
    }

    #[tokio::test]
    async fn a_forgejo_host_gets_the_gitea_adapter() {
        let fake = Fake::new(Shape::Gitea);
        fake.arm(Case::IdentifyOk).expect("scenario");
        let api = forges()
            .select("git.example.com", fake.clone(), fake.clone())
            .expect("known host");
        assert!(matches!(api, HostApi::Gitea(_)));
        assert_eq!(api.identify(&fake.host()).await, Ok(HostKind::Forgejo));
    }

    #[tokio::test]
    async fn each_adapter_refuses_the_other_kind_of_server() {
        let gitea = Fake::new(Shape::Gitea);
        gitea.arm(Case::IdentifyOk).expect("scenario");
        let github = forges()
            .select("github.com", gitea.clone(), gitea.clone())
            .expect("known host");
        assert_eq!(
            github.identify(&gitea.host()).await,
            Err(ForgeError::WrongKind)
        );
        let github_fake = Fake::new(Shape::GitHub);
        github_fake.arm(Case::IdentifyOk).expect("scenario");
        let forgejo = forges()
            .select("git.example.com", github_fake.clone(), github_fake.clone())
            .expect("known host");
        assert_eq!(
            forgejo.identify(&github_fake.host()).await,
            Err(ForgeError::WrongKind)
        );
    }

    #[test]
    fn an_unknown_host_gets_the_fixed_error_for_both_forms() {
        let fake = Fake::new(Shape::GitHub);
        for host in [
            "gitlab.com",
            "github.com.evil.example",
            "evil.example/github.com",
            "github.com ",
            "",
        ] {
            let selected = forges().select(host, fake.clone(), fake.clone());
            assert_eq!(selected.err(), Some(UnknownHost), "{host:?}");
            assert_eq!(forges().for_host(host).err(), Some(UnknownHost), "{host:?}");
        }
        assert_eq!(UnknownHost.to_string(), "forge host not configured");
        assert_eq!(UNKNOWN_HOST, "forge host not configured");
        assert!(Forges::default().for_host("github.com").is_err());
    }

    #[test]
    fn the_host_match_ignores_ascii_case() {
        let fake = Fake::new(Shape::GitHub);
        assert!(forges().select("GitHub.COM", fake.clone(), fake).is_ok());
    }

    #[test]
    fn for_host_builds_the_adapter_of_the_kind() {
        assert!(matches!(
            forges().for_host("github.com"),
            Ok(HostApi::Github(_))
        ));
        assert!(matches!(
            forges().for_host("git.example.com"),
            Ok(HostApi::Gitea(_))
        ));
    }

    #[tokio::test]
    async fn the_production_adapter_refuses_every_git_operation() {
        use fleet_forge::{Credential, Token};
        let repo = repo_ref("https://github.com/o/r.git").expect("repo");
        let token = Token::new(Fake::TOKEN.to_owned()).expect("token");
        let access = RepoAccess::new(repo.clone(), Credential::new(repo.host().clone(), token));
        let api = forges().for_host("github.com").expect("known host");
        assert!(api.fetch(&access).await.is_err());
        let target = PushTarget::new(access, "swarm/job1", "main").expect("target");
        assert!(api.push(&target).await.is_err());
    }

    #[test]
    fn repo_ref_reads_only_https_owner_repo_urls() {
        let good = repo_ref("https://github.com/o/r.git").expect("repo");
        assert_eq!((good.owner(), good.repo()), ("o", "r"));
        let bare = repo_ref("https://git.example.com/o/r").expect("repo");
        assert_eq!(bare.host().as_str(), "git.example.com");
        for hostile in [
            "http://github.com/o/r",
            "file:///srv/o/r",
            "/srv/o/r",
            "https://github.com/o",
            "https://github.com/o/r/extra",
            "https://u@github.com/o/r",
            "https://github.com:443/o/r",
            "https://github.com/o/r?x=1",
            "https://github.com/o/r#f",
            "https://github.com/o/../r",
            "https://github.com/o/r\r\nHost: x",
            "https://github.com/o /r",
            "https:///o/r",
            "",
        ] {
            assert!(repo_ref(hostile).is_none(), "{hostile:?}");
        }
    }
}
