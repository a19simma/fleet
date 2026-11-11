//! The forge a Job's broker publishes through: push, pull request creation and fetch.
//!
//! [`JobForge`] holds the [`Forges`] of the Job, one [`Http`] seam, the Job's repo and base
//! branch, and the token of the repo host. Every call resolves the token for that host, builds a
//! [`RepoAccess`] and hands it to the adapter [`Forges::select`] picks by host kind. A host with
//! no policy gets [`UnknownHost`] and the broker's fixed error. The returned pull request URL is
//! checked against the repo host before it leaves.

use std::future::Future;
use std::sync::Arc;

use fleet_forge::{
    Credential, ForgeApi, ForgeGit, Git, Http, HttpError, HttpRequest, HttpResponse, PushTarget,
    RepoAccess, RepoRef, Token,
};

use super::checks::on_host;
use super::{Forges, HostApi, NoGit};
use crate::broker::ExecError;
use crate::cred::{LeasedToken, TokenSource};

struct Shared<H>(Arc<H>);

impl<H> Clone for Shared<H> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<H: Http> Http for Shared<H> {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        self.0.send(request)
    }
}

/// The push, pull request and fetch calls of one Job over the adapter of its repo host.
pub struct JobForge<H> {
    forges: Forges,
    http: Shared<H>,
    repo: RepoRef,
    base: String,
    token: String,
    source: Option<Arc<dyn TokenSource>>,
}

impl<H> std::fmt::Debug for JobForge<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobForge")
            .field("repo", &self.repo)
            .finish_non_exhaustive()
    }
}

impl<H: Http> JobForge<H> {
    /// A forge for `repo`, whose base branch is `base`, with `token` as the credential of the
    /// repo host and `http` as the seam every adapter call goes through.
    #[must_use]
    pub fn new(forges: Forges, http: H, repo: RepoRef, base: &str, token: String) -> Self {
        Self {
            forges,
            http: Shared(Arc::new(http)),
            repo,
            base: base.to_owned(),
            token,
            source: None,
        }
    }

    /// Resolves the token from `source` on every call and holds its lease until the call ends,
    /// instead of the token given to [`JobForge::new`].
    #[must_use]
    pub fn with_token_source(mut self, source: Arc<dyn TokenSource>) -> Self {
        self.source = Some(source);
        self
    }

    async fn access(&self) -> Result<(RepoAccess, Option<LeasedToken>), ExecError> {
        let leased = match &self.source {
            Some(source) => Some(source.lease().await.map_err(|failure| {
                tracing::warn!(
                    reason = failure.reason(),
                    "broker token could not be resolved"
                );
                ExecError
            })?),
            None => None,
        };
        let text = leased
            .as_ref()
            .map_or(self.token.as_str(), LeasedToken::token);
        let token = Token::new(text.to_owned()).map_err(|_| ExecError)?;
        let access = RepoAccess::new(
            self.repo.clone(),
            Credential::new(self.repo.host().clone(), token),
        );
        Ok((access, leased))
    }

    fn api<G: Git>(&self, git: G) -> Result<HostApi<Shared<H>, G>, ExecError> {
        self.forges
            .select(self.repo.host().as_str(), self.http.clone(), git)
            .map_err(|error| {
                tracing::warn!(%error, "no forge adapter for the job repo host");
                ExecError
            })
    }

    /// Pushes `branch` through [`ForgeGit::push`], with `git` as the seam that runs git.
    ///
    /// # Errors
    ///
    /// The broker's fixed [`ExecError`] when the host has no adapter, the token cannot be
    /// resolved, the branch is refused or the adapter fails.
    pub async fn push<G: Git>(&self, git: G, branch: &str) -> Result<String, ExecError> {
        let (access, leased) = self.access().await?;
        let target = PushTarget::new(access, branch, &self.base).map_err(|_| ExecError)?;
        let pushed = self.api(git)?.push(&target).await.map_err(|error| {
            tracing::warn!(%error, "broker push failed");
            ExecError
        });
        drop(leased);
        pushed
    }

    /// Fetches the repo through [`ForgeGit::fetch`], with `git` as the seam that runs git.
    ///
    /// # Errors
    ///
    /// The broker's fixed [`ExecError`], as for [`JobForge::push`].
    pub async fn fetch<G: Git>(&self, git: G) -> Result<String, ExecError> {
        let (access, leased) = self.access().await?;
        let fetched = self.api(git)?.fetch(&access).await.map_err(|error| {
            tracing::warn!(%error, "broker fetch failed");
            ExecError
        });
        drop(leased);
        fetched
    }

    /// Opens the pull request of `branch` through [`ForgeApi::create_pr`], or returns the URL of
    /// the one already open for it.
    ///
    /// # Errors
    ///
    /// The broker's fixed [`ExecError`], as for [`JobForge::push`], and when the URL the adapter
    /// returns is not an `https` URL of the repo host.
    pub async fn create_pr(
        &self,
        branch: &str,
        title: &str,
        body: &str,
    ) -> Result<String, ExecError> {
        let (access, leased) = self.access().await?;
        let target = PushTarget::new(access, branch, &self.base).map_err(|_| ExecError)?;
        let created = self
            .api(NoGit)?
            .create_pr(&target, title, body)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "broker pr_create failed");
                ExecError
            });
        drop(leased);
        let url = created?;
        if on_host(&url, self.repo.host().as_str()) {
            Ok(url)
        } else {
            Err(ExecError)
        }
    }
}
