//! The `FleetRepos` handlers (ADR-0059).
//!
//! Every call acts on the authenticated user passed in by the service layer, never on a field of
//! the request. Replies and errors carry fixed text: no credential, upstream body or address.

use std::sync::Arc;

use fleet_core::repo::{ForgeKind, RepoRef};
use fleet_proto::v1::{
    AddRepoRequest, ListReposReply, RemoveRepoReply, RemoveRepoRequest, RepoInfo,
};
use tokio::sync::Semaphore;
use tonic::Status;

use super::repo_limit::{CheckLimiter, MAX_CONCURRENT_REPO_CHECKS};
use super::repo_store::{NewRepo, RepoRow, RepoStore, RepoStoreError};
use super::repo_verify::{RepoRefusal, RepoVerifiers};

const GITHUB_HOST: &str = "github.com";

/// The repository registry logic over a store, the verifier registry and the check bounds.
#[derive(Clone)]
pub struct RepoService {
    store: RepoStore,
    verifiers: Arc<RepoVerifiers>,
    limiter: Arc<CheckLimiter>,
    permits: Arc<Semaphore>,
}

impl std::fmt::Debug for RepoService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RepoService(..)")
    }
}

fn refused(refusal: RepoRefusal) -> Status {
    Status::failed_precondition(refusal.reason())
}

fn store_status(err: &RepoStoreError) -> Status {
    match err {
        RepoStoreError::CredentialGone => refused(RepoRefusal::NoCredential),
        RepoStoreError::TooMany => Status::resource_exhausted(fleet_proto::ERR_REPO_LIMIT),
        RepoStoreError::NotFound => Status::not_found(fleet_proto::ERR_REPO_NOT_FOUND),
        RepoStoreError::Credential(_) => {
            tracing::error!(%err, "repository credential lookup failed");
            Status::internal("credential store error")
        }
        RepoStoreError::Db(_) => {
            tracing::error!(%err, "repository storage failed");
            Status::unavailable("storage unavailable")
        }
    }
}

fn kind_name(kind: ForgeKind) -> &'static str {
    match kind {
        ForgeKind::Github => "github",
        ForgeKind::Forgejo => "forgejo",
    }
}

fn info(row: RepoRow) -> RepoInfo {
    RepoInfo {
        runnable: row.host == GITHUB_HOST,
        host: row.host,
        path: row.path,
        forge_kind: row.forge_kind,
        verified_at_ms: u64::try_from(row.verified_at_ms).unwrap_or_default(),
        push: row.push,
    }
}

impl RepoService {
    /// Builds the service over `store`, verifying through `verifiers`, with the production check
    /// bounds.
    pub fn new(store: RepoStore, verifiers: Arc<RepoVerifiers>) -> Self {
        Self {
            store,
            verifiers,
            limiter: Arc::new(CheckLimiter::system()),
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_REPO_CHECKS)),
        }
    }

    /// Replaces the per-User check limiter. Tests inject a clock.
    #[must_use]
    pub fn with_limiter(mut self, limiter: CheckLimiter) -> Self {
        self.limiter = Arc::new(limiter);
        self
    }

    /// Replaces the global cap on concurrent checks. Tests shrink it.
    #[must_use]
    pub fn with_concurrency(mut self, permits: usize) -> Self {
        self.permits = Arc::new(Semaphore::new(permits));
        self
    }

    async fn parse(&self, input: &str) -> Result<(RepoRef, ForgeKind), Status> {
        let first =
            RepoRef::parse(input).map_err(|err| Status::invalid_argument(err.to_string()))?;
        let kind = self
            .verifiers
            .kind_for(first.host())
            .await
            .map_err(refused)?
            .ok_or_else(|| refused(RepoRefusal::NotAllowedHost))?;
        let repo = RepoRef::parse_as(input, kind)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        Ok((repo, kind))
    }

    /// Verifies and registers a repository for `user_id`. Re-adding a row refreshes `push` and
    /// `verified_at`.
    ///
    /// # Errors
    ///
    /// `INVALID_ARGUMENT` for a reference outside the grammar of its forge. `FAILED_PRECONDITION`
    /// with one `PRECONDITION_REPO_*` reason for a host off the operator list, a missing
    /// credential, a repository the forge hides, an unreachable forge or a check past its
    /// budget, and with `PRECONDITION_REPO_NO_CREDENTIAL` when the credential was deleted
    /// after the check. `RESOURCE_EXHAUSTED` past the per-User check rate, the global
    /// concurrency cap or the per-User row cap. `INTERNAL` when a credential cannot be opened,
    /// `UNAVAILABLE` when storage fails. Nothing is stored on any error.
    pub async fn add(&self, user_id: i64, request: &AddRepoRequest) -> Result<RepoInfo, Status> {
        let (repo, kind) = self.parse(&request.repo).await?;
        let (credential_id, verdict) = {
            if !self.limiter.admit(user_id) {
                return Err(Status::resource_exhausted(
                    fleet_proto::ERR_REPO_RATE_LIMITED,
                ));
            }
            let _permit = self
                .permits
                .try_acquire()
                .map_err(|_| Status::resource_exhausted(fleet_proto::ERR_REPO_BUSY))?;
            let credential = if kind == ForgeKind::Github && repo.host() == GITHUB_HOST {
                self.store
                    .github_credential(user_id)
                    .await
                    .map_err(|err| store_status(&err))?
            } else if kind == ForgeKind::Forgejo {
                self.store
                    .forgejo_credential(user_id, repo.host())
                    .await
                    .map_err(|err| store_status(&err))?
            } else {
                None
            };
            let verdict = self
                .verifiers
                .verify(credential.as_ref().map(|(_, c)| c), &repo)
                .await
                .map_err(refused)?;
            let (credential_id, _) =
                credential.ok_or_else(|| refused(RepoRefusal::NoCredential))?;
            (credential_id, verdict)
        };
        if !verdict.read {
            return Err(refused(RepoRefusal::NotFoundOrNoAccess));
        }
        let canonical = RepoRef::parse_as(
            &format!("{}/{}", repo.host(), verdict.canonical_path),
            kind,
        )
        .map_err(|_| {
            tracing::warn!(host = %repo.host(), "verdict path is outside the forge grammar");
            refused(RepoRefusal::UpstreamUnavailable)
        })?;
        let verified_at_ms = self
            .store
            .insert(
                user_id,
                &NewRepo {
                    host: canonical.host(),
                    path: canonical.path(),
                    forge_kind: kind_name(kind),
                    push: verdict.push,
                    credential_id,
                },
            )
            .await
            .map_err(|err| store_status(&err))?;
        Ok(info(RepoRow {
            host: canonical.host().to_owned(),
            path: canonical.path().to_owned(),
            forge_kind: kind_name(kind).to_owned(),
            push: verdict.push,
            verified_at_ms,
        }))
    }

    /// Lists the repositories of `user_id`.
    ///
    /// # Errors
    ///
    /// `UNAVAILABLE` when storage fails.
    pub async fn list(&self, user_id: i64) -> Result<ListReposReply, Status> {
        let repos = self
            .store
            .list(user_id)
            .await
            .map_err(|err| store_status(&err))?
            .into_iter()
            .map(info)
            .collect();
        Ok(ListReposReply { repos })
    }

    /// Removes a repository of `user_id`. The host and path are matched in lowercase.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` with one fixed message when the user has no such row, whether it never
    /// existed or belongs to another user. `UNAVAILABLE` when storage fails.
    pub async fn remove(
        &self,
        user_id: i64,
        request: &RemoveRepoRequest,
    ) -> Result<RemoveRepoReply, Status> {
        self.store
            .remove(
                user_id,
                &request.host.to_ascii_lowercase(),
                &request.path.to_ascii_lowercase(),
            )
            .await
            .map_err(|err| store_status(&err))?;
        Ok(RemoveRepoReply {})
    }
}
