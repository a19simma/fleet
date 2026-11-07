//! The `FleetCredentials` handlers (ADR-0040, ADR-0043).
//!
//! Every call acts on the caller's own credentials. Replies and errors carry fixed text and
//! never the secret value.

use std::sync::Arc;

use fleet_core::credential::{CredentialKind, CredentialShape, Secret, validate};
use fleet_proto::v1::{
    CredentialInfo, DeleteCredentialReply, DeleteCredentialRequest, GetJobCredentialsReply,
    GitIdentity, JobCredential, ListCredentialsReply, PutCredentialRequest, VerifyCredentialReply,
    VerifyCredentialRequest,
};
use fleet_proto::{MAX_CREDENTIAL_VALUE_BYTES, MAX_CREDENTIALS_PER_USER};
use tonic::Status;

use super::github::{GithubApi, GithubError, GithubUser, MAX_EXPIRY_MS};
use super::repo_api::RepoService;
use super::store::{CredentialStore, CredentialSummary, StoreError};

/// The credential RPC logic over a sealed store and a GitHub seam.
#[derive(Clone)]
pub struct CredentialService {
    store: CredentialStore,
    github: Arc<dyn GithubApi>,
    repos: Option<RepoService>,
}

impl std::fmt::Debug for CredentialService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialService(..)")
    }
}

fn store_status(err: &StoreError) -> Status {
    match err {
        StoreError::Seal(_) => {
            tracing::error!(%err, "credential sealing failed");
            Status::new(err.code(), "credential store error")
        }
        StoreError::Db(_) => {
            tracing::error!(%err, "credential storage failed");
            Status::new(err.code(), "storage unavailable")
        }
        _ => Status::new(err.code(), err.to_string()),
    }
}

fn github_status(err: GithubError) -> Status {
    match err {
        GithubError::Rejected => Status::invalid_argument(fleet_proto::ERR_GITHUB_REJECTED),
        GithubError::Unavailable => Status::unavailable("github is unavailable"),
    }
}

fn info(summary: CredentialSummary) -> CredentialInfo {
    CredentialInfo {
        id: u64::try_from(summary.id).unwrap_or_default(),
        kind: summary.kind.wire_name().to_owned(),
        shape: summary.shape.wire_name().to_owned(),
        fingerprint: summary.fingerprint,
        login: summary.login,
        expires_at_ms: summary.expires_at_ms.and_then(|ms| u64::try_from(ms).ok()),
    }
}

fn wire_kind(kind: CredentialKind) -> &'static str {
    if kind == CredentialKind::GithubApp {
        fleet_proto::GITHUB_INSTALLATION_TOKEN_KIND
    } else {
        kind.wire_name()
    }
}

fn row_id(id: u64) -> Result<i64, Status> {
    i64::try_from(id).map_err(|_| Status::not_found("credential not found"))
}

impl CredentialService {
    /// Builds the service over `store`, verifying GitHub tokens through `github`.
    pub fn new(store: CredentialStore, github: Arc<dyn GithubApi>) -> Self {
        Self {
            store,
            github,
            repos: None,
        }
    }

    /// Enables the repository registry RPCs.
    #[must_use]
    pub fn with_repos(mut self, repos: RepoService) -> Self {
        self.repos = Some(repos);
        self
    }

    /// The repository registry, when enabled.
    pub fn repos(&self) -> Option<&RepoService> {
        self.repos.as_ref()
    }

    /// Validates, verifies where the kind allows it and stores a credential for `user_id`.
    ///
    /// # Errors
    ///
    /// `INVALID_ARGUMENT` for an unknown kind, an unsupported shape, an invalid value or a
    /// token GitHub refuses (a `github_app` value must be a `u64` installation id with no
    /// leading zero) or an expiry outside the allowed range, `PERMISSION_DENIED` with
    /// `ERR_CAPABILITY_NOT_GRANTED` when the kind needs a capability the user lacks (the check
    /// runs at save, under `FOR SHARE`),
    /// `RESOURCE_EXHAUSTED` past the per-user cap.
    ///
    /// `FAILED_PRECONDITION` with `PRECONDITION_APP_INSTALLATION` when a `github_app`
    /// installation id is off the operator allowlist or GitHub reports it suspended, owned by
    /// another App or installed on another account (checked after the capability, before
    /// anything is stored), and with `PRECONDITION_CREDENTIAL_TOMBSTONED` when the user's
    /// credential of this kind was deleted and kept as a tombstone.
    ///
    /// `INTERNAL` when the value cannot be sealed or a stored kind is unknown.
    ///
    /// `UNAVAILABLE` when GitHub or storage cannot answer. Nothing is stored on any error.
    pub async fn put(
        &self,
        user_id: i64,
        request: PutCredentialRequest,
    ) -> Result<CredentialInfo, Status> {
        let kind = CredentialKind::from_wire_name(&request.kind)
            .ok_or_else(|| Status::invalid_argument("unknown credential kind"))?;
        if request.shape != CredentialShape::StaticSecret.wire_name() {
            return Err(Status::invalid_argument(
                "credential shape is not supported in v1",
            ));
        }
        if request.value.len() > MAX_CREDENTIAL_VALUE_BYTES {
            return Err(Status::invalid_argument("credential is too long"));
        }
        validate(kind, CredentialShape::StaticSecret, &request.value)
            .map_err(|fault| Status::invalid_argument(fault.to_string()))?;
        let mut expires_at_ms = match request.expires_at_ms {
            Some(ms) => Some(
                i64::try_from(ms)
                    .ok()
                    .filter(|ms| (0..=MAX_EXPIRY_MS).contains(ms))
                    .ok_or_else(|| Status::invalid_argument("invalid expiry"))?,
            ),
            None => None,
        };
        let existing = self
            .store
            .list(user_id)
            .await
            .map_err(|e| store_status(&e))?;
        if existing.len() >= MAX_CREDENTIALS_PER_USER && existing.iter().all(|c| c.kind != kind) {
            return Err(Status::resource_exhausted("too many credentials"));
        }
        let value = Secret::new(request.value);
        let mut login = None;
        if kind == CredentialKind::GithubPat {
            let GithubUser {
                login: name,
                expires_at_ms: expiry,
            } = self.github.user(&value).await.map_err(github_status)?;
            login = Some(name);
            expires_at_ms = expiry;
        } else if kind == CredentialKind::GithubApp {
            expires_at_ms = None;
            self.store
                .vet_installation(user_id, &value)
                .await
                .map_err(|err| match err {
                    StoreError::MintFailed => github_status(GithubError::Unavailable),
                    other => store_status(&other),
                })?;
        }
        let summary = self
            .store
            .put(
                user_id,
                kind,
                CredentialShape::StaticSecret,
                value,
                login,
                expires_at_ms,
            )
            .await
            .map_err(|e| store_status(&e))?;
        Ok(info(summary))
    }

    /// Lists the credentials of `user_id`.
    ///
    /// # Errors
    ///
    /// `INTERNAL` when a stored kind is unknown, `UNAVAILABLE` when storage fails.
    pub async fn list(&self, user_id: i64) -> Result<ListCredentialsReply, Status> {
        let credentials = self
            .store
            .list(user_id)
            .await
            .map_err(|e| store_status(&e))?
            .into_iter()
            .map(info)
            .collect();
        Ok(ListCredentialsReply { credentials })
    }

    /// Deletes a credential of `user_id`. A credential with mint history is tombstoned, not
    /// removed, and cannot be replaced.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` when the id is unknown, belongs to another user or is already tombstoned,
    /// `UNAVAILABLE` when storage fails.
    pub async fn delete(
        &self,
        user_id: i64,
        request: &DeleteCredentialRequest,
    ) -> Result<DeleteCredentialReply, Status> {
        self.store
            .delete(user_id, row_id(request.id)?)
            .await
            .map_err(|e| store_status(&e))?;
        Ok(DeleteCredentialReply {})
    }

    /// Releases the credentials of the owner of the job a Box holds the lease for.
    ///
    /// A released `github_app` credential carries `expires_at_ms` and the bot `GitIdentity`; a
    /// PAT carries neither.
    ///
    /// # Errors
    ///
    /// `PERMISSION_DENIED` with `lease does not match` for any lease mismatch, and with
    /// `ERR_CAPABILITY_NOT_GRANTED` when the owner lost the capability a stored kind needs.
    ///
    /// `FAILED_PRECONDITION` with `PRECONDITION_APP_MINT` when the App token cannot be minted,
    /// with `PRECONDITION_APP_INSTALLATION` when the installation is off the allowlist or fails
    /// the owner binding, with `PRECONDITION_APP_REPO` when the Job repository is not allowed
    /// (neither falls back to a PAT), with `PRECONDITION_APP_MINT_CAP` when the per-Job mint
    /// cap is reached (terminal), with `PRECONDITION_APP_MINT_RATE` when the per-User mint rate
    /// limit is reached (retryable; no PAT fallback), and with another
    /// message when the owner has no GitHub credential, no credential the agent accepts, or a
    /// needed credential is expired.
    ///
    /// `NOT_FOUND` when a credential row vanishes during release.
    ///
    /// `INTERNAL` when a sealed value cannot be opened, a stored kind is unknown or a value is
    /// not text.
    ///
    /// `UNAVAILABLE` when storage fails. No use row is written on error; mint attempts write
    /// `github_app_mint` audit rows.
    pub async fn job_credentials(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<GetJobCredentialsReply, Status> {
        let released = self
            .store
            .release_for_job(job_id, attempt, box_name)
            .await
            .map_err(|e| store_status(&e))?;
        let mut credentials = Vec::with_capacity(released.len());
        for item in released {
            let value = String::from_utf8(item.value.expose().to_vec()).map_err(|_| {
                tracing::error!("released credential is not text");
                Status::internal("credential store error")
            })?;
            credentials.push(JobCredential {
                kind: wire_kind(item.kind).to_owned(),
                shape: item.shape.wire_name().to_owned(),
                value,
                expires_at_ms: item.expires_at_ms,
                git_identity: item.git_identity.map(|identity| GitIdentity {
                    name: identity.name().to_owned(),
                    email: identity.email().to_owned(),
                }),
            });
        }
        Ok(GetJobCredentialsReply { credentials })
    }

    /// Checks a stored GitHub credential against GitHub. No use row is written.
    ///
    /// A `github_pat` is checked with a user lookup. A `github_app` mints one installation
    /// token, revokes it and drops it, so the reply holds no token text: `valid` is true when
    /// the mint succeeded and the revoke was accepted, and false on any mint failure (lane
    /// absent, malformed id, GitHub refusal) and when GitHub refuses the revoke.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for an unknown, foreign or tombstoned id, `FAILED_PRECONDITION` for a kind
    /// without a verifier and, for `github_app`, when the user has no Job to scope the mint to,
    /// with `PRECONDITION_APP_INSTALLATION` or `PRECONDITION_APP_REPO` when the installation or
    /// the repository of the user's latest Job is refused, and with
    /// `PRECONDITION_APP_MINT_RATE` when the per-User mint rate limit is reached (a probe
    /// never counts toward a Job's cap), `PERMISSION_DENIED` with `ERR_CAPABILITY_NOT_GRANTED` when a
    /// `github_app` owner lacks the capability, `INTERNAL` when a sealed value cannot be opened
    /// or a stored kind is unknown, `UNAVAILABLE` when GitHub or storage cannot answer.
    ///
    /// A `github_app` mint failure, including a failed installation lookup and a signing
    /// failure, is a reply with `valid: false`, not an error.
    pub async fn verify(
        &self,
        user_id: i64,
        request: &VerifyCredentialRequest,
    ) -> Result<VerifyCredentialReply, Status> {
        let (kind, value) = self
            .store
            .open_for_verify(user_id, row_id(request.id)?)
            .await
            .map_err(|e| store_status(&e))?;
        if kind == CredentialKind::GithubApp {
            return match self
                .store
                .probe_app(user_id, row_id(request.id)?, &value)
                .await
            {
                Ok(()) => Ok(VerifyCredentialReply {
                    valid: true,
                    login: None,
                    expires_at_ms: None,
                }),
                Err(StoreError::MintFailed) => Ok(VerifyCredentialReply {
                    valid: false,
                    login: None,
                    expires_at_ms: None,
                }),
                Err(err) => Err(store_status(&err)),
            };
        }
        if kind != CredentialKind::GithubPat {
            return Err(Status::failed_precondition(
                "this credential kind cannot be verified",
            ));
        }
        match self.github.user(&value).await {
            Ok(user) => Ok(VerifyCredentialReply {
                valid: true,
                login: Some(user.login),
                expires_at_ms: user.expires_at_ms.and_then(|ms| u64::try_from(ms).ok()),
            }),
            Err(GithubError::Rejected) => Ok(VerifyCredentialReply {
                valid: false,
                login: None,
                expires_at_ms: None,
            }),
            Err(err) => Err(github_status(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use fleet_core::credential::CredentialError;
    use tonic::Code;

    use super::super::seal::SealError;
    use super::*;

    #[test]
    fn every_store_error_keeps_its_wire_code_and_message() {
        let cases = [
            (
                StoreError::Invalid(CredentialError::Empty),
                Code::InvalidArgument,
                None,
            ),
            (
                StoreError::InvalidExpiry,
                Code::InvalidArgument,
                Some("invalid expiry"),
            ),
            (
                StoreError::NotFound,
                Code::NotFound,
                Some("credential not found"),
            ),
            (
                StoreError::TooMany,
                Code::ResourceExhausted,
                Some("too many credentials"),
            ),
            (
                StoreError::LeaseDenied,
                Code::PermissionDenied,
                Some("lease does not match"),
            ),
            (
                StoreError::NoGithub,
                Code::FailedPrecondition,
                Some("no github credential"),
            ),
            (
                StoreError::NoAgentCredential,
                Code::FailedPrecondition,
                Some("no agent credential"),
            ),
            (
                StoreError::Expired,
                Code::FailedPrecondition,
                Some("credential expired"),
            ),
            (
                StoreError::CapabilityDenied,
                Code::PermissionDenied,
                Some("credential kind needs a capability the user lacks"),
            ),
            (
                StoreError::MintFailed,
                Code::FailedPrecondition,
                Some("github app token unavailable"),
            ),
            (
                StoreError::MintCapReached,
                Code::FailedPrecondition,
                Some("github app token limit reached"),
            ),
            (
                StoreError::MintRateLimited,
                Code::FailedPrecondition,
                Some("github app token rate limited"),
            ),
            (
                StoreError::NoJobRepo,
                Code::FailedPrecondition,
                Some("no job to verify the github app against"),
            ),
            (
                StoreError::Tombstoned,
                Code::FailedPrecondition,
                Some("credential was deleted and cannot be replaced"),
            ),
            (
                StoreError::InstallationDenied,
                Code::FailedPrecondition,
                Some("github app installation is not allowed"),
            ),
            (
                StoreError::RepoDenied,
                Code::FailedPrecondition,
                Some("repository is not allowed for the github app"),
            ),
            (
                StoreError::Seal(SealError::Open),
                Code::Internal,
                Some("credential store error"),
            ),
            (
                StoreError::Db(sqlx::Error::PoolTimedOut),
                Code::Unavailable,
                Some("storage unavailable"),
            ),
        ];
        for (err, code, message) in cases {
            let status = store_status(&err);
            assert_eq!(status.code(), code, "{err}");
            assert_eq!(err.code(), code, "{err}");
            if let Some(message) = message {
                assert_eq!(status.message(), message, "{err}");
            }
        }
    }

    #[test]
    fn a_lost_lease_answers_with_the_shared_constant() {
        let status = store_status(&StoreError::LeaseDenied);
        assert_eq!(status.message(), fleet_proto::ERR_LEASE_MISMATCH);
        assert_eq!(
            StoreError::LeaseDenied.to_string(),
            fleet_proto::ERR_LEASE_MISMATCH
        );
    }
}
