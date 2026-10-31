//! The `FleetCredentials` handlers (ADR-0040, ADR-0043).
//!
//! Every call acts on the caller's own credentials. Replies and errors carry fixed text and
//! never the secret value.

use std::sync::Arc;

use fleet_core::credential::{CredentialKind, CredentialShape, Secret, validate};
use fleet_proto::v1::{
    CredentialInfo, DeleteCredentialReply, DeleteCredentialRequest, GetJobCredentialsReply,
    JobCredential, ListCredentialsReply, PutCredentialRequest, VerifyCredentialReply,
    VerifyCredentialRequest,
};
use fleet_proto::{MAX_CREDENTIAL_VALUE_BYTES, MAX_CREDENTIALS_PER_USER};
use tonic::Status;

use super::github::{GithubApi, GithubError, GithubUser, MAX_EXPIRY_MS};
use super::store::{CredentialStore, CredentialSummary, StoreError};

/// The credential RPC logic over a sealed store and a GitHub seam.
#[derive(Clone)]
pub struct CredentialService {
    store: CredentialStore,
    github: Arc<dyn GithubApi>,
}

impl std::fmt::Debug for CredentialService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CredentialService(..)")
    }
}

fn store_status(err: &StoreError) -> Status {
    match err {
        StoreError::Invalid(fault) => Status::invalid_argument(fault.to_string()),
        StoreError::InvalidExpiry => Status::invalid_argument("invalid expiry"),
        StoreError::NotFound => Status::not_found("credential not found"),
        StoreError::TooMany => Status::resource_exhausted("too many credentials"),
        StoreError::LeaseDenied => Status::permission_denied("lease does not match"),
        StoreError::NoGithub => Status::failed_precondition(fleet_proto::PRECONDITION_NO_GITHUB),
        StoreError::NoAgentCredential => {
            Status::failed_precondition(fleet_proto::PRECONDITION_NO_AGENT)
        }
        StoreError::Expired => Status::failed_precondition(fleet_proto::PRECONDITION_EXPIRED),
        StoreError::Seal(_) => {
            tracing::error!(%err, "credential sealing failed");
            Status::internal("credential store error")
        }
        StoreError::Db(_) => {
            tracing::error!(%err, "credential storage failed");
            Status::unavailable("storage unavailable")
        }
    }
}

fn github_status(err: GithubError) -> Status {
    match err {
        GithubError::Rejected => Status::invalid_argument("github rejected the token"),
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

fn row_id(id: u64) -> Result<i64, Status> {
    i64::try_from(id).map_err(|_| Status::not_found("credential not found"))
}

impl CredentialService {
    /// Builds the service over `store`, verifying GitHub tokens through `github`.
    pub fn new(store: CredentialStore, github: Arc<dyn GithubApi>) -> Self {
        Self { store, github }
    }

    /// Validates, verifies where the kind allows it and stores a credential for `user_id`.
    ///
    /// # Errors
    ///
    /// `INVALID_ARGUMENT` for an unknown kind, an unsupported shape, an invalid value or a
    /// token GitHub refuses, `RESOURCE_EXHAUSTED` past the per-user cap, `UNAVAILABLE` when
    /// GitHub or storage cannot answer. Nothing is stored on any error.
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
    /// `UNAVAILABLE` when storage fails.
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

    /// Deletes a credential of `user_id`.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` when the id is unknown or belongs to another user.
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
    /// # Errors
    ///
    /// `PERMISSION_DENIED` with one fixed message for any lease mismatch, `FAILED_PRECONDITION`
    /// when the owner has no GitHub credential, no credential the agent accepts, or a needed
    /// credential is expired, `UNAVAILABLE` when storage fails. Nothing is recorded on error.
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
                kind: item.kind.wire_name().to_owned(),
                shape: item.shape.wire_name().to_owned(),
                value,
            });
        }
        Ok(GetJobCredentialsReply { credentials })
    }

    /// Checks a stored GitHub token against GitHub. No use row is written.
    ///
    /// # Errors
    ///
    /// `NOT_FOUND` for an unknown or foreign id, `FAILED_PRECONDITION` for a kind without a
    /// verifier, `UNAVAILABLE` when GitHub or storage cannot answer.
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
