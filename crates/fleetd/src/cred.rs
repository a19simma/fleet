//! Job credentials: the `GetJobCredentials` client and the per-job holder.
//!
//! A [`CredentialBook`] asks the server for the credentials of one claimed job, holds them in
//! memory under the job id and drops them when the job ends. Nothing here writes a value to
//! disk, to a log or to an error. A value lives in a [`Secret`], which zeroes its buffer on
//! drop and prints as `[REDACTED]`.
//!
//! The call is authorised by the job lease (ADR-0033), so the caller fetches only after the
//! claim is held and before the agent starts. The server's fixed refusals map to one
//! [`CredentialFailure`] each, and each failure has a fixed reason the job report carries.
//! There is no fallback to a box credential on any failure.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use fleet_core::Redactor;
use fleet_core::credential::{
    CredentialKind, CredentialShape, MAX_CREDENTIAL_LEN, MIN_CREDENTIAL_LEN, Secret,
};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{GetJobCredentialsReply, GetJobCredentialsRequest};
use fleet_proto::{MAX_CREDENTIAL_VALUE_BYTES, MAX_CREDENTIALS_PER_USER};
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

use crate::Error;
use crate::poller::{CALL_BACKSTOP, TOKEN_ENV};

/// Largest `GetJobCredentials` reply the client decodes, in bytes: the most credentials one
/// user holds, each at the longest value plus 64 bytes of framing and field overhead.
pub const MAX_REPLY_BYTES: usize = MAX_CREDENTIALS_PER_USER * (MAX_CREDENTIAL_VALUE_BYTES + 64);

const _: () = assert!(MAX_REPLY_BYTES >= MAX_CREDENTIALS_PER_USER * MAX_CREDENTIAL_VALUE_BYTES);
const _: () = assert!(MAX_REPLY_BYTES < 1024 * 1024);

/// Job failure reason: the server says the lease does not match.
pub const ERR_LEASE: &str = "credentials refused: lease does not match";

/// Job failure reason: the owner stored no GitHub credential.
pub const ERR_NO_GITHUB: &str = "no github credential";

/// Job failure reason: the owner stored no credential for the job's agent.
pub const ERR_NO_AGENT: &str = "no agent credential";

/// Job failure reason: a credential the job needs has expired.
pub const ERR_EXPIRED: &str = "credential expired";

/// Job failure reason: the server runs without a credential store.
pub const ERR_NOT_CONFIGURED: &str = "credentials are not configured";

/// Job failure reason: the call failed or timed out.
pub const ERR_UNAVAILABLE: &str = "credentials could not be fetched";

/// Job failure reason: the reply broke a rule the server keeps.
pub const ERR_MALFORMED: &str = "credentials reply was invalid";

/// Why a job could not get its credentials. Each variant has one fixed reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialFailure {
    /// `PERMISSION_DENIED`: wrong box, wrong attempt, lost lease or unknown job.
    LeaseMismatch,
    /// `FAILED_PRECONDITION` `no github credential`.
    NoGithub,
    /// `FAILED_PRECONDITION` `no agent credential`.
    NoAgent,
    /// `FAILED_PRECONDITION` `credential expired`.
    Expired,
    /// `FAILED_PRECONDITION` `credentials are not configured`.
    NotConfigured,
    /// Any other status, a timeout or a transport error.
    Unavailable,
    /// The reply held an unknown kind or shape, a bad value, a duplicate kind, or lacked the
    /// GitHub or agent credential.
    Malformed,
}

impl CredentialFailure {
    /// The fixed text the failed job reports. It never holds a credential value.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::LeaseMismatch => ERR_LEASE,
            Self::NoGithub => ERR_NO_GITHUB,
            Self::NoAgent => ERR_NO_AGENT,
            Self::Expired => ERR_EXPIRED,
            Self::NotConfigured => ERR_NOT_CONFIGURED,
            Self::Unavailable => ERR_UNAVAILABLE,
            Self::Malformed => ERR_MALFORMED,
        }
    }

    fn from_status(status: &Status) -> Self {
        match (status.code(), status.message()) {
            (Code::PermissionDenied, _) => Self::LeaseMismatch,
            (Code::FailedPrecondition, ERR_NO_GITHUB) => Self::NoGithub,
            (Code::FailedPrecondition, ERR_NO_AGENT) => Self::NoAgent,
            (Code::FailedPrecondition, ERR_EXPIRED) => Self::Expired,
            (Code::FailedPrecondition, ERR_NOT_CONFIGURED) => Self::NotConfigured,
            _ => Self::Unavailable,
        }
    }
}

impl fmt::Display for CredentialFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for CredentialFailure {}

/// One credential of a job: its kind and its secret value.
#[derive(Debug)]
pub struct Credential {
    kind: CredentialKind,
    value: Secret,
}

impl Credential {
    /// What the credential authenticates against.
    #[must_use]
    pub const fn kind(&self) -> CredentialKind {
        self.kind
    }

    /// The secret value. Hand it to a child or a client, never to a log or a file.
    #[must_use]
    pub const fn value(&self) -> &Secret {
        &self.value
    }
}

/// The credentials of one job, one per kind.
#[derive(Debug)]
pub struct JobCredentials {
    items: Vec<Credential>,
}

impl JobCredentials {
    fn from_reply(reply: GetJobCredentialsReply) -> Result<Self, CredentialFailure> {
        let mut seen = HashSet::new();
        let mut items = Vec::with_capacity(reply.credentials.len());
        for wire in reply.credentials {
            let kind =
                CredentialKind::from_wire_name(&wire.kind).ok_or(CredentialFailure::Malformed)?;
            if wire.shape != CredentialShape::StaticSecret.wire_name()
                || !(MIN_CREDENTIAL_LEN..=MAX_CREDENTIAL_LEN).contains(&wire.value.len())
                || !seen.insert(kind.wire_name())
            {
                return Err(CredentialFailure::Malformed);
            }
            items.push(Credential {
                kind,
                value: Secret::new(wire.value),
            });
        }
        if !items.iter().any(|c| c.kind == CredentialKind::GithubPat) {
            return Err(CredentialFailure::NoGithub);
        }
        if items.iter().all(|c| c.kind == CredentialKind::GithubPat) {
            return Err(CredentialFailure::NoAgent);
        }
        Ok(Self { items })
    }

    /// The credential of `kind`, if the job has one.
    #[must_use]
    pub fn get(&self, kind: CredentialKind) -> Option<&Secret> {
        self.items
            .iter()
            .find(|c| c.kind == kind)
            .map(Credential::value)
    }

    /// The GitHub token. Every successful fetch holds one.
    #[must_use]
    pub fn github(&self) -> Option<&Secret> {
        self.get(CredentialKind::GithubPat)
    }

    /// The credentials, in reply order.
    pub fn iter(&self) -> std::slice::Iter<'_, Credential> {
        self.items.iter()
    }

    /// A redactor over every value held, to merge into the job's output scrubbing.
    ///
    /// The values that are valid UTF-8 are registered. Values the server accepted are plain
    /// text, so none is skipped in practice.
    #[must_use]
    pub fn redactor(&self) -> Redactor {
        Redactor::new(self.items.iter().filter_map(|c| {
            std::str::from_utf8(c.value.expose())
                .ok()
                .map(str::to_owned)
        }))
    }
}

impl<'a> IntoIterator for &'a JobCredentials {
    type Item = &'a Credential;
    type IntoIter = std::slice::Iter<'a, Credential>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

fn bearer_header(token: &str) -> Result<MetadataValue<tonic::metadata::Ascii>, Error> {
    let mut header: MetadataValue<_> =
        format!("Bearer {token}")
            .parse()
            .map_err(|_| Error::InvalidValue {
                name: TOKEN_ENV,
                value: String::from("<redacted>"),
            })?;
    header.set_sensitive(true);
    Ok(header)
}

type Attach = Box<dyn FnMut(Request<()>) -> Result<Request<()>, Status> + Send>;

type Client = FleetWorkerClient<InterceptedService<Channel, Attach>>;

/// The `GetJobCredentials` caller, with the bearer token attached.
pub struct CredentialClient {
    client: tokio::sync::Mutex<Client>,
}

impl fmt::Debug for CredentialClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialClient").finish_non_exhaustive()
    }
}

impl CredentialClient {
    /// A client over `channel`. The caller sets the request timeout on the channel.
    ///
    /// # Errors
    ///
    /// Fails when the token is not a valid header value. The error never contains it.
    pub fn new(channel: Channel, token: &str) -> Result<Self, Error> {
        let header = bearer_header(token)?;
        let attach: Attach = Box::new(move |mut request| {
            request
                .metadata_mut()
                .insert("authorization", header.clone());
            Ok(request)
        });
        let client = FleetWorkerClient::with_interceptor(channel, attach)
            .max_decoding_message_size(MAX_REPLY_BYTES);
        Ok(Self {
            client: tokio::sync::Mutex::new(client),
        })
    }

    async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<JobCredentials, CredentialFailure> {
        let request = GetJobCredentialsRequest {
            job_id: job_id.to_owned(),
            attempt,
            r#box: box_name.to_owned(),
        };
        let mut client = self.client.lock().await;
        let call = tokio::time::timeout(CALL_BACKSTOP, client.get_job_credentials(request)).await;
        drop(client);
        let reply = call
            .map_err(|_| CredentialFailure::Unavailable)?
            .map_err(|status| CredentialFailure::from_status(&status))?
            .into_inner();
        JobCredentials::from_reply(reply)
    }
}

/// Fetches and holds the credentials of the jobs that run on this box.
#[derive(Debug)]
pub struct CredentialBook {
    client: CredentialClient,
    held: Mutex<HashMap<String, Arc<JobCredentials>>>,
}

impl CredentialBook {
    /// An empty book that fetches through `client`.
    #[must_use]
    pub fn new(client: CredentialClient) -> Self {
        Self {
            client,
            held: Mutex::new(HashMap::new()),
        }
    }

    /// Fetches the credentials of a claimed job and holds them under its id.
    ///
    /// Call it once the lease is held and before the agent starts. A second fetch for the
    /// same id replaces the first.
    ///
    /// # Errors
    ///
    /// Returns the failure whose [`CredentialFailure::reason`] the job reports. Nothing is
    /// held after an error.
    pub async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<Arc<JobCredentials>, CredentialFailure> {
        let credentials = Arc::new(self.client.fetch(job_id, attempt, box_name).await?);
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job_id.to_owned(), Arc::clone(&credentials));
        Ok(credentials)
    }

    /// The credentials held for `job_id`.
    #[must_use]
    pub fn get(&self, job_id: &str) -> Option<Arc<JobCredentials>> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(job_id)
            .cloned()
    }

    /// Drops the credentials of `job_id`. The buffers zero when the last borrower lets go.
    /// Dropping an id that is not held does nothing.
    pub fn forget(&self, job_id: &str) {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }

    /// The job end hook: pass it to [`crate::runner::JobEnd::on_end`].
    pub fn end_hook(self: &Arc<Self>) -> impl Fn(&str) + Send + Sync + 'static {
        let book = Arc::clone(self);
        move |job_id| book.forget(job_id)
    }
}

#[cfg(test)]
mod tests {
    use super::bearer_header;

    #[test]
    fn the_authorization_header_is_sensitive() {
        let header = bearer_header("tok-abc").map_err(|_| ());
        assert!(header.is_ok_and(|header| header.is_sensitive()));
    }
}
