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
use std::time::Duration;

use fleet_core::Redactor;
use fleet_core::credential::{
    CredentialKind, CredentialShape, MAX_CREDENTIAL_LEN, MIN_CREDENTIAL_LEN, Secret,
};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{GetJobCredentialsReply, GetJobCredentialsRequest};
use fleet_proto::{
    MAX_CREDENTIAL_VALUE_BYTES, MAX_CREDENTIALS_PER_USER, PRECONDITION_EXPIRED,
    PRECONDITION_NO_AGENT, PRECONDITION_NO_GITHUB, PRECONDITION_NOT_CONFIGURED,
};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};
use zeroize::Zeroizing;

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
            (Code::FailedPrecondition, PRECONDITION_NO_GITHUB) => Self::NoGithub,
            (Code::FailedPrecondition, PRECONDITION_NO_AGENT) => Self::NoAgent,
            (Code::FailedPrecondition, PRECONDITION_EXPIRED) => Self::Expired,
            (Code::FailedPrecondition, PRECONDITION_NOT_CONFIGURED) => Self::NotConfigured,
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
        let mut wires: Vec<(String, String, Zeroizing<String>)> = reply
            .credentials
            .into_iter()
            .map(|wire| (wire.kind, wire.shape, Zeroizing::new(wire.value)))
            .collect();
        let mut seen = HashSet::new();
        let mut items = Vec::with_capacity(wires.len());
        for (kind, shape, value) in &mut wires {
            let kind = CredentialKind::from_wire_name(kind).ok_or(CredentialFailure::Malformed)?;
            if shape != CredentialShape::StaticSecret.wire_name()
                || !(MIN_CREDENTIAL_LEN..=MAX_CREDENTIAL_LEN).contains(&value.len())
                || !seen.insert(kind.wire_name())
            {
                return Err(CredentialFailure::Malformed);
            }
            items.push(Credential {
                kind,
                value: Secret::new(std::mem::take(&mut **value)),
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
    ///
    /// The [`Redactor`] keeps its own plain `String` copies, which are not zeroed when it
    /// drops. The copies live as long as the redactor, so drop it when the job ends.
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
    let text = Zeroizing::new(format!("Bearer {token}"));
    let mut header: MetadataValue<_> = text.as_str().parse().map_err(|_| Error::InvalidValue {
        name: TOKEN_ENV,
        value: String::from("<redacted>"),
    })?;
    header.set_sensitive(true);
    Ok(header)
}

#[derive(Clone)]
struct Attach(MetadataValue<tonic::metadata::Ascii>);

impl Interceptor for Attach {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        request
            .metadata_mut()
            .insert("authorization", self.0.clone());
        Ok(request)
    }
}

type Client = FleetWorkerClient<InterceptedService<Channel, Attach>>;

/// The `GetJobCredentials` caller, with the bearer token attached.
///
/// Each call builds its own client over a clone of the channel, so concurrent calls never
/// queue behind one another and the backstop covers the whole call.
pub struct CredentialClient {
    channel: Channel,
    attach: Attach,
    backstop: Duration,
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
        Ok(Self {
            channel,
            attach: Attach(bearer_header(token)?),
            backstop: CALL_BACKSTOP,
        })
    }

    /// Replaces the longest time one call may take, [`CALL_BACKSTOP`] by default.
    #[must_use]
    pub const fn with_backstop(mut self, backstop: Duration) -> Self {
        self.backstop = backstop;
        self
    }

    fn client(&self) -> Client {
        FleetWorkerClient::with_interceptor(self.channel.clone(), self.attach.clone())
            .max_decoding_message_size(MAX_REPLY_BYTES)
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
        let mut client = self.client();
        let call = tokio::time::timeout(self.backstop, client.get_job_credentials(request)).await;
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
    /// Call it once the lease is held and before the agent starts. A fetch first drops any
    /// entry held for the same id, so a second fetch replaces the first and a failed one
    /// leaves nothing readable.
    ///
    /// # Errors
    ///
    /// Returns the failure whose [`CredentialFailure::reason`] the job reports. Nothing is
    /// held for `job_id` after an error.
    pub async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<Arc<JobCredentials>, CredentialFailure> {
        self.forget(job_id);
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
