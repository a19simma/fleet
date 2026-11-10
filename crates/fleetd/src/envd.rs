//! Job environments: the `GetJobEnvironment` client, the held secret map and its redaction
//! (ADR-0067).
//!
//! A [`ReleasedEnvironment`] holds the secret values the server released to one claimed job, in
//! memory only. It zeroes them on drop and prints names only. Nothing here touches the
//! filesystem: delivery of the values is a later step.
//!
//! Every refusal of the call, whatever its cause, becomes the one [`EnvDenied`] with the fixed
//! reason [`ERR_ENV_DENIED`], so a User cannot probe the server's reasons through the Job
//! error. A refused call fails the Job before its workspace exists.
//!
//! Zeroing is partial. The bearer header value, the `prost` decode buffers and the [`Redactor`]
//! copies are plain allocations that are not zeroed when dropped.
//!
//! The Redactor registers each secret in full and each line of 8 or more bytes of a multi-line
//! secret, at most [`MAX_REDACT_LINES`] lines in total, longest first.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error as StdError;
use std::fmt;
use std::time::Duration;

use fleet_core::{MIN_SECRET_LEN, Redactor};
use fleet_proto::ERR_ENV_RELEASE_DENIED;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{GetJobEnvironmentReply, GetJobEnvironmentRequest};
use tonic::metadata::MetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Request, Status};
use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::Error;
use crate::poller::{CALL_BACKSTOP, TOKEN_ENV};

/// Job failure reason for every refused environment release.
pub const ERR_ENV_DENIED: &str = ERR_ENV_RELEASE_DENIED;

/// Most secret lines the Redactor registers for one Job.
pub const MAX_REDACT_LINES: usize = 4096;

/// Largest `GetJobEnvironment` reply the client decodes, in bytes: the ADR-0018 decode limit.
pub const MAX_REPLY_BYTES: usize = 1024 * 1024;

/// Job note text when [`MAX_REDACT_LINES`] cut the registered lines.
pub const NOTE_COVERAGE_REDUCED: &str = "redaction coverage reduced";

/// The refusal of a `GetJobEnvironment` call. Carries no cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvDenied;

impl EnvDenied {
    /// The fixed Job failure reason.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        ERR_ENV_DENIED
    }
}

impl fmt::Display for EnvDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(ERR_ENV_DENIED)
    }
}

impl StdError for EnvDenied {}

/// A [`Redactor`] over released values and whether the line limit cut its coverage.
#[derive(Debug, Clone)]
pub struct Redaction {
    /// Masks every registered value and line.
    pub redactor: Redactor,
    /// True when more lines qualified than the limit allows and the shortest were left out.
    pub reduced: bool,
}

/// The secret values released to one Job, by name.
///
/// Values are zeroed on [`ReleasedEnvironment::wipe`] and on drop. `Debug` prints names only.
#[derive(Default)]
pub struct ReleasedEnvironment {
    secrets: BTreeMap<String, Zeroizing<String>>,
}

impl fmt::Debug for ReleasedEnvironment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReleasedEnvironment")
            .field("names", &self.secrets.keys().collect::<Vec<_>>())
            .finish_non_exhaustive()
    }
}

impl ZeroizeOnDrop for ReleasedEnvironment {}

impl Drop for ReleasedEnvironment {
    fn drop(&mut self) {
        self.wipe();
    }
}

impl ReleasedEnvironment {
    /// Takes the secrets out of `reply`. A name sent twice keeps its last value.
    #[must_use]
    pub fn from_reply(mut reply: GetJobEnvironmentReply) -> Self {
        let mut secrets = BTreeMap::new();
        for secret in std::mem::take(&mut reply.secrets) {
            secrets.insert(secret.name, Zeroizing::new(secret.value));
        }
        Self { secrets }
    }

    /// The value held under `name`.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.secrets.get(name).map(|value| value.as_str())
    }

    /// Number of secrets held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether no secret is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Zeroes every value and empties the map.
    pub fn wipe(&mut self) {
        for value in self.secrets.values_mut() {
            zeroize::Zeroize::zeroize(value);
        }
        self.secrets.clear();
    }

    /// The redactor of these values under [`MAX_REDACT_LINES`].
    #[must_use]
    pub fn redaction(&self) -> Redaction {
        self.redaction_with_limit(MAX_REDACT_LINES)
    }

    /// The redactor of these values with at most `limit` registered lines.
    ///
    /// Each value is registered in full. Each line of [`MIN_SECRET_LEN`] bytes or more of a value
    /// with more than one line is registered too. When more lines qualify than `limit`, the
    /// longest `limit` are kept, ties broken by text, and `reduced` is set. A single-line value
    /// is its own line and does not count against the limit.
    #[must_use]
    pub fn redaction_with_limit(&self, limit: usize) -> Redaction {
        let mut lines = BTreeSet::new();
        for value in self.secrets.values() {
            if value.contains('\n') {
                lines.extend(
                    value
                        .lines()
                        .filter(|line| line.len() >= MIN_SECRET_LEN)
                        .map(str::to_owned),
                );
            }
        }
        let mut lines: Vec<String> = lines.into_iter().collect();
        lines.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        let reduced = lines.len() > limit;
        lines.truncate(limit);
        let values = self.secrets.values().map(|value| value.as_str().to_owned());
        Redaction {
            redactor: Redactor::new(values.chain(lines)),
            reduced,
        }
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

/// The `GetJobEnvironment` caller, with the bearer token attached.
///
/// Each call builds its own client over a clone of the channel and runs under a backstop.
pub struct EnvironmentClient {
    channel: Channel,
    attach: Attach,
    backstop: Duration,
}

impl fmt::Debug for EnvironmentClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvironmentClient").finish_non_exhaustive()
    }
}

impl EnvironmentClient {
    /// A client over `channel`. The caller sets the request timeout on the channel.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidValue`] when the token is not a valid header value. The error
    /// never contains it.
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

    /// Fetches the secrets the lease of `job_id` and `attempt` releases.
    ///
    /// # Errors
    ///
    /// Returns [`EnvDenied`] for every failure: a refusal, a transport error, a reply over
    /// [`MAX_REPLY_BYTES`] or a call past the backstop. The cause is not kept.
    pub async fn fetch(
        &self,
        job_id: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<ReleasedEnvironment, EnvDenied> {
        let request = GetJobEnvironmentRequest {
            job_id: job_id.to_owned(),
            attempt,
            r#box: box_name.to_owned(),
        };
        let mut client = self.client();
        let call = tokio::time::timeout(self.backstop, client.get_job_environment(request)).await;
        let reply = call.map_err(|_| EnvDenied)?.map_err(|_| EnvDenied)?;
        Ok(ReleasedEnvironment::from_reply(reply.into_inner()))
    }
}
