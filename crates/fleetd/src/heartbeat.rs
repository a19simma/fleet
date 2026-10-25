//! The unary `Heartbeat` call to the Fleet server.

use std::fmt;
use std::future::Future;

use std::time::Duration;

use fleet_core::Identity;
use fleet_proto::v1::HeartbeatRequest;
use fleet_proto::v1::fleet_ingest_client::FleetIngestClient;
use tokio::time::{Instant, MissedTickBehavior};
use tonic::Request;
use tonic::metadata::{Ascii, MetadataValue};
use tonic::transport::Channel;

use crate::Store;
use crate::system::now_ms;
use crate::transport::endpoint;

/// Time between heartbeats. The server marks a box stale after 90 seconds of silence.
pub const HEARTBEAT_PERIOD: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Queue figures carried in a heartbeat.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueSnapshot {
    /// Events waiting in the queue.
    pub pending: u64,
    /// Age of the oldest queued event in seconds.
    pub oldest_age_s: u64,
}

/// Where a heartbeat reads its queue figures.
pub trait QueueSource: Send + Sync + 'static {
    /// Reads the current figures.
    fn snapshot(&self) -> impl Future<Output = QueueSnapshot> + Send;
}

impl QueueSource for Store {
    /// Reads the row count and the oldest row. When the queue cannot be read, logs a
    /// warning and returns zeros so the heartbeat still goes out.
    async fn snapshot(&self) -> QueueSnapshot {
        read_queue(self)
            .await
            .map_err(|_| tracing::warn!("queue figures unavailable for the heartbeat"))
            .unwrap_or_default()
    }
}

async fn read_queue(store: &Store) -> Result<QueueSnapshot, crate::Error> {
    let pending = store.count().await?;
    let oldest = store.list(Some(1)).await?;
    let oldest_age_s = oldest.first().map_or(0, |event| {
        u64::try_from(event.ts).map_or(0, |ts| now_ms().saturating_sub(ts) / 1000)
    });
    Ok(QueueSnapshot {
        pending,
        oldest_age_s,
    })
}

/// Why a heartbeat target could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TargetError {
    /// `FLEET_SERVER_URL` is set but `FLEET_TOKEN` is not.
    MissingToken,
    /// The server URL is not a valid endpoint.
    InvalidUrl,
    /// The token cannot be sent as a header value.
    InvalidToken,
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingToken => "FLEET_TOKEN is not set",
            Self::InvalidUrl => "FLEET_SERVER_URL is not a valid URL",
            Self::InvalidToken => "FLEET_TOKEN is not a valid header value",
        })
    }
}

impl std::error::Error for TargetError {}

/// A server to heartbeat to, with the bearer token for it.
pub struct Heartbeat {
    channel: Channel,
    authorization: MetadataValue<Ascii>,
    period: Duration,
}

impl fmt::Debug for Heartbeat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Heartbeat").finish_non_exhaustive()
    }
}

impl Heartbeat {
    /// Builds a target for `url` that sends `token` as a bearer token.
    ///
    /// The connection opens on the first call and reopens after a failure. Call this
    /// inside a tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not an endpoint, or the token is empty or not valid in a
    /// header.
    pub fn new(url: &str, token: &str) -> Result<Self, TargetError> {
        Self::new_with_ca(url, token, None)
    }

    /// Like [`Heartbeat::new`], and for an `https` URL also trusts the PEM certificate in
    /// `ca_pem`.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not an endpoint, or the token is empty or not valid in a
    /// header.
    pub fn new_with_ca(url: &str, token: &str, ca_pem: Option<&[u8]>) -> Result<Self, TargetError> {
        let endpoint = endpoint(url, ca_pem).map_err(|_| TargetError::InvalidUrl)?;
        if token.is_empty() {
            return Err(TargetError::MissingToken);
        }
        let mut authorization = MetadataValue::try_from(format!("Bearer {token}"))
            .map_err(|_| TargetError::InvalidToken)?;
        authorization.set_sensitive(true);
        Ok(Self {
            channel: endpoint.connect_lazy(),
            authorization,
            period: HEARTBEAT_PERIOD,
        })
    }

    /// Replaces the time between heartbeats, [`HEARTBEAT_PERIOD`] by default.
    #[must_use]
    pub const fn with_period(mut self, period: Duration) -> Self {
        self.period = period;
        self
    }

    /// Reads the target from `FLEET_SERVER_URL` and `FLEET_TOKEN`.
    ///
    /// Returns `None` when `FLEET_SERVER_URL` is unset or empty. Call this inside a
    /// tokio runtime.
    ///
    /// # Errors
    ///
    /// Fails when the URL is set and [`Heartbeat::new`] rejects it or the token.
    pub fn from_env(env: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, TargetError> {
        let Some(url) = env("FLEET_SERVER_URL").filter(|url| !url.is_empty()) else {
            return Ok(None);
        };
        let token = env("FLEET_TOKEN").unwrap_or_default();
        Self::new(&url, &token).map(Some)
    }

    /// Sends a heartbeat now and then once per period until `shutdown` resolves.
    ///
    /// A failed call logs a warning with the status code only and waits for the next
    /// period. The loop never returns early and never panics on a server error.
    pub async fn run(
        self,
        identity: Identity,
        queue: impl QueueSource,
        shutdown: impl Future<Output = ()>,
    ) {
        let started = Instant::now();
        let mut client = FleetIngestClient::new(self.channel.clone());
        let mut tick = tokio::time::interval(self.period);
        tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
        tokio::pin!(shutdown);
        loop {
            let beat = async {
                tick.tick().await;
                let request = request(&identity, started.elapsed(), queue.snapshot().await);
                self.send(&mut client, request).await;
            };
            tokio::select! {
                () = &mut shutdown => return,
                () = beat => {}
            }
        }
    }

    async fn send(&self, client: &mut FleetIngestClient<Channel>, request: HeartbeatRequest) {
        let mut request = Request::new(request);
        request
            .metadata_mut()
            .insert("authorization", self.authorization.clone());
        match tokio::time::timeout(REQUEST_TIMEOUT, client.heartbeat(request)).await {
            Ok(Ok(_)) => {}
            Ok(Err(status)) => {
                tracing::warn!(code = ?status.code(), "heartbeat failed");
            }
            Err(_) => tracing::warn!("heartbeat failed: timed out"),
        }
    }
}

fn request(identity: &Identity, uptime: Duration, queue: QueueSnapshot) -> HeartbeatRequest {
    HeartbeatRequest {
        r#box: identity.box_name.clone(),
        hostname: identity.hostname.clone(),
        machine_id: identity.machine_id.clone(),
        boot_id: identity.boot_id.clone(),
        fleetd_version: env!("CARGO_PKG_VERSION").to_owned(),
        uptime_s: uptime.as_secs(),
        queue_pending: queue.pending,
        queue_oldest_age_s: queue.oldest_age_s,
        last_ack_age_s: None,
    }
}
