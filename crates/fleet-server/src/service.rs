//! The `FleetIngest` and `FleetQuery` gRPC handlers.

use std::time::Duration;

use fleet_core::{BoxName, Envelope};
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::fleet_query_server::{FleetQuery, FleetQueryServer};
use fleet_proto::v1::{
    HeartbeatReply, HeartbeatRequest, ListFleetReply, ListFleetRequest, PushEventsReply,
    PushEventsRequest, QueuedEvent, Rejection,
};
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::Router;
use tonic::{Request, Response, Status};

use crate::auth::BearerAuth;
use crate::store::{Store, StoreError};

/// Seconds a box should wait before its next heartbeat.
pub const HEARTBEAT_INTERVAL_S: u32 = 30;

/// Most events one `PushEvents` call may carry.
pub const MAX_EVENTS_PER_PUSH: usize = 500;

/// Largest `payload_json` one event may carry, in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// Largest request message the server decodes, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const CONCURRENCY_PER_CONNECTION: usize = 8;
const MAX_CONCURRENT_STREAMS: u32 = 32;

fn storage_unavailable(err: &StoreError) -> Status {
    tracing::error!(%err, "storage failed");
    Status::unavailable("storage unavailable")
}

fn check_box(raw: &str) -> Result<BoxName, Status> {
    BoxName::new(raw).map_err(|err| Status::invalid_argument(err.to_string()))
}

fn batch_box(events: &[QueuedEvent]) -> Result<Option<BoxName>, Status> {
    let mut names = events
        .iter()
        .filter_map(|event| event.envelope.as_ref())
        .map(|envelope| envelope.r#box.as_str());
    let Some(first) = names.next() else {
        return Ok(None);
    };
    let name = check_box(first)?;
    if names.any(|other| other != first) {
        return Err(Status::invalid_argument(
            "every event in a request must carry the same box",
        ));
    }
    Ok(Some(name))
}

fn no_nul(field: &str, value: &str) -> Result<(), Status> {
    if value.contains('\0') {
        return Err(Status::invalid_argument(format!(
            "{field} contains a NUL character"
        )));
    }
    Ok(())
}

/// Handler for `FleetIngest` and `FleetQuery`.
#[derive(Debug, Clone)]
pub struct FleetService {
    store: Store,
}

impl FleetService {
    /// Builds the handler over `store`.
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl FleetIngest for FleetService {
    async fn push_events(
        &self,
        request: Request<PushEventsRequest>,
    ) -> Result<Response<PushEventsReply>, Status> {
        let events = request.into_inner().events;
        if events.len() > MAX_EVENTS_PER_PUSH {
            return Err(Status::invalid_argument(format!(
                "a request may carry at most {MAX_EVENTS_PER_PUSH} events"
            )));
        }
        batch_box(&events)?;
        let max_seq = events.iter().map(|event| event.seq).max().unwrap_or(0);

        let mut valid: Vec<(u64, Envelope)> = Vec::with_capacity(events.len());
        let mut rejected = Vec::new();
        for event in events {
            let seq = event.seq;
            let Some(wire) = event.envelope else {
                rejected.push(Rejection {
                    seq,
                    reason: "missing envelope".to_owned(),
                });
                continue;
            };
            if wire.payload_json.len() > MAX_PAYLOAD_BYTES {
                rejected.push(Rejection {
                    seq,
                    reason: format!("payload_json exceeds {MAX_PAYLOAD_BYTES} bytes"),
                });
                continue;
            }
            match Envelope::try_from(wire) {
                Ok(envelope) => valid.push((seq, envelope)),
                Err(err) => rejected.push(Rejection {
                    seq,
                    reason: err.to_string(),
                }),
            }
        }

        let outcome = self
            .store
            .ingest(&valid)
            .await
            .map_err(|err| storage_unavailable(&err))?;
        rejected.extend(
            outcome
                .rejected
                .into_iter()
                .map(|(seq, reason)| Rejection { seq, reason }),
        );
        rejected.sort_by_key(|rejection| rejection.seq);
        let acked_through_seq = outcome
            .retry_from_seq
            .map_or(max_seq, |seq| seq.saturating_sub(1));
        Ok(Response::new(PushEventsReply {
            acked_through_seq,
            stored: outcome.stored,
            duplicate: outcome.duplicate,
            rejected,
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        let request = request.into_inner();
        let name = check_box(&request.r#box)?;
        no_nul("hostname", &request.hostname)?;
        no_nul("machine_id", &request.machine_id)?;
        no_nul("boot_id", &request.boot_id)?;
        no_nul("fleetd_version", &request.fleetd_version)?;
        self.store
            .heartbeat(&name, &request)
            .await
            .map_err(|err| storage_unavailable(&err))?;
        Ok(Response::new(HeartbeatReply {
            next_in_s: HEARTBEAT_INTERVAL_S,
        }))
    }
}

#[tonic::async_trait]
impl FleetQuery for FleetService {
    async fn list_fleet(
        &self,
        request: Request<ListFleetRequest>,
    ) -> Result<Response<ListFleetReply>, Status> {
        let only = request.into_inner().r#box;
        let (as_of_ms, boxes) = self
            .store
            .list_fleet(only.as_deref())
            .await
            .map_err(|err| storage_unavailable(&err))?;
        Ok(Response::new(ListFleetReply { as_of_ms, boxes }))
    }
}

/// Builds the gRPC router with both services behind `auth`.
///
/// The server applies a 30 second request timeout, 8 concurrent requests and 32
/// concurrent streams per connection, an HTTP/2 keepalive ping every 30 seconds and a
/// 1 MiB request message limit.
pub fn router(store: &Store, auth: &BearerAuth) -> Router {
    let service = FleetService::new(store.clone());
    let ingest = InterceptedService::new(
        FleetIngestServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES),
        auth.clone(),
    );
    let query = InterceptedService::new(
        FleetQueryServer::new(service).max_decoding_message_size(MAX_MESSAGE_BYTES),
        auth.clone(),
    );
    tonic::transport::Server::builder()
        .timeout(REQUEST_TIMEOUT)
        .concurrency_limit_per_connection(CONCURRENCY_PER_CONNECTION)
        .http2_keepalive_interval(Some(KEEPALIVE_INTERVAL))
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .add_service(ingest)
        .add_service(query)
}
