//! The `FleetIngest` and `FleetQuery` gRPC handlers.

use fleet_core::{BoxName, Envelope};
use fleet_proto::ConvertError;
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::fleet_query_server::{FleetQuery, FleetQueryServer};
use fleet_proto::v1::{
    HeartbeatReply, HeartbeatRequest, ListFleetReply, ListFleetRequest, PushEventsReply,
    PushEventsRequest, QueuedEvent, Rejection,
};
use tonic::transport::server::Router;
use tonic::{Request, Response, Status};

use crate::auth::BearerAuth;
use crate::store::{Store, StoreError};

/// Seconds a box should wait before its next heartbeat.
pub const HEARTBEAT_INTERVAL_S: u32 = 30;

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

fn reject(seq: u64, reason: String) -> Rejection {
    Rejection { seq, reason }
}

/// Handler for `FleetIngest`.
#[derive(Debug, Clone)]
pub struct IngestService {
    store: Store,
}

impl IngestService {
    /// Builds the handler over `store`.
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl FleetIngest for IngestService {
    async fn push_events(
        &self,
        request: Request<PushEventsRequest>,
    ) -> Result<Response<PushEventsReply>, Status> {
        let events = request.into_inner().events;
        batch_box(&events)?;
        let acked_through_seq = events.iter().map(|event| event.seq).max().unwrap_or(0);

        let mut valid: Vec<(u64, Envelope)> = Vec::with_capacity(events.len());
        let mut rejected = Vec::new();
        for event in events {
            let Some(wire) = event.envelope else {
                rejected.push(reject(event.seq, "missing envelope".to_owned()));
                continue;
            };
            match Envelope::try_from(wire) {
                Ok(envelope) => valid.push((event.seq, envelope)),
                Err(err @ ConvertError::InvalidBox(_)) => {
                    return Err(Status::invalid_argument(err.to_string()));
                }
                Err(err) => rejected.push(reject(event.seq, err.to_string())),
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
                .map(|(seq, reason)| reject(seq, reason)),
        );
        rejected.sort_by_key(|rejection| rejection.seq);
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
        self.store
            .heartbeat(&name, &request)
            .await
            .map_err(|err| storage_unavailable(&err))?;
        Ok(Response::new(HeartbeatReply {
            next_in_s: HEARTBEAT_INTERVAL_S,
        }))
    }
}

/// Handler for `FleetQuery`.
#[derive(Debug, Clone)]
pub struct QueryService {
    store: Store,
}

impl QueryService {
    /// Builds the handler over `store`.
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[tonic::async_trait]
impl FleetQuery for QueryService {
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
pub fn router(store: &Store, auth: &BearerAuth) -> Router {
    let ingest =
        FleetIngestServer::with_interceptor(IngestService::new(store.clone()), auth.clone());
    let query = FleetQueryServer::with_interceptor(QueryService::new(store.clone()), auth.clone());
    tonic::transport::Server::builder()
        .add_service(ingest)
        .add_service(query)
}
