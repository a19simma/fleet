//! The `FleetIngest`, `FleetQuery`, `FleetWorker`, `FleetJobs`, `FleetProfiles` and
//! `FleetBatches` gRPC handlers.

use std::time::Duration;

use fleet_core::Envelope;
use fleet_proto::v1::fleet_batches_server::{FleetBatches, FleetBatchesServer};
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::fleet_profiles_server::{FleetProfiles, FleetProfilesServer};
use fleet_proto::v1::fleet_query_server::{FleetQuery, FleetQueryServer};
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    CancelJobRequest, ClaimJobReply, ClaimJobRequest, CreateProfileRequest, GetBatchReply,
    GetBatchRequest, GetJobRequest, GetProfileBlobReply, GetProfileBlobRequest, GetProfileRequest,
    GetStatsReply, GetStatsRequest, HeartbeatReply, HeartbeatRequest, Job, ListFleetReply,
    ListFleetRequest, ListJobsReply, ListJobsRequest, ListProfilesReply, ListProfilesRequest,
    ProfileVersion, PushEventsReply, PushEventsRequest, QueuedEvent, ReadJobEventsReply,
    ReadJobEventsRequest, ReadTranscriptReply, ReadTranscriptRequest, Rejection, ReportJobReply,
    ReportJobRequest, SubmitBatchReply, SubmitBatchRequest, SubmitJobRequest,
};
use fleet_proto::{ConvertError, validate_box};
use tonic::transport::server::Router;
use tonic::{Request, Response, Status};
use tower::layer::util::{Identity, Stack};

use crate::auth::BearerAuth;
use crate::store::{Store, StoreError};
use fleet_proto::MAX_PROFILE_MESSAGE_BYTES;

/// Seconds a box should wait before its next heartbeat.
pub const HEARTBEAT_INTERVAL_S: u32 = 30;

/// Most events one `PushEvents` call may carry.
pub const MAX_EVENTS_PER_PUSH: usize = 500;

/// Largest `payload_json` one event may carry, in bytes.
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;

/// Seconds a box should wait before it claims again.
pub const CLAIM_INTERVAL_S: u32 = 5;

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

fn same_box(events: &[QueuedEvent]) -> Result<(), Status> {
    let mut names = events
        .iter()
        .filter_map(|event| event.envelope.as_ref())
        .map(|envelope| envelope.r#box.as_str());
    let Some(first) = names.next() else {
        return Ok(());
    };
    if names.any(|other| other != first) {
        return Err(Status::invalid_argument(
            "every event in a request must carry the same box",
        ));
    }
    Ok(())
}

fn no_nul(field: &str, value: &str) -> Result<(), Status> {
    if value.contains('\0') {
        return Err(Status::invalid_argument(format!(
            "{field} contains a NUL character"
        )));
    }
    Ok(())
}

/// Handler for `FleetIngest`, `FleetQuery`, `FleetWorker`, `FleetJobs`, `FleetProfiles` and
/// `FleetBatches`.
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
        same_box(&events)?;
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
                Err(ConvertError::InvalidBox) => {
                    return Err(Status::invalid_argument(
                        ConvertError::InvalidBox.to_string(),
                    ));
                }
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
        let name = validate_box(&request.r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
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

fn worker_error(err: &StoreError) -> Status {
    match err {
        StoreError::StaleReport => {
            Status::failed_precondition("report does not match the running job")
        }
        StoreError::InvalidChunk => Status::invalid_argument("invalid transcript chunk"),
        StoreError::InvalidJob(_) => Status::invalid_argument("invalid job report"),
        StoreError::InvalidTelemetry => Status::invalid_argument("invalid job telemetry"),
        StoreError::TelemetryTooLarge => {
            Status::invalid_argument("too many telemetry events in one report")
        }
        StoreError::NotFound => Status::not_found("job not found"),
        StoreError::LeaseDenied => Status::permission_denied("lease does not match"),
        StoreError::UnknownProfile => Status::not_found("profile not found"),
        other => storage_unavailable(other),
    }
}

#[tonic::async_trait]
impl FleetWorker for FleetService {
    async fn claim_job(
        &self,
        request: Request<ClaimJobRequest>,
    ) -> Result<Response<ClaimJobReply>, Status> {
        let name = validate_box(&request.into_inner().r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let job = self
            .store
            .claim_job(&name)
            .await
            .map_err(|err| worker_error(&err))?;
        let lease_s = if job.is_some() {
            u32::try_from(self.store.lease().as_secs()).unwrap_or(u32::MAX)
        } else {
            0
        };
        Ok(Response::new(ClaimJobReply {
            job,
            lease_s,
            next_in_s: CLAIM_INTERVAL_S,
        }))
    }

    async fn get_profile_blob(
        &self,
        request: Request<GetProfileBlobRequest>,
    ) -> Result<Response<GetProfileBlobReply>, Status> {
        let request = request.into_inner();
        let name = validate_box(&request.r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let reply = self
            .store
            .get_profile_blob(&request.job_id, request.attempt, &name)
            .await
            .map_err(|err| worker_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn report_job(
        &self,
        request: Request<ReportJobRequest>,
    ) -> Result<Response<ReportJobReply>, Status> {
        let request = request.into_inner();
        let name = validate_box(&request.r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let reply = self
            .store
            .report_job(&name, &request)
            .await
            .map_err(|err| worker_error(&err))?;
        Ok(Response::new(reply))
    }
}

fn jobs_error(err: &StoreError) -> Status {
    match err {
        StoreError::KeyConflict => {
            Status::already_exists("idempotency key already used with other parameters")
        }
        StoreError::NotFound => Status::not_found("job not found"),
        StoreError::InvalidJob(_) | StoreError::InvalidChunk => {
            Status::invalid_argument("invalid job request")
        }
        other => storage_unavailable(other),
    }
}

fn profiles_error(err: &StoreError) -> Status {
    match err {
        StoreError::InvalidProfile(fault) => Status::invalid_argument(fault.to_string()),
        StoreError::NotFound => Status::not_found("profile not found"),
        other => storage_unavailable(other),
    }
}

fn batches_error(err: &StoreError) -> Status {
    match err {
        StoreError::KeyConflict => {
            Status::already_exists("idempotency key already used with other parameters")
        }
        StoreError::UnknownProfile => Status::not_found("profile not found"),
        StoreError::NotFound => Status::not_found("batch not found"),
        StoreError::InvalidBatch(reason) => Status::invalid_argument(reason.to_string()),
        StoreError::InvalidProfile(_) => Status::invalid_argument("invalid profile name"),
        StoreError::InvalidJob(_) => Status::invalid_argument("invalid job request"),
        other => storage_unavailable(other),
    }
}

#[tonic::async_trait]
impl FleetBatches for FleetService {
    async fn submit_batch(
        &self,
        request: Request<SubmitBatchRequest>,
    ) -> Result<Response<SubmitBatchReply>, Status> {
        let reply = self
            .store
            .submit_batch(&request.into_inner())
            .await
            .map_err(|err| batches_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_batch(
        &self,
        request: Request<GetBatchRequest>,
    ) -> Result<Response<GetBatchReply>, Status> {
        let reply = self
            .store
            .get_batch(&request.into_inner().batch_id)
            .await
            .map_err(|err| batches_error(&err))?;
        Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl FleetProfiles for FleetService {
    async fn create_profile(
        &self,
        request: Request<CreateProfileRequest>,
    ) -> Result<Response<ProfileVersion>, Status> {
        let request = request.into_inner();
        let reply = self
            .store
            .create_profile(&request.name, &request.content_json)
            .await
            .map_err(|err| profiles_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_profile(
        &self,
        request: Request<GetProfileRequest>,
    ) -> Result<Response<ProfileVersion>, Status> {
        let request = request.into_inner();
        let reply = self
            .store
            .get_profile(&request.name, request.version)
            .await
            .map_err(|err| profiles_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_profiles(
        &self,
        request: Request<ListProfilesRequest>,
    ) -> Result<Response<ListProfilesReply>, Status> {
        let request = request.into_inner();
        let reply = self
            .store
            .list_profiles(request.limit, request.after_name.as_deref())
            .await
            .map_err(|err| profiles_error(&err))?;
        Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl FleetJobs for FleetService {
    async fn submit_job(
        &self,
        request: Request<SubmitJobRequest>,
    ) -> Result<Response<Job>, Status> {
        let job = self
            .store
            .submit_job(&request.into_inner())
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(job))
    }

    async fn get_job(&self, request: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        let job = self
            .store
            .get_job_with_summary(&request.into_inner().job_id)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(job))
    }

    async fn list_jobs(
        &self,
        request: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        let request = request.into_inner();
        let jobs = self
            .store
            .list_jobs(request.state, request.limit)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(ListJobsReply { jobs }))
    }

    async fn cancel_job(
        &self,
        request: Request<CancelJobRequest>,
    ) -> Result<Response<Job>, Status> {
        let job = self
            .store
            .cancel_job(&request.into_inner().job_id)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(job))
    }

    async fn read_transcript(
        &self,
        request: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        let request = request.into_inner();
        let reply = self
            .store
            .read_transcript(&request.job_id, request.after_seq, request.limit)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn read_job_events(
        &self,
        request: Request<ReadJobEventsRequest>,
    ) -> Result<Response<ReadJobEventsReply>, Status> {
        let request = request.into_inner();
        let reply = self
            .store
            .read_job_events(&request.job_id, request.after_seq, request.limit)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsReply>, Status> {
        let reply = self
            .store
            .stats(&request.into_inner())
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(reply))
    }
}

/// Builds the gRPC router with `auth` applied once as a layer over every service.
///
/// The server applies a 30 second request timeout, 8 concurrent requests and 32
/// concurrent streams per connection, an HTTP/2 keepalive ping every 30 seconds and a
/// 1 MiB request message limit.
pub fn router(store: &Store, auth: &BearerAuth) -> Router<Stack<BearerAuth, Identity>> {
    let service = FleetService::new(store.clone());
    let ingest =
        FleetIngestServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let query = FleetQueryServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let worker = FleetWorkerServer::new(service.clone())
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_PROFILE_MESSAGE_BYTES);
    let jobs = FleetJobsServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let batches =
        FleetBatchesServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let profiles =
        FleetProfilesServer::new(service).max_decoding_message_size(MAX_PROFILE_MESSAGE_BYTES);
    tonic::transport::Server::builder()
        .timeout(REQUEST_TIMEOUT)
        .concurrency_limit_per_connection(CONCURRENCY_PER_CONNECTION)
        .http2_keepalive_interval(Some(KEEPALIVE_INTERVAL))
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
        .layer(auth.clone())
        .add_service(ingest)
        .add_service(query)
        .add_service(worker)
        .add_service(jobs)
        .add_service(profiles)
        .add_service(batches)
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::*;
    use crate::jobs::JobInvalid;

    #[test]
    fn jobs_errors_map_to_fixed_statuses() {
        let cases = [
            (StoreError::KeyConflict, Code::AlreadyExists),
            (StoreError::NotFound, Code::NotFound),
            (
                StoreError::InvalidJob(JobInvalid::JobId),
                Code::InvalidArgument,
            ),
            (StoreError::InvalidChunk, Code::InvalidArgument),
            (
                StoreError::Database(sqlx::Error::PoolTimedOut),
                Code::Unavailable,
            ),
        ];
        for (err, code) in cases {
            let status = jobs_error(&err);
            assert_eq!(status.code(), code, "{err}");
            assert!(!status.message().contains("pool"), "{err}");
        }
    }

    #[test]
    fn worker_errors_map_to_fixed_statuses() {
        let cases = [
            (StoreError::StaleReport, Code::FailedPrecondition),
            (StoreError::InvalidChunk, Code::InvalidArgument),
            (StoreError::InvalidTelemetry, Code::InvalidArgument),
            (StoreError::TelemetryTooLarge, Code::InvalidArgument),
            (
                StoreError::InvalidJob(JobInvalid::PrUrl),
                Code::InvalidArgument,
            ),
            (StoreError::NotFound, Code::NotFound),
            (
                StoreError::Database(sqlx::Error::PoolTimedOut),
                Code::Unavailable,
            ),
        ];
        for (err, code) in cases {
            let status = worker_error(&err);
            assert_eq!(status.code(), code, "{err}");
            assert!(!status.message().contains("pool"), "{err}");
        }
    }
}
