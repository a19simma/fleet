//! The `FleetIngest`, `FleetQuery`, `FleetWorker`, `FleetJobs`, `FleetJudge`, `FleetProfiles`,
//! `FleetBatches` and `FleetCredentials` gRPC handlers.

use std::path::{Path, PathBuf};
use std::time::Duration;

use fleet_core::Envelope;
use fleet_proto::v1::fleet_batches_server::{FleetBatches, FleetBatchesServer};
use fleet_proto::v1::fleet_capability_admin_server::{
    FleetCapabilityAdmin, FleetCapabilityAdminServer,
};
use fleet_proto::v1::fleet_catalog_admin_server::{FleetCatalogAdmin, FleetCatalogAdminServer};
use fleet_proto::v1::fleet_catalog_server::{FleetCatalog, FleetCatalogServer};
use fleet_proto::v1::fleet_credentials_server::{FleetCredentials, FleetCredentialsServer};
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::fleet_judge_server::{FleetJudge, FleetJudgeServer};
use fleet_proto::v1::fleet_profiles_server::{FleetProfiles, FleetProfilesServer};
use fleet_proto::v1::fleet_query_server::{FleetQuery, FleetQueryServer};
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    CancelJobRequest, CatalogItem, ClaimJobReply, ClaimJobRequest, CreateProfileRequest,
    CredentialInfo, DeleteCredentialReply, DeleteCredentialRequest, GetBatchReply, GetBatchRequest,
    GetJobCredentialsReply, GetJobCredentialsRequest, GetJobRequest, GetJobTimingReply,
    GetJobTimingRequest, GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply,
    GetProfileBlobRequest, GetProfileRequest, GetStatsReply, GetStatsRequest,
    GrantCapabilityRequest, HeartbeatReply, HeartbeatRequest, Job, ListCapabilitiesReply,
    ListCapabilitiesRequest, ListCatalogReply, ListCatalogRequest, ListCredentialsReply,
    ListCredentialsRequest, ListFleetReply, ListFleetRequest, ListJobsReply, ListJobsRequest,
    ListProfilesReply, ListProfilesRequest, Profile, ProfileVersion, PushEventsReply,
    PushEventsRequest, PutCredentialRequest, QueuedEvent, ReadJobEventsReply, ReadJobEventsRequest,
    ReadTranscriptReply, ReadTranscriptRequest, Rejection, ReportJobReply, ReportJobRequest,
    ReportShellLogReply, ReportShellLogRequest, ReportTimingReply, ReportTimingRequest,
    RevokeCapabilityReply, RevokeCapabilityRequest, SetCatalogItemEnabledRequest,
    ShareProfileRequest, StreamShellLogChunk, StreamShellLogRequest, SubmitBatchReply,
    SubmitBatchRequest, SubmitJobRequest, SubmitJudgeRequest, UnshareProfileRequest,
    UpsertCatalogItemRequest, UserCapability, VerifyCredentialReply, VerifyCredentialRequest,
};
use fleet_proto::{ConvertError, validate_box};
use tonic::codegen::BoxStream;
use tonic::service::Routes;
use tonic::transport::Server;
use tonic::transport::server::{Router, TcpIncoming};
use tonic::{Request, Response, Status};
use tonic_prost::prost::Message;
use tower::layer::util::{Identity, Stack};

use crate::auth::{ADMIN_REQUIRED, BearerAuth, Caller};
use crate::catalog;
use crate::cred::CredentialService;
use crate::cred::capability::{self, Capabilities};
use crate::jobs::validate_job_id;
use crate::profiles::{self, ProfileContent, ProfileFault, Viewer};
use crate::store::{Store, StoreError};
use crate::timing;
use crate::web::{Dispatch, HEADER_READ_TIMEOUT, Web, serve};
use fleet_proto::MAX_PROFILE_MESSAGE_BYTES;

/// Relays a signed update manifest to boxes in `HeartbeatReply`.
///
/// The server holds no key and verifies nothing: it passes two files on, the manifest and the
/// signature beside it. fleetd checks the signature against its own trust root.
#[derive(Debug, Clone, Default)]
pub struct UpdateRelay {
    manifest: Option<PathBuf>,
}

impl UpdateRelay {
    /// Relays the manifest at `manifest` and the signature at `manifest` plus `.minisig`.
    /// `None` relays nothing.
    #[must_use]
    pub fn new(manifest: Option<PathBuf>) -> Self {
        Self { manifest }
    }

    /// Reads both files and returns them as `(manifest, signature)`. A missing file, a read
    /// error, a manifest that is not JSON or a pair over the caps in
    /// [`fleet_proto::update_within_caps`] gives `None`, so the reply carries neither.
    async fn load(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        let path = self.manifest.as_ref()?;
        let mut sig_path = path.clone().into_os_string();
        sig_path.push(".minisig");
        let manifest = read_capped(path, fleet_proto::MAX_MANIFEST_BYTES).await?;
        let signature =
            read_capped(&PathBuf::from(sig_path), fleet_proto::MAX_SIGNATURE_BYTES).await?;
        if serde_json::from_slice::<serde_json::Value>(&manifest).is_err() {
            tracing::warn!(path = %path.display(), "update manifest is not JSON; not relayed");
            return None;
        }
        let probe = HeartbeatReply {
            next_in_s: 0,
            update_manifest: Some(manifest),
            update_signature: Some(signature),
        };
        if !fleet_proto::update_within_caps(&probe) {
            return None;
        }
        Some((probe.update_manifest?, probe.update_signature?))
    }
}

async fn read_capped(path: &Path, cap: usize) -> Option<Vec<u8>> {
    use tokio::io::AsyncReadExt;
    let read = async {
        let file = tokio::fs::File::open(path).await?;
        let mut buf = Vec::new();
        file.take(cap as u64 + 1).read_to_end(&mut buf).await?;
        Ok::<_, std::io::Error>(buf)
    };
    match read.await {
        Ok(buf) if buf.len() <= cap => Some(buf),
        Ok(_) => {
            tracing::warn!(path = %path.display(), cap, "update file over its cap; not relayed");
            None
        }
        Err(err) => {
            tracing::warn!(path = %path.display(), %err, "update file unreadable; not relayed");
            None
        }
    }
}

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

const TIMING_SPAN_WIRE_OVERHEAD: usize = 64;

const TIMING_COMMAND_WIRE_OVERHEAD: usize = 128;

const TIMING_SUMMARY_WIRE_OVERHEAD: usize = 128;

/// Largest `GetJobTimingReply` the server encodes, in bytes.
///
/// Derived from the stored caps: [`fleet_proto::MAX_SPANS`] spans of two names each and
/// [`fleet_proto::MAX_SHELL_COMMANDS`] commands of id, command, log and `ended_by`, plus
/// fixed per-item wire overhead. A reply over it is refused instead of sent.
pub const MAX_JOB_TIMING_REPLY_BYTES: usize = fleet_proto::MAX_SPANS
    * (2 * fleet_proto::MAX_TIMING_NAME_BYTES + TIMING_SPAN_WIRE_OVERHEAD)
    + fleet_proto::MAX_SHELL_COMMANDS
        * (fleet_proto::MAX_COMMAND_ID_BYTES
            + fleet_proto::MAX_TIMING_NAME_BYTES
            + fleet_proto::MAX_COMMAND_BYTES
            + fleet_proto::MAX_SHELL_LOG_BYTES
            + TIMING_COMMAND_WIRE_OVERHEAD)
    + TIMING_SUMMARY_WIRE_OVERHEAD;

/// Largest `FleetCredentials` request message the server decodes, in bytes.
pub const MAX_CREDENTIAL_MESSAGE_BYTES: usize = 4 * 1024;

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
    credentials: Option<CredentialService>,
    capabilities: Capabilities,
    update: UpdateRelay,
    timing_reply_cap: usize,
}

impl FleetService {
    /// Builds the handler over `store`. The credential RPCs answer `FAILED_PRECONDITION`.
    pub fn new(store: Store) -> Self {
        Self {
            capabilities: Capabilities::new(store.pool().clone()),
            store,
            credentials: None,
            update: UpdateRelay::default(),
            timing_reply_cap: MAX_JOB_TIMING_REPLY_BYTES,
        }
    }

    /// Sets the largest `GetJobTimingReply` the handler returns, in encoded bytes.
    #[must_use]
    pub fn with_timing_reply_cap(mut self, cap: usize) -> Self {
        self.timing_reply_cap = cap;
        self
    }

    /// Relays the signed update manifest in `HeartbeatReply`.
    #[must_use]
    pub fn with_update(mut self, update: UpdateRelay) -> Self {
        self.update = update;
        self
    }

    /// Enables the credential RPCs.
    #[must_use]
    pub fn with_credentials(mut self, credentials: Option<CredentialService>) -> Self {
        self.credentials = credentials;
        self
    }

    fn credential_owner<T>(
        &self,
        request: &Request<T>,
    ) -> Result<(&CredentialService, i64), Status> {
        let user_id = caller_of(request)
            .ok_or_else(|| Status::permission_denied("credentials need a user token"))?;
        let service = self
            .credentials
            .as_ref()
            .ok_or_else(|| Status::failed_precondition(fleet_proto::PRECONDITION_NOT_CONFIGURED))?;
        Ok((service, user_id))
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
        let (update_manifest, update_signature) = match self.update.load().await {
            Some((manifest, signature)) => (Some(manifest), Some(signature)),
            None => (None, None),
        };
        Ok(Response::new(HeartbeatReply {
            next_in_s: HEARTBEAT_INTERVAL_S,
            update_manifest,
            update_signature,
        }))
    }
}

#[tonic::async_trait]
impl FleetQuery for FleetService {
    async fn list_fleet(
        &self,
        request: Request<ListFleetRequest>,
    ) -> Result<Response<ListFleetReply>, Status> {
        let owner = caller_of(&request);
        let only = request.into_inner().r#box;
        let (as_of_ms, boxes) = self
            .store
            .list_fleet_for(owner, only.as_deref())
            .await
            .map_err(|err| storage_unavailable(&err))?;
        Ok(Response::new(ListFleetReply { as_of_ms, boxes }))
    }
}

/// Validates the box and job id of a timing report before any query.
///
/// The live lease (job, attempt and box) is checked inside the transaction of
/// [`timing::store_timing`].
///
/// # Errors
/// `FAILED_PRECONDITION` when the box or job id is malformed.
fn report_box(request: &ReportTimingRequest) -> Result<fleet_core::BoxName, Status> {
    let stale = || Status::failed_precondition("report does not match the running job");
    let name = validate_box(&request.r#box).map_err(|_| stale())?;
    validate_job_id(&request.job_id).map_err(|_| stale())?;
    Ok(name)
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

    async fn get_job_transcript(
        &self,
        request: Request<GetJobTranscriptRequest>,
    ) -> Result<Response<GetJobTranscriptReply>, Status> {
        let request = request.into_inner();
        let name = validate_box(&request.r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let reply = self
            .store
            .get_job_transcript(&request.job_id, request.attempt, &name)
            .await
            .map_err(|err| worker_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_job_credentials(
        &self,
        request: Request<GetJobCredentialsRequest>,
    ) -> Result<Response<GetJobCredentialsReply>, Status> {
        let service = self
            .credentials
            .as_ref()
            .ok_or_else(|| Status::failed_precondition(fleet_proto::PRECONDITION_NOT_CONFIGURED))?;
        let request = request.into_inner();
        let name = validate_box(&request.r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let reply = service
            .job_credentials(&request.job_id, request.attempt, name.as_str())
            .await?;
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

    async fn report_timing(
        &self,
        request: Request<ReportTimingRequest>,
    ) -> Result<Response<ReportTimingReply>, Status> {
        let name = report_box(request.get_ref())?;
        timing::store_timing(self.store.pool(), &name, request.get_ref())
            .await
            .map(Response::new)
    }

    async fn report_shell_log(
        &self,
        request: Request<ReportShellLogRequest>,
    ) -> Result<Response<ReportShellLogReply>, Status> {
        timing::report_shell_log(self.store.pool(), request.get_ref())
            .await
            .map(Response::new)
    }
}

#[tonic::async_trait]
impl FleetCredentials for FleetService {
    async fn put_credential(
        &self,
        request: Request<PutCredentialRequest>,
    ) -> Result<Response<CredentialInfo>, Status> {
        let (service, user_id) = self.credential_owner(&request)?;
        let info = service.put(user_id, request.into_inner()).await?;
        Ok(Response::new(info))
    }

    async fn list_credentials(
        &self,
        request: Request<ListCredentialsRequest>,
    ) -> Result<Response<ListCredentialsReply>, Status> {
        let (service, user_id) = self.credential_owner(&request)?;
        Ok(Response::new(service.list(user_id).await?))
    }

    async fn delete_credential(
        &self,
        request: Request<DeleteCredentialRequest>,
    ) -> Result<Response<DeleteCredentialReply>, Status> {
        let (service, user_id) = self.credential_owner(&request)?;
        Ok(Response::new(
            service.delete(user_id, request.get_ref()).await?,
        ))
    }

    async fn verify_credential(
        &self,
        request: Request<VerifyCredentialRequest>,
    ) -> Result<Response<VerifyCredentialReply>, Status> {
        let (service, user_id) = self.credential_owner(&request)?;
        Ok(Response::new(
            service.verify(user_id, request.get_ref()).await?,
        ))
    }
}

fn caller_of<T>(request: &Request<T>) -> Option<i64> {
    request
        .extensions()
        .get::<Caller>()
        .map(|caller| caller.user_id)
}

fn admin_of<T>(request: &Request<T>) -> Result<i64, Status> {
    let caller = request
        .extensions()
        .get::<Caller>()
        .ok_or_else(|| Status::permission_denied(ADMIN_REQUIRED))?;
    caller.require_admin()?;
    Ok(caller.user_id)
}

fn jobs_error(err: &StoreError) -> Status {
    match err {
        StoreError::KeyConflict => {
            Status::already_exists("idempotency key already used with other parameters")
        }
        StoreError::NotFound => Status::not_found("job not found"),
        StoreError::UnknownProfile => Status::not_found("profile not found"),
        StoreError::ToolsNotGranted => {
            Status::permission_denied(profiles::ERR_PROFILE_TOOLS_NOT_GRANTED)
        }
        StoreError::InvalidProfile(ProfileFault::Unowned) => {
            Status::permission_denied(profiles::ERR_PROFILE_SUBMIT_UNOWNED)
        }
        StoreError::InvalidJob(_) | StoreError::InvalidChunk => {
            Status::invalid_argument("invalid job request")
        }
        other => storage_unavailable(other),
    }
}

fn profiles_error(err: &StoreError) -> Status {
    match err {
        StoreError::InvalidProfile(ProfileFault::Unowned) => {
            Status::permission_denied(profiles::ERR_PROFILE_UNOWNED)
        }
        StoreError::InvalidProfile(fault @ ProfileFault::NotOwner) => {
            Status::permission_denied(fault.to_string())
        }
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
        let owner = caller_of(&request);
        let reply = self
            .store
            .submit_batch_for(owner, &request.into_inner())
            .await
            .map_err(|err| batches_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_batch(
        &self,
        request: Request<GetBatchRequest>,
    ) -> Result<Response<GetBatchReply>, Status> {
        let owner = caller_of(&request);
        let reply = self
            .store
            .get_batch_for(owner, &request.into_inner().batch_id)
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
        let caller = caller_of(&request)
            .ok_or_else(|| Status::permission_denied(profiles::ERR_PROFILE_UNOWNED))?;
        let request = request.into_inner();
        let content = ProfileContent::select(&request.content_json, &request.content_toml)
            .map_err(|fault| Status::invalid_argument(fault.to_string()))?;
        let reply = self
            .store
            .create_profile_content(Some(caller), &request.name, content)
            .await
            .map_err(|err| profiles_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_profile(
        &self,
        request: Request<GetProfileRequest>,
    ) -> Result<Response<ProfileVersion>, Status> {
        let viewer = Viewer::from(caller_of(&request));
        let request = request.into_inner();
        let reply = self
            .store
            .get_profile(viewer, &request.name, request.version)
            .await
            .map_err(|err| profiles_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_profiles(
        &self,
        request: Request<ListProfilesRequest>,
    ) -> Result<Response<ListProfilesReply>, Status> {
        let viewer = Viewer::from(caller_of(&request));
        let request = request.into_inner();
        let reply = self
            .store
            .list_profiles(viewer, request.limit, request.after_name.as_deref())
            .await
            .map_err(|err| profiles_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn share_profile(
        &self,
        request: Request<ShareProfileRequest>,
    ) -> Result<Response<Profile>, Status> {
        let caller = caller_of(&request);
        profiles::share_owned(self.store.pool(), caller, &request.get_ref().name)
            .await
            .map(Response::new)
            .map_err(|err| profiles_error(&err))
    }

    async fn unshare_profile(
        &self,
        request: Request<UnshareProfileRequest>,
    ) -> Result<Response<Profile>, Status> {
        let caller = caller_of(&request);
        profiles::unshare_owned(self.store.pool(), caller, &request.get_ref().name)
            .await
            .map(Response::new)
            .map_err(|err| profiles_error(&err))
    }
}

#[tonic::async_trait]
impl FleetCatalog for FleetService {
    async fn list_catalog(
        &self,
        request: Request<ListCatalogRequest>,
    ) -> Result<Response<ListCatalogReply>, Status> {
        catalog::list_catalog(self.store.pool(), request.get_ref())
            .await
            .map(Response::new)
    }
}

#[tonic::async_trait]
impl FleetCatalogAdmin for FleetService {
    async fn upsert_catalog_item(
        &self,
        request: Request<UpsertCatalogItemRequest>,
    ) -> Result<Response<CatalogItem>, Status> {
        let actor = admin_of(&request)?;
        catalog::upsert_item(self.store.pool(), actor, request.get_ref())
            .await
            .map(Response::new)
    }

    async fn set_catalog_item_enabled(
        &self,
        request: Request<SetCatalogItemEnabledRequest>,
    ) -> Result<Response<CatalogItem>, Status> {
        let actor = admin_of(&request)?;
        catalog::set_enabled(self.store.pool(), actor, request.get_ref())
            .await
            .map(Response::new)
    }
}

#[tonic::async_trait]
impl FleetCapabilityAdmin for FleetService {
    async fn grant_capability(
        &self,
        request: Request<GrantCapabilityRequest>,
    ) -> Result<Response<UserCapability>, Status> {
        let actor = admin_of(&request)?;
        capability::grant(&self.capabilities, actor, request.get_ref())
            .await
            .map(Response::new)
    }

    async fn revoke_capability(
        &self,
        request: Request<RevokeCapabilityRequest>,
    ) -> Result<Response<RevokeCapabilityReply>, Status> {
        let actor = admin_of(&request)?;
        capability::revoke(&self.capabilities, actor, request.get_ref())
            .await
            .map(Response::new)
    }

    async fn list_capabilities(
        &self,
        request: Request<ListCapabilitiesRequest>,
    ) -> Result<Response<ListCapabilitiesReply>, Status> {
        let actor = admin_of(&request)?;
        capability::list(&self.capabilities, actor, request.get_ref())
            .await
            .map(Response::new)
    }
}

#[tonic::async_trait]
impl FleetJudge for FleetService {
    async fn submit_judge(
        &self,
        request: Request<SubmitJudgeRequest>,
    ) -> Result<Response<Job>, Status> {
        let owner = caller_of(&request);
        let job = self
            .store
            .submit_judge_for(owner, &request.into_inner())
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(job))
    }
}

#[tonic::async_trait]
impl FleetJobs for FleetService {
    async fn submit_job(
        &self,
        request: Request<SubmitJobRequest>,
    ) -> Result<Response<Job>, Status> {
        let owner = caller_of(&request);
        let job = self
            .store
            .submit_job_for(owner, &request.into_inner())
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(job))
    }

    async fn get_job(&self, request: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        let owner = caller_of(&request);
        let job = self
            .store
            .get_job_with_summary_for(owner, &request.into_inner().job_id)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(job))
    }

    async fn list_jobs(
        &self,
        request: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        let owner = caller_of(&request);
        let request = request.into_inner();
        let jobs = self
            .store
            .list_jobs_for(owner, request.state, request.limit)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(ListJobsReply { jobs }))
    }

    async fn cancel_job(
        &self,
        request: Request<CancelJobRequest>,
    ) -> Result<Response<Job>, Status> {
        let owner = caller_of(&request);
        let job = self
            .store
            .cancel_job_for(owner, &request.into_inner().job_id)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(job))
    }

    async fn read_transcript(
        &self,
        request: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        let owner = caller_of(&request);
        let request = request.into_inner();
        let reply = self
            .store
            .read_transcript_for(owner, &request.job_id, request.after_seq, request.limit)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn read_job_events(
        &self,
        request: Request<ReadJobEventsRequest>,
    ) -> Result<Response<ReadJobEventsReply>, Status> {
        let owner = caller_of(&request);
        let request = request.into_inner();
        let reply = self
            .store
            .read_job_events_for(owner, &request.job_id, request.after_seq, request.limit)
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsReply>, Status> {
        let owner = caller_of(&request);
        let reply = self
            .store
            .stats_for(owner, &request.into_inner())
            .await
            .map_err(|err| jobs_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_job_timing(
        &self,
        request: Request<GetJobTimingRequest>,
    ) -> Result<Response<GetJobTimingReply>, Status> {
        let owner = caller_of(&request)
            .ok_or_else(|| Status::permission_denied("job timing needs a user token"))?;
        let reply =
            timing::read_job_timing(self.store.pool(), Some(owner), request.get_ref()).await?;
        if reply.encoded_len() > self.timing_reply_cap {
            return Err(Status::internal("job timing too large"));
        }
        Ok(Response::new(reply))
    }

    type StreamShellLogStream = BoxStream<StreamShellLogChunk>;

    async fn stream_shell_log(
        &self,
        request: Request<StreamShellLogRequest>,
    ) -> Result<Response<Self::StreamShellLogStream>, Status> {
        let owner = caller_of(&request);
        let request = request.into_inner();
        self.store
            .get_job_for(owner, &request.job_id)
            .await
            .map_err(|err| jobs_error(&err))?;
        timing::stream_shell_log(self.store.pool(), &request, timing::StreamLimits::default())
            .map(Response::new)
    }
}

/// Builds the gRPC router with `auth` applied once as a layer over every service.
///
/// The server applies a 30 second request timeout, 8 concurrent requests and 32
/// concurrent streams per connection, an HTTP/2 keepalive ping every 30 seconds and a
/// 1 MiB request message limit.
pub fn router(store: &Store, auth: &BearerAuth) -> Router<Stack<BearerAuth, Identity>> {
    router_with(store, auth, None)
}

/// Same as [`router`] with the credential RPCs backed by `credentials`.
pub fn router_with(
    store: &Store,
    auth: &BearerAuth,
    credentials: Option<CredentialService>,
) -> Router<Stack<BearerAuth, Identity>> {
    server()
        .layer(auth.clone())
        .add_routes(routes(store, credentials, UpdateRelay::default()))
}

fn server() -> Server {
    Server::builder()
        .timeout(REQUEST_TIMEOUT)
        .concurrency_limit_per_connection(CONCURRENCY_PER_CONNECTION)
        .http2_keepalive_interval(Some(KEEPALIVE_INTERVAL))
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
}

/// Serves the gRPC services and the web pages on one listener until `shutdown` resolves.
///
/// Runs the accept loop in [`crate::web::serve`] with the connection limits of [`router`]
/// and accepts HTTP/1.1 for browsers, giving each client [`HEADER_READ_TIMEOUT`] to send a
/// request head. The bearer `auth` wraps the gRPC services only; the web router has its own
/// session checks. In-flight requests drain on shutdown.
///
/// # Errors
///
/// Returns the I/O error that stopped the server.
pub async fn serve_with_web(
    store: &Store,
    auth: &BearerAuth,
    web: Web,
    incoming: TcpIncoming,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    serve_with_credentials(
        store,
        auth,
        web,
        None,
        UpdateRelay::default(),
        incoming,
        shutdown,
    )
    .await
}

/// Same as [`serve_with_web`] with the credential RPCs backed by `credentials`.
///
/// # Errors
///
/// Returns the I/O error that stopped the server.
pub async fn serve_with_credentials(
    store: &Store,
    auth: &BearerAuth,
    web: Web,
    credentials: Option<CredentialService>,
    update: UpdateRelay,
    incoming: TcpIncoming,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    serve_routes(
        routes(store, credentials, update),
        auth,
        web,
        incoming,
        shutdown,
        HEADER_READ_TIMEOUT,
    )
    .await
}

/// Same as [`serve_with_web`] with an explicit HTTP/1 header-read timeout.
///
/// # Errors
///
/// Returns the I/O error that stopped the server.
pub async fn serve_with_web_timeout(
    store: &Store,
    auth: &BearerAuth,
    web: Web,
    incoming: TcpIncoming,
    shutdown: impl Future<Output = ()>,
    header_read_timeout: Duration,
) -> std::io::Result<()> {
    serve_routes(
        routes(store, None, UpdateRelay::default()),
        auth,
        web,
        incoming,
        shutdown,
        header_read_timeout,
    )
    .await
}

async fn serve_routes(
    routes: Routes,
    auth: &BearerAuth,
    web: Web,
    incoming: TcpIncoming,
    shutdown: impl Future<Output = ()>,
    header_read_timeout: Duration,
) -> std::io::Result<()> {
    let grpc = tower::Layer::layer(auth, routes);
    serve(
        Dispatch::new(grpc, web),
        incoming,
        shutdown,
        header_read_timeout,
    )
    .await
}

fn routes(store: &Store, credentials: Option<CredentialService>, update: UpdateRelay) -> Routes {
    let service = FleetService::new(store.clone())
        .with_credentials(credentials)
        .with_update(update);
    let ingest =
        FleetIngestServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let query = FleetQueryServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let worker = FleetWorkerServer::new(service.clone())
        .max_decoding_message_size(MAX_MESSAGE_BYTES)
        .max_encoding_message_size(MAX_PROFILE_MESSAGE_BYTES);
    let jobs = FleetJobsServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let judge = FleetJudgeServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let batches =
        FleetBatchesServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let credentials = FleetCredentialsServer::new(service.clone())
        .max_decoding_message_size(MAX_CREDENTIAL_MESSAGE_BYTES);
    let catalog = FleetCatalogServer::new(service.clone());
    let catalog_admin = FleetCatalogAdminServer::new(service.clone())
        .max_decoding_message_size(MAX_PROFILE_MESSAGE_BYTES);
    let capability_admin = FleetCapabilityAdminServer::new(service.clone());
    let profiles =
        FleetProfilesServer::new(service).max_decoding_message_size(MAX_PROFILE_MESSAGE_BYTES);
    Routes::new(ingest)
        .add_service(query)
        .add_service(worker)
        .add_service(jobs)
        .add_service(judge)
        .add_service(profiles)
        .add_service(batches)
        .add_service(credentials)
        .add_service(catalog)
        .add_service(catalog_admin)
        .add_service(capability_admin)
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::*;
    use crate::jobs::JobInvalid;
    use fleet_proto::v1::{GetJobTimingReply, ShellCommand, TimingSpan, TimingSummary};
    use tonic_prost::prost::Message;

    #[test]
    fn the_worst_case_timing_reply_fits_the_encoding_limit() {
        let name = "n".repeat(fleet_proto::MAX_TIMING_NAME_BYTES);
        let span = TimingSpan {
            kind: i32::MAX,
            start_ms: u64::MAX,
            end_ms: u64::MAX,
            name: name.clone(),
            tool_use_id: Some(name.clone()),
        };
        let command = ShellCommand {
            id: name.clone(),
            command: "c".repeat(fleet_proto::MAX_COMMAND_BYTES),
            background: true,
            started_ms: u64::MAX,
            ended_ms: Some(u64::MAX),
            duration_ms: u64::MAX,
            exit_code: Some(i32::MIN),
            log: "l".repeat(fleet_proto::MAX_SHELL_LOG_BYTES),
            log_truncated: true,
            ended_by: Some(name),
        };
        let reply = GetJobTimingReply {
            summary: Some(TimingSummary {
                wall_ms: u64::MAX,
                api_wait_ms: u64::MAX,
                tool_ms: u64::MAX,
                shell_ms: u64::MAX,
                idle_ms: u64::MAX,
                overhead_ms: u64::MAX,
            }),
            spans: vec![span; fleet_proto::MAX_SPANS],
            shell_commands: vec![command; fleet_proto::MAX_SHELL_COMMANDS],
        };
        let size = reply.encoded_len();
        assert!(size <= MAX_JOB_TIMING_REPLY_BYTES, "{size}");
        assert!(size * 10 >= MAX_JOB_TIMING_REPLY_BYTES * 9, "{size}");
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("fleet-upd3-{}-{tag}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn relay_at(dir: &Path) -> UpdateRelay {
        UpdateRelay::new(Some(dir.join("manifest.json")))
    }

    #[tokio::test]
    async fn no_manifest_set_relays_nothing() {
        assert_eq!(UpdateRelay::default().load().await, None);
        assert_eq!(UpdateRelay::new(None).load().await, None);
    }

    #[tokio::test]
    async fn both_files_are_relayed_verbatim() {
        let dir = scratch("both");
        std::fs::write(dir.join("manifest.json"), b"{\"seq\":1}").unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), b"sig-bytes").unwrap();
        assert_eq!(
            relay_at(&dir).load().await,
            Some((b"{\"seq\":1}".to_vec(), b"sig-bytes".to_vec()))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn one_missing_file_relays_nothing() {
        let dir = scratch("missing");
        std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
        assert_eq!(relay_at(&dir).load().await, None);
        std::fs::remove_file(dir.join("manifest.json")).unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), b"sig").unwrap();
        assert_eq!(relay_at(&dir).load().await, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn over_cap_files_relay_nothing() {
        let dir = scratch("cap");
        let json = |len: usize| format!("\"{}\"", "a".repeat(len - 2)).into_bytes();
        std::fs::write(dir.join("manifest.json.minisig"), b"sig").unwrap();
        std::fs::write(
            dir.join("manifest.json"),
            json(fleet_proto::MAX_MANIFEST_BYTES),
        )
        .unwrap();
        assert!(relay_at(&dir).load().await.is_some());
        std::fs::write(
            dir.join("manifest.json"),
            json(fleet_proto::MAX_MANIFEST_BYTES + 1),
        )
        .unwrap();
        assert_eq!(relay_at(&dir).load().await, None);
        std::fs::write(dir.join("manifest.json"), b"{}").unwrap();
        std::fs::write(
            dir.join("manifest.json.minisig"),
            vec![b'x'; fleet_proto::MAX_SIGNATURE_BYTES],
        )
        .unwrap();
        assert!(relay_at(&dir).load().await.is_some());
        std::fs::write(
            dir.join("manifest.json.minisig"),
            vec![b'x'; fleet_proto::MAX_SIGNATURE_BYTES + 1],
        )
        .unwrap();
        assert_eq!(relay_at(&dir).load().await, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn non_json_manifest_relays_nothing() {
        let dir = scratch("json");
        std::fs::write(dir.join("manifest.json"), b"not json").unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), b"sig").unwrap();
        assert_eq!(relay_at(&dir).load().await, None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn swapped_files_are_picked_up() {
        let dir = scratch("swap");
        let relay = relay_at(&dir);
        assert_eq!(relay.load().await, None);
        std::fs::write(dir.join("manifest.json"), b"{\"seq\":1}").unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), b"one").unwrap();
        assert_eq!(
            relay.load().await,
            Some((b"{\"seq\":1}".to_vec(), b"one".to_vec()))
        );
        std::fs::write(dir.join("manifest.json"), b"{\"seq\":2}").unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), b"two").unwrap();
        assert_eq!(
            relay.load().await,
            Some((b"{\"seq\":2}".to_vec(), b"two".to_vec()))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

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
