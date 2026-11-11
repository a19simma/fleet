//! The `FleetIngest`, `FleetQuery`, `FleetWorker`, `FleetJobs`, `FleetJudge`, `FleetProfiles`,
//! `FleetBatches` and `FleetCredentials` gRPC handlers.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fleet_core::ProfileError;
use fleet_core::graph;
use fleet_core::{Envelope, Redactor};
use fleet_proto::v1::fleet_batches_server::{FleetBatches, FleetBatchesServer};
use fleet_proto::v1::fleet_box_tokens_server::{FleetBoxTokens, FleetBoxTokensServer};
use fleet_proto::v1::fleet_capability_admin_server::{
    FleetCapabilityAdmin, FleetCapabilityAdminServer,
};
use fleet_proto::v1::fleet_catalog_admin_server::{FleetCatalogAdmin, FleetCatalogAdminServer};
use fleet_proto::v1::fleet_catalog_server::{FleetCatalog, FleetCatalogServer};
use fleet_proto::v1::fleet_credentials_server::{FleetCredentials, FleetCredentialsServer};
use fleet_proto::v1::fleet_edit_server::{FleetEdit, FleetEditServer};
use fleet_proto::v1::fleet_environments_server::{FleetEnvironments, FleetEnvironmentsServer};
use fleet_proto::v1::fleet_hosts_server::{FleetHosts, FleetHostsServer};
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::fleet_judge_server::{FleetJudge, FleetJudgeServer};
use fleet_proto::v1::fleet_profiles_server::{FleetProfiles, FleetProfilesServer};
use fleet_proto::v1::fleet_query_server::{FleetQuery, FleetQueryServer};
use fleet_proto::v1::fleet_repos_server::{FleetRepos, FleetReposServer};
use fleet_proto::v1::fleet_retro_server::{FleetRetro, FleetRetroServer};
use fleet_proto::v1::fleet_work_server::{FleetWork, FleetWorkServer};
use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    AddHostRequest, AddRepoRequest, AddWorkDepRequest, AddWorkItemRequest, AddWorkNoteRequest,
    ApproveHostPrivateRequest, CancelJobRequest, CancelWorkRequest, CatalogItem, ClaimJobReply,
    ClaimJobRequest, ClaimWorkRequest, CreateProfileRequest, CreateWorkProjectRequest,
    CredentialInfo, DeleteCredentialReply, DeleteCredentialRequest, GetBatchReply, GetBatchRequest,
    GetJobCredentialsReply, GetJobCredentialsRequest, GetJobEnvironmentReply,
    GetJobEnvironmentRequest, GetJobRequest, GetJobTimingReply, GetJobTimingRequest,
    GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply, GetProfileBlobRequest,
    GetProfileRequest, GetStatsReply, GetStatsRequest, GetWorkItemReply, GetWorkItemRequest,
    GrantCapabilityRequest, HeartbeatReply, HeartbeatRequest, HostInfo, Job, ListCapabilitiesReply,
    ListCapabilitiesRequest, ListCatalogReply, ListCatalogRequest, ListCredentialsReply,
    ListCredentialsRequest, ListFleetReply, ListFleetRequest, ListHostRequestsReply,
    ListHostRequestsRequest, ListHostsReply, ListHostsRequest, ListJobsReply, ListJobsRequest,
    ListProfilesReply, ListProfilesRequest, ListReposReply, ListReposRequest, ListWorkDefersReply,
    ListWorkDefersRequest, ListWorkItemsReply, ListWorkItemsRequest, ListWorkProjectsReply,
    ListWorkProjectsRequest, NextWorkReply, NextWorkRequest, Profile, ProfileVersion,
    PushEventsReply, PushEventsRequest, PutCredentialRequest, QueuedEvent, ReadJobEventsReply,
    ReadJobEventsRequest, ReadTranscriptReply, ReadTranscriptRequest, RecordWorkDeferRequest,
    Rejection, RemoveHostReply, RemoveHostRequest, RemoveRepoReply, RemoveRepoRequest,
    RemoveWorkDepRequest, RenewLeaseRequest, RepoInfo, ReportAttemptRequest, ReportJobReply,
    ReportJobRequest, ReportShellLogReply, ReportShellLogRequest, ReportTimingReply,
    ReportTimingRequest, ResolveWorkDeferRequest, RevokeCapabilityReply, RevokeCapabilityRequest,
    RevokeHostPrivateRequest, SetCatalogItemEnabledRequest, SetWorkSlicesRequest,
    ShareProfileRequest, StreamShellLogChunk, StreamShellLogRequest, SubmitBatchReply,
    SubmitBatchRequest, SubmitJobRequest, SubmitJudgeRequest, UnblockWorkRequest,
    UnshareProfileRequest, UpsertCatalogItemRequest, UserCapability, VerifyCredentialReply,
    VerifyCredentialRequest, WorkAttempt, WorkDefer, WorkEvent, WorkItem, WorkProject,
};
use fleet_proto::v1::{
    BoxTokenInfo, IssueBoxTokenReply, IssueBoxTokenRequest, ListBoxTokensReply,
    ListBoxTokensRequest, RevokeBoxTokenReply, RevokeBoxTokenRequest,
};
use fleet_proto::v1::{
    ClearEnvironmentDefaultReply, ClearEnvironmentDefaultRequest, GetEnvironmentDefaultReply,
    GetEnvironmentDefaultRequest, SetEnvironmentDefaultReply, SetEnvironmentDefaultRequest,
};
use fleet_proto::v1::{
    CloseRetroRequest, DecideEditRequest, DispositionImprovementRequest, ExportWorkReply,
    ExportWorkRequest, FileEditRequest, FileImprovementRequest, GetEditRequest, GetWorkBriefReply,
    GetWorkBriefRequest, ImportWorkReply, ImportWorkRequest, Improvement, ListEditsReply,
    ListEditsRequest, ListImprovementsReply, ListImprovementsRequest, ListPitfallsReply,
    ListPitfallsRequest, ListRetrosReply, ListRetrosRequest, OpenRetroRequest, Pitfall,
    RecordPitfallRequest, Retro, SuggestedEdit,
};
use fleet_proto::v1::{
    CreateEnvironmentRequest, DeleteEnvironmentReply, DeleteEnvironmentRequest,
    DeleteEnvironmentSecretReply, DeleteEnvironmentSecretRequest, EnvironmentDetail,
    EnvironmentInfo, EnvironmentVersion, GetEnvironmentRequest, GetEnvironmentVersionRequest,
    ListEnvironmentVersionsReply, ListEnvironmentVersionsRequest, ListEnvironmentsReply,
    ListEnvironmentsRequest, PutEnvironmentSecretReply, PutEnvironmentSecretRequest,
    SaveEnvironmentVersionReply, SaveEnvironmentVersionRequest,
};
use fleet_proto::{ConvertError, validate_box};
use tonic::codegen::BoxStream;
use tonic::service::Routes;
use tonic::transport::Server;
use tonic::transport::server::{Router, TcpIncoming};
use tonic::{Request, Response, Status};
use tonic_prost::prost::Message;
use tower::layer::util::{Identity, Stack};

use crate::auth::{ADMIN_REQUIRED, BOX_TOKENS_NEED_USER_TOKEN, BearerAuth, BoxCaller, Caller};
use crate::catalog;
use crate::config::Config;
use crate::cred::capability::{self, Capabilities};
use crate::cred::limiter::Limiter;
use crate::cred::password::BootstrapPassword;
use crate::cred::users::{BoxTokenLabel, BoxTokenTtl, UserError};
use crate::cred::{CredentialService, RepoService, Users};
use crate::environments::EnvironmentService;
use crate::hosts::HostService;
use crate::jobs::validate_job_id;
use crate::profiles::{self, ProfileContent, ProfileFault, Viewer};
use crate::store::{Store, StoreError, WorkFault};
use crate::supervise::BoxError;
use crate::timing;
use crate::update_feed::FeedCache;
use crate::web::{Dispatch, HEADER_READ_TIMEOUT, Web, WebAuth, serve};
use fleet_proto::MAX_PROFILE_MESSAGE_BYTES;

/// Where an [`UpdateRelay`] gets the pair it passes on.
#[derive(Debug, Clone, Default)]
enum Source {
    #[default]
    None,
    File(PathBuf),
    Feed(FeedCache),
}

/// Relays a signed update manifest to boxes in `HeartbeatReply`.
///
/// The server holds no key and verifies nothing: it passes the manifest and its signature on.
/// The pair comes from two files ([`UpdateRelay::new`]) or from the last good pair of the
/// release feed ([`UpdateRelay::from_feed`], ADR-0060). fleetd checks the signature against its
/// own trust root.
#[derive(Debug, Clone, Default)]
pub struct UpdateRelay {
    source: Source,
}

impl UpdateRelay {
    /// Relays the manifest at `manifest` and the signature at `manifest` plus `.minisig`.
    /// `None` relays nothing.
    #[must_use]
    pub fn new(manifest: Option<PathBuf>) -> Self {
        Self {
            source: manifest.map_or(Source::None, Source::File),
        }
    }

    /// Relays the last good pair in `cache`. An empty cache relays nothing, and the reply
    /// carries the pair after the poller's first accepted fetch. The pair is read on every
    /// heartbeat, so a later accepted fetch replaces it.
    #[must_use]
    pub fn from_feed(cache: FeedCache) -> Self {
        Self {
            source: Source::Feed(cache),
        }
    }

    /// Returns the pair as `(manifest, signature)`. A file source reads both files: a missing
    /// file, a read error, a manifest that is not JSON or a pair over the caps in
    /// [`fleet_proto::update_within_caps`] gives `None`, so the reply carries neither. A feed
    /// source gives the cached pair, which [`FeedCache::offer`] already held to those caps.
    async fn load(&self) -> Option<(Vec<u8>, Vec<u8>)> {
        match &self.source {
            Source::None => None,
            Source::File(path) => Self::load_files(path).await,
            Source::Feed(cache) => {
                let pair = cache.current()?;
                Some((pair.manifest().to_vec(), pair.signature().to_vec()))
            }
        }
    }

    async fn load_files(path: &Path) -> Option<(Vec<u8>, Vec<u8>)> {
        let mut sig_path = path.to_path_buf().into_os_string();
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

/// Bytes one span adds to a `GetJobTimingReply` beyond its two names: field tags, length
/// prefixes and the numeric fields.
const TIMING_SPAN_WIRE_OVERHEAD: usize = 64;

/// Bytes one shell command adds to a `GetJobTimingReply` beyond its id, command, log and
/// `ended_by` text: field tags, length prefixes and the numeric and flag fields.
const TIMING_COMMAND_WIRE_OVERHEAD: usize = 128;

/// Bytes the summary and reply envelope add to a `GetJobTimingReply`: field tags and the five
/// duration fields.
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

/// Refuses a request naming a Box other than the one a per-Box token is bound to. A request
/// without a [`BoxCaller`] (a static token) passes.
fn bound_box<T>(request: &Request<T>, requested: &str) -> Result<(), Status> {
    request
        .extensions()
        .get::<BoxCaller>()
        .map_or(Ok(()), |bound| bound.require_box(requested))
}

fn bound_user<T>(request: &Request<T>) -> Option<i64> {
    request
        .extensions()
        .get::<BoxCaller>()
        .map(|bound| bound.user_id)
}

fn same_box(events: &[QueuedEvent]) -> Result<Option<&str>, Status> {
    let mut names = events
        .iter()
        .filter_map(|event| event.envelope.as_ref())
        .map(|envelope| envelope.r#box.as_str());
    let Some(first) = names.next() else {
        return Ok(None);
    };
    if names.any(|other| other != first) {
        return Err(Status::invalid_argument(
            "every event in a request must carry the same box",
        ));
    }
    Ok(Some(first))
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
    environments: Option<EnvironmentService>,
    hosts: Option<HostService>,
    capabilities: Capabilities,
    update: UpdateRelay,
    timing_reply_cap: usize,
    work_redactor: Redactor,
}

impl FleetService {
    /// Refuses a per-Box token acting on a job it does not own, with the lease-mismatch text so
    /// a foreign job and an unknown one look alike. A static token passes.
    async fn owned_by_token(&self, bound_user: Option<i64>, job_id: &str) -> Result<(), Status> {
        let Some(user_id) = bound_user else {
            return Ok(());
        };
        let owned = self
            .store
            .job_owned_by(job_id, user_id)
            .await
            .map_err(|err| storage_unavailable(&err))?;
        if owned {
            Ok(())
        } else {
            Err(Status::permission_denied(fleet_proto::ERR_LEASE_MISMATCH))
        }
    }

    /// Builds the handler over `store`. The credential RPCs answer `FAILED_PRECONDITION`.
    pub fn new(store: Store) -> Self {
        Self {
            capabilities: Capabilities::new(store.pool().clone()),
            store,
            credentials: None,
            environments: None,
            hosts: None,
            update: UpdateRelay::default(),
            timing_reply_cap: MAX_JOB_TIMING_REPLY_BYTES,
            work_redactor: Redactor::default()
                .with_installation_tokens()
                .with_box_tokens(),
        }
    }

    /// Sets the redactor that masks secrets in the evidence of a reported work attempt. The
    /// default masks GitHub App installation tokens by shape.
    #[must_use]
    pub fn with_work_redactor(mut self, redactor: Redactor) -> Self {
        self.work_redactor = redactor;
        self
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

    /// Enables the host RPCs.
    #[must_use]
    pub fn with_hosts(mut self, hosts: Option<HostService>) -> Self {
        self.hosts = hosts;
        self
    }

    /// Enables the Environment RPCs.
    #[must_use]
    pub fn with_environments(mut self, environments: Option<EnvironmentService>) -> Self {
        self.environments = environments;
        self
    }

    fn environment_owner<T>(
        &self,
        request: &Request<T>,
    ) -> Result<(&EnvironmentService, i64), Status> {
        let user_id = caller_of(request)
            .ok_or_else(|| Status::permission_denied(fleet_proto::ERR_ENV_NEEDS_USER_TOKEN))?;
        let service = self
            .environments
            .as_ref()
            .ok_or_else(|| Status::failed_precondition(fleet_proto::PRECONDITION_NOT_CONFIGURED))?;
        Ok((service, user_id))
    }

    fn credential_owner<T>(
        &self,
        request: &Request<T>,
    ) -> Result<(&CredentialService, i64), Status> {
        let user_id = caller_of(request)
            .ok_or_else(|| Status::permission_denied(fleet_proto::ERR_NEEDS_USER_TOKEN))?;
        let service = self
            .credentials
            .as_ref()
            .ok_or_else(|| Status::failed_precondition(fleet_proto::PRECONDITION_NOT_CONFIGURED))?;
        Ok((service, user_id))
    }

    fn repo_owner<T>(&self, request: &Request<T>) -> Result<(&RepoService, i64), Status> {
        let user_id = caller_of(request)
            .ok_or_else(|| Status::permission_denied(fleet_proto::ERR_NEEDS_USER_TOKEN))?;
        let service = self
            .credentials
            .as_ref()
            .and_then(CredentialService::repos)
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
        let bound = request.extensions().get::<BoxCaller>().cloned();
        let events = request.into_inner().events;
        if events.len() > MAX_EVENTS_PER_PUSH {
            return Err(Status::invalid_argument(format!(
                "a request may carry at most {MAX_EVENTS_PER_PUSH} events"
            )));
        }
        if let (Some(bound), Some(first)) = (bound, same_box(&events)?) {
            bound.require_box(first)?;
        }
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
        bound_box(&request, &request.get_ref().r#box)?;
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
        StoreError::LeaseDenied => Status::permission_denied(fleet_proto::ERR_LEASE_MISMATCH),
        StoreError::UnknownProfile => Status::not_found("profile not found"),
        StoreError::InvalidProfile(
            fault @ ProfileFault::Malformed(ProfileError::EnvironmentNotAllowed),
        ) => Status::invalid_argument(fault.to_string()),
        StoreError::ToolsNotGranted => {
            Status::permission_denied(profiles::ERR_PROFILE_TOOLS_NOT_GRANTED)
        }
        StoreError::ModelDenied(denied) => Status::permission_denied(denied.to_string()),
        StoreError::CatalogTooLarge => Status::unavailable(profiles::ERR_BLOB_CATALOG_TOO_LARGE),
        other => storage_unavailable(other),
    }
}

#[tonic::async_trait]
impl FleetWorker for FleetService {
    async fn claim_job(
        &self,
        request: Request<ClaimJobRequest>,
    ) -> Result<Response<ClaimJobReply>, Status> {
        bound_box(&request, &request.get_ref().r#box)?;
        let owner = bound_user(&request);
        let name = validate_box(&request.into_inner().r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let job = self
            .store
            .claim_job_for(&name, owner)
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
        bound_box(&request, &request.get_ref().r#box)?;
        self.owned_by_token(bound_user(&request), &request.get_ref().job_id)
            .await?;
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
        bound_box(&request, &request.get_ref().r#box)?;
        self.owned_by_token(bound_user(&request), &request.get_ref().job_id)
            .await?;
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
        bound_box(&request, &request.get_ref().r#box)?;
        self.owned_by_token(bound_user(&request), &request.get_ref().job_id)
            .await?;
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

    async fn get_job_environment(
        &self,
        request: Request<GetJobEnvironmentRequest>,
    ) -> Result<Response<GetJobEnvironmentReply>, Status> {
        bound_box(&request, &request.get_ref().r#box)?;
        self.owned_by_token(bound_user(&request), &request.get_ref().job_id)
            .await?;
        let service = self
            .environments
            .as_ref()
            .ok_or_else(|| Status::failed_precondition(fleet_proto::PRECONDITION_NOT_CONFIGURED))?;
        let request = request.into_inner();
        let name = validate_box(&request.r#box)
            .map_err(|err| Status::invalid_argument(err.to_string()))?;
        let reply = service
            .job_environment(&request.job_id, request.attempt, name.as_str())
            .await?;
        Ok(Response::new(reply))
    }

    async fn report_job(
        &self,
        request: Request<ReportJobRequest>,
    ) -> Result<Response<ReportJobReply>, Status> {
        bound_box(&request, &request.get_ref().r#box)?;
        self.owned_by_token(bound_user(&request), &request.get_ref().job_id)
            .await?;
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
        bound_box(&request, &request.get_ref().r#box)?;
        let name = report_box(request.get_ref())?;
        self.owned_by_token(bound_user(&request), &request.get_ref().job_id)
            .await?;
        timing::store_timing(self.store.pool(), &name, request.get_ref())
            .await
            .map(Response::new)
    }

    async fn report_shell_log(
        &self,
        request: Request<ReportShellLogRequest>,
    ) -> Result<Response<ReportShellLogReply>, Status> {
        bound_box(&request, &request.get_ref().r#box)?;
        self.owned_by_token(bound_user(&request), &request.get_ref().job_id)
            .await?;
        let leased_to = request
            .extensions()
            .get::<BoxCaller>()
            .map(|bound| bound.box_name.as_str());
        timing::report_shell_log(self.store.pool(), request.get_ref(), leased_to)
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

fn box_token_error(err: &UserError) -> Status {
    match err {
        UserError::InvalidLabel => Status::invalid_argument("invalid label"),
        UserError::InvalidTtl => Status::invalid_argument(format!(
            "ttl_days must be from 1 to {}",
            crate::cred::users::MAX_BOX_TOKEN_DAYS
        )),
        UserError::BoxNameTaken => Status::already_exists("box name is not available"),
        UserError::TooManyBoxTokens => Status::resource_exhausted("too many active box tokens"),
        UserError::NotFound => Status::not_found("token not found"),
        other => {
            tracing::error!(%other, "box token storage failed");
            Status::unavailable("storage unavailable")
        }
    }
}

#[tonic::async_trait]
impl FleetBoxTokens for FleetService {
    async fn issue_box_token(
        &self,
        request: Request<IssueBoxTokenRequest>,
    ) -> Result<Response<IssueBoxTokenReply>, Status> {
        let user_id = box_token_user(&request)?;
        let request = request.into_inner();
        let name = validate_box(&request.r#box)
            .map_err(|_| Status::invalid_argument("invalid box name"))?;
        let label = BoxTokenLabel::new(&request.label).map_err(|err| box_token_error(&err))?;
        let ttl = request
            .ttl_days
            .map_or_else(|| Ok(BoxTokenTtl::default()), BoxTokenTtl::new)
            .map_err(|err| box_token_error(&err))?;
        let issued = Users::new(self.store.pool().clone())
            .issue_box_token(user_id, &name, &label, ttl)
            .await
            .map_err(|err| box_token_error(&err))?;
        let token = String::from_utf8(issued.token.expose().to_vec())
            .map_err(|_| Status::internal("token encoding"))?;
        Ok(Response::new(IssueBoxTokenReply {
            id: issued.id,
            token,
            r#box: name.as_str().to_owned(),
            expires_at: issued.expires_at,
        }))
    }

    async fn list_box_tokens(
        &self,
        request: Request<ListBoxTokensRequest>,
    ) -> Result<Response<ListBoxTokensReply>, Status> {
        let user_id = box_token_user(&request)?;
        let rows = Users::new(self.store.pool().clone())
            .list_box_tokens(user_id)
            .await
            .map_err(|err| box_token_error(&err))?;
        let tokens = rows
            .into_iter()
            .map(|row| BoxTokenInfo {
                id: row.id,
                r#box: row.box_name,
                label: row.label,
                created_at: row.created_at,
                expires_at: row.expires_at,
                last_used_at: row.last_used_at,
                revoked_at: row.revoked_at,
            })
            .collect();
        Ok(Response::new(ListBoxTokensReply { tokens }))
    }

    async fn revoke_box_token(
        &self,
        request: Request<RevokeBoxTokenRequest>,
    ) -> Result<Response<RevokeBoxTokenReply>, Status> {
        let user_id = box_token_user(&request)?;
        Users::new(self.store.pool().clone())
            .revoke_box_token(user_id, request.get_ref().id)
            .await
            .map_err(|err| box_token_error(&err))?;
        Ok(Response::new(RevokeBoxTokenReply {}))
    }
}

fn box_token_user<T>(request: &Request<T>) -> Result<i64, Status> {
    caller_of(request).ok_or_else(|| Status::permission_denied(BOX_TOKENS_NEED_USER_TOKEN))
}

#[tonic::async_trait]
impl FleetHosts for FleetService {
    async fn add_host(
        &self,
        request: Request<AddHostRequest>,
    ) -> Result<Response<HostInfo>, Status> {
        let user_id = caller_of(&request)
            .ok_or_else(|| Status::permission_denied(fleet_proto::ERR_NEEDS_USER_TOKEN))?;
        let hosts = self.hosts_service()?;
        Ok(Response::new(hosts.add(user_id, request.get_ref()).await?))
    }

    async fn list_hosts(
        &self,
        request: Request<ListHostsRequest>,
    ) -> Result<Response<ListHostsReply>, Status> {
        let caller = request
            .extensions()
            .get::<Caller>()
            .copied()
            .ok_or_else(|| Status::permission_denied(fleet_proto::ERR_NEEDS_USER_TOKEN))?;
        let hosts = self.hosts_service()?;
        Ok(Response::new(hosts.list(caller.is_admin).await?))
    }

    async fn remove_host(
        &self,
        request: Request<RemoveHostRequest>,
    ) -> Result<Response<RemoveHostReply>, Status> {
        let admin_id = admin_of(&request)?;
        let hosts = self.hosts_service()?;
        Ok(Response::new(
            hosts.remove(admin_id, request.get_ref()).await?,
        ))
    }

    async fn approve_host_private(
        &self,
        request: Request<ApproveHostPrivateRequest>,
    ) -> Result<Response<HostInfo>, Status> {
        let admin_id = match request.extensions().get::<Caller>() {
            Some(caller) if caller.is_admin => caller.user_id,
            _ => return Err(Status::not_found(fleet_proto::ERR_HOST_NOT_FOUND)),
        };
        let hosts = self.hosts_service()?;
        Ok(Response::new(
            hosts.approve(admin_id, request.get_ref()).await?,
        ))
    }

    async fn revoke_host_private(
        &self,
        request: Request<RevokeHostPrivateRequest>,
    ) -> Result<Response<HostInfo>, Status> {
        let admin_id = admin_of(&request)?;
        let hosts = self.hosts_service()?;
        Ok(Response::new(
            hosts.revoke(admin_id, request.get_ref()).await?,
        ))
    }

    async fn list_host_requests(
        &self,
        request: Request<ListHostRequestsRequest>,
    ) -> Result<Response<ListHostRequestsReply>, Status> {
        admin_of(&request)?;
        let hosts = self.hosts_service()?;
        Ok(Response::new(hosts.list_requests().await?))
    }
}

impl FleetService {
    fn hosts_service(&self) -> Result<&HostService, Status> {
        self.hosts
            .as_ref()
            .ok_or_else(|| Status::failed_precondition(fleet_proto::PRECONDITION_NOT_CONFIGURED))
    }
}

#[tonic::async_trait]
impl FleetRepos for FleetService {
    async fn add_repo(
        &self,
        request: Request<AddRepoRequest>,
    ) -> Result<Response<RepoInfo>, Status> {
        let (service, user_id) = self.repo_owner(&request)?;
        Ok(Response::new(
            service.add(user_id, request.get_ref()).await?,
        ))
    }

    async fn list_repos(
        &self,
        request: Request<ListReposRequest>,
    ) -> Result<Response<ListReposReply>, Status> {
        let (service, user_id) = self.repo_owner(&request)?;
        Ok(Response::new(service.list(user_id).await?))
    }

    async fn remove_repo(
        &self,
        request: Request<RemoveRepoRequest>,
    ) -> Result<Response<RemoveRepoReply>, Status> {
        let (service, user_id) = self.repo_owner(&request)?;
        Ok(Response::new(
            service.remove(user_id, request.get_ref()).await?,
        ))
    }
}

fn work_user<T>(request: &Request<T>) -> Result<i64, Status> {
    caller_of(request).ok_or_else(|| Status::permission_denied(fleet_proto::ERR_NEEDS_USER_TOKEN))
}

fn work_error(err: &StoreError) -> Status {
    match err {
        StoreError::KeyConflict => {
            Status::already_exists("idempotency key already used with other parameters")
        }
        StoreError::Work(fault) => match fault {
            WorkFault::ProjectNotFound
            | WorkFault::ItemNotFound
            | WorkFault::DepNotFound
            | WorkFault::AttemptNotFound
            | WorkFault::DeferNotFound
            | WorkFault::RetroNotFound
            | WorkFault::EditNotFound
            | WorkFault::ImprovementNotFound => Status::not_found(fault.to_string()),
            WorkFault::NotInteractive => Status::permission_denied(fault.to_string()),
            WorkFault::Invalid(reason) => Status::invalid_argument(*reason),
            WorkFault::Graph(graph::GraphError::Cycle(_))
            | WorkFault::RepoNotRegistered
            | WorkFault::CrossProject
            | WorkFault::Undecided(_) => Status::failed_precondition(fault.to_string()),
            WorkFault::Graph(_) => Status::invalid_argument(fault.to_string()),
            WorkFault::Exists(reason) => Status::already_exists(*reason),
            WorkFault::Precondition(reason) => Status::failed_precondition(*reason),
        },
        other => storage_unavailable(other),
    }
}

#[tonic::async_trait]
impl FleetWork for FleetService {
    async fn create_work_project(
        &self,
        request: Request<CreateWorkProjectRequest>,
    ) -> Result<Response<WorkProject>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .create_work_project(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_work_projects(
        &self,
        request: Request<ListWorkProjectsRequest>,
    ) -> Result<Response<ListWorkProjectsReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .list_work_projects(user_id)
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn set_work_slices(
        &self,
        request: Request<SetWorkSlicesRequest>,
    ) -> Result<Response<WorkProject>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .set_work_slices(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn add_work_item(
        &self,
        request: Request<AddWorkItemRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .add_work_item(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_work_items(
        &self,
        request: Request<ListWorkItemsRequest>,
    ) -> Result<Response<ListWorkItemsReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .list_work_items(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_work_item(
        &self,
        request: Request<GetWorkItemRequest>,
    ) -> Result<Response<GetWorkItemReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .get_work_item(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn add_work_dep(
        &self,
        request: Request<AddWorkDepRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .add_work_dep(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn remove_work_dep(
        &self,
        request: Request<RemoveWorkDepRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .remove_work_dep(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn cancel_work(
        &self,
        request: Request<CancelWorkRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .cancel_work(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn unblock_work(
        &self,
        request: Request<UnblockWorkRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .unblock_work(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn next_work(
        &self,
        request: Request<NextWorkRequest>,
    ) -> Result<Response<NextWorkReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .next_work(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn claim_work(
        &self,
        request: Request<ClaimWorkRequest>,
    ) -> Result<Response<WorkAttempt>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .claim_work(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn renew_lease(
        &self,
        request: Request<RenewLeaseRequest>,
    ) -> Result<Response<WorkAttempt>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .renew_lease(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn import_work(
        &self,
        request: Request<ImportWorkRequest>,
    ) -> Result<Response<ImportWorkReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .import_work(user_id, request.get_ref(), &self.work_redactor)
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn export_work(
        &self,
        request: Request<ExportWorkRequest>,
    ) -> Result<Response<ExportWorkReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .export_work(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn report_attempt(
        &self,
        request: Request<ReportAttemptRequest>,
    ) -> Result<Response<WorkAttempt>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .report_attempt(user_id, request.get_ref(), &self.work_redactor)
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn add_work_note(
        &self,
        request: Request<AddWorkNoteRequest>,
    ) -> Result<Response<WorkEvent>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .add_work_note(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn record_work_defer(
        &self,
        request: Request<RecordWorkDeferRequest>,
    ) -> Result<Response<WorkDefer>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .record_work_defer(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn resolve_work_defer(
        &self,
        request: Request<ResolveWorkDeferRequest>,
    ) -> Result<Response<WorkDefer>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .resolve_work_defer(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_work_defers(
        &self,
        request: Request<ListWorkDefersRequest>,
    ) -> Result<Response<ListWorkDefersReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .list_work_defers(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl FleetEnvironments for FleetService {
    async fn create_environment(
        &self,
        request: Request<CreateEnvironmentRequest>,
    ) -> Result<Response<EnvironmentInfo>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.create(user_id, request.get_ref()).await?,
        ))
    }

    async fn list_environments(
        &self,
        request: Request<ListEnvironmentsRequest>,
    ) -> Result<Response<ListEnvironmentsReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(service.list(user_id).await?))
    }

    async fn get_environment(
        &self,
        request: Request<GetEnvironmentRequest>,
    ) -> Result<Response<EnvironmentDetail>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.get(user_id, request.get_ref()).await?,
        ))
    }

    async fn delete_environment(
        &self,
        request: Request<DeleteEnvironmentRequest>,
    ) -> Result<Response<DeleteEnvironmentReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.delete(user_id, request.get_ref()).await?,
        ))
    }

    async fn put_environment_secret(
        &self,
        request: Request<PutEnvironmentSecretRequest>,
    ) -> Result<Response<PutEnvironmentSecretReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.put_secret(user_id, request.get_ref()).await?,
        ))
    }

    async fn delete_environment_secret(
        &self,
        request: Request<DeleteEnvironmentSecretRequest>,
    ) -> Result<Response<DeleteEnvironmentSecretReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.delete_secret(user_id, request.get_ref()).await?,
        ))
    }

    async fn save_environment_version(
        &self,
        request: Request<SaveEnvironmentVersionRequest>,
    ) -> Result<Response<SaveEnvironmentVersionReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.save_version(user_id, request.get_ref()).await?,
        ))
    }

    async fn get_environment_version(
        &self,
        request: Request<GetEnvironmentVersionRequest>,
    ) -> Result<Response<EnvironmentVersion>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.get_version(user_id, request.get_ref()).await?,
        ))
    }

    async fn list_environment_versions(
        &self,
        request: Request<ListEnvironmentVersionsRequest>,
    ) -> Result<Response<ListEnvironmentVersionsReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.list_versions(user_id, request.get_ref()).await?,
        ))
    }

    async fn set_environment_default(
        &self,
        request: Request<SetEnvironmentDefaultRequest>,
    ) -> Result<Response<SetEnvironmentDefaultReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.set_default(user_id, request.get_ref()).await?,
        ))
    }

    async fn get_environment_default(
        &self,
        request: Request<GetEnvironmentDefaultRequest>,
    ) -> Result<Response<GetEnvironmentDefaultReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.get_default(user_id, request.get_ref()).await?,
        ))
    }

    async fn clear_environment_default(
        &self,
        request: Request<ClearEnvironmentDefaultRequest>,
    ) -> Result<Response<ClearEnvironmentDefaultReply>, Status> {
        let (service, user_id) = self.environment_owner(&request)?;
        Ok(Response::new(
            service.clear_default(user_id, request.get_ref()).await?,
        ))
    }
}

#[tonic::async_trait]
impl FleetEdit for FleetService {
    async fn file_edit(
        &self,
        request: Request<FileEditRequest>,
    ) -> Result<Response<SuggestedEdit>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .file_edit(
                user_id,
                request.get_ref(),
                &self.work_redactor,
                fleet_proto::MAX_PENDING_EDITS_PER_PROJECT,
            )
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_edits(
        &self,
        request: Request<ListEditsRequest>,
    ) -> Result<Response<ListEditsReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .list_edits(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_edit(
        &self,
        request: Request<GetEditRequest>,
    ) -> Result<Response<SuggestedEdit>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .get_edit(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn decide_edit(
        &self,
        request: Request<DecideEditRequest>,
    ) -> Result<Response<SuggestedEdit>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .decide_edit(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }
}

#[tonic::async_trait]
impl FleetRetro for FleetService {
    async fn open_retro(
        &self,
        request: Request<OpenRetroRequest>,
    ) -> Result<Response<Retro>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .open_retro(user_id, request.get_ref(), &self.work_redactor)
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn close_retro(
        &self,
        request: Request<CloseRetroRequest>,
    ) -> Result<Response<Retro>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .close_retro(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_retros(
        &self,
        request: Request<ListRetrosRequest>,
    ) -> Result<Response<ListRetrosReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .list_retros(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn file_improvement(
        &self,
        request: Request<FileImprovementRequest>,
    ) -> Result<Response<Improvement>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .file_improvement(user_id, request.get_ref(), &self.work_redactor)
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_improvements(
        &self,
        request: Request<ListImprovementsRequest>,
    ) -> Result<Response<ListImprovementsReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .list_improvements(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn disposition_improvement(
        &self,
        request: Request<DispositionImprovementRequest>,
    ) -> Result<Response<Improvement>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .disposition_improvement(user_id, request.get_ref(), &self.work_redactor)
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn record_pitfall(
        &self,
        request: Request<RecordPitfallRequest>,
    ) -> Result<Response<Pitfall>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .record_pitfall(user_id, request.get_ref(), &self.work_redactor)
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn list_pitfalls(
        &self,
        request: Request<ListPitfallsRequest>,
    ) -> Result<Response<ListPitfallsReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .list_pitfalls(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
    }

    async fn get_work_brief(
        &self,
        request: Request<GetWorkBriefRequest>,
    ) -> Result<Response<GetWorkBriefReply>, Status> {
        let user_id = work_user(&request)?;
        let reply = self
            .store
            .get_work_brief(user_id, request.get_ref())
            .await
            .map_err(|err| work_error(&err))?;
        Ok(Response::new(reply))
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
        StoreError::UnknownEnvironment => Status::not_found(fleet_proto::ERR_ENV_NOT_FOUND),
        StoreError::EnvironmentWithoutVersion => {
            Status::not_found(fleet_proto::ERR_ENV_VERSION_NOT_FOUND)
        }
        StoreError::EnvironmentScriptsNotGranted => {
            Status::permission_denied(fleet_proto::ERR_ENV_SCRIPTS_NOT_GRANTED)
        }
        StoreError::ToolsNotGranted => {
            Status::permission_denied(profiles::ERR_PROFILE_TOOLS_NOT_GRANTED)
        }
        StoreError::ModelDenied(denied) => Status::permission_denied(denied.to_string()),
        StoreError::InvalidProfile(ProfileFault::Unowned) => {
            Status::permission_denied(profiles::ERR_PROFILE_SUBMIT_UNOWNED)
        }
        StoreError::InvalidProfile(
            fault @ ProfileFault::Malformed(ProfileError::EnvironmentNotAllowed),
        ) => Status::invalid_argument(fault.to_string()),
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
        StoreError::ToolsNotGranted => {
            Status::permission_denied(profiles::ERR_PROFILE_TOOLS_NOT_GRANTED)
        }
        StoreError::ModelDenied(denied) => Status::permission_denied(denied.to_string()),
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
        StoreError::InvalidProfile(
            fault @ ProfileFault::Malformed(ProfileError::EnvironmentNotAllowed),
        ) => Status::invalid_argument(fault.to_string()),
        StoreError::InvalidProfile(_) => Status::invalid_argument("invalid profile name"),
        StoreError::InvalidJob(_) => Status::invalid_argument("invalid job request"),
        StoreError::ToolsNotGranted => {
            Status::permission_denied(profiles::ERR_PROFILE_TOOLS_NOT_GRANTED)
        }
        StoreError::ModelDenied(denied) => Status::permission_denied(denied.to_string()),
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
        let saved = if request.edit {
            self.store
                .edit_profile_content(Some(caller), &request.name, content)
                .await
        } else {
            self.store
                .create_profile_content(Some(caller), &request.name, content)
                .await
        };
        saved.map(Response::new).map_err(|err| profiles_error(&err))
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
        admin_of(&request)?;
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
    router_with_environments(store, auth, credentials, None)
}

/// Same as [`router_with`] with the Environment RPCs backed by `environments`.
pub fn router_with_environments(
    store: &Store,
    auth: &BearerAuth,
    credentials: Option<CredentialService>,
    environments: Option<EnvironmentService>,
) -> Router<Stack<BearerAuth, Identity>> {
    server().layer(auth.clone()).add_routes(routes(
        store,
        auth,
        credentials,
        environments,
        UpdateRelay::default(),
    ))
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
    serve_with_environments(
        store,
        auth,
        web,
        credentials,
        None,
        update,
        incoming,
        shutdown,
    )
    .await
}

/// Builds the web router from `config`: login off without `FLEET_WEB_ORIGIN`, otherwise the
/// console pages and, when `environments` is set, the environment pages (ADR-0067).
///
/// # Errors
///
/// Returns the error from [`WebAuth::new`] when the origin or relying party id is invalid.
pub fn build_web(
    config: &Config,
    pool: &sqlx::PgPool,
    users: &Users,
    credentials: Option<CredentialService>,
    environments: Option<EnvironmentService>,
    store: Store,
    password: BootstrapPassword,
) -> Result<Web, BoxError> {
    let Some(origin) = config.web_origin.as_deref() else {
        tracing::warn!("FLEET_WEB_ORIGIN is unset: web login is off");
        return Ok(Web::new());
    };
    let auth = WebAuth::new(
        pool.clone(),
        users.clone(),
        origin,
        config.web_rp_id.as_deref(),
    )?
    .with_bootstrap(
        password,
        Arc::new(Limiter::system()),
        config.trusted_proxy_hops,
    );
    Ok(Web::with_environments(
        auth,
        credentials,
        environments,
        store,
    ))
}

/// Same as [`serve_with_credentials`] with the Environment RPCs backed by `environments`.
///
/// # Errors
///
/// Returns the I/O error that stopped the server.
#[expect(
    clippy::too_many_arguments,
    reason = "one wiring entry point for the server main"
)]
pub async fn serve_with_environments(
    store: &Store,
    auth: &BearerAuth,
    web: Web,
    credentials: Option<CredentialService>,
    environments: Option<EnvironmentService>,
    update: UpdateRelay,
    incoming: TcpIncoming,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    serve_routes(
        routes(store, auth, credentials, environments, update),
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
        routes(store, auth, None, None, UpdateRelay::default()),
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

fn routes(
    store: &Store,
    auth: &BearerAuth,
    credentials: Option<CredentialService>,
    environments: Option<EnvironmentService>,
    update: UpdateRelay,
) -> Routes {
    let hosts = match HostService::system(store.pool().clone()) {
        Ok(hosts) => Some(hosts),
        Err(error) => {
            tracing::error!(%error, "host RPCs disabled");
            None
        }
    };
    let service = FleetService::new(store.clone())
        .with_work_redactor(auth.redactor())
        .with_hosts(hosts)
        .with_credentials(credentials)
        .with_environments(environments)
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
    let repos = FleetReposServer::new(service.clone());
    let work = FleetWorkServer::new(service.clone());
    let retro = FleetRetroServer::new(service.clone());
    let edit = FleetEditServer::new(service.clone());
    let environments =
        FleetEnvironmentsServer::new(service.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    let hosts = FleetHostsServer::new(service.clone());
    let box_tokens = FleetBoxTokensServer::new(service.clone());
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
        .add_service(repos)
        .add_service(work)
        .add_service(retro)
        .add_service(edit)
        .add_service(environments)
        .add_service(hosts)
        .add_service(box_tokens)
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

    #[tokio::test]
    async fn an_empty_feed_cache_relays_nothing() {
        assert_eq!(UpdateRelay::from_feed(FeedCache::new()).load().await, None);
    }

    #[tokio::test]
    async fn a_feed_relays_the_cached_pair_and_follows_replacements() {
        let cache = FeedCache::new();
        let relay = UpdateRelay::from_feed(cache.clone());
        cache.offer(b"{\"seq\":1}", b"one");
        assert_eq!(
            relay.load().await,
            Some((b"{\"seq\":1}".to_vec(), b"one".to_vec()))
        );
        cache.offer(b"{\"seq\":2}", b"two");
        assert_eq!(
            relay.load().await,
            Some((b"{\"seq\":2}".to_vec(), b"two".to_vec()))
        );
        cache.offer(b"{\"seq\":1}", b"old");
        assert_eq!(
            relay.load().await,
            Some((b"{\"seq\":2}".to_vec(), b"two".to_vec()))
        );
    }

    #[tokio::test]
    async fn a_feed_ignores_files_on_disk() {
        let dir = scratch("feedfile");
        std::fs::write(dir.join("manifest.json"), b"{\"seq\":9}").unwrap();
        std::fs::write(dir.join("manifest.json.minisig"), b"disk").unwrap();
        assert_eq!(UpdateRelay::from_feed(FeedCache::new()).load().await, None);
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
    fn a_denied_model_maps_to_permission_denied_naming_it_on_every_path() {
        let denied = || {
            let list = fleet_core::model_allowlist::ModelAllowlist::parse("a").unwrap();
            StoreError::ModelDenied(list.check("gpt-5").unwrap_err())
        };
        for status in [
            jobs_error(&denied()),
            profiles_error(&denied()),
            batches_error(&denied()),
        ] {
            assert_eq!(status.code(), Code::PermissionDenied);
            assert_eq!(status.message(), "model gpt-5 is not in the allowlist");
        }
    }

    #[test]
    fn an_environment_key_maps_to_invalid_argument_with_the_distinct_message() {
        let err = || {
            StoreError::InvalidProfile(ProfileFault::Malformed(ProfileError::EnvironmentNotAllowed))
        };
        for status in [
            jobs_error(&err()),
            batches_error(&err()),
            worker_error(&err()),
        ] {
            assert_eq!(status.code(), Code::InvalidArgument);
            assert_eq!(status.message(), "a profile cannot name an environment");
        }
    }

    #[test]
    fn a_lost_lease_answers_with_the_shared_constant() {
        let status = worker_error(&StoreError::LeaseDenied);
        assert_eq!(status.code(), Code::PermissionDenied);
        assert_eq!(status.message(), fleet_proto::ERR_LEASE_MISMATCH);
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
            (StoreError::CatalogTooLarge, Code::Unavailable),
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
