//! Job poller: claims one job at a time from the Fleet server and hands it to a runner.
//!
//! While no job runs, the poller calls `ClaimJob` about every five seconds. It honours
//! `next_in_s` from the reply up to [`MAX_IDLE_WAIT`] and backs off with full jitter on
//! a claim error or a failed run, including a job whose workspace could not be prepared.
//! A claim already in flight when shutdown starts gets [`CLAIM_GRACE`] to return, and a job
//! it returns goes to the runner with shutdown already signalled, so the runner reports it.
//! Concurrency is one:
//! the next claim is not issued until the runner returns.
//!
//! The server URL must use `http` or `https`. An `https` URL gets TLS with the webpki roots,
//! the same provider and roots as the laptop CLI, and the bearer token travels inside it.
//! [`TimingReporter`] sends one job's timing summary over `ReportTiming` with retry. It is
//! built and tested, and no runtime path calls it yet.
//!
//! A certificate the roots do not vouch for fails the call. A handshake that never completes is
//! cut off by [`CALL_BACKSTOP`], because the channel timeout does not cover it.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fleet_proto::MAX_PROFILE_MESSAGE_BYTES;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply,
    GetProfileBlobRequest, Job, ReportJobReply, ReportJobRequest, ReportTimingReply,
    ReportTimingRequest,
};
use tokio::sync::watch;
use tonic::codegen::http::Uri;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;
use tonic::{Code, Request, Status};

use crate::Error;
use crate::backoff::{Backoff, Random, SystemRandom};
use crate::runner::Reporter;
use crate::transport::endpoint;

/// Environment variable that enables the poller and names the server.
pub const SERVER_URL_ENV: &str = "FLEET_SERVER_URL";

/// Environment variable holding the box bearer token.
pub const TOKEN_ENV: &str = "FLEET_TOKEN";

/// Nominal time between claims while idle.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

const JITTER: f64 = 0.4;

/// Longest the poller waits after an idle reply, whatever `next_in_s` says.
pub const MAX_IDLE_WAIT: Duration = Duration::from_secs(300);

/// Timeout applied to every `ClaimJob` call.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard bound on a claim or report call. It exceeds [`REQUEST_TIMEOUT`] so the channel timeout
/// fires first on a slow reply, and it catches a TLS handshake that never completes.
pub const CALL_BACKSTOP: Duration = Duration::from_secs(11);

/// Longest the poller waits for a claim already in flight when shutdown starts.
pub const CLAIM_GRACE: Duration = Duration::from_secs(1);

/// Longest the poller waits for a runner to return after it signals shutdown. It exceeds the
/// default terminal report timeout plus the stdout drain, so the runner can report the stop.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(15);

const _: () = assert!(
    SHUTDOWN_GRACE.as_secs()
        > crate::runner::DEFAULT_TERMINAL_REPORT_TIMEOUT.as_secs()
            + crate::runner::STDOUT_DRAIN.as_secs()
);

/// A clone-able signal that the poller is shutting down.
#[derive(Debug, Clone)]
pub struct Shutdown(watch::Receiver<bool>);

impl Shutdown {
    /// A trigger and the signal it fires. Sending `true` requests shutdown.
    #[must_use]
    pub fn channel() -> (watch::Sender<bool>, Self) {
        let (trigger, signal) = watch::channel(false);
        (trigger, Self(signal))
    }

    /// Completes once shutdown has been requested or the poller is gone.
    pub async fn requested(&mut self) {
        let _ = self.0.wait_for(|requested| *requested).await;
    }
}

/// A clone-able switch that pauses claiming without stopping the poller.
///
/// While paused the poller issues no `ClaimJob` call. A job already running is untouched. The
/// update drain (ADR-0047) pauses it and resumes it when the attempt ends.
#[derive(Debug, Clone)]
pub struct ClaimGate(Arc<GateInner>);

#[derive(Debug)]
struct GateInner {
    paused: watch::Sender<bool>,
    claiming: AtomicUsize,
}

impl Default for ClaimGate {
    fn default() -> Self {
        Self(Arc::new(GateInner {
            paused: watch::channel(false).0,
            claiming: AtomicUsize::new(0),
        }))
    }
}

impl ClaimGate {
    /// An open gate.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Stops new claims.
    pub fn pause(&self) {
        self.0.paused.send_replace(true);
    }

    /// Allows claims again.
    pub fn resume(&self) {
        self.0.paused.send_replace(false);
    }

    /// Whether claims are stopped.
    #[must_use]
    pub fn is_paused(&self) -> bool {
        *self.0.paused.borrow()
    }

    /// Whether the poller is between the start of a claim and the end of the job that claim
    /// returned, so a job may exist that no lease tracking sees yet.
    ///
    /// [`Poller::run`] holds this from before each claim until the job's runner returns.
    /// [`Poller::claim`] called directly holds it only for the call.
    #[must_use]
    pub fn claim_in_flight(&self) -> bool {
        self.0.claiming.load(Ordering::SeqCst) > 0
    }

    fn hold(&self) -> InFlight {
        self.0.claiming.fetch_add(1, Ordering::SeqCst);
        InFlight(Arc::clone(&self.0))
    }

    async fn opened(&self) {
        let _ = self.0.paused.subscribe().wait_for(|paused| !*paused).await;
    }
}

struct InFlight(Arc<GateInner>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.claiming.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A job runner failure. It carries no detail, so nothing from the job can reach a log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunError;

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("job runner failed")
    }
}

impl std::error::Error for RunError {}

/// Executes a claimed job.
///
/// The poller runs [`JobRunner::run`] in its own task and awaits it before it claims again,
/// so an implementation owns the job until it returns. When the poller stops, it triggers
/// the [`Shutdown`] passed to `run` and waits up to [`SHUTDOWN_GRACE`] before it drops the
/// task.
///
/// If `run` returns `Err` or panics, the poller logs a fixed message, backs off and keeps
/// polling. The job is left to its lease, so the server marks it `LOST` when the lease
/// lapses. The runner must report a terminal state itself before it returns `Ok`.
pub trait JobRunner: Send + Sync + 'static {
    /// Runs `job` to a terminal state and reports it.
    ///
    /// # Errors
    ///
    /// Returns [`RunError`] when the job could not be run to a reported end.
    fn run(
        &self,
        job: Job,
        shutdown: Shutdown,
    ) -> impl Future<Output = Result<(), RunError>> + Send;
}

/// A bearer token whose `Debug` output hides the value.
#[derive(Clone)]
pub struct Token(String);

impl Token {
    /// Wraps a token value.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// A failed `ClaimJob` call. Only the gRPC status code is kept, never the server's text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClaimError {
    code: Code,
}

impl ClaimError {
    /// Returns the gRPC status code of the failure.
    pub fn code(&self) -> Code {
        self.code
    }
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "claim failed with status {:?}", self.code)
    }
}

impl std::error::Error for ClaimError {}

impl From<Status> for ClaimError {
    fn from(status: Status) -> Self {
        Self {
            code: status.code(),
        }
    }
}

/// What one successful claim asks the loop to do next.
#[derive(Debug)]
pub enum Claimed {
    /// A job was assigned.
    Job(Box<Job>),
    /// No job is queued. Wait this long before asking again.
    Idle(Duration),
}

type Attach = Box<dyn FnMut(Request<()>) -> Result<Request<()>, Status> + Send>;

type Client = FleetWorkerClient<InterceptedService<Channel, Attach>>;

fn attach_client(channel: Channel, header: MetadataValue<tonic::metadata::Ascii>) -> Client {
    let attach: Attach = Box::new(move |mut request| {
        request
            .metadata_mut()
            .insert("authorization", header.clone());
        Ok(request)
    });
    FleetWorkerClient::with_interceptor(channel, attach)
        .max_decoding_message_size(MAX_PROFILE_MESSAGE_BYTES)
}

/// Sends job reports to the Fleet server over `ReportJob` with the bearer token attached.
pub struct GrpcReporter {
    client: tokio::sync::Mutex<Client>,
}

impl fmt::Debug for GrpcReporter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcReporter").finish_non_exhaustive()
    }
}

impl GrpcReporter {
    /// A reporter over `channel`. The caller sets the request timeout on the channel.
    ///
    /// # Errors
    ///
    /// Fails when the token is not a valid header value. The error never contains it.
    pub fn new(channel: Channel, token: &Token) -> Result<Self, Error> {
        let client = attach_client(channel, bearer_header(token)?);
        Ok(Self {
            client: tokio::sync::Mutex::new(client),
        })
    }
}

impl Reporter for GrpcReporter {
    async fn report(&self, request: ReportJobRequest) -> Result<ReportJobReply, Status> {
        let mut client = self.client.lock().await;
        backstop(client.report_job(request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn profile_blob(
        &self,
        request: GetProfileBlobRequest,
    ) -> Result<GetProfileBlobReply, Status> {
        let mut client = self.client.lock().await;
        backstop(client.get_profile_blob(request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn job_transcript(
        &self,
        request: GetJobTranscriptRequest,
    ) -> Result<GetJobTranscriptReply, Status> {
        let mut client = self.client.lock().await;
        backstop(client.get_job_transcript(request))
            .await
            .map(tonic::Response::into_inner)
    }
}

/// Metadata key a server uses to ask for a longer wait before the next try, in milliseconds.
pub const PUSHBACK_METADATA: &str = "grpc-retry-pushback-ms";

/// Metadata key that carries the idempotency key of a timing report.
pub const IDEMPOTENCY_METADATA: &str = "idempotency-key";

/// Longest a timing report waits on a server-supplied pushback, whatever the server says.
pub const MAX_SERVER_WAIT: Duration = Duration::from_secs(60);

/// Most calls one timing report makes before it gives up.
pub const MAX_TIMING_ATTEMPTS: u32 = 10;

/// Longest one timing report keeps retrying, counted on its [`RetryClock`].
pub const TIMING_REPORT_DEADLINE: Duration = Duration::from_secs(600);

/// A time source and sleeper for retry loops. A test passes a fake that never really sleeps.
pub trait RetryClock: Send + Sync {
    /// Time since a fixed origin. Later calls never return less.
    fn now(&self) -> Duration;

    /// Completes after `duration`.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send;
}

/// The real clock: monotonic time and `tokio::time::sleep`.
#[derive(Debug)]
pub struct TokioClock {
    origin: tokio::time::Instant,
}

impl TokioClock {
    /// A clock whose origin is now.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: tokio::time::Instant::now(),
        }
    }
}

impl Default for TokioClock {
    fn default() -> Self {
        Self::new()
    }
}

impl RetryClock for TokioClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        tokio::time::sleep(duration)
    }
}

/// Where a timing report goes. The real one is [`GrpcTimingTransport`].
pub trait TimingTransport: Send + Sync {
    /// Sends `request` with `idempotency_key` attached.
    ///
    /// # Errors
    ///
    /// Returns the gRPC status when the call fails.
    fn report_timing(
        &self,
        idempotency_key: &str,
        request: ReportTimingRequest,
    ) -> impl Future<Output = Result<ReportTimingReply, Status>> + Send;
}

/// Sends timing reports over `ReportTiming` with the bearer token attached.
pub struct GrpcTimingTransport {
    client: tokio::sync::Mutex<Client>,
}

impl fmt::Debug for GrpcTimingTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrpcTimingTransport")
            .finish_non_exhaustive()
    }
}

impl GrpcTimingTransport {
    /// A transport over `channel`. The caller sets the request timeout on the channel.
    ///
    /// # Errors
    ///
    /// Fails when the token is not a valid header value. The error never contains it.
    pub fn new(channel: Channel, token: &Token) -> Result<Self, Error> {
        let client = attach_client(channel, bearer_header(token)?);
        Ok(Self {
            client: tokio::sync::Mutex::new(client),
        })
    }
}

impl TimingTransport for GrpcTimingTransport {
    async fn report_timing(
        &self,
        idempotency_key: &str,
        request: ReportTimingRequest,
    ) -> Result<ReportTimingReply, Status> {
        let mut request = Request::new(request);
        let Ok(value) = MetadataValue::try_from(idempotency_key) else {
            return Err(Status::invalid_argument(
                "idempotency key is not a header value",
            ));
        };
        request.metadata_mut().insert(IDEMPOTENCY_METADATA, value);
        let mut client = self.client.lock().await;
        backstop(client.report_timing(request))
            .await
            .map(tonic::Response::into_inner)
    }
}

/// What became of one timing report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimingOutcome {
    /// The server stored the report after this many calls.
    Acked {
        /// Calls made, the acknowledged one included.
        attempts: u32,
    },
    /// The job is gone from the server. Terminal, never retried.
    Pruned,
    /// The server refused the report for good with this code. Terminal, never retried.
    Refused(Code),
    /// The attempt or deadline budget ran out while the server kept failing.
    GaveUp,
}

/// Why a timing report was not attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TimingReportError {
    /// The request names no job, so no stable idempotency key exists.
    EmptyJobId,
    /// The job id is too long or holds a byte outside printable ASCII without space.
    BadJobId,
}

impl fmt::Display for TimingReportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::EmptyJobId => "timing report has no job id",
            Self::BadJobId => "timing report job id is not a short run of printable ASCII",
        })
    }
}

impl std::error::Error for TimingReportError {}

/// Longest job id, in bytes, that a timing idempotency key accepts.
pub const MAX_TIMING_JOB_ID_BYTES: usize = 128;

/// The idempotency key of a timing report: stable for one job attempt, never empty.
///
/// # Errors
///
/// Fails with [`TimingReportError::EmptyJobId`] when `job_id` is empty, and with
/// [`TimingReportError::BadJobId`] when it is longer than [`MAX_TIMING_JOB_ID_BYTES`] or
/// holds any byte that is not printable ASCII, space excluded. The error never contains it.
pub fn timing_idempotency_key(job_id: &str, attempt: u32) -> Result<String, TimingReportError> {
    if job_id.is_empty() {
        return Err(TimingReportError::EmptyJobId);
    }
    if job_id.len() > MAX_TIMING_JOB_ID_BYTES || !job_id.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(TimingReportError::BadJobId);
    }
    Ok(format!("timing:{job_id}:{attempt}"))
}

/// Reads the server's pushback from `status`, capped at [`MAX_SERVER_WAIT`].
///
/// A value that is not a plain run of digits is ignored. A run of digits too long for a
/// `u64` counts as the largest wait and is capped.
fn server_wait(status: &Status) -> Option<Duration> {
    let text = status.metadata().get(PUSHBACK_METADATA)?.to_str().ok()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let millis = text.parse::<u64>().unwrap_or(u64::MAX);
    Some(Duration::from_millis(millis).min(MAX_SERVER_WAIT))
}

/// Sends the timing of a job to the server and retries until it is stored or refused.
///
/// One call to [`TimingReporter::report`] sends one idempotency key, the same on every retry.
/// The backoff schedule lives in the reporter and resets only when the server stores a
/// report, so a server that keeps failing is not hit faster by the next job.
#[derive(Debug)]
pub struct TimingReporter<T, C = TokioClock, R = SystemRandom> {
    transport: T,
    clock: C,
    backoff: Backoff<R>,
}

impl<T: TimingTransport, C: RetryClock, R: Random> TimingReporter<T, C, R> {
    /// A reporter over `transport` with the standard backoff drawn from `random`.
    pub fn new(transport: T, clock: C, random: R) -> Self {
        Self {
            transport,
            clock,
            backoff: Backoff::standard(random),
        }
    }

    /// Sends `request` until the server stores it or refuses it for good.
    ///
    /// `NotFound` means the job was pruned and ends the report as [`TimingOutcome::Pruned`].
    /// `InvalidArgument` and `PermissionDenied` end it as [`TimingOutcome::Refused`]. Any other
    /// failure waits the backoff delay, raised to the server's pushback capped at
    /// [`MAX_SERVER_WAIT`], and tries again. It stops with [`TimingOutcome::GaveUp`] after
    /// [`MAX_TIMING_ATTEMPTS`] calls or when the next wait would pass
    /// [`TIMING_REPORT_DEADLINE`].
    ///
    /// # Errors
    ///
    /// Fails before any call when the request has no job id.
    pub async fn report(
        &mut self,
        request: ReportTimingRequest,
    ) -> Result<TimingOutcome, TimingReportError> {
        let key = timing_idempotency_key(&request.job_id, request.attempt)?;
        let started = self.clock.now();
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            let Err(status) = self.transport.report_timing(&key, request.clone()).await else {
                self.backoff.reset();
                return Ok(TimingOutcome::Acked { attempts });
            };
            match status.code() {
                Code::NotFound => return Ok(TimingOutcome::Pruned),
                Code::InvalidArgument | Code::PermissionDenied => {
                    return Ok(TimingOutcome::Refused(status.code()));
                }
                _ => {}
            }
            let delay = self.backoff.next_delay();
            let wait = server_wait(&status).map_or(delay, |server| server.max(delay));
            let spent = self.clock.now().saturating_sub(started);
            if attempts >= MAX_TIMING_ATTEMPTS
                || spent.saturating_add(wait) > TIMING_REPORT_DEADLINE
            {
                tracing::warn!(code = ?status.code(), attempts, "timing report abandoned");
                return Ok(TimingOutcome::GaveUp);
            }
            tracing::warn!(code = ?status.code(), retry_in = ?wait, "timing report failed");
            self.clock.sleep(wait).await;
        }
    }
}

/// The random sources a [`Poller`] draws from, named so they cannot be swapped.
#[derive(Debug)]
pub struct PollRandom<G = SystemRandom> {
    /// Source for error backoff delays.
    pub backoff: G,
    /// Source for the idle interval jitter.
    pub jitter: G,
}

impl PollRandom {
    /// Builds two independent system random sources.
    pub fn system() -> Self {
        Self {
            backoff: SystemRandom::new(),
            jitter: SystemRandom::new(),
        }
    }
}

/// Claims jobs from the server and runs them one at a time.
pub struct Poller<R, G = SystemRandom> {
    client: Client,
    box_name: String,
    runner: Arc<R>,
    backoff: Backoff<G>,
    jitter: G,
    gate: ClaimGate,
}

impl<R: JobRunner> Poller<R> {
    /// Builds a poller when `FLEET_SERVER_URL` is set and non-empty.
    ///
    /// Returns `Ok(None)` when it is unset. The bearer token comes from `FLEET_TOKEN`.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not an `http` or `https` URL, or when `FLEET_TOKEN` is missing,
    /// empty or not a valid header value. The error never contains either value.
    pub fn from_env(
        env: &dyn Fn(&str) -> Option<String>,
        box_name: String,
        runner: R,
    ) -> Result<Option<Self>, Error> {
        let Some(url) = env(SERVER_URL_ENV).filter(|url| !url.is_empty()) else {
            return Ok(None);
        };
        let token = env(TOKEN_ENV)
            .filter(|token| !token.is_empty())
            .map(Token::new)
            .ok_or_else(|| invalid(TOKEN_ENV))?;
        Self::connect(&url, &token, box_name, runner).map(Some)
    }

    /// Builds a poller for `url` with the system random source.
    ///
    /// The connection is lazy, so an unreachable server shows up as a claim error.
    ///
    /// # Errors
    ///
    /// Fails when the URL or the token cannot be used.
    pub fn connect(url: &str, token: &Token, box_name: String, runner: R) -> Result<Self, Error> {
        Self::connect_with(url, token, box_name, runner, PollRandom::system())
    }
}

impl<R: JobRunner, G: Random> Poller<R, G> {
    /// Builds a poller with explicit random sources.
    ///
    /// # Errors
    ///
    /// Fails when the URL is not an `http` or `https` URL or the token cannot be used.
    pub fn connect_with(
        url: &str,
        token: &Token,
        box_name: String,
        runner: R,
        random: PollRandom<G>,
    ) -> Result<Self, Error> {
        Self::with_channel(channel(url)?, token, box_name, runner, random)
    }

    /// Builds a poller over an existing channel.
    ///
    /// The caller sets the request timeout on the channel; [`REQUEST_TIMEOUT`] is the
    /// value [`Poller::connect_with`] uses.
    ///
    /// # Errors
    ///
    /// Fails when the token is not a valid header value.
    pub fn with_channel(
        channel: Channel,
        token: &Token,
        box_name: String,
        runner: R,
        random: PollRandom<G>,
    ) -> Result<Self, Error> {
        let header = bearer_header(token)?;
        let client = attach_client(channel, header);
        Ok(Self {
            client,
            box_name,
            runner: Arc::new(runner),
            backoff: Backoff::standard(random.backoff),
            jitter: random.jitter,
            gate: ClaimGate::new(),
        })
    }

    /// Uses `gate` to pause and resume claiming.
    #[must_use]
    pub fn with_gate(mut self, gate: ClaimGate) -> Self {
        self.gate = gate;
        self
    }

    /// Issues one `ClaimJob` call.
    ///
    /// # Errors
    ///
    /// Fails with the gRPC status code when the call fails.
    pub async fn claim(&mut self) -> Result<Claimed, ClaimError> {
        let _in_flight = self.gate.hold();
        if self.gate.is_paused() {
            return Ok(Claimed::Idle(Duration::ZERO));
        }
        let reply = backstop(self.client.claim_job(ClaimJobRequest {
            r#box: self.box_name.clone(),
        }))
        .await?
        .into_inner();
        Ok(match reply.job {
            Some(job) => Claimed::Job(Box::new(job)),
            None => Claimed::Idle(self.idle_wait(reply.next_in_s)),
        })
    }

    fn idle_wait(&mut self, next_in_s: u32) -> Duration {
        if next_in_s > 0 {
            return Duration::from_secs(u64::from(next_in_s)).min(MAX_IDLE_WAIT);
        }
        let factor = JITTER.mul_add(self.jitter.next_unit(), 1.0 - JITTER / 2.0);
        POLL_INTERVAL.mul_f64(factor)
    }

    /// Polls until `stop` completes.
    ///
    /// An idle reply waits `next_in_s`, capped at [`MAX_IDLE_WAIT`], or the jittered
    /// interval when it is zero. A claim error is logged with its status code only and
    /// delays the next claim by the backoff schedule. A claimed job runs in its own task to completion before the
    /// next claim. When `stop` completes mid-job, the runner is signalled and given
    /// [`SHUTDOWN_GRACE`] to return. A runner `Ok` resets the schedule. A runner error or
    /// panic is logged with a fixed message and grows it, so a crash-looping runner cannot
    /// claim faster than the schedule allows.
    pub async fn run(mut self, stop: impl Future<Output = ()> + Send) {
        tokio::pin!(stop);
        let mut stop = Stop {
            fut: stop,
            fired: false,
        };
        let (trigger, signal) = watch::channel(false);
        loop {
            tokio::select! {
                () = stop.fired() => return,
                () = self.gate.opened() => {}
            }
            let busy = self.gate.hold();
            let wait = match self.claim_or_stop(&mut stop).await {
                None => return,
                Some(Ok(Claimed::Job(job))) => {
                    match self.run_job(*job, &signal, &trigger, &mut stop).await {
                        Some(wait) => wait,
                        None => return,
                    }
                }
                Some(Ok(Claimed::Idle(wait))) => {
                    self.backoff.reset();
                    wait
                }
                Some(Err(err)) => {
                    let wait = self.backoff.next_delay();
                    tracing::warn!(code = ?err.code(), retry_in = ?wait, "job claim failed");
                    wait
                }
            };
            drop(busy);
            tokio::select! {
                () = stop.fired() => return,
                () = tokio::time::sleep(wait) => {}
            }
        }
    }

    async fn run_job<F: Future<Output = ()>>(
        &mut self,
        job: Job,
        signal: &watch::Receiver<bool>,
        trigger: &watch::Sender<bool>,
        stop: &mut Stop<'_, F>,
    ) -> Option<Duration> {
        let runner = Arc::clone(&self.runner);
        let shutdown = Shutdown(signal.clone());
        let mut handle = tokio::spawn(async move { runner.run(job, shutdown).await });
        tokio::select! {
            joined = &mut handle => Some(match joined {
                Ok(Ok(())) => {
                    self.backoff.reset();
                    Duration::ZERO
                }
                Ok(Err(_)) => self.runner_failed("job runner failed"),
                Err(_) => self.runner_failed("job runner panicked"),
            }),
            () = stop.fired() => {
                let _ = trigger.send(true);
                if tokio::time::timeout(SHUTDOWN_GRACE, &mut handle).await.is_err() {
                    handle.abort();
                }
                None
            }
        }
    }

    fn runner_failed(&mut self, message: &'static str) -> Duration {
        let wait = self.backoff.next_delay();
        tracing::warn!(retry_in = ?wait, "{message}");
        wait
    }

    async fn claim_or_stop<F: Future<Output = ()>>(
        &mut self,
        stop: &mut Stop<'_, F>,
    ) -> Option<Result<Claimed, ClaimError>> {
        let claim = self.claim();
        tokio::pin!(claim);
        tokio::select! {
            biased;
            claimed = &mut claim => Some(claimed),
            () = stop.fired() => match tokio::time::timeout(CLAIM_GRACE, claim).await {
                Ok(Ok(claimed @ Claimed::Job(_))) => Some(Ok(claimed)),
                _ => None,
            },
        }
    }
}

struct Stop<'a, F> {
    fut: Pin<&'a mut F>,
    fired: bool,
}

impl<F: Future<Output = ()>> Stop<'_, F> {
    async fn fired(&mut self) {
        if !self.fired {
            self.fut.as_mut().await;
            self.fired = true;
        }
    }
}

async fn backstop<T>(call: impl Future<Output = Result<T, Status>>) -> Result<T, Status> {
    tokio::time::timeout(CALL_BACKSTOP, call)
        .await
        .unwrap_or_else(|_| Err(Status::deadline_exceeded("call timed out")))
}

/// A lazy channel to `url` with [`REQUEST_TIMEOUT`] applied to every call.
///
/// # Errors
///
/// Fails when the URL is not an `http` or `https` URL. The error never holds the URL.
pub fn channel(url: &str) -> Result<Channel, Error> {
    channel_with_ca(url, None)
}

/// Like [`channel`], and for an `https` URL also trusts the PEM certificate in `ca_pem`.
///
/// # Errors
///
/// Fails when the URL is not an `http` or `https` URL. The error never holds the URL.
pub fn channel_with_ca(url: &str, ca_pem: Option<&[u8]>) -> Result<Channel, Error> {
    let uri: Uri = url.parse().map_err(|_| invalid(SERVER_URL_ENV))?;
    if !matches!(uri.scheme_str(), Some("http" | "https")) {
        return Err(invalid(SERVER_URL_ENV));
    }
    let endpoint = endpoint(url, ca_pem)
        .map_err(|_| invalid(SERVER_URL_ENV))?
        .timeout(REQUEST_TIMEOUT);
    Ok(endpoint.connect_lazy())
}

fn bearer_header(token: &Token) -> Result<MetadataValue<tonic::metadata::Ascii>, Error> {
    let mut header: MetadataValue<_> = format!("Bearer {}", token.0)
        .parse()
        .map_err(|_| invalid(TOKEN_ENV))?;
    header.set_sensitive(true);
    Ok(header)
}

fn invalid(name: &'static str) -> Error {
    Error::InvalidValue {
        name,
        value: String::from("<redacted>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authorization_header_is_sensitive() {
        let header = bearer_header(&Token::new("tok-abc")).map_err(|_| ());
        assert!(header.is_ok_and(|header| header.is_sensitive()));
    }
}
