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
//! A certificate the roots do not vouch for fails the call. A handshake that never completes is
//! cut off by [`CALL_BACKSTOP`], because the channel timeout does not cover it.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{ClaimJobRequest, Job, ReportJobReply, ReportJobRequest};
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
        })
    }

    /// Issues one `ClaimJob` call.
    ///
    /// # Errors
    ///
    /// Fails with the gRPC status code when the call fails.
    pub async fn claim(&mut self) -> Result<Claimed, ClaimError> {
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
