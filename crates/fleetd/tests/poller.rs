//! Poller behaviour against an in-memory `FleetWorker` stub, with tokio time paused.
//!
//! The stub runs on the test runtime behind a duplex connector, so no real socket is
//! involved. Paused time then advances only when every task is idle, which makes the
//! recorded claim times exact. Tests that need a real socket run on the real clock.

use std::collections::VecDeque;
use std::error::Error;
use std::future::Future;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{
    ClaimJobReply, ClaimJobRequest, GetProfileBlobReply, GetProfileBlobRequest, Job,
    ReportJobReply, ReportJobRequest, ReportTimingReply, ReportTimingRequest,
};
use fleetd::backoff::Random;
use fleetd::poller::{
    CLAIM_GRACE, ClaimGate, Claimed, GrpcReporter, GrpcTimingTransport, IDEMPOTENCY_METADATA,
    JobRunner, MAX_IDLE_WAIT, MAX_SERVER_WAIT, MAX_TIMING_ATTEMPTS, MAX_TIMING_JOB_ID_BYTES,
    PUSHBACK_METADATA, PollRandom, Poller, REQUEST_TIMEOUT, RetryClock, RunError, SHUTDOWN_GRACE,
    Shutdown, TIMING_REPORT_DEADLINE, TimingOutcome, TimingReportError, TimingReporter,
    TimingTransport, Token, timing_idempotency_key,
};
use fleetd::runner::Reporter;
use fleetd::update::{DrainController, DrainOutcome};
use hyper_util::rt::TokioIo;
use tokio::io::DuplexStream;
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::codegen::http::Uri;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Response, Status};

type Test = Result<(), Box<dyn Error>>;

const SECRET: &str = "tok-0123456789";
const RAW: &str = "raw-server-detail-9f3a";

#[derive(Clone, Copy)]
struct Fixed(f64);

impl Random for Fixed {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

enum Step {
    Fail,
    Hang,
    Idle(u32),
    Job(&'static str),
    SlowJob(&'static str),
}

#[derive(Default)]
struct Shared {
    script: Mutex<VecDeque<Step>>,
    times: Mutex<Vec<Instant>>,
    auth: Mutex<Vec<String>>,
    report_auth: Mutex<Vec<String>>,
    timing_keys: Mutex<Vec<String>>,
    arrived: Notify,
}

#[derive(Clone)]
struct Stub(Arc<Shared>);

#[tonic::async_trait]
impl FleetWorker for Stub {
    async fn claim_job(
        &self,
        request: Request<ClaimJobRequest>,
    ) -> Result<Response<ClaimJobReply>, Status> {
        let header = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.0
            .auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(header);
        self.0
            .times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Instant::now());
        self.0.arrived.notify_one();
        let step = self
            .0
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or(Step::Idle(0));
        match step {
            Step::Fail => Err(Status::internal(format!("{RAW} {SECRET}"))),
            Step::Hang => std::future::pending().await,
            Step::Idle(next_in_s) => Ok(Response::new(ClaimJobReply {
                job: None,
                lease_s: 0,
                next_in_s,
            })),
            Step::SlowJob(id) => {
                tokio::time::sleep(Duration::from_millis(200)).await;
                Ok(Response::new(ClaimJobReply {
                    job: Some(Job {
                        job_id: id.to_owned(),
                        ..Job::default()
                    }),
                    lease_s: 60,
                    next_in_s: 0,
                }))
            }
            Step::Job(id) => Ok(Response::new(ClaimJobReply {
                job: Some(Job {
                    job_id: id.to_owned(),
                    ..Job::default()
                }),
                lease_s: 60,
                next_in_s: 0,
            })),
        }
    }

    async fn get_profile_blob(
        &self,
        _request: Request<GetProfileBlobRequest>,
    ) -> Result<Response<GetProfileBlobReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_job_transcript(
        &self,
        _request: Request<fleet_proto::v1::GetJobTranscriptRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobTranscriptReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn get_job_environment(
        &self,
        _: Request<fleet_proto::v1::GetJobEnvironmentRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobEnvironmentReply>, Status> {
        Err(Status::unimplemented("get_job_environment"))
    }

    async fn get_job_credentials(
        &self,
        _request: Request<fleet_proto::v1::GetJobCredentialsRequest>,
    ) -> Result<Response<fleet_proto::v1::GetJobCredentialsReply>, Status> {
        Err(Status::unimplemented("get_job_credentials"))
    }

    async fn report_job(
        &self,
        request: Request<ReportJobRequest>,
    ) -> Result<Response<ReportJobReply>, Status> {
        let header = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.0
            .report_auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(header);
        Ok(Response::new(ReportJobReply {
            acked_through_seq: request.into_inner().job_id.len() as u64,
            ..ReportJobReply::default()
        }))
    }

    async fn report_shell_log(
        &self,
        _: Request<fleet_proto::v1::ReportShellLogRequest>,
    ) -> Result<Response<fleet_proto::v1::ReportShellLogReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn report_timing(
        &self,
        request: Request<ReportTimingRequest>,
    ) -> Result<Response<ReportTimingReply>, Status> {
        let key = request
            .metadata()
            .get(IDEMPOTENCY_METADATA)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        self.0
            .timing_keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(key);
        Ok(Response::new(ReportTimingReply {}))
    }
}

struct Rig {
    shared: Arc<Shared>,
    channel: Channel,
    origin: Instant,
}

fn rig(script: Vec<Step>) -> Rig {
    let shared = Arc::new(Shared {
        script: Mutex::new(script.into()),
        ..Shared::default()
    });
    let (accept, incoming) = mpsc::unbounded_channel::<DuplexStream>();
    let service = FleetWorkerServer::new(Stub(Arc::clone(&shared)));
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(UnboundedReceiverStream::new(incoming).map(Ok::<_, io::Error>))
            .await;
    });
    let connector = tower::service_fn(move |_: Uri| {
        let accept = accept.clone();
        async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            accept.send(server).map_err(|_| io::ErrorKind::BrokenPipe)?;
            Ok::<_, io::Error>(TokioIo::new(client))
        }
    });
    let channel = Endpoint::from_static("http://stub.invalid")
        .timeout(REQUEST_TIMEOUT)
        .connect_with_connector_lazy(connector);
    Rig {
        shared,
        channel,
        origin: Instant::now(),
    }
}

impl Rig {
    fn claims(&self) -> usize {
        self.shared
            .times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn offsets(&self) -> Vec<Duration> {
        self.shared
            .times
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|at| at.duration_since(self.origin))
            .collect()
    }

    fn gaps(&self) -> Vec<Duration> {
        let at = self.offsets();
        at.iter()
            .zip(at.iter().skip(1))
            .map(|(a, b)| b.saturating_sub(*a))
            .collect()
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Gate,
    Ok,
    Fail,
    Panic,
    Stubborn,
    Lease,
}

#[derive(Clone)]
struct Double {
    mode: Mode,
    started: Arc<Mutex<Vec<String>>>,
    began: Arc<Notify>,
    gate: Arc<Notify>,
    saw_shutdown: Arc<AtomicBool>,
    leased: Arc<AtomicBool>,
}

impl Double {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            started: Arc::default(),
            began: Arc::default(),
            gate: Arc::default(),
            saw_shutdown: Arc::default(),
            leased: Arc::default(),
        }
    }

    fn started(&self) -> Vec<String> {
        self.started
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl JobRunner for Double {
    #[expect(
        clippy::panic,
        reason = "the Panic mode exists to prove the poller survives"
    )]
    async fn run(&self, job: Job, mut shutdown: Shutdown) -> Result<(), RunError> {
        self.started
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(job.job_id);
        self.began.notify_one();
        match self.mode {
            Mode::Ok => Ok(()),
            Mode::Fail => Err(RunError),
            Mode::Panic => panic!("runner double panic"),
            Mode::Stubborn => std::future::pending().await,
            Mode::Lease => {
                pause(5).await;
                self.leased.store(true, Ordering::SeqCst);
                pause(5).await;
                self.leased.store(false, Ordering::SeqCst);
                Ok(())
            }
            Mode::Gate => {
                tokio::select! {
                    () = self.gate.notified() => {}
                    () = shutdown.requested() => self.saw_shutdown.store(true, Ordering::SeqCst),
                }
                Ok(())
            }
        }
    }
}

fn poller(rig: &Rig, runner: Double, unit: f64) -> Result<Poller<Double, Fixed>, Box<dyn Error>> {
    Ok(Poller::with_channel(
        rig.channel.clone(),
        &Token::new(SECRET),
        String::from("test-box"),
        runner,
        PollRandom {
            backoff: Fixed(unit),
            jitter: Fixed(unit),
        },
    )?)
}

struct Running {
    task: JoinHandle<()>,
    stop: oneshot::Sender<()>,
}

fn start(poller: Poller<Double, Fixed>) -> Running {
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(poller.run(async move {
        let _ = stopped.await;
    }));
    Running { task, stop }
}

impl Running {
    async fn stop_within(self, limit: Duration) -> Test {
        let _ = self.stop.send(());
        tokio::time::timeout(limit, self.task).await??;
        Ok(())
    }
}

async fn pause(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

fn between(value: Duration, low: f64, high: f64) -> bool {
    (low..=high).contains(&value.as_secs_f64())
}

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn capture() -> (tracing::subscriber::DefaultGuard, Sink) {
    let sink = Sink::default();
    let writer = sink.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .with_writer(move || writer.clone())
        .finish();
    (tracing::subscriber::set_default(subscriber), sink)
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
    }
}

#[tokio::test(start_paused = true)]
async fn one_job_at_a_time() -> Test {
    let rig = rig(vec![Step::Job("job-a"), Step::Job("job-b")]);
    let runner = Double::new(Mode::Gate);
    let running = start(poller(&rig, runner.clone(), 0.5)?);

    pause(120).await;
    assert_eq!(rig.claims(), 1);
    assert_eq!(runner.started().len(), 1);

    runner.gate.notify_one();
    pause(10).await;
    assert_eq!(rig.claims(), 2);
    assert_eq!(runner.started(), ["job-a", "job-b"]);
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn backoff_gaps_double() -> Test {
    let rig = rig((0..6).map(|_| Step::Fail).collect());
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.999_999)?);

    pause(35).await;
    assert_eq!(rig.claims(), 6);
    for (gap, ceiling) in rig.gaps().into_iter().zip([1.0, 2.0, 4.0, 8.0, 16.0]) {
        assert!(
            between(gap, ceiling * 0.9, ceiling),
            "gap {gap:?} vs {ceiling}"
        );
    }
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn backoff_resets_after_an_idle_reply() -> Test {
    let mut script: Vec<Step> = (0..4).map(|_| Step::Fail).collect();
    script.push(Step::Idle(3));
    script.extend((0..2).map(|_| Step::Fail));
    let rig = rig(script);
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.999_999)?);

    pause(25).await;
    assert!(rig.claims() >= 8, "claims: {}", rig.claims());
    let gaps = rig.gaps();
    let gap = |index: usize| gaps.get(index).copied().unwrap_or_default();
    assert!(between(gap(3), 7.0, 8.0), "before: {:?}", gap(3));
    assert!(between(gap(4), 2.9, 3.1), "idle: {:?}", gap(4));
    assert!(between(gap(5), 0.0, 1.0), "first after: {:?}", gap(5));
    assert!(between(gap(6), 0.0, 2.0), "second after: {:?}", gap(6));
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn backoff_resets_after_the_runner_succeeds() -> Test {
    let mut script: Vec<Step> = (0..4).map(|_| Step::Fail).collect();
    script.push(Step::Job("job-a"));
    script.extend((0..2).map(|_| Step::Fail));
    let rig = rig(script);
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.999_999)?);

    pause(25).await;
    assert!(rig.claims() >= 8, "claims: {}", rig.claims());
    let gaps = rig.gaps();
    let gap = |index: usize| gaps.get(index).copied().unwrap_or_default();
    assert!(between(gap(3), 7.0, 8.0), "before: {:?}", gap(3));
    assert!(between(gap(4), 0.0, 0.1), "after job: {:?}", gap(4));
    assert!(between(gap(5), 0.0, 1.0), "first after: {:?}", gap(5));
    assert!(between(gap(6), 0.0, 2.0), "second after: {:?}", gap(6));
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn a_failing_runner_does_not_reset_the_backoff() -> Test {
    let rig = rig((0..6).map(|_| Step::Job("job")).collect());
    let runner = Double::new(Mode::Fail);
    let running = start(poller(&rig, runner.clone(), 0.999_999)?);

    pause(35).await;
    assert_eq!(rig.claims(), 6);
    assert_eq!(runner.started().len(), 6);
    for (gap, ceiling) in rig.gaps().into_iter().zip([1.0, 2.0, 4.0, 8.0, 16.0]) {
        assert!(
            between(gap, ceiling * 0.9, ceiling),
            "gap {gap:?} vs {ceiling}"
        );
    }
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn a_huge_next_in_s_is_capped() -> Test {
    let rig = rig(vec![Step::Idle(u32::MAX), Step::Idle(0)]);
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.5)?);

    pause(310).await;
    assert!(rig.claims() >= 2, "claims: {}", rig.claims());
    let first = rig.gaps().first().copied().unwrap_or_default();
    assert!(
        between(
            first,
            MAX_IDLE_WAIT.as_secs_f64() - 1.0,
            MAX_IDLE_WAIT.as_secs_f64() + 1.0
        ),
        "first gap: {first:?}"
    );
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn next_in_s_overrides_the_interval() -> Test {
    let rig = rig(vec![Step::Idle(30), Step::Idle(0)]);
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.5)?);

    pause(40).await;
    let first = rig.gaps().first().copied().unwrap_or_default();
    assert!(between(first, 29.0, 32.0), "first gap: {first:?}");
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn the_idle_wait_is_five_seconds_plus_or_minus_twenty_percent() -> Test {
    for (unit, low, high) in [(0.0, 3.9, 4.1), (1.0, 5.9, 6.1)] {
        let rig = rig(vec![Step::Idle(0), Step::Idle(0)]);
        let running = start(poller(&rig, Double::new(Mode::Ok), unit)?);
        pause(10).await;
        let first = rig.gaps().first().copied().unwrap_or_default();
        assert!(between(first, low, high), "unit {unit}: {first:?}");
        running.stop_within(Duration::from_secs(1)).await?;
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn shutdown_while_idle_stops_the_poller() -> Test {
    let rig = rig(vec![Step::Idle(0)]);
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.5)?);
    rig.shared.arrived.notified().await;
    pause(1).await;
    running.stop_within(Duration::from_secs(1)).await?;
    assert_eq!(rig.claims(), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn shutdown_during_a_claim_stops_the_poller() -> Test {
    let rig = rig(vec![Step::Hang]);
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.5)?);
    rig.shared.arrived.notified().await;
    running.stop_within(CLAIM_GRACE * 2).await
}

#[tokio::test(start_paused = true)]
async fn a_claim_in_flight_at_shutdown_still_reaches_the_runner() -> Test {
    let rig = rig(vec![Step::SlowJob("job-a")]);
    let runner = Double::new(Mode::Gate);
    let running = start(poller(&rig, runner.clone(), 0.5)?);
    rig.shared.arrived.notified().await;
    running.stop_within(CLAIM_GRACE * 2).await?;
    assert_eq!(runner.started(), ["job-a"]);
    assert!(runner.saw_shutdown.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn shutdown_while_a_job_runs_signals_the_runner() -> Test {
    let rig = rig(vec![Step::Job("job-a")]);
    let runner = Double::new(Mode::Gate);
    let running = start(poller(&rig, runner.clone(), 0.5)?);
    runner.began.notified().await;
    let before = Instant::now();
    running.stop_within(Duration::from_secs(1)).await?;
    assert!(runner.saw_shutdown.load(Ordering::SeqCst));
    assert!(before.elapsed() < SHUTDOWN_GRACE);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_runner_that_ignores_shutdown_is_dropped_after_the_grace() -> Test {
    let rig = rig(vec![Step::Job("job-a")]);
    let runner = Double::new(Mode::Stubborn);
    let running = start(poller(&rig, runner.clone(), 0.5)?);
    runner.began.notified().await;
    let before = Instant::now();
    running.stop_within(SHUTDOWN_GRACE * 3).await?;
    let waited = before.elapsed();
    assert!(waited >= SHUTDOWN_GRACE, "{waited:?}");
    assert!(waited < SHUTDOWN_GRACE * 2, "{waited:?}");
    Ok(())
}

async fn survives_runner_failure(mode: Mode) -> Test {
    let (_guard, sink) = capture();
    let rig = rig(vec![Step::Job("job-a"), Step::Job("job-b"), Step::Idle(0)]);
    let runner = Double::new(mode);
    let running = start(poller(&rig, runner.clone(), 0.5)?);

    pause(30).await;
    assert!(!running.task.is_finished());
    assert!(rig.claims() >= 4, "claims: {}", rig.claims());
    assert_eq!(runner.started(), ["job-a", "job-b"]);
    let gaps = rig.gaps();
    let gap = |index: usize| gaps.get(index).copied().unwrap_or_default();
    assert!(between(gap(0), 0.4, 0.6), "first: {:?}", gap(0));
    assert!(between(gap(1), 0.9, 1.1), "second: {:?}", gap(1));
    assert!(sink.text().contains("job runner"), "{}", sink.text());
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn a_runner_error_keeps_the_poller_alive() -> Test {
    survives_runner_failure(Mode::Fail).await
}

#[tokio::test(start_paused = true)]
async fn a_runner_panic_keeps_the_poller_alive() -> Test {
    survives_runner_failure(Mode::Panic).await
}

#[tokio::test(start_paused = true)]
async fn the_claim_warning_carries_the_status_code_only() -> Test {
    let (_guard, sink) = capture();
    let rig = rig(vec![Step::Fail]);
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.5)?);
    rig.shared.arrived.notified().await;
    pause(1).await;
    running.stop_within(Duration::from_secs(1)).await?;

    let text = sink.text();
    assert!(text.contains("job claim failed"), "{text}");
    assert!(text.contains("Internal"), "{text}");
    assert!(!text.contains(RAW), "{text}");
    assert!(!text.contains(SECRET), "{text}");
    Ok(())
}

#[tokio::test]
async fn the_token_is_sent_as_a_bearer_header() -> Test {
    let rig = rig(vec![Step::Idle(0)]);
    let mut poller = poller(&rig, Double::new(Mode::Ok), 0.5)?;
    assert!(matches!(poller.claim().await?, Claimed::Idle(_)));
    let seen = rig.shared.auth.lock().map_err(|e| e.to_string())?.clone();
    assert_eq!(seen, [format!("Bearer {SECRET}")]);
    Ok(())
}

#[tokio::test]
async fn errors_do_not_leak_the_token_or_server_text() -> Test {
    let rig = rig(vec![Step::Fail]);
    let mut poller = poller(&rig, Double::new(Mode::Ok), 0.5)?;
    let err = poller.claim().await.err().ok_or("claim should fail")?;
    let shown = format!("{err} {err:?}");
    assert!(!shown.contains(RAW), "{shown}");
    assert!(!shown.contains(SECRET), "{shown}");
    assert_eq!(err.code(), tonic::Code::Internal);
    assert!(!format!("{:?}", Token::new(SECRET)).contains(SECRET));
    Ok(())
}

#[tokio::test]
async fn an_unreachable_server_is_an_error_not_a_panic() -> Test {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    drop(listener);
    let mut poller = Poller::connect(
        &url,
        &Token::new(SECRET),
        String::from("b"),
        Double::new(Mode::Ok),
    )?;
    let err = poller.claim().await.err().ok_or("claim should fail")?;
    assert_eq!(err.code(), tonic::Code::Unavailable);
    Ok(())
}

fn from_env(url: Option<&str>, token: Option<&str>) -> Result<Option<Poller<Double>>, String> {
    Poller::from_env(
        &|name| match name {
            "FLEET_SERVER_URL" => url.map(str::to_owned),
            "FLEET_TOKEN" => token.map(str::to_owned),
            _ => None,
        },
        String::from("b"),
        Double::new(Mode::Ok),
    )
    .map_err(|err| err.to_string())
}

#[tokio::test]
async fn from_env_is_off_without_a_server_url() {
    assert!(from_env(None, None).is_ok_and(|poller| poller.is_none()));
    assert!(from_env(Some(""), None).is_ok_and(|poller| poller.is_none()));
}

#[tokio::test]
async fn from_env_accepts_an_http_url_with_a_token() {
    assert!(
        from_env(Some("http://127.0.0.1:1"), Some(SECRET)).is_ok_and(|poller| poller.is_some())
    );
}

#[tokio::test]
async fn a_missing_or_empty_token_is_rejected() {
    for token in [None, Some("")] {
        let err = from_env(Some("http://127.0.0.1:1"), token).err();
        assert!(
            err.is_some_and(|err| err.contains("FLEET_TOKEN") && !err.contains("127.0.0.1")),
            "token {token:?}"
        );
    }
}

#[tokio::test]
async fn a_bad_token_is_rejected_without_echoing_it() {
    let err = from_env(Some("http://127.0.0.1:1"), Some("line\nbreak")).err();
    assert!(err.is_some_and(|err| !err.contains("break")));
}

#[tokio::test]
async fn a_non_http_scheme_is_rejected_without_echoing_the_url() {
    for url in [
        "ftp://secret-host:1",
        "secret-host:1",
        "unix:///secret/path",
    ] {
        let err = from_env(Some(url), Some(SECRET)).err();
        assert!(
            err.is_some_and(|err| err.contains("FLEET_SERVER_URL") && !err.contains("secret")),
            "url {url}"
        );
    }
}

#[tokio::test]
async fn grpc_reporter_sends_report_job_with_the_bearer_token() -> Test {
    let rig = rig(Vec::new());
    let reporter = GrpcReporter::new(rig.channel.clone(), &Token::new(SECRET))?;
    let reply = reporter
        .report(ReportJobRequest {
            job_id: "job-abc".into(),
            ..ReportJobRequest::default()
        })
        .await?;
    assert_eq!(reply.acked_through_seq, 7);
    let seen = rig
        .shared
        .report_auth
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(seen, [format!("Bearer {SECRET}")]);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_paused_gate_stops_claims_and_resuming_restarts_them() -> Test {
    let rig = rig(vec![]);
    let gate = ClaimGate::new();
    gate.pause();
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.5)?.with_gate(gate.clone()));

    pause(120).await;
    assert_eq!(rig.claims(), 0);

    gate.resume();
    pause(10).await;
    assert!(rig.claims() >= 1);
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn a_drain_does_not_finish_while_a_claimed_job_is_not_yet_leased() -> Test {
    let rig = rig(vec![Step::Job("job-a")]);
    let gate = ClaimGate::new();
    let runner = Double::new(Mode::Lease);
    let running = start(poller(&rig, runner.clone(), 0.5)?.with_gate(gate.clone()));
    runner.began.notified().await;
    let control = DrainController::new(
        gate.clone(),
        Duration::from_secs(60),
        Duration::from_secs(1),
    );
    let mut drain = control.begin_drain()?;
    let began = Instant::now();
    let leased = Arc::clone(&runner.leased);
    let outcome = drain.wait(|| !leased.load(Ordering::SeqCst)).await;
    assert_eq!(outcome, DrainOutcome::Drained);
    assert!(began.elapsed() >= Duration::from_secs(10));
    assert!(!runner.leased.load(Ordering::SeqCst));
    drop(drain);
    running.stop_within(Duration::from_secs(1)).await
}

#[tokio::test(start_paused = true)]
async fn pausing_the_gate_mid_run_stops_new_claims() -> Test {
    let rig = rig(vec![]);
    let gate = ClaimGate::new();
    let running = start(poller(&rig, Double::new(Mode::Ok), 0.5)?.with_gate(gate.clone()));

    pause(20).await;
    gate.pause();
    pause(10).await;
    let seen = rig.claims();
    pause(300).await;
    assert_eq!(rig.claims(), seen);
    running.stop_within(Duration::from_secs(1)).await
}

struct ClockState {
    now: Mutex<Duration>,
    sleeps: Mutex<Vec<Duration>>,
}

#[derive(Clone)]
struct FakeClock(Arc<ClockState>);

impl FakeClock {
    fn new() -> Self {
        Self(Arc::new(ClockState {
            now: Mutex::new(Duration::from_secs(1000)),
            sleeps: Mutex::new(Vec::new()),
        }))
    }

    fn sleeps(&self) -> Vec<Duration> {
        self.0
            .sleeps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl RetryClock for FakeClock {
    fn now(&self) -> Duration {
        *self.0.now.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send {
        *self.0.now.lock().unwrap_or_else(PoisonError::into_inner) += duration;
        self.0
            .sleeps
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(duration);
        std::future::ready(())
    }
}

struct TransportState {
    cost: Option<(FakeClock, Duration)>,
    script: Mutex<VecDeque<Result<(), Status>>>,
    keys: Mutex<Vec<String>>,
}

#[derive(Clone)]
struct FakeTransport(Arc<TransportState>);

impl FakeTransport {
    fn scripted(steps: Vec<Result<(), Status>>) -> Self {
        Self(Arc::new(TransportState {
            cost: None,
            script: Mutex::new(steps.into()),
            keys: Mutex::new(Vec::new()),
        }))
    }

    fn costing(steps: Vec<Result<(), Status>>, clock: &FakeClock, cost: Duration) -> Self {
        Self(Arc::new(TransportState {
            cost: Some((clock.clone(), cost)),
            script: Mutex::new(steps.into()),
            keys: Mutex::new(Vec::new()),
        }))
    }

    fn keys(&self) -> Vec<String> {
        self.0
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl TimingTransport for FakeTransport {
    fn report_timing(
        &self,
        idempotency_key: &str,
        _request: ReportTimingRequest,
    ) -> impl Future<Output = Result<ReportTimingReply, Status>> + Send {
        self.0
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(idempotency_key.to_owned());
        if let Some((clock, cost)) = &self.0.cost {
            *clock.0.now.lock().unwrap_or_else(PoisonError::into_inner) += *cost;
        }
        let step = self
            .0
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front()
            .unwrap_or_else(|| Err(Status::unavailable("script ended")));
        std::future::ready(step.map(|()| ReportTimingReply {}))
    }
}

fn timing_request(job: &str) -> ReportTimingRequest {
    ReportTimingRequest {
        job_id: job.into(),
        attempt: 1,
        ..ReportTimingRequest::default()
    }
}

fn unavailable() -> Result<(), Status> {
    Err(Status::unavailable("down"))
}

fn pushback(value: &str) -> Result<(), Status> {
    let mut status = Status::unavailable("busy");
    if let Ok(parsed) = value.parse() {
        status.metadata_mut().insert(PUSHBACK_METADATA, parsed);
    }
    Err(status)
}

type TimingRig = (
    TimingReporter<FakeTransport, FakeClock, Fixed>,
    FakeTransport,
    FakeClock,
);

fn timing_rig(steps: Vec<Result<(), Status>>) -> TimingRig {
    let transport = FakeTransport::scripted(steps);
    let clock = FakeClock::new();
    let reporter = TimingReporter::new(transport.clone(), clock.clone(), Fixed(1.0));
    (reporter, transport, clock)
}

fn quiet_rig(steps: Vec<Result<(), Status>>, cost: Duration) -> TimingRig {
    let clock = FakeClock::new();
    let transport = FakeTransport::costing(steps, &clock, cost);
    let reporter = TimingReporter::new(transport.clone(), clock.clone(), Fixed(0.0));
    (reporter, transport, clock)
}

async fn bounded<T>(future: impl Future<Output = T>) -> Result<T, Box<dyn Error>> {
    Ok(tokio::time::timeout(Duration::from_secs(10), future).await?)
}

#[tokio::test]
async fn timing_report_is_acked_on_the_first_call() -> Test {
    let (mut reporter, transport, clock) = timing_rig(vec![Ok(())]);
    let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(outcome, TimingOutcome::Acked { attempts: 1 });
    assert_eq!(transport.keys().len(), 1);
    assert_eq!(clock.sleeps().len(), 0);
    Ok(())
}

#[tokio::test]
async fn timing_report_retries_then_acks_with_one_stable_key() -> Test {
    let (mut reporter, transport, clock) = timing_rig(vec![unavailable(), unavailable(), Ok(())]);
    let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(outcome, TimingOutcome::Acked { attempts: 3 });
    let keys = transport.keys();
    assert_eq!(keys.len(), 3);
    assert!(keys.iter().all(|key| *key == keys[0] && !key.is_empty()));
    assert_eq!(keys[0], timing_idempotency_key("job-1", 1)?);
    assert_eq!(
        clock.sleeps(),
        [Duration::from_secs(1), Duration::from_secs(2)]
    );
    Ok(())
}

#[tokio::test]
async fn timing_report_key_differs_per_job_and_attempt_and_is_never_empty()
-> Result<(), Box<dyn Error>> {
    let first = timing_idempotency_key("job-1", 1)?;
    assert_ne!(first, timing_idempotency_key("job-2", 1)?);
    assert_ne!(first, timing_idempotency_key("job-1", 2)?);
    assert_eq!(first, timing_idempotency_key("job-1", 1)?);
    assert_eq!(
        timing_idempotency_key("", 1),
        Err(TimingReportError::EmptyJobId)
    );
    let (mut reporter, transport, _clock) = timing_rig(vec![Ok(())]);
    let refused = bounded(reporter.report(timing_request(""))).await?;
    assert_eq!(refused, Err(TimingReportError::EmptyJobId));
    assert_eq!(transport.keys().len(), 0);
    Ok(())
}

#[tokio::test]
async fn timing_report_stops_on_a_permanent_refusal() -> Test {
    for code in [
        Status::invalid_argument("bad"),
        Status::permission_denied("no"),
    ] {
        let want = code.code();
        let (mut reporter, transport, clock) = timing_rig(vec![Err(code), Ok(())]);
        let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
        assert_eq!(outcome, TimingOutcome::Refused(want));
        assert_eq!(transport.keys().len(), 1);
        assert_eq!(clock.sleeps().len(), 0);
    }
    Ok(())
}

#[tokio::test]
async fn timing_report_stops_when_the_job_is_pruned() -> Test {
    let (mut reporter, transport, clock) =
        timing_rig(vec![unavailable(), Err(Status::not_found("gone")), Ok(())]);
    let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(outcome, TimingOutcome::Pruned);
    assert_eq!(transport.keys().len(), 2);
    assert_eq!(clock.sleeps().len(), 1);
    Ok(())
}

#[tokio::test]
async fn timing_report_caps_a_hostile_server_wait() -> Test {
    for hostile in [
        "99999999999999999999999999",
        "18446744073709551615",
        "86400000",
    ] {
        let (mut reporter, _transport, clock) = timing_rig(vec![pushback(hostile), Ok(())]);
        let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
        assert_eq!(outcome, TimingOutcome::Acked { attempts: 2 });
        assert_eq!(clock.sleeps(), [MAX_SERVER_WAIT]);
    }
    Ok(())
}

#[tokio::test]
async fn timing_report_honours_a_small_server_wait_above_the_backoff() -> Test {
    let (mut reporter, _transport, clock) = timing_rig(vec![pushback("5000"), Ok(())]);
    bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(clock.sleeps(), [Duration::from_secs(5)]);
    let (mut reporter, _transport, clock) =
        timing_rig(vec![pushback("-5"), pushback("x"), pushback(""), Ok(())]);
    bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(
        clock.sleeps(),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(4)
        ]
    );
    Ok(())
}

#[tokio::test]
async fn timing_report_gives_up_after_the_attempt_budget() -> Test {
    let steps = (0..MAX_TIMING_ATTEMPTS + 5)
        .map(|_| unavailable())
        .collect();
    let (mut reporter, transport, _clock) = quiet_rig(steps, Duration::ZERO);
    let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(outcome, TimingOutcome::GaveUp);
    assert_eq!(
        transport.keys().len(),
        usize::try_from(MAX_TIMING_ATTEMPTS)?
    );
    Ok(())
}

#[tokio::test]
async fn timing_report_gives_up_at_the_deadline() -> Test {
    let steps = (0..MAX_TIMING_ATTEMPTS)
        .map(|_| pushback("60000"))
        .collect();
    let (mut reporter, transport, clock) = timing_rig(steps);
    let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(outcome, TimingOutcome::GaveUp);
    let slept: Duration = clock.sleeps().iter().sum();
    assert!(slept <= TIMING_REPORT_DEADLINE);
    assert!(slept + MAX_SERVER_WAIT > TIMING_REPORT_DEADLINE);
    assert!(transport.keys().len() < usize::try_from(MAX_TIMING_ATTEMPTS)?);
    Ok(())
}

#[tokio::test]
async fn timing_backoff_resets_after_an_ack() -> Test {
    let (mut reporter, _transport, clock) = timing_rig(vec![
        unavailable(),
        unavailable(),
        Ok(()),
        unavailable(),
        Ok(()),
    ]);
    bounded(reporter.report(timing_request("job-1"))).await??;
    bounded(reporter.report(timing_request("job-2"))).await??;
    assert_eq!(
        clock.sleeps(),
        [
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1)
        ]
    );
    Ok(())
}

#[tokio::test]
async fn timing_backoff_does_not_reset_after_a_refusal_or_a_prune() -> Test {
    for end in [Status::invalid_argument("bad"), Status::not_found("gone")] {
        let (mut reporter, _transport, clock) =
            timing_rig(vec![unavailable(), Err(end), unavailable(), Ok(())]);
        bounded(reporter.report(timing_request("job-1"))).await??;
        bounded(reporter.report(timing_request("job-2"))).await??;
        assert_eq!(
            clock.sleeps(),
            [Duration::from_secs(1), Duration::from_secs(2)]
        );
    }
    Ok(())
}

#[tokio::test]
async fn grpc_timing_transport_sends_the_idempotency_key() -> Test {
    let rig = rig(Vec::new());
    let transport = GrpcTimingTransport::new(rig.channel.clone(), &Token::new(SECRET))?;
    let mut reporter = TimingReporter::new(transport, FakeClock::new(), Fixed(1.0));
    let outcome = bounded(reporter.report(timing_request("job-9"))).await??;
    assert_eq!(outcome, TimingOutcome::Acked { attempts: 1 });
    let keys = rig
        .shared
        .timing_keys
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(keys, [timing_idempotency_key("job-9", 1)?]);
    Ok(())
}

#[tokio::test]
async fn timing_report_deadline_is_inclusive() -> Test {
    let steps = (0..MAX_TIMING_ATTEMPTS).map(|_| pushback("1000")).collect();
    let (mut reporter, transport, _clock) = quiet_rig(steps, Duration::from_secs(99));
    let outcome = bounded(reporter.report(timing_request("job-1"))).await??;
    assert_eq!(outcome, TimingOutcome::GaveUp);
    assert_eq!(transport.keys().len(), 7);
    Ok(())
}

fn hostile_job_ids() -> Vec<(&'static str, String)> {
    vec![
        ("space", "a b".into()),
        ("tab", "a\tb".into()),
        ("cr", "a\rb".into()),
        ("lf", "a\nb".into()),
        ("crlf", "a\r\nb".into()),
        ("nel", "a\u{85}b".into()),
        ("u2028", "a\u{2028}b".into()),
        ("non_ascii", "j\u{f6}b".into()),
        ("nul", "a\0b".into()),
        ("cap_plus_one", "a".repeat(MAX_TIMING_JOB_ID_BYTES + 1)),
    ]
}

#[tokio::test]
async fn timing_key_rejects_every_hostile_job_id_without_sending() -> Test {
    assert_eq!(
        timing_idempotency_key("", 1),
        Err(TimingReportError::EmptyJobId)
    );
    for (name, job) in hostile_job_ids() {
        assert_eq!(
            timing_idempotency_key(&job, 1),
            Err(TimingReportError::BadJobId),
            "{name}"
        );
        let (mut reporter, transport, _clock) = timing_rig(vec![Ok(())]);
        let refused = bounded(reporter.report(timing_request(&job))).await?;
        assert_eq!(refused, Err(TimingReportError::BadJobId), "{name}");
        assert_eq!(transport.keys().len(), 0, "{name}");
    }
    let longest = "a".repeat(MAX_TIMING_JOB_ID_BYTES);
    assert!(timing_idempotency_key(&longest, 1).is_ok());
    let control = "!~09Az-_.:/".repeat(2);
    assert!(timing_idempotency_key(&control, 1).is_ok());
    assert_eq!(
        TimingReportError::BadJobId.to_string(),
        "timing report job id is not a short run of printable ASCII"
    );
    Ok(())
}

#[tokio::test]
async fn grpc_timing_transport_refuses_a_key_that_is_not_a_header_value() -> Test {
    let rig = rig(Vec::new());
    let transport = GrpcTimingTransport::new(rig.channel.clone(), &Token::new(SECRET))?;
    for key in ["a\r\nb", "a\rb", "a\nb", "a\0b", "a\x7fb"] {
        let status = transport
            .report_timing(key, timing_request("job-1"))
            .await
            .err()
            .ok_or_else(|| format!("sent {key:?}"))?;
        assert_eq!(status.code(), tonic::Code::InvalidArgument, "{key:?}");
    }
    let sent = rig
        .shared
        .timing_keys
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .len();
    assert_eq!(sent, 0);
    transport
        .report_timing("timing:job-1:1", timing_request("job-1"))
        .await?;
    let sent = rig
        .shared
        .timing_keys
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    assert_eq!(sent, ["timing:job-1:1"]);
    Ok(())
}
