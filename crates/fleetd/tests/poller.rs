//! Poller behaviour against an in-memory `FleetWorker` stub, with tokio time paused.
//!
//! The stub runs on the test runtime behind a duplex connector, so no real socket is
//! involved. Paused time then advances only when every task is idle, which makes the
//! recorded claim times exact. Tests that need a real socket run on the real clock.

use std::collections::VecDeque;
use std::error::Error;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
use fleet_proto::v1::{ClaimJobReply, ClaimJobRequest, Job, ReportJobReply, ReportJobRequest};
use fleetd::backoff::Random;
use fleetd::poller::{
    CLAIM_GRACE, Claimed, GrpcReporter, JobRunner, MAX_IDLE_WAIT, PollRandom, Poller,
    REQUEST_TIMEOUT, RunError, SHUTDOWN_GRACE, Shutdown, Token,
};
use fleetd::runner::Reporter;
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
}

#[derive(Clone)]
struct Double {
    mode: Mode,
    started: Arc<Mutex<Vec<String>>>,
    began: Arc<Notify>,
    gate: Arc<Notify>,
    saw_shutdown: Arc<AtomicBool>,
}

impl Double {
    fn new(mode: Mode) -> Self {
        Self {
            mode,
            started: Arc::default(),
            began: Arc::default(),
            gate: Arc::default(),
            saw_shutdown: Arc::default(),
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
