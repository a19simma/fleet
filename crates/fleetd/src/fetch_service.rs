//! The fetch service on the per-job unix socket (ADR-0038, ADR-0036).
//!
//! A client sends frames, each a JSON [`Request`] `{"url": "<url>"}`, and reads one reply frame
//! per request: `{"status":"ok","body":"<render>"}` or `{"status":"error","error":"<text>"}`.
//! The body is [`crate::fetch::Fetched::render`], the untrusted-framed text. Every error text is
//! fixed and holds nothing from the client or the network.
//!
//! The order of one request is fixed. The service refuses a lost lease, parses the frame
//! (`deny_unknown_fields`, at most [`MAX_FRAME_BYTES`]), runs the URL rules, the URL cap and
//! the host policy, takes one slot of the per-Job fetch cap and one concurrency slot, records
//! the intent event, fetches, and records the outcome event. A failed intent record refuses the
//! fetch before any name is resolved, so a Job that cannot be audited cannot fetch. A failed
//! outcome record does not hide the body: the feed adds `fetch_outcome` to the summary
//! `missing` list. If the request future is dropped after the intent (the socket is cancelled,
//! the lease is lost, the task panics), a drop guard records a failed outcome with no status, so
//! every intent gets an outcome or a `fetch_outcome` mark. "Recorded" means the feed accepted
//! the event, not that the server did.
//!
//! The job id comes from the listener's [`JobContext`], never from the client. One service
//! instance serves every Job of the Box, so the caps are kept per job id: call
//! [`FetchService::forget`] when a Job ends. A cap slot is spent once the intent is recorded,
//! so a fetch that then fails still spends it. A request refused before that point spends none:
//! a frame, URL or host refusal, a reached cap, a busy Job, a lease lost at the second check and
//! a failed intent record all leave the count as it was.
//!
//! A reply must fit one frame. A rendered page that does not is refused with a fixed error.
//!
//! This module is built, not wired: no runtime path registers the service yet, and the
//! production recorder over the runner's feed lands with that wiring.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use tokio::io::BufReader;
use tokio::net::UnixStream;

use crate::fetch::{Dialer, FetchError, Fetcher, Resolver};
use crate::fetch_policy::{FetchCaps, FetchPolicy};
use crate::jobsock::{JobContext, MAX_FRAME_BYTES, ServeFuture, Service, read_frame, write_frame};
use crate::netguard::{UrlRefusal, precheck_url};
use crate::telemetry::{FetchPhase, FetchRecordError};

/// Most fetches of one Job in flight at once.
pub const MAX_CONCURRENT_FETCHES: u32 = 4;

/// Records the fetch events of a Job. A test substitutes a fake.
pub trait FetchRecorder: Send + Sync {
    /// Records one event for `job_id`.
    ///
    /// # Errors
    ///
    /// Fails when the event feed did not accept the event.
    fn record(&self, job_id: &str, url: &str, phase: FetchPhase) -> Result<(), FetchRecordError>;
}

/// One fetch request. The URL is the only key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The URL to fetch.
    pub url: String,
}

impl Request {
    /// Parses one frame. An oversize frame, bad UTF-8, a duplicate or unknown key and a missing
    /// `url` yield [`Refusal::InvalidRequest`].
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::InvalidRequest`] when the frame is not exactly one request.
    pub fn parse(frame: &[u8]) -> Result<Self, Refusal> {
        if frame.len() > MAX_FRAME_BYTES {
            return Err(Refusal::InvalidRequest);
        }
        serde_json::from_slice(frame).map_err(|_| Refusal::InvalidRequest)
    }
}

/// Why the service refused a fetch before or instead of fetching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The frame is not a valid request.
    InvalidRequest,
    /// The lease of the Job is lost.
    LeaseLost,
    /// The Job spent its fetch cap.
    CapReached,
    /// The Job already has the most fetches in flight.
    Busy,
    /// The intent event was not recorded.
    NotRecorded,
    /// The rendered page does not fit one reply frame.
    TooLarge,
}

impl Refusal {
    /// The fixed error text sent to the client.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid fetch request",
            Self::LeaseLost => "fetch refused: job lease lost",
            Self::CapReached => "fetch refused: per-job fetch limit reached",
            Self::Busy => "fetch refused: too many fetches in flight",
            Self::NotRecorded => "fetch refused: could not be recorded",
            Self::TooLarge => "fetch result too large for one reply",
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Reply {
    Ok { body: String },
    Error { error: String },
}

impl Reply {
    fn refused(refusal: Refusal) -> Self {
        Self::Error {
            error: refusal.message().to_owned(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        let frame = serde_json::to_vec(self).unwrap_or_default();
        if frame.len() <= MAX_FRAME_BYTES {
            return frame;
        }
        serde_json::to_vec(&Self::refused(Refusal::TooLarge)).unwrap_or_default()
    }
}

#[derive(Default)]
struct JobCounts {
    used: u32,
    inflight: u32,
}

struct OutcomeGuard<'a, Rec: FetchRecorder> {
    recorder: &'a Rec,
    job_id: &'a str,
    url: &'a str,
    armed: bool,
}

impl<Rec: FetchRecorder> OutcomeGuard<'_, Rec> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<Rec: FetchRecorder> Drop for OutcomeGuard<'_, Rec> {
    fn drop(&mut self) {
        if self.armed {
            let _ =
                self.recorder
                    .record(self.job_id, self.url, FetchPhase::Failed { status: None });
        }
    }
}

struct Slot<'a> {
    jobs: &'a Mutex<HashMap<String, JobCounts>>,
    job_id: &'a str,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(counts) = jobs.get_mut(self.job_id) {
            counts.inflight = counts.inflight.saturating_sub(1);
        }
    }
}

/// The fetch service. Register it under [`crate::jobsock::ServiceName::Fetch`].
pub struct FetchService<Rec, R, D> {
    policy: FetchPolicy,
    caps: FetchCaps,
    max_concurrent: u32,
    fetcher: Fetcher<R, D>,
    recorder: Rec,
    jobs: Mutex<HashMap<String, JobCounts>>,
}

impl<Rec, R, D> fmt::Debug for FetchService<Rec, R, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FetchService")
            .field("policy", &self.policy)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl<Rec: FetchRecorder, R: Resolver, D: Dialer> FetchService<Rec, R, D> {
    /// A service that fetches through `fetcher`. `policy` and `caps` must be the ones the
    /// fetcher was built with: the service applies them before it records the intent.
    #[must_use]
    pub fn new(
        policy: FetchPolicy,
        caps: FetchCaps,
        max_concurrent: u32,
        fetcher: Fetcher<R, D>,
        recorder: Rec,
    ) -> Self {
        Self {
            policy,
            caps,
            max_concurrent,
            fetcher,
            recorder,
            jobs: Mutex::default(),
        }
    }

    /// Drops the counters of a finished Job.
    pub fn forget(&self, job_id: &str) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }

    /// Serves one frame for `job_id` and returns the rendered page or the fixed error text.
    /// `lease_lost` is read first and again right before the intent is recorded.
    ///
    /// # Errors
    ///
    /// Returns the fixed error text of the first rule the request breaks.
    pub async fn handle_frame(
        &self,
        job_id: &str,
        lease_lost: &(dyn Fn() -> bool + Sync),
        frame: &[u8],
    ) -> Result<String, String> {
        if lease_lost() {
            return Err(Refusal::LeaseLost.message().to_owned());
        }
        let request = Request::parse(frame).map_err(|refusal| refusal.message().to_owned())?;
        self.precheck(&request.url)?;
        let _slot = self
            .reserve(job_id)
            .map_err(|refusal| refusal.message().to_owned())?;
        if lease_lost() {
            self.refund(job_id);
            return Err(Refusal::LeaseLost.message().to_owned());
        }
        if self
            .recorder
            .record(job_id, &request.url, FetchPhase::Intent)
            .is_err()
        {
            self.refund(job_id);
            return Err(Refusal::NotRecorded.message().to_owned());
        }
        let mut guard = OutcomeGuard {
            recorder: &self.recorder,
            job_id,
            url: &request.url,
            armed: true,
        };
        let result = self.fetcher.fetch(&request.url).await;
        let phase = match &result {
            Ok(fetched) => FetchPhase::Succeeded {
                status: fetched.status,
                bytes: fetched.bytes,
            },
            Err(FetchError::Status(code)) => FetchPhase::Failed {
                status: Some(*code),
            },
            Err(_) => FetchPhase::Failed { status: None },
        };
        guard.disarm();
        if self.recorder.record(job_id, &request.url, phase).is_err() {
            tracing::warn!("fetch outcome not recorded");
        }
        result
            .map(|fetched| fetched.render())
            .map_err(|error| error.to_string())
    }

    fn refund(&self, job_id: &str) {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(counts) = jobs.get_mut(job_id) {
            counts.used = counts.used.saturating_sub(1);
        }
    }

    fn precheck(&self, url: &str) -> Result<(), String> {
        if !self.caps.url_within_cap(url) {
            return Err(FetchError::Refused(UrlRefusal::TooLong).to_string());
        }
        let target =
            precheck_url(url).map_err(|refusal| FetchError::Refused(refusal).to_string())?;
        if !self.policy.permits_host(&target.host) {
            return Err(FetchError::HostNotPermitted.to_string());
        }
        Ok(())
    }

    fn reserve<'a>(&'a self, job_id: &'a str) -> Result<Slot<'a>, Refusal> {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = jobs.entry(job_id.to_owned()).or_default();
        if counts.used >= self.caps.max_fetches_per_job {
            return Err(Refusal::CapReached);
        }
        if counts.inflight >= self.max_concurrent {
            return Err(Refusal::Busy);
        }
        counts.used += 1;
        counts.inflight += 1;
        drop(jobs);
        Ok(Slot {
            jobs: &self.jobs,
            job_id,
        })
    }

    async fn serve_stream(&self, ctx: JobContext, stream: UnixStream) {
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        loop {
            let frame = match read_frame(&mut reader).await {
                Ok(frame) => frame,
                Err(err) if err.kind() == std::io::ErrorKind::InvalidData => {
                    let reply = Reply::refused(Refusal::InvalidRequest).encode();
                    let _ = write_frame(&mut write, &reply).await;
                    return;
                }
                Err(_) => return,
            };
            let lost = || ctx.cancel.is_cancelled();
            let reply = match self.handle_frame(&ctx.job_id, &lost, &frame).await {
                Ok(body) => Reply::Ok { body },
                Err(error) => Reply::Error { error },
            };
            if write_frame(&mut write, &reply.encode()).await.is_err() {
                return;
            }
        }
    }
}

impl<Rec: FetchRecorder, R: Resolver, D: Dialer> Service for FetchService<Rec, R, D> {
    fn serve(&self, ctx: JobContext, stream: UnixStream) -> ServeFuture<'_> {
        Box::pin(self.serve_stream(ctx, stream))
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
    use std::time::Duration;

    use fleet_core::Redactor;
    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::Notify;
    use tokio::time::Instant;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::feed::Feed;
    use crate::fetch::tls_config_with_roots;
    use crate::fetch_policy::HostPattern;
    use crate::jobsock::{AGENT_SLICE, JobSocket, Limits, Peer, PeerId, ServiceName, Services};
    use crate::telemetry::{Limits as TelemetryLimits, Telemetry, Terminal};

    type Registered = (Arc<Mutex<Feed>>, Redactor);

    #[derive(Default)]
    struct FeedBook {
        feeds: Mutex<HashMap<String, Registered>>,
    }

    impl fmt::Debug for FeedBook {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("FeedBook").finish_non_exhaustive()
        }
    }

    impl FeedBook {
        /// Makes `feed` the feed that records the fetch events of `job_id`.
        fn register(&self, job_id: &str, feed: Arc<Mutex<Feed>>, redactor: Redactor) {
            self.feeds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(job_id.to_owned(), (feed, redactor));
        }
    }

    impl FetchRecorder for FeedBook {
        fn record(
            &self,
            job_id: &str,
            url: &str,
            phase: FetchPhase,
        ) -> Result<(), FetchRecordError> {
            let found = self
                .feeds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(job_id)
                .cloned();
            let (feed, redactor) = found.ok_or(FetchRecordError::Closed)?;
            feed.lock()
                .unwrap_or_else(PoisonError::into_inner)
                .record_fetch(&redactor, url, phase, Instant::now())
        }
    }

    type Log = Arc<Mutex<Vec<String>>>;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const OUTER: Duration = Duration::from_secs(20);
    const NEVER: &(dyn Fn() -> bool + Sync) = &|| false;
    const GOOD: &[u8] = br#"{"url":"https://a.example.test/page"}"#;

    fn push(log: &Log, entry: &str) {
        log.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(entry.to_owned());
    }

    fn entries(log: &Log) -> Vec<String> {
        log.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }

    #[derive(Clone)]
    struct Count {
        log: Log,
        dials: Arc<AtomicUsize>,
        resolves: Arc<AtomicUsize>,
        gate: Option<Arc<Notify>>,
        entered: Arc<Notify>,
        port: Option<u16>,
        explode: bool,
    }

    impl Count {
        fn new(log: &Log) -> Self {
            Self {
                log: Arc::clone(log),
                dials: Arc::default(),
                resolves: Arc::default(),
                gate: None,
                entered: Arc::default(),
                port: None,
                explode: false,
            }
        }

        fn network(&self) -> usize {
            self.dials.load(Ordering::SeqCst) + self.resolves.load(Ordering::SeqCst)
        }
    }

    impl Resolver for Count {
        fn resolve(&self, _host: &str) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send {
            self.resolves.fetch_add(1, Ordering::SeqCst);
            push(&self.log, "resolve");
            assert!(!self.explode, "resolver exploded");
            std::future::ready(Ok(vec![IpAddr::V4(PUBLIC)]))
        }
    }

    impl Dialer for Count {
        async fn dial(&self, _addr: SocketAddr) -> io::Result<TcpStream> {
            self.dials.fetch_add(1, Ordering::SeqCst);
            push(&self.log, "dial");
            self.entered.notify_one();
            if let Some(gate) = &self.gate {
                gate.notified().await;
            }
            match self.port {
                Some(port) => TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await,
                None => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
            }
        }
    }

    struct Recorder {
        log: Log,
        fail_intent: AtomicBool,
        phases: Mutex<Vec<(String, FetchPhase)>>,
    }

    impl Recorder {
        fn new(log: &Log, fail_intent: bool) -> Arc<Self> {
            Arc::new(Self {
                log: Arc::clone(log),
                fail_intent: AtomicBool::new(fail_intent),
                phases: Mutex::default(),
            })
        }

        fn heal(&self) {
            self.fail_intent.store(false, Ordering::SeqCst);
        }

        fn phases(&self) -> Vec<(String, FetchPhase)> {
            self.phases
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl FetchRecorder for Arc<Recorder> {
        fn record(
            &self,
            job_id: &str,
            _url: &str,
            phase: FetchPhase,
        ) -> Result<(), FetchRecordError> {
            push(&self.log, &format!("record {phase:?}"));
            self.phases
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((job_id.to_owned(), phase));
            if self.fail_intent.load(Ordering::SeqCst) && phase == FetchPhase::Intent {
                return Err(FetchRecordError::Truncated);
            }
            Ok(())
        }
    }

    fn build<Rec: FetchRecorder>(
        policy: FetchPolicy,
        caps: FetchCaps,
        max_concurrent: u32,
        count: &Count,
        roots: RootCertStore,
        recorder: Rec,
    ) -> FetchService<Rec, Count, Count> {
        let fetcher = Fetcher::new(
            policy.clone(),
            caps,
            count.clone(),
            count.clone(),
            tls_config_with_roots(roots),
        );
        FetchService::new(policy, caps, max_concurrent, fetcher, recorder)
    }

    fn fake(
        caps: FetchCaps,
        count: &Count,
        recorder: &Arc<Recorder>,
    ) -> FetchService<Arc<Recorder>, Count, Count> {
        build(
            FetchPolicy::default(),
            caps,
            MAX_CONCURRENT_FETCHES,
            count,
            RootCertStore::empty(),
            Arc::clone(recorder),
        )
    }

    fn caps() -> FetchCaps {
        FetchCaps {
            connect_timeout: Duration::from_secs(5),
            total_timeout: Duration::from_secs(15),
            ..FetchCaps::default()
        }
    }

    struct Server {
        port: u16,
        roots: RootCertStore,
    }

    async fn serve_text(body: String) -> Server {
        let key =
            rcgen::generate_simple_self_signed(vec!["a.example.test".to_owned()]).expect("cert");
        let der = key.cert.der().clone();
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).expect("root");
        let private =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(der.to_vec())], private)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let body = body.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut head = Vec::new();
                    let mut chunk = [0_u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: text/plain; charset=utf-8\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(reply.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Server { port, roots }
    }

    fn live(count: &mut Count, server: &Server) {
        count.port = Some(server.port);
    }

    fn real_feed(limits: TelemetryLimits) -> (Arc<FeedBook>, Arc<Mutex<Feed>>) {
        let feed = Arc::new(Mutex::new(Feed::with(
            Instant::now(),
            limits,
            Telemetry::feed_line_with,
        )));
        let book = Arc::new(FeedBook::default());
        book.register("job1", Arc::clone(&feed), Redactor::default());
        (book, feed)
    }

    impl FetchRecorder for Arc<FeedBook> {
        fn record(
            &self,
            job_id: &str,
            url: &str,
            phase: FetchPhase,
        ) -> Result<(), FetchRecordError> {
            self.as_ref().record(job_id, url, phase)
        }
    }

    async fn run(
        svc: &FetchService<Arc<Recorder>, Count, Count>,
        job: &str,
        frame: &[u8],
    ) -> Result<String, String> {
        tokio::time::timeout(OUTER, svc.handle_frame(job, NEVER, frame))
            .await
            .expect("outer timeout")
    }

    #[tokio::test]
    async fn hostile_requests_are_refused_before_any_resolve_dial_or_record() {
        let huge = format!(r#"{{"url":"https://a.example.test/{}"}}"#, "a".repeat(2000));
        let mut oversize = br#"{"url":"https://a.example.test/"}"#.to_vec();
        oversize.resize(MAX_FRAME_BYTES + 1, b' ');
        let invalid = Refusal::InvalidRequest.message();
        let table: Vec<(&str, Vec<u8>, &str)> = vec![
            (
                "unknown field",
                br#"{"url":"https://a.example.test/","x":1}"#.to_vec(),
                invalid,
            ),
            ("oversize", oversize, invalid),
            (
                "non-https",
                br#"{"url":"http://a.example.test/"}"#.to_vec(),
                "fetch refused: url scheme must be https",
            ),
            (
                "userinfo",
                br#"{"url":"https://u:p@a.example.test/"}"#.to_vec(),
                "fetch refused: url userinfo refused",
            ),
            (
                "non-utf8",
                b"{\"url\":\"https://a.example.test/\xff\"}".to_vec(),
                invalid,
            ),
            (
                "duplicate keys",
                br#"{"url":"https://a.example.test/","url":"https://b.example.test/"}"#.to_vec(),
                invalid,
            ),
            ("huge url", huge.into_bytes(), "fetch refused: url too long"),
            (
                "private literal",
                br#"{"url":"https://10.0.0.1/"}"#.to_vec(),
                "fetch refused: url host address not public",
            ),
            ("empty", Vec::new(), invalid),
            ("array", b"[]".to_vec(), invalid),
            ("missing url", b"{}".to_vec(), invalid),
            ("number url", br#"{"url":5}"#.to_vec(), invalid),
        ];
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let svc = fake(caps(), &count, &recorder);
        for (name, bytes, want) in table {
            assert_eq!(run(&svc, "j", &bytes).await, Err(want.to_owned()), "{name}");
        }
        assert_eq!(count.network(), 0);
        assert_eq!(recorder.phases().len(), 0);
        assert_eq!(
            run(&svc, "j", GOOD).await.err().as_deref(),
            Some("fetch connect failed")
        );
        assert_eq!(recorder.phases().len(), 2);
    }

    #[tokio::test]
    async fn a_host_outside_the_allowlist_is_refused_before_any_record() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let policy = FetchPolicy::Allowlist(vec![HostPattern::parse("docs.example.test").unwrap()]);
        let svc = build(
            policy,
            caps(),
            MAX_CONCURRENT_FETCHES,
            &count,
            RootCertStore::empty(),
            Arc::clone(&recorder),
        );
        assert_eq!(
            run(&svc, "j", GOOD).await,
            Err("fetch host not permitted".to_owned())
        );
        assert_eq!(count.network(), 0);
        assert_eq!(entries(&log), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_failed_intent_record_refuses_the_fetch_with_no_network_call() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, true);
        let svc = fake(caps(), &count, &recorder);
        assert_eq!(
            run(&svc, "j", GOOD).await,
            Err(Refusal::NotRecorded.message().to_owned())
        );
        assert_eq!(count.network(), 0);
        assert_eq!(entries(&log), ["record Intent"]);
    }

    #[tokio::test]
    async fn the_order_is_intent_then_network_then_outcome() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let svc = fake(caps(), &count, &recorder);
        assert_eq!(
            run(&svc, "job9", GOOD).await,
            Err("fetch connect failed".to_owned())
        );
        assert_eq!(
            entries(&log),
            [
                "record Intent",
                "resolve",
                "dial",
                "record Failed { status: None }"
            ]
        );
        assert_eq!(recorder.phases()[0].0, "job9");
    }

    #[tokio::test]
    async fn the_per_job_cap_counts_attempts_and_is_per_job() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let capped = FetchCaps {
            max_fetches_per_job: 2,
            ..caps()
        };
        let svc = fake(capped, &count, &recorder);
        let invalid = run(&svc, "a", b"{}").await;
        assert_eq!(invalid, Err(Refusal::InvalidRequest.message().to_owned()));
        for _ in 0..2 {
            assert_eq!(
                run(&svc, "a", GOOD).await,
                Err("fetch connect failed".to_owned())
            );
        }
        let dials = count.dials.load(Ordering::SeqCst);
        let before = recorder.phases().len();
        assert_eq!(
            run(&svc, "a", GOOD).await,
            Err(Refusal::CapReached.message().to_owned())
        );
        assert_eq!(count.dials.load(Ordering::SeqCst), dials);
        assert_eq!(recorder.phases().len(), before);
        assert_eq!(
            run(&svc, "b", GOOD).await,
            Err("fetch connect failed".to_owned())
        );
        svc.forget("a");
        assert_eq!(
            run(&svc, "a", GOOD).await,
            Err("fetch connect failed".to_owned())
        );
    }

    #[tokio::test]
    async fn the_concurrency_cap_refuses_without_spending_a_slot() {
        let log = Log::default();
        let mut count = Count::new(&log);
        let gate = Arc::new(Notify::new());
        count.gate = Some(Arc::clone(&gate));
        let recorder = Recorder::new(&log, false);
        let capped = FetchCaps {
            max_fetches_per_job: 2,
            ..caps()
        };
        let svc = Arc::new(build(
            FetchPolicy::default(),
            capped,
            1,
            &count,
            RootCertStore::empty(),
            Arc::clone(&recorder),
        ));
        let first = {
            let svc = Arc::clone(&svc);
            tokio::spawn(async move { svc.handle_frame("a", NEVER, GOOD).await })
        };
        tokio::time::timeout(OUTER, count.entered.notified())
            .await
            .expect("first fetch dialing");
        assert_eq!(
            svc.handle_frame("a", NEVER, GOOD).await,
            Err(Refusal::Busy.message().to_owned())
        );
        assert_eq!(count.dials.load(Ordering::SeqCst), 1);
        gate.notify_one();
        assert_eq!(
            first.await.expect("join"),
            Err("fetch connect failed".to_owned())
        );
        gate.notify_one();
        assert_eq!(
            svc.handle_frame("a", NEVER, GOOD).await,
            Err("fetch connect failed".to_owned())
        );
        assert_eq!(
            svc.handle_frame("a", NEVER, GOOD).await,
            Err(Refusal::CapReached.message().to_owned())
        );
    }

    #[tokio::test]
    async fn a_lost_lease_refuses_at_the_start_and_before_the_intent() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let svc = fake(caps(), &count, &recorder);
        let lost = svc.handle_frame("j", &|| true, GOOD).await;
        assert_eq!(lost, Err(Refusal::LeaseLost.message().to_owned()));
        let reads = AtomicU32::new(0);
        let flips = || reads.fetch_add(1, Ordering::SeqCst) >= 1;
        let late = svc.handle_frame("j", &flips, GOOD).await;
        assert_eq!(late, Err(Refusal::LeaseLost.message().to_owned()));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(count.network(), 0);
        assert_eq!(entries(&log), Vec::<String>::new());
    }

    #[test]
    fn a_reply_over_one_frame_becomes_the_fixed_too_large_error() {
        let big = Reply::Ok {
            body: "a".repeat(MAX_FRAME_BYTES),
        };
        let small = Reply::refused(Refusal::TooLarge);
        assert_eq!(big.encode(), small.encode());
        assert!(
            String::from_utf8(small.encode())
                .unwrap()
                .contains(Refusal::TooLarge.message())
        );
    }

    struct Cgroup(String);

    impl Peer for Cgroup {
        fn identity(&self, _: &UnixStream) -> io::Result<PeerId> {
            Ok(PeerId {
                pid: 7,
                cgroup: format!("0::/{AGENT_SLICE}/fleet-agent@{}.service\n", self.0),
            })
        }
    }

    async fn on_socket<Rec: FetchRecorder + 'static>(
        dir: &TempDir,
        svc: FetchService<Rec, Count, Count>,
    ) -> io::Result<(JobSocket, UnixStream)> {
        let path = dir.path().join("job.sock");
        let mut services = Services::new();
        services.insert(ServiceName::Fetch, Arc::new(svc));
        let socket = JobSocket::bind(
            &path,
            "job1",
            services,
            Arc::new(Cgroup("job1".into())),
            Limits::default(),
        )?;
        let mut stream = UnixStream::connect(&path).await?;
        write_frame(&mut stream, b"fetch").await?;
        Ok((socket, stream))
    }

    async fn ask(stream: &mut UnixStream, frame: &[u8]) -> io::Result<serde_json::Value> {
        write_frame(stream, frame).await?;
        let mut reader = BufReader::new(stream);
        let reply = tokio::time::timeout(OUTER, read_frame(&mut reader))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        serde_json::from_slice(&reply).map_err(io::Error::other)
    }

    #[tokio::test]
    async fn a_real_fetch_over_the_job_socket_is_framed_and_recorded_in_the_real_feed() -> TestResult
    {
        let server = serve_text("hello".to_owned()).await;
        let log = Log::default();
        let mut count = Count::new(&log);
        live(&mut count, &server);
        let (book, feed) = real_feed(TelemetryLimits::default());
        let svc = build(
            FetchPolicy::default(),
            caps(),
            MAX_CONCURRENT_FETCHES,
            &count,
            server.roots.clone(),
            book,
        );
        let dir = TempDir::new()?;
        let (_socket, mut stream) = on_socket(&dir, svc).await?;
        let reply = ask(&mut stream, GOOD).await?;
        assert_eq!(reply["status"], "ok");
        let body = reply["body"].as_str().ok_or("body")?;
        assert!(body.starts_with("untrusted web content from a.example.test (text/plain, 5 bytes"));
        assert!(body.contains("\nhello\n"));
        let bad = ask(
            &mut stream,
            br#"{"url":"http://a.example.test/","job_id":"x"}"#,
        )
        .await?;
        assert_eq!(bad["error"], Refusal::InvalidRequest.message());
        let events = feed.lock().map_err(|_| "feed")?.batch();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].detail.as_deref(), Some("intent"));
        assert_eq!(events[0].exit_code, None);
        assert_eq!(events[1].detail.as_deref(), Some("ok"));
        assert_eq!(events[1].exit_code, Some(200));
        assert_eq!(events[1].out_bytes, Some(5));
        assert_eq!(
            events[1].cmd.as_deref(),
            Some("https://a.example.test/page")
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_full_real_feed_refuses_the_next_fetch_with_no_network_call() -> TestResult {
        let server = serve_text("hello".to_owned()).await;
        let log = Log::default();
        let mut count = Count::new(&log);
        live(&mut count, &server);
        let limits = TelemetryLimits {
            max_events: 1,
            ..TelemetryLimits::default()
        };
        let (book, feed) = real_feed(limits);
        let svc = build(
            FetchPolicy::default(),
            caps(),
            MAX_CONCURRENT_FETCHES,
            &count,
            server.roots.clone(),
            book,
        );
        let first = svc.handle_frame("job1", NEVER, GOOD).await;
        assert!(first.is_ok_and(|body| body.contains("hello")));
        let dials = count.dials.load(Ordering::SeqCst);
        assert_eq!(dials, 1);
        let second = svc.handle_frame("job1", NEVER, GOOD).await;
        assert_eq!(second, Err(Refusal::NotRecorded.message().to_owned()));
        assert_eq!(count.dials.load(Ordering::SeqCst), dials);
        assert_eq!(count.resolves.load(Ordering::SeqCst), 1);
        let summary = feed.lock().map_err(|_| "feed")?.finish(Terminal::Succeeded);
        assert!(summary.missing.contains(&"fetch_outcome".to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn a_job_with_no_registered_feed_cannot_fetch() {
        let log = Log::default();
        let count = Count::new(&log);
        let svc = build(
            FetchPolicy::default(),
            caps(),
            MAX_CONCURRENT_FETCHES,
            &count,
            RootCertStore::empty(),
            Arc::new(FeedBook::default()),
        );
        assert_eq!(
            svc.handle_frame("ghost", NEVER, GOOD).await,
            Err(Refusal::NotRecorded.message().to_owned())
        );
        assert_eq!(count.network(), 0);
    }

    #[tokio::test]
    async fn an_oversize_frame_gets_an_invalid_reply_and_the_connection_closes() -> TestResult {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let svc = fake(caps(), &count, &recorder);
        let dir = TempDir::new()?;
        let (_socket, mut stream) = on_socket(&dir, svc).await?;
        let mut line = vec![b'a'; MAX_FRAME_BYTES + 2];
        line.push(b'\n');
        stream.write_all(&line).await?;
        let mut reader = BufReader::new(&mut stream);
        let reply = tokio::time::timeout(OUTER, read_frame(&mut reader)).await??;
        let reply: serde_json::Value = serde_json::from_slice(&reply)?;
        assert_eq!(reply["error"], Refusal::InvalidRequest.message());
        let mut rest = Vec::new();
        tokio::time::timeout(OUTER, reader.read_to_end(&mut rest)).await??;
        assert_eq!(count.network(), 0);
        Ok(())
    }

    struct Tapped {
        book: Arc<FeedBook>,
        seen: Arc<AtomicUsize>,
    }

    impl FetchRecorder for Tapped {
        fn record(
            &self,
            job_id: &str,
            url: &str,
            phase: FetchPhase,
        ) -> Result<(), FetchRecordError> {
            let result = self.book.record(job_id, url, phase);
            self.seen.fetch_add(1, Ordering::SeqCst);
            result
        }
    }

    async fn cancel_in_flight(
        max_events: usize,
    ) -> Result<Arc<Mutex<Feed>>, Box<dyn std::error::Error>> {
        let log = Log::default();
        let mut count = Count::new(&log);
        count.gate = Some(Arc::new(Notify::new()));
        let limits = TelemetryLimits {
            max_events,
            ..TelemetryLimits::default()
        };
        let (book, feed) = real_feed(limits);
        let seen = Arc::new(AtomicUsize::new(0));
        let tapped = Tapped {
            book,
            seen: Arc::clone(&seen),
        };
        let svc = build(
            FetchPolicy::default(),
            caps(),
            MAX_CONCURRENT_FETCHES,
            &count,
            RootCertStore::empty(),
            tapped,
        );
        let entered = Arc::clone(&count.entered);
        let dir = TempDir::new()?;
        let (socket, mut stream) = on_socket(&dir, svc).await?;
        write_frame(&mut stream, GOOD).await?;
        tokio::time::timeout(OUTER, entered.notified()).await?;
        socket.cancel();
        let mut reader = BufReader::new(&mut stream);
        let closed = tokio::time::timeout(OUTER, read_frame(&mut reader)).await?;
        assert!(closed.is_err());
        let deadline = Instant::now() + OUTER;
        while seen.load(Ordering::SeqCst) < 2 {
            assert!(Instant::now() < deadline, "the outcome was never recorded");
            tokio::task::yield_now().await;
        }
        Ok(feed)
    }

    #[tokio::test]
    async fn cancelling_the_socket_records_a_failed_outcome_for_an_in_flight_fetch() -> TestResult {
        let feed = cancel_in_flight(2000).await?;
        let (events, summary) = {
            let mut guard = feed.lock().map_err(|_| "feed")?;
            (guard.batch(), guard.finish(Terminal::Succeeded))
        };
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].detail.as_deref(), Some("intent"));
        assert_eq!(events[1].detail.as_deref(), Some("failed"));
        assert_eq!(events[1].exit_code, None);
        assert!(!summary.missing.contains(&"fetch_outcome".to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_the_socket_marks_the_outcome_missing_when_the_feed_refuses() -> TestResult {
        let feed = cancel_in_flight(1).await?;
        let (events, summary) = {
            let mut guard = feed.lock().map_err(|_| "feed")?;
            (guard.batch(), guard.finish(Terminal::Succeeded))
        };
        assert_eq!(events[0].detail.as_deref(), Some("intent"));
        assert!(events.iter().all(|e| e.detail.as_deref() != Some("failed")));
        assert!(summary.missing.contains(&"fetch_outcome".to_owned()));
        Ok(())
    }

    #[tokio::test]
    async fn a_panic_in_flight_records_a_failed_outcome() {
        let log = Log::default();
        let mut count = Count::new(&log);
        count.explode = true;
        let recorder = Recorder::new(&log, false);
        let svc = Arc::new(fake(caps(), &count, &recorder));
        let task = tokio::spawn({
            let svc = Arc::clone(&svc);
            async move { svc.handle_frame("j", NEVER, GOOD).await }
        });
        let joined = tokio::time::timeout(OUTER, task)
            .await
            .expect("outer timeout");
        assert!(joined.is_err_and(|error| error.is_panic()));
        let phases: Vec<FetchPhase> = recorder.phases().into_iter().map(|(_, p)| p).collect();
        assert_eq!(
            phases,
            [FetchPhase::Intent, FetchPhase::Failed { status: None }]
        );
    }

    #[tokio::test]
    async fn a_normal_fetch_records_exactly_one_outcome() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let svc = fake(caps(), &count, &recorder);
        let _ = run(&svc, "j", GOOD).await;
        assert_eq!(recorder.phases().len(), 2);
    }

    #[tokio::test]
    async fn a_failed_intent_record_does_not_burn_a_cap_slot() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, true);
        let capped = FetchCaps {
            max_fetches_per_job: 1,
            ..caps()
        };
        let svc = fake(capped, &count, &recorder);
        assert_eq!(
            run(&svc, "j", GOOD).await,
            Err(Refusal::NotRecorded.message().to_owned())
        );
        recorder.heal();
        assert_eq!(
            run(&svc, "j", GOOD).await,
            Err("fetch connect failed".to_owned())
        );
        assert_eq!(
            run(&svc, "j", GOOD).await,
            Err(Refusal::CapReached.message().to_owned())
        );
    }

    #[tokio::test]
    async fn a_lease_lost_before_the_intent_does_not_burn_a_cap_slot() {
        let log = Log::default();
        let count = Count::new(&log);
        let recorder = Recorder::new(&log, false);
        let capped = FetchCaps {
            max_fetches_per_job: 1,
            ..caps()
        };
        let svc = fake(capped, &count, &recorder);
        let calls = AtomicU32::new(0);
        let flips = || calls.fetch_add(1, Ordering::SeqCst) == 1;
        assert_eq!(
            svc.handle_frame("j", &flips, GOOD).await,
            Err(Refusal::LeaseLost.message().to_owned())
        );
        assert_eq!(
            run(&svc, "j", GOOD).await,
            Err("fetch connect failed".to_owned())
        );
    }
}
