//! The heartbeat task against an in-process `FleetIngest` stub, on real time with a short period.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::{Envelope, Identity, Source};
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::{HeartbeatReply, HeartbeatRequest, PushEventsReply, PushEventsRequest};
use fleetd::heartbeat::{Heartbeat, QueueSnapshot, QueueSource, TargetError};
use fleetd::{Limits, Store, fresh_id, now_ms};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status};
use tracing_subscriber::fmt::MakeWriter;

const PERIOD: Duration = Duration::from_millis(100);
const WIDE: Duration = Duration::from_secs(5);
const TOKEN: &str = "heartbeat-token-0123456789abcdef";

type Seen = (Instant, Option<String>, HeartbeatRequest);

struct Stub {
    seen: mpsc::UnboundedSender<Seen>,
}

#[tonic::async_trait]
impl FleetIngest for Stub {
    async fn push_events(
        &self,
        _request: Request<PushEventsRequest>,
    ) -> Result<Response<PushEventsReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        let auth = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let _ = self.seen.send((Instant::now(), auth, request.into_inner()));
        Ok(Response::new(HeartbeatReply { next_in_s: 30 }))
    }
}

fn stub() -> (SocketAddr, mpsc::UnboundedReceiver<Seen>) {
    let (seen, rx) = mpsc::unbounded_channel();
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(FleetIngestServer::new(Stub { seen }))
            .serve_with_incoming(incoming),
    );
    (addr, rx)
}

fn identity() -> Identity {
    Identity {
        box_name: "alpha".into(),
        hostname: "host".into(),
        machine_id: "machine".into(),
        boot_id: "boot".into(),
    }
}

struct Fixed(QueueSnapshot);

impl QueueSource for Fixed {
    fn snapshot(&self) -> impl Future<Output = QueueSnapshot> + Send {
        std::future::ready(self.0)
    }
}

fn queue(pending: u64, oldest_age_s: u64) -> Fixed {
    Fixed(QueueSnapshot {
        pending,
        oldest_age_s,
    })
}

async fn store_with(dir: &TempDir, events: usize) -> Store {
    let store = Store::open(
        &dir.path().join("q.db"),
        Limits {
            max_bytes: u64::MAX,
            max_age: Duration::from_secs(14 * 86_400),
        },
    )
    .await
    .unwrap();
    for _ in 0..events {
        let ts = now_ms();
        let env = Envelope::new(&identity(), fresh_id(ts), Source::Fleetd, "Stop", ts);
        store.enqueue(&env, ts).await.unwrap();
    }
    store
}

fn target(addr: SocketAddr) -> Heartbeat {
    Heartbeat::new(&format!("http://{addr}"), TOKEN)
        .unwrap()
        .with_period(PERIOD)
}

async fn next(rx: &mut mpsc::UnboundedReceiver<Seen>) -> Seen {
    tokio::time::timeout(WIDE, rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[tokio::test]
async fn heartbeat_updates_box() {
    let (addr, mut rx) = stub();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(target(addr).run(identity(), queue(2, 7), async move {
        let _ = stopped.await;
    }));

    let (first_at, auth, first) = next(&mut rx).await;
    assert_eq!(auth.as_deref(), Some(format!("Bearer {TOKEN}").as_str()));
    assert_eq!(first.r#box, "alpha");
    assert_eq!(first.hostname, "host");
    assert_eq!(first.machine_id, "machine");
    assert_eq!(first.boot_id, "boot");
    assert_eq!(first.fleetd_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(first.queue_pending, 2);
    assert_eq!(first.queue_oldest_age_s, 7);

    let (second_at, _, second) = next(&mut rx).await;
    let gap = second_at - first_at;
    assert!(gap >= PERIOD / 2 && gap <= WIDE, "gap was {gap:?}");
    assert_eq!(second.r#box, "alpha");
    assert!(second.uptime_s >= first.uptime_s);

    let _ = stop.send(());
    tokio::time::timeout(WIDE, task).await.unwrap().unwrap();
}

#[tokio::test]
async fn heartbeat_stops_on_shutdown() {
    let (addr, mut rx) = stub();
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(target(addr).run(identity(), queue(0, 0), async move {
        let _ = stopped.await;
    }));
    next(&mut rx).await;

    let _ = stop.send(());
    tokio::time::timeout(WIDE, task).await.unwrap().unwrap();
    while rx.try_recv().is_ok() {}
    let late = tokio::time::timeout(PERIOD * 5, rx.recv()).await;
    assert!(late.is_err(), "heartbeat sent after shutdown");
}

#[derive(Clone)]
struct Capture {
    buf: Arc<Mutex<Vec<u8>>>,
    wrote: mpsc::UnboundedSender<()>,
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf
            .lock()
            .map_err(|_| std::io::Error::other("capture poisoned"))?
            .extend_from_slice(buf);
        let _ = self.wrote.send(());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn failure_warns_without_the_token_and_keeps_running() {
    let closed = {
        let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        incoming.local_addr().unwrap()
    };
    let (wrote, mut writes) = mpsc::unbounded_channel();
    let capture = Capture {
        buf: Arc::default(),
        wrote,
    };
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish(),
    );
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn(target(closed).run(identity(), queue(0, 0), async move {
        let _ = stopped.await;
    }));

    for _ in 0..2 {
        tokio::time::timeout(WIDE, writes.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert!(!task.is_finished());
    let _ = stop.send(());
    tokio::time::timeout(WIDE, task).await.unwrap().unwrap();

    let logs = String::from_utf8(capture.buf.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("WARN"), "logs were {logs:?}");
    assert!(logs.contains("heartbeat failed"), "logs were {logs:?}");
    assert!(!logs.contains(TOKEN));
}

fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    move |name| map.get(name).cloned()
}

#[tokio::test]
async fn from_env_needs_a_url_and_then_a_token() {
    assert!(Heartbeat::from_env(&env_of(&[])).unwrap().is_none());
    assert!(
        Heartbeat::from_env(&env_of(&[("FLEET_SERVER_URL", "")]))
            .unwrap()
            .is_none()
    );
    let missing = Heartbeat::from_env(&env_of(&[("FLEET_SERVER_URL", "http://127.0.0.1:1")]));
    assert_eq!(missing.unwrap_err(), TargetError::MissingToken);
    let set = env_of(&[
        ("FLEET_SERVER_URL", "http://127.0.0.1:1"),
        ("FLEET_TOKEN", TOKEN),
    ]);
    assert!(Heartbeat::from_env(&set).unwrap().is_some());
}

#[tokio::test]
async fn bad_url_and_bad_token_are_rejected_without_echo() {
    let bad_url = Heartbeat::new("not a url \u{1}", TOKEN).unwrap_err();
    assert_eq!(bad_url, TargetError::InvalidUrl);
    let secret = "line\nbreak-secret";
    let bad_token = Heartbeat::new("http://127.0.0.1:1", secret).unwrap_err();
    assert_eq!(bad_token, TargetError::InvalidToken);
    assert!(!bad_token.to_string().contains("secret"));
    assert!(!format!("{bad_token:?}").contains("secret"));
}

#[tokio::test]
async fn store_snapshot_counts_and_ages_the_queue() {
    let dir = TempDir::new().unwrap();
    let empty = store_with(&dir, 0).await;
    assert_eq!(empty.snapshot().await, QueueSnapshot::default());
    let ts = now_ms() - 90_000;
    let env = Envelope::new(&identity(), fresh_id(ts), Source::Fleetd, "Stop", ts);
    empty.enqueue(&env, now_ms()).await.unwrap();
    let later = Envelope::new(
        &identity(),
        fresh_id(now_ms()),
        Source::Fleetd,
        "Stop",
        now_ms(),
    );
    empty.enqueue(&later, now_ms()).await.unwrap();
    let snap = empty.snapshot().await;
    assert_eq!(snap.pending, 2);
    assert!(
        (89..=200).contains(&snap.oldest_age_s),
        "age was {}",
        snap.oldest_age_s
    );
}
