//! The forwarder against an in-process `PushEvents` stub.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::{Envelope, Identity, Source};
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::{HeartbeatReply, HeartbeatRequest, PushEventsReply, PushEventsRequest};
use fleetd::backoff::{Random, SystemRandom};
use fleetd::forwarder::{self, Batching, Ingest, MAX_MESSAGE_BYTES};
use fleetd::{Error, Limits, Store, fresh_id, now_ms};
use prost::Message;
use serde_json::json;
use sqlx::ConnectOptions;
use sqlx::sqlite::SqliteConnectOptions;
use tempfile::TempDir;
use tokio::sync::{Notify, oneshot, watch};
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Endpoint, Server};
use tonic::{Code, Request, Response, Status};

const BIG: Limits = Limits {
    max_bytes: u64::MAX,
    max_age: Duration::from_secs(14 * 86_400),
};

#[derive(Clone, Copy)]
enum Mode {
    Ack,
    AckFixed(u64),
    AckAboveSent(u64),
    AckFirst(usize),
    Fail,
    Invalid,
    Hang,
}

#[derive(Clone)]
struct Call {
    events: usize,
    bytes: usize,
    seqs: Vec<u64>,
}

#[derive(Clone)]
struct Stub {
    mode: Arc<Mutex<Mode>>,
    calls: Arc<Mutex<Vec<Call>>>,
    entered: Arc<Notify>,
}

impl Stub {
    fn new(mode: Mode) -> Self {
        Self {
            mode: Arc::new(Mutex::new(mode)),
            calls: Arc::default(),
            entered: Arc::default(),
        }
    }

    fn set(&self, mode: Mode) {
        *self.mode.lock().unwrap() = mode;
    }

    fn log(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }

    fn sizes(&self) -> Vec<usize> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.events)
            .collect()
    }
}

#[tonic::async_trait]
impl FleetIngest for Stub {
    async fn push_events(
        &self,
        request: Request<PushEventsRequest>,
    ) -> Result<Response<PushEventsReply>, Status> {
        let request = request.into_inner();
        let seqs: Vec<u64> = request.events.iter().map(|e| e.seq).collect();
        let through = seqs.iter().copied().max().unwrap_or(0);
        self.calls.lock().unwrap().push(Call {
            events: seqs.len(),
            bytes: request.encoded_len(),
            seqs: seqs.clone(),
        });
        let mode = *self.mode.lock().unwrap();
        let acked = match mode {
            Mode::Ack => through,
            Mode::AckFixed(seq) => seq,
            Mode::AckAboveSent(extra) => through + extra,
            Mode::AckFirst(count) => seqs.get(count - 1).copied().unwrap(),
            Mode::Fail => return Err(Status::internal("SECRET-SERVER-DETAIL")),
            Mode::Invalid => return Err(Status::invalid_argument("SECRET-SERVER-DETAIL")),
            Mode::Hang => {
                self.entered.notify_one();
                std::future::pending::<()>().await;
                0
            }
        };
        Ok(Response::new(PushEventsReply {
            acked_through_seq: acked,
            stored: u32::try_from(seqs.len()).unwrap(),
            duplicate: 0,
            rejected: Vec::new(),
        }))
    }

    async fn heartbeat(
        &self,
        _request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        Err(Status::unimplemented("not needed"))
    }
}

struct Fixed(f64);

impl Random for Fixed {
    fn next_unit(&mut self) -> f64 {
        self.0
    }
}

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(30), future)
        .await
        .unwrap()
}

fn serve(stub: &Stub) -> Ingest {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    let service = FleetIngestServer::new(stub.clone()).max_decoding_message_size(MAX_MESSAGE_BYTES);
    tokio::spawn(
        Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming),
    );
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    Ingest::new(channel)
}

fn envelope(pad: usize) -> Envelope {
    let identity = Identity {
        box_name: format!("box-{}", 7),
        hostname: "host".to_owned(),
        machine_id: "machine".to_owned(),
        boot_id: "boot".to_owned(),
    };
    let ts = now_ms();
    let mut env = Envelope::new(&identity, fresh_id(ts), Source::Hook, "hook.stop", ts);
    env.payload = json!({ "pad": "x".repeat(pad) });
    env
}

async fn store_with(dir: &TempDir, count: usize, pad: usize) -> Store {
    let store = Store::open(&dir.path().join("queue.db"), BIG)
        .await
        .unwrap();
    for _ in 0..count {
        store.enqueue(&envelope(pad), now_ms()).await.unwrap();
    }
    store
}

#[tokio::test]
async fn acks_delete_queue() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 250, 10).await;
    let stub = Stub::new(Mode::Ack);
    let mut client = serve(&stub);

    let deleted = within(forwarder::drain(&store, &mut client, &Batching::default()))
        .await
        .unwrap();

    assert_eq!(deleted, 250);
    assert_eq!(store.count().await.unwrap(), 0);
    assert_eq!(stub.sizes(), vec![100, 100, 50]);
}

#[tokio::test]
async fn batch_stays_under_decode_cap() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 40, 200 * 1024).await;
    let stub = Stub::new(Mode::Ack);
    let mut client = serve(&stub);
    let wide = Batching {
        max_bytes: u64::MAX,
        ..Batching::default()
    };

    within(forwarder::drain(&store, &mut client, &wide))
        .await
        .unwrap();

    assert_eq!(store.count().await.unwrap(), 0);
    let calls = stub.log();
    assert!(calls.len() > 1);
    assert!(calls.iter().all(|call| call.bytes <= MAX_MESSAGE_BYTES));
}

#[tokio::test]
async fn ack_zero_ends_the_drain_with_an_error() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 5, 10).await;
    let stub = Stub::new(Mode::AckFixed(0));
    let mut client = serve(&stub);

    let result = within(forwarder::drain(&store, &mut client, &Batching::default())).await;

    assert!(matches!(
        result,
        Err(Error::AckIgnored { acked_through: 0 })
    ));
    assert_eq!(store.count().await.unwrap(), 5);
    assert_eq!(stub.sizes(), vec![5]);
}

#[tokio::test]
async fn ack_below_the_head_ends_the_drain_with_an_error() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 3, 10).await;
    let stub = Stub::new(Mode::Ack);
    let mut client = serve(&stub);
    within(forwarder::drain(&store, &mut client, &Batching::default()))
        .await
        .unwrap();
    for _ in 0..3 {
        store.enqueue(&envelope(10), now_ms()).await.unwrap();
    }
    stub.set(Mode::AckFixed(2));

    let result = within(forwarder::drain(&store, &mut client, &Batching::default())).await;

    assert!(matches!(
        result,
        Err(Error::AckIgnored { acked_through: 2 })
    ));
    assert_eq!(store.count().await.unwrap(), 3);
    assert_eq!(stub.sizes(), vec![3, 3]);
}

#[tokio::test]
async fn ack_above_the_sent_rows_leaves_unsent_rows_queued() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 4, 400 * 1024).await;
    let stub = Stub::new(Mode::AckAboveSent(1000));
    let mut client = serve(&stub);
    let batching = Batching {
        max_events: 4,
        max_bytes: u64::MAX,
        ..Batching::default()
    };

    let sent = within(forwarder::send_batch(&store, &mut client, &batching))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(sent.events, 2);
    assert_eq!(sent.deleted, 2);
    assert_eq!(store.count().await.unwrap(), 2);
}

#[tokio::test]
async fn a_partial_ack_resends_the_rest() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 10, 10).await;
    let stub = Stub::new(Mode::AckFirst(4));
    let mut client = serve(&stub);
    let batching = Batching::default();

    let first = within(forwarder::send_batch(&store, &mut client, &batching))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((first.events, first.deleted), (10, 4));
    assert_eq!(store.count().await.unwrap(), 6);

    stub.set(Mode::Ack);
    let second = within(forwarder::send_batch(&store, &mut client, &batching))
        .await
        .unwrap()
        .unwrap();

    assert_eq!((second.events, second.deleted), (6, 6));
    assert_eq!(store.count().await.unwrap(), 0);
    let calls = stub.log();
    assert_eq!(calls[1].seqs, calls[0].seqs[4..]);
}

#[tokio::test]
async fn rows_that_are_not_envelopes_are_dropped_without_a_call() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 0, 0).await;
    let mut raw = SqliteConnectOptions::new()
        .filename(dir.path().join("queue.db"))
        .connect()
        .await
        .unwrap();
    for n in 0..3 {
        sqlx::query(
            "INSERT INTO events (id, ts, kind, priority, payload) VALUES (?, ?, 'x', 0, '{\"a\":1}')",
        )
        .bind(format!("raw-{n}"))
        .bind(i64::try_from(now_ms()).unwrap())
        .execute(&mut raw)
        .await
        .unwrap();
    }
    let stub = Stub::new(Mode::Ack);
    let mut client = serve(&stub);

    let deleted = within(forwarder::drain(&store, &mut client, &Batching::default()))
        .await
        .unwrap();

    assert_eq!(deleted, 3);
    assert_eq!(store.count().await.unwrap(), 0);
    assert!(stub.sizes().is_empty());
}

#[tokio::test]
async fn a_server_error_message_is_not_echoed() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 2, 10).await;
    let stub = Stub::new(Mode::Fail);
    let mut client = serve(&stub);

    let err = within(forwarder::send_batch(
        &store,
        &mut client,
        &Batching::default(),
    ))
    .await
    .unwrap_err();

    let shown = err.to_string();
    assert!(!shown.contains("SECRET-SERVER-DETAIL"), "{shown}");
    assert!(shown.contains(&format!("{:?}", Code::Internal)), "{shown}");
    assert!(std::error::Error::source(&err).is_none());
    assert_eq!(store.count().await.unwrap(), 2);
}

#[tokio::test]
async fn run_flushes_a_partial_batch_after_the_wait() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 0, 0).await;
    let stub = Stub::new(Mode::Ack);
    let client = serve(&stub);
    let batching = Batching {
        max_wait: Duration::from_secs(5),
        ..Batching::default()
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let (drained, mut first) = watch::channel(0);
    let task = tokio::spawn({
        let (store, mut client) = (store.clone(), client.clone());
        async move {
            forwarder::run_observed(
                &store,
                &mut client,
                &batching,
                SystemRandom::new(),
                &drained,
                async {
                    stopped.await.ok();
                },
            )
            .await;
        }
    });
    within(first.changed()).await.unwrap();

    for _ in 0..3 {
        store.enqueue(&envelope(10), now_ms()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(store.count().await.unwrap(), 3);
    assert!(stub.sizes().is_empty());

    within(async {
        while store.count().await.unwrap() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    stop.send(()).unwrap();
    within(task).await.unwrap();

    assert_eq!(stub.sizes(), vec![3]);
}

#[tokio::test]
async fn shutdown_does_not_wait_for_a_hung_call() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 2, 10).await;
    let stub = Stub::new(Mode::Hang);
    let client = serve(&stub);
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn({
        let (store, mut client) = (store.clone(), client.clone());
        async move {
            forwarder::run(&store, &mut client, &Batching::default(), async {
                stopped.await.ok();
            })
            .await;
        }
    });

    within(stub.entered.notified()).await;
    stop.send(()).unwrap();

    within(task).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 2);
}

async fn raw_row(dir: &TempDir, name: &str) {
    let mut raw = SqliteConnectOptions::new()
        .filename(dir.path().join("queue.db"))
        .connect()
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO events (id, ts, kind, priority, payload) VALUES (?, ?, 'x', 0, '{\"a\":1}')",
    )
    .bind(name)
    .bind(i64::try_from(now_ms()).unwrap())
    .execute(&mut raw)
    .await
    .unwrap();
}

#[tokio::test]
async fn invalid_argument_keeps_queue() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 3, 10).await;
    let stub = Stub::new(Mode::Invalid);
    let client = serve(&stub);

    let mut direct = client.clone();
    let err = within(forwarder::send_batch(
        &store,
        &mut direct,
        &Batching::default(),
    ))
    .await
    .unwrap_err();
    let shown = err.to_string();
    assert!(!shown.contains("SECRET-SERVER-DETAIL"), "{shown}");
    assert!(
        matches!(&err, Error::Rpc(status) if status.code() == Code::InvalidArgument),
        "{shown}"
    );
    assert_eq!(store.count().await.unwrap(), 3);

    let batching = Batching {
        max_wait: Duration::from_secs(60),
        ..Batching::default()
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let task = tokio::spawn({
        let (store, mut client) = (store.clone(), client.clone());
        async move {
            forwarder::run_with(&store, &mut client, &batching, Fixed(0.01), async {
                stopped.await.ok();
            })
            .await;
        }
    });
    within(async {
        while stub.log().len() < 5 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    stop.send(()).unwrap();
    within(task).await.unwrap();

    assert_eq!(store.count().await.unwrap(), 3);
    let calls = stub.log();
    assert!(calls.iter().all(|call| call.seqs == calls[0].seqs));
}

#[tokio::test]
async fn a_lone_oversized_event_stays_queued() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 1, MAX_MESSAGE_BYTES + 1024).await;
    let stub = Stub::new(Mode::Ack);
    let mut client = serve(&stub);

    let err = within(forwarder::send_batch(
        &store,
        &mut client,
        &Batching::default(),
    ))
    .await
    .unwrap_err();

    assert!(matches!(&err, Error::Rpc(_)), "{err}");
    assert_eq!(store.count().await.unwrap(), 1);
    assert!(stub.sizes().is_empty());
}

#[tokio::test]
async fn undecodable_rows_mixed_with_good_rows_are_skipped_then_dropped() {
    let dir = TempDir::new().unwrap();
    let store = store_with(&dir, 0, 0).await;
    raw_row(&dir, "raw-a").await;
    store.enqueue(&envelope(10), now_ms()).await.unwrap();
    raw_row(&dir, "raw-b").await;
    store.enqueue(&envelope(10), now_ms()).await.unwrap();
    raw_row(&dir, "raw-c").await;
    let stub = Stub::new(Mode::Ack);
    let mut client = serve(&stub);
    let batching = Batching::default();

    let first = within(forwarder::send_batch(&store, &mut client, &batching))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((first.events, first.deleted), (2, 4));
    assert_eq!(store.count().await.unwrap(), 1);

    let second = within(forwarder::send_batch(&store, &mut client, &batching))
        .await
        .unwrap()
        .unwrap();

    assert_eq!((second.events, second.deleted), (0, 1));
    assert_eq!(store.count().await.unwrap(), 0);
    assert_eq!(stub.sizes(), vec![2]);
}
