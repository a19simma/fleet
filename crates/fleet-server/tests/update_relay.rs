//! The release feed through the real heartbeat path: a poller over an injected source fills the
//! cache and `HeartbeatReply` carries the cached pair. The tests need a Postgres superuser URL
//! in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test. They live in
//! their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::time::Duration;

use fleet_proto::v1::fleet_ingest_client::FleetIngestClient;
use fleet_proto::v1::fleet_ingest_server::FleetIngestServer;
use fleet_proto::v1::{HeartbeatReply, HeartbeatRequest};
use fleet_server::cred::release::ReleaseRefusal;
use fleet_server::service::{FleetService, UpdateRelay};
use fleet_server::store::Store;
use fleet_server::update_feed::{FeedCache, FeedPoller, FeedSource, SystemJitter};
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::{Instant, sleep, timeout};
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint, Server};

const WAIT: Duration = Duration::from_secs(30);

struct Fixed(Vec<u8>, Vec<u8>);

#[tonic::async_trait]
impl FeedSource for Fixed {
    async fn fetch_pair(&self) -> Result<(Vec<u8>, Vec<u8>), ReleaseRefusal> {
        Ok((self.0.clone(), self.1.clone()))
    }
}

async fn serve(pool: PgPool, relay: UpdateRelay) -> Channel {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = FleetService::new(store).with_update(relay);
    tokio::spawn(
        Server::builder()
            .add_service(FleetIngestServer::new(service))
            .serve_with_incoming(TcpIncoming::from(listener)),
    );
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

async fn heartbeat(channel: &Channel) -> HeartbeatReply {
    FleetIngestClient::new(channel.clone())
        .heartbeat(HeartbeatRequest {
            r#box: format!("box-{}", 1),
            ..HeartbeatRequest::default()
        })
        .await
        .unwrap()
        .into_inner()
}

#[sqlx::test]
async fn a_heartbeat_reply_carries_the_cached_pair(pool: PgPool) {
    let cache = FeedCache::new();
    let channel = serve(pool, UpdateRelay::from_feed(cache.clone())).await;

    let empty = heartbeat(&channel).await;
    assert_eq!(empty.update_manifest, None);
    assert_eq!(empty.update_signature, None);

    let manifest = br#"{"seq":7,"tag":"v7"}"#.to_vec();
    let signature = b"minisig-bytes".to_vec();
    let (stop_tx, stop_rx) = watch::channel(false);
    let poller = FeedPoller::new(
        Arc::new(Fixed(manifest.clone(), signature.clone())),
        cache.clone(),
        Duration::from_secs(60),
        Arc::new(SystemJitter),
    );
    let task = poller.spawn(stop_rx);
    let deadline = Instant::now() + WAIT;
    while cache.current().is_none() {
        assert!(Instant::now() < deadline);
        sleep(Duration::from_millis(10)).await;
    }

    let reply = heartbeat(&channel).await;
    assert_eq!(reply.update_manifest, Some(manifest));
    assert_eq!(reply.update_signature, Some(signature));

    stop_tx.send_replace(true);
    timeout(WAIT, task).await.unwrap().unwrap();
}
