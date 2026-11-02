//! `/jobs/{id}/timing` is registered and answers 501 until the page is built. The test
//! needs a Postgres superuser URL in `DATABASE_URL` and lives in its own binary because it
//! binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";

async fn get(addr: std::net::SocketAddr, path: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    raw.split(' ').nth(1).unwrap().parse().unwrap()
}

#[sqlx::test]
async fn the_timing_route_answers_501(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let auth = WebAuth::new(pool, users, ORIGIN, Some("example.com")).unwrap();
    let bearer = BearerAuth::new(
        &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        serve_with_web(
            &store,
            &bearer,
            Web::with_auth(auth),
            TcpIncoming::from(listener),
            async {
                let _ = rx.await;
            },
        )
        .await
    });
    assert_eq!(get(addr, "/jobs/abc/timing").await, 501);
    assert_eq!(get(addr, "/jobs/abc/nope").await, 404);
    let _ = stop.send(());
    tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
