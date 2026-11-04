//! `/catalog` and `/users/{id}/capabilities` are registered, need a session and answer 501 until the pages are built. The tests need a Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]` and
//! live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const PATHS: [&str; 2] = ["/catalog", "/users/1/capabilities"];

async fn send(addr: std::net::SocketAddr, path: &str, cookie: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let cookie = cookie.map_or_else(String::new, |c| format!("Cookie: {c}\r\n"));
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\n{cookie}\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, _) = raw.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    let location = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("location")
                .then(|| value.trim().to_owned())
        })
        .unwrap_or_default();
    (status, location)
}

async fn session(pool: &PgPool) -> String {
    let user_id: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(pool)
            .await
            .unwrap();
    let id = "a".repeat(64);
    sqlx::query(
        "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
         VALUES (sha256($1::bytea), $2, 'csrf-alice-token', now() + interval '1 hour')",
    )
    .bind(id.as_bytes())
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    format!("{SESSION_COOKIE}={id}")
}

#[sqlx::test]
async fn the_catalog_and_capability_routes_need_a_session_and_answer_501(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
    let bearer = BearerAuth::new(
        &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel::<()>();
    let serving = store.clone();
    let task = tokio::spawn(async move {
        serve_with_web(
            &serving,
            &bearer,
            Web::with_auth(auth),
            TcpIncoming::from(listener),
            async {
                let _ = rx.await;
            },
        )
        .await
    });
    let cookie = session(&pool).await;
    for path in PATHS {
        let (status, location) = send(addr, path, None).await;
        assert_eq!((status, location.as_str()), (303, "/login"), "{path}");
        let (status, _) = send(addr, path, Some(&cookie)).await;
        assert_eq!(status, 501, "{path}");
    }
    let (status, _) = send(addr, "/users/1/nope", Some(&cookie)).await;
    assert_eq!(status, 404);
    let _ = stop.send(());
    tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
