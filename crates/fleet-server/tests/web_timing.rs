//! `/jobs/{id}/timing` is registered and answers 501 to a session until the page is built, and redirects to the login page without one. The test
//! needs a Postgres superuser URL in `DATABASE_URL` and lives in its own binary because it
//! binds a socket.

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

struct Reply {
    status: u16,
    location: String,
}

async fn get(addr: std::net::SocketAddr, path: &str, cookie: Option<&str>) -> Reply {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let cookie = cookie
        .map(|c| format!("Cookie: {c}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\n{cookie}\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let location = raw
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("location")
                .then(|| value.trim().to_owned())
        })
        .unwrap_or_default();
    Reply {
        status: raw.split(' ').nth(1).unwrap().parse().unwrap(),
        location,
    }
}

async fn serve(
    pool: PgPool,
    configured: bool,
) -> (
    std::net::SocketAddr,
    oneshot::Sender<()>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let web = if configured {
        Web::with_auth(WebAuth::new(pool, users, ORIGIN, Some("example.com")).unwrap())
    } else {
        Web::new()
    };
    let bearer = BearerAuth::new(
        &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
        None,
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        serve_with_web(&store, &bearer, web, TcpIncoming::from(listener), async {
            let _ = rx.await;
        })
        .await
    });
    (addr, stop, task)
}

async fn finish(stop: oneshot::Sender<()>, task: tokio::task::JoinHandle<std::io::Result<()>>) {
    let _ = stop.send(());
    tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

async fn cookie(pool: &PgPool) -> String {
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
async fn the_timing_route_answers_501_with_a_session(pool: PgPool) {
    let (addr, stop, task) = serve(pool.clone(), true).await;
    let cookie = cookie(&pool).await;
    assert_eq!(
        get(addr, "/jobs/abc/timing", Some(&cookie)).await.status,
        501
    );
    assert_eq!(get(addr, "/jobs/abc/nope", Some(&cookie)).await.status, 404);
    finish(stop, task).await;
}

#[sqlx::test]
async fn the_timing_route_redirects_to_login_without_a_session(pool: PgPool) {
    let (addr, stop, task) = serve(pool, true).await;
    let reply = get(addr, "/jobs/abc/timing", None).await;
    assert_eq!(reply.status, 303);
    assert_eq!(reply.location, "/login");
    finish(stop, task).await;
}

#[sqlx::test]
async fn the_timing_route_is_off_when_web_auth_is_not_configured(pool: PgPool) {
    let (addr, stop, task) = serve(pool, false).await;
    assert_eq!(get(addr, "/jobs/abc/timing", None).await.status, 404);
    assert_eq!(get(addr, "/jobs/abc", None).await.status, 404);
    finish(stop, task).await;
}
