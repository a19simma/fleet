//! The production `build_web` path serves the environment pages (ADR-0067). The tests need a
//! Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]` and live in their own binary
//! because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_server::auth::BearerAuth;
use fleet_server::config::{Config, Token};
use fleet_server::cred::Users;
use fleet_server::cred::password::BootstrapPassword;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{EnvironmentService, EnvironmentStore};
use fleet_server::service::{build_web, serve_with_web};
use fleet_server::store::Store;
use fleet_server::web::SESSION_COOKIE;
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const ORIGIN: &str = "https://fleet.example.com";

fn config() -> Config {
    Config::from_lookup(|var| match var {
        "FLEET_DATABASE_URL" => Some("postgres://u:pw@h/db".to_owned()),
        "FLEET_TOKEN" => Some(BOX_TOKEN.to_owned()),
        "FLEET_WEB_ORIGIN" => Some(ORIGIN.to_owned()),
        "FLEET_WEB_RP_ID" => Some("example.com".to_owned()),
        _ => None,
    })
    .unwrap()
}

fn service(pool: &PgPool, tag: &str) -> EnvironmentService {
    let path = std::env::temp_dir().join(format!(
        "fleet-web-wiring-{}-{tag}.keys",
        std::process::id()
    ));
    std::fs::write(&path, format!("k1:{}\n", "cd".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path).unwrap();
    EnvironmentService::new(EnvironmentStore::new(
        pool.clone(),
        std::sync::Arc::new(sealer),
    ))
}

async fn statuses(pool: PgPool, environments: Option<EnvironmentService>) -> Vec<u16> {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let user_id: i64 = sqlx::query_scalar(
        "INSERT INTO users (username, is_admin) VALUES ('wired', false) RETURNING id",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let id = "e".repeat(64);
    sqlx::query(
        "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
         VALUES (sha256($1::bytea), $2, 'csrf-wired-token', now() + interval '1 hour')",
    )
    .bind(id.as_bytes())
    .bind(user_id)
    .execute(&pool)
    .await
    .unwrap();
    let web = build_web(
        &config(),
        &pool,
        &users,
        None,
        environments,
        store.clone(),
        BootstrapPassword::disarmed(),
    )
    .unwrap();
    let bearer = BearerAuth::new(&Token::new(BOX_TOKEN.to_owned()).unwrap(), None);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        serve_with_web(&store, &bearer, web, TcpIncoming::from(listener), async {
            let _ = rx.await;
        })
        .await
    });
    let mut found = Vec::new();
    for path in ["/environments", "/submit"] {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\nCookie: {SESSION_COOKIE}={id}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        found.push(raw.split(' ').nth(1).unwrap().parse().unwrap());
    }
    let _ = stop.send(());
    tokio::time::timeout(WAIT, task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    found
}

#[sqlx::test]
async fn build_web_serves_the_environment_pages_for_a_signed_in_user(pool: PgPool) {
    let environments = service(&pool, "on");
    assert_eq!(statuses(pool, Some(environments)).await, vec![200, 200]);
}

#[sqlx::test]
async fn build_web_without_an_environment_service_answers_404(pool: PgPool) {
    assert_eq!(statuses(pool, None).await, vec![404, 200]);
}
