//! `fleet profile` against a real in-process server on Postgres. The tests need a Postgres
//! superuser URL in `DATABASE_URL`. They live in their own binary because each one binds a
//! socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::transport::server::TcpIncoming;

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const WAIT: Duration = Duration::from_secs(60);
const ONE: &str = r#"{"claude_md":"one","max_turns":5}"#;
const ONE_CANONICAL: &str = r#"{"claude_md":"one","max_turns":5}"#;
const ONE_REORDERED: &str = r#"{ "max_turns": 5, "claude_md": "one" }"#;
const TWO: &str = r#"{"claude_md":"two"}"#;

async fn serve(pool: PgPool) -> SocketAddr {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    addr
}

async fn cli_as(addr: SocketAddr, token: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    let url = format!("http://{addr}");
    let mut full = vec!["fleet", "--server", url.as_str()];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let token = token.to_owned();
    let mut out = Vec::new();
    let result = tokio::time::timeout(
        WAIT,
        run(
            parsed,
            move |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.clone()),
            &mut &b""[..],
            &mut out,
        ),
    )
    .await
    .unwrap();
    (result, String::from_utf8_lossy(&out).into_owned())
}

async fn cli(addr: SocketAddr, args: &[&str]) -> (Result<(), CliError>, String) {
    cli_as(addr, CLIENT, args).await
}

fn file(dir: &tempfile::TempDir, content: &str) -> String {
    let path = dir.path().join("profile.json");
    std::fs::write(&path, content).unwrap();
    path.to_str().unwrap().to_owned()
}

fn field<'a>(text: &'a str, key: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(&format!("{key}: ")))
        .unwrap()
}

async fn create(addr: SocketAddr, name: &str, content: &str) -> String {
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, content);
    let (result, out) = cli(addr, &["profile", "create", name, "--file", &path]).await;
    result.unwrap();
    out
}

#[sqlx::test]
async fn create_prints_version_one_and_created(pool: PgPool) {
    let addr = serve(pool).await;
    let out = create(addr, "alpha", ONE).await;
    assert_eq!(field(&out, "name"), "alpha");
    assert_eq!(field(&out, "version"), "1");
    assert_eq!(field(&out, "hash").len(), 64);
    assert_eq!(field(&out, "created"), "yes");
}

#[sqlx::test]
async fn the_same_file_again_is_version_one_and_not_created(pool: PgPool) {
    let addr = serve(pool).await;
    let first = create(addr, "alpha", ONE).await;
    let again = create(addr, "alpha", ONE_REORDERED).await;
    assert_eq!(field(&again, "version"), "1");
    assert_eq!(field(&again, "created"), "no");
    assert_eq!(field(&again, "hash"), field(&first, "hash"));
}

#[sqlx::test]
async fn changed_content_is_version_two(pool: PgPool) {
    let addr = serve(pool).await;
    let first = create(addr, "alpha", ONE).await;
    let second = create(addr, "alpha", TWO).await;
    assert_eq!(field(&second, "version"), "2");
    assert_eq!(field(&second, "created"), "yes");
    assert_ne!(field(&second, "hash"), field(&first, "hash"));
}

#[sqlx::test]
async fn list_shows_latest_version_and_hash(pool: PgPool) {
    let addr = serve(pool).await;
    create(addr, "beta", ONE).await;
    create(addr, "alpha", ONE).await;
    let alpha2 = create(addr, "alpha", TWO).await;
    let (result, out) = cli(addr, &["profile", "list"]).await;
    result.unwrap();
    let rows: Vec<Vec<&str>> = out.lines().map(|l| l.split('\t').collect()).collect();
    assert_eq!(rows.len(), 2, "{out}");
    assert_eq!(rows[0][..2], ["alpha", "2"]);
    assert_eq!(rows[0][2], field(&alpha2, "hash"));
    assert_eq!(rows[1][..2], ["beta", "1"]);
}

#[sqlx::test]
async fn list_follows_pagination_to_the_end(pool: PgPool) {
    let addr = serve(pool).await;
    for n in 0..205 {
        create(addr, &format!("p{n:03}"), ONE).await;
    }
    let (result, out) = cli(addr, &["profile", "list"]).await;
    result.unwrap();
    let names: Vec<&str> = out.lines().map(|l| l.split('\t').next().unwrap()).collect();
    assert_eq!(names.len(), 205);
    assert_eq!(names[0], "p000");
    assert_eq!(names[204], "p204");
}

#[sqlx::test]
async fn show_prints_content_and_hash_for_latest_and_pinned(pool: PgPool) {
    let addr = serve(pool).await;
    let one = create(addr, "alpha", ONE).await;
    let two = create(addr, "alpha", TWO).await;

    let (result, latest) = cli(addr, &["profile", "show", "alpha"]).await;
    result.unwrap();
    assert_eq!(field(&latest, "version"), "2");
    assert_eq!(field(&latest, "hash"), field(&two, "hash"));
    assert_eq!(field(&latest, "content"), TWO);
    assert_eq!(field(&latest, "used-by"), "-");

    let (result, pinned) = cli(addr, &["profile", "show", "alpha@1"]).await;
    result.unwrap();
    assert_eq!(field(&pinned, "name"), "alpha");
    assert_eq!(field(&pinned, "version"), "1");
    assert_eq!(field(&pinned, "hash"), field(&one, "hash"));
    assert_eq!(field(&pinned, "content"), ONE_CANONICAL);
}

#[sqlx::test]
async fn show_of_an_unknown_name_or_version_fails(pool: PgPool) {
    let addr = serve(pool).await;
    create(addr, "alpha", ONE).await;
    for target in ["missing", "alpha@9"] {
        let (result, out) = cli(addr, &["profile", "show", target]).await;
        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), 1);
        let text = err.to_string();
        assert!(text.contains("NotFound"), "{text}");
        assert!(text.contains("profile not found"), "{text}");
        assert_eq!(out, "");
    }
}

#[sqlx::test]
async fn an_invalid_profile_prints_the_fixed_message_and_never_echoes_the_file(pool: PgPool) {
    let addr = serve(pool).await;
    let secret = "zzz-private-input";
    let dir = tempfile::tempdir().unwrap();
    for content in [format!("{{\"{secret}\":1}}"), format!("not json {secret}")] {
        let path = file(&dir, &content);
        let (result, out) = cli(addr, &["profile", "create", "alpha", "--file", &path]).await;
        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), 1);
        let text = err.to_string();
        assert!(text.contains("InvalidArgument"), "{text}");
        assert!(!text.contains(secret), "{text}");
        assert!(!text.contains('{'), "{text}");
        assert_eq!(out, "");
    }
}

#[sqlx::test]
async fn the_box_token_is_denied(pool: PgPool) {
    let addr = serve(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, ONE);
    let (result, _) = cli_as(addr, BOX, &["profile", "create", "alpha", "--file", &path]).await;
    let text = result.unwrap_err().to_string();
    assert!(text.contains("PermissionDenied"), "{text}");
}

#[sqlx::test]
async fn a_missing_file_is_an_error_without_a_server_call(pool: PgPool) {
    let addr = serve(pool).await;
    let (result, out) = cli(
        addr,
        &[
            "profile",
            "create",
            "alpha",
            "--file",
            "/nonexistent/p.json",
        ],
    )
    .await;
    assert!(result.is_err());
    assert_eq!(out, "");
}

#[sqlx::test]
async fn an_over_cap_file_is_a_usage_error_without_a_connection(pool: PgPool) {
    drop(pool);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.json");
    std::fs::write(&path, vec![b'a'; fleet_proto::MAX_PROFILE_JSON_BYTES + 1]).unwrap();
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (result, out) = cli(
        dead,
        &[
            "profile",
            "create",
            "alpha",
            "--file",
            path.to_str().unwrap(),
        ],
    )
    .await;
    assert_eq!(result.unwrap_err().exit_code(), 2);
    assert_eq!(out, "");
}

#[sqlx::test]
async fn a_bad_version_suffix_is_a_usage_error(pool: PgPool) {
    let addr = serve(pool).await;
    for target in ["a@", "a@x", "a@0", "@1", "a@1@2"] {
        let (result, _) = cli(addr, &["profile", "show", target]).await;
        assert_eq!(result.unwrap_err().exit_code(), 2, "{target}");
    }
}
