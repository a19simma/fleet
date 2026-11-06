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
use fleet_server::cred::Users;
use fleet_server::cred::admin::{AdminCommand, run as admin_run};
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
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(Users::new(pool));
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

#[sqlx::test]
async fn list_shows_owner_and_visibility_and_share_flips_it(pool: PgPool) {
    let addr = serve(pool).await;
    create(addr, "alpha", ONE).await;
    let (result, out) = cli(addr, &["profile", "list"]).await;
    result.unwrap();
    let row: Vec<&str> = out.trim_end().split('\t').collect();
    assert_eq!(row.len(), 5, "{out}");
    assert!(!row[3].is_empty() && row[3] != "-", "{out}");
    assert_eq!(row[4], "private");
    let owner = row[3].to_owned();

    let (result, shared) = cli(addr, &["profile", "share", "alpha"]).await;
    result.unwrap();
    assert_eq!(field(&shared, "name"), "alpha");
    assert_eq!(field(&shared, "visibility"), "shared");
    let (result, out) = cli(addr, &["profile", "list"]).await;
    result.unwrap();
    let row: Vec<&str> = out.trim_end().split('\t').collect();
    assert_eq!((row[3], row[4]), (owner.as_str(), "shared"));

    let (result, unshared) = cli(addr, &["profile", "unshare", "alpha"]).await;
    result.unwrap();
    assert_eq!(field(&unshared, "name"), "alpha");
    assert_eq!(field(&unshared, "visibility"), "private");
    let (result, out) = cli(addr, &["profile", "list"]).await;
    result.unwrap();
    assert_eq!(out.trim_end().split('\t').nth(4), Some("private"));
}

#[sqlx::test]
async fn show_prints_owner_visibility_selection_and_prompt(pool: PgPool) {
    let addr = serve(pool).await;
    create(addr, "alpha", ONE).await;
    let (result, out) = cli(addr, &["profile", "show", "alpha"]).await;
    result.unwrap();
    assert_eq!(field(&out, "visibility"), "private");
    assert_ne!(field(&out, "owner"), "");
    assert_eq!(field(&out, "selection"), "-");
    assert_eq!(field(&out, "prompt"), "-");
    cli(addr, &["profile", "share", "alpha"]).await.0.unwrap();
    let (result, out) = cli(addr, &["profile", "show", "alpha@1"]).await;
    result.unwrap();
    assert_eq!(field(&out, "visibility"), "shared");
}

#[sqlx::test]
async fn share_of_an_unknown_name_fails_and_prints_nothing(pool: PgPool) {
    let addr = serve(pool).await;
    for verb in ["share", "unshare"] {
        let (result, out) = cli(addr, &["profile", verb, "missing"]).await;
        let text = result.unwrap_err().to_string();
        assert!(text.contains("NotFound"), "{text}");
        assert_eq!(out, "");
    }
}

struct Admin {
    addr: SocketAddr,
    token: String,
}

async fn serve_admin(pool: PgPool) -> Admin {
    let users = Users::new(pool.clone());
    let addr = serve(pool.clone()).await;
    let id = admin_run(&pool, &AdminCommand::CreateUser("root".into()), "op")
        .await
        .unwrap()
        .user_id;
    users.set_admin(id, true).await.unwrap();
    let token = users.create_api_token(id, "t").await.unwrap();
    Admin {
        addr,
        token: String::from_utf8(token.token.expose().to_vec()).unwrap(),
    }
}

async fn run_as(admin: &Admin, args: &[&str], stdin: &[u8]) -> (Result<(), CliError>, String) {
    let url = format!("http://{}", admin.addr);
    let mut full = vec!["fleet", "--server", url.as_str()];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let token = admin.token.clone();
    let mut out = Vec::new();
    let mut stdin = stdin;
    let result = tokio::time::timeout(
        WAIT,
        run(
            parsed,
            move |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.clone()),
            &mut stdin,
            &mut out,
        ),
    )
    .await
    .unwrap();
    (result, String::from_utf8_lossy(&out).into_owned())
}

async fn add_item(admin: &Admin, kind: &str, id: &str, enable: bool) {
    let upsert = ["catalog", "upsert", kind, id, id, "--file", "-"];
    let body: &[u8] = if kind == "tool" { b"22.1.0" } else { b"body" };
    run_as(admin, &upsert, body).await.0.unwrap();
    if enable {
        run_as(admin, &["catalog", "enable", id], b"")
            .await
            .0
            .unwrap();
    }
}

async fn show_as(admin: &Admin, target: &str) -> String {
    let (result, out) = run_as(admin, &["profile", "show", target], b"").await;
    result.unwrap();
    out
}

#[sqlx::test]
async fn item_off_then_on_round_trips_the_selection(pool: PgPool) {
    let admin = serve_admin(pool).await;
    add_item(&admin, "skill", "tdd", true).await;
    add_item(&admin, "context", "style", true).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();

    let (result, out) = run_as(
        &admin,
        &["profile", "item", "alpha", "skill", "tdd", "off"],
        b"",
    )
    .await;
    result.unwrap();
    assert_eq!(field(&out, "name"), "alpha");
    assert_eq!(field(&out, "version"), "2");
    assert_eq!(field(&out, "created"), "yes");
    assert_eq!(field(&show_as(&admin, "alpha").await, "selection"), "tdd");

    let (result, _) = run_as(
        &admin,
        &["profile", "item", "alpha", "context", "style", "off"],
        b"",
    )
    .await;
    result.unwrap();
    let shown = show_as(&admin, "alpha").await;
    assert_eq!(field(&shown, "selection"), "style,tdd");
    assert!(
        field(&shown, "content").contains("\"claude_md\":\"one\""),
        "{shown}"
    );

    let (result, out) = run_as(
        &admin,
        &["profile", "item", "alpha", "skill", "tdd", "on"],
        b"",
    )
    .await;
    result.unwrap();
    assert_eq!(field(&out, "version"), "4");
    assert_eq!(field(&show_as(&admin, "alpha").await, "selection"), "style");

    let (result, out) = run_as(
        &admin,
        &["profile", "item", "alpha", "skill", "tdd", "on"],
        b"",
    )
    .await;
    result.unwrap();
    assert_eq!(field(&out, "version"), "4");
    assert_eq!(field(&out, "created"), "no");
}

#[sqlx::test]
async fn item_off_twice_is_idempotent(pool: PgPool) {
    let admin = serve_admin(pool).await;
    add_item(&admin, "skill", "tdd", true).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();
    let args = ["profile", "item", "alpha", "skill", "tdd", "off"];
    run_as(&admin, &args, b"").await.0.unwrap();
    let (result, out) = run_as(&admin, &args, b"").await;
    result.unwrap();
    assert_eq!(field(&out, "version"), "2");
    assert_eq!(field(&out, "created"), "no");
}

#[sqlx::test]
async fn an_unknown_item_surfaces_the_server_text_and_writes_nothing(pool: PgPool) {
    let admin = serve_admin(pool).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();
    let (result, out) = run_as(
        &admin,
        &["profile", "item", "alpha", "skill", "ghost", "off"],
        b"",
    )
    .await;
    let err = result.unwrap_err();
    assert_eq!(err.exit_code(), 1);
    let text = err.to_string();
    assert!(text.contains("InvalidArgument"), "{text}");
    assert!(text.contains("not in the catalog"), "{text}");
    assert_eq!(out, "");
    assert_eq!(field(&show_as(&admin, "alpha").await, "version"), "1");
}

#[sqlx::test]
async fn a_disabled_item_surfaces_the_server_text(pool: PgPool) {
    let admin = serve_admin(pool).await;
    add_item(&admin, "skill", "off", false).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();
    let (result, _) = run_as(
        &admin,
        &["profile", "item", "alpha", "skill", "off", "off"],
        b"",
    )
    .await;
    let text = result.unwrap_err().to_string();
    assert!(text.contains("InvalidArgument"), "{text}");
    assert!(text.contains("admin disabled"), "{text}");
}

#[sqlx::test]
async fn a_tool_item_without_the_grant_is_permission_denied(pool: PgPool) {
    let admin = serve_admin(pool).await;
    add_item(&admin, "tool", "node", true).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();
    let (result, out) = run_as(
        &admin,
        &["profile", "item", "alpha", "tool", "node", "off"],
        b"",
    )
    .await;
    let text = result.unwrap_err().to_string();
    assert!(text.contains("PermissionDenied"), "{text}");
    assert_eq!(out, "");
}

#[sqlx::test]
async fn item_of_an_unknown_profile_is_not_found(pool: PgPool) {
    let admin = serve_admin(pool).await;
    let (result, out) = run_as(
        &admin,
        &["profile", "item", "missing", "skill", "tdd", "off"],
        b"",
    )
    .await;
    let text = result.unwrap_err().to_string();
    assert!(text.contains("NotFound"), "{text}");
    assert_eq!(out, "");
}

#[sqlx::test]
async fn hostile_item_arguments_are_usage_errors_without_a_connection(pool: PgPool) {
    drop(pool);
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let long = "a".repeat(65);
    let ids = [
        "",
        "A",
        "a b",
        "a\n",
        "a\r\n",
        "a\u{85}",
        "a\u{2028}",
        "../x",
        "a:b",
        "a\\b",
        "_a",
        "\u{e9}",
        "a\0b",
        long.as_str(),
        "[::1]",
        "u@h",
    ];
    for id in ids {
        let (result, out) = cli(dead, &["profile", "item", "alpha", "skill", id, "off"]).await;
        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), 2, "{id:?}");
        assert!(matches!(err, CliError::Usage(_)), "{id:?}");
        assert_eq!(out, "");
    }
}

#[test]
fn hostile_kind_and_state_are_refused_by_the_parser() {
    for kind in ["", "Skill", "skills", "skill\n", "tool ", "x", "\u{e9}"] {
        let args = ["fleet", "profile", "item", "alpha", kind, "tdd", "off"];
        assert!(Cli::try_parse_from(args).is_err(), "{kind:?}");
    }
    for state in ["", "ON", "true", "1", "on ", "enable"] {
        let args = ["fleet", "profile", "item", "alpha", "skill", "tdd", state];
        assert!(Cli::try_parse_from(args).is_err(), "{state:?}");
    }
    for kind in ["skill", "subagent", "tool", "context"] {
        let args = ["fleet", "profile", "item", "alpha", kind, "tdd", "on"];
        assert!(Cli::try_parse_from(args).is_ok(), "{kind}");
    }
    assert!(Cli::try_parse_from(["fleet", "profile", "prompt", "alpha"]).is_err());
}

#[sqlx::test]
async fn prompt_sets_replaces_and_keeps_other_fields(pool: PgPool) {
    let admin = serve_admin(pool).await;
    add_item(&admin, "skill", "tdd", true).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();
    run_as(
        &admin,
        &["profile", "item", "alpha", "skill", "tdd", "off"],
        b"",
    )
    .await
    .0
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = file(&dir, "be brief\nand kind\t\u{e9}");
    let (result, out) = run_as(
        &admin,
        &["profile", "prompt", "alpha", "--file", &path],
        b"",
    )
    .await;
    result.unwrap();
    assert_eq!(field(&out, "version"), "3");
    let shown = show_as(&admin, "alpha").await;
    assert!(
        field(&shown, "content").contains(r#""authored_prompt":"be brief\nand kind\té""#),
        "{shown}"
    );
    assert_eq!(field(&shown, "selection"), "tdd");
    assert!(
        field(&shown, "content").contains("\"claude_md\":\"one\""),
        "{shown}"
    );

    let (result, out) = run_as(
        &admin,
        &["profile", "prompt", "alpha", "--file", "-"],
        b"second",
    )
    .await;
    result.unwrap();
    assert_eq!(field(&out, "version"), "4");
    assert_eq!(field(&show_as(&admin, "alpha").await, "prompt"), "second");
}

#[sqlx::test]
async fn an_edit_equal_to_an_older_version_fails_and_the_latest_stays(pool: PgPool) {
    let admin = serve_admin(pool).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();
    run_as(
        &admin,
        &["profile", "prompt", "alpha", "--file", "-"],
        b"hi",
    )
    .await
    .0
    .unwrap();
    let (result, out) = run_as(&admin, &["profile", "prompt", "alpha", "--file", "-"], b"").await;
    let text = result.unwrap_err().to_string();
    assert!(text.contains("FailedPrecondition"), "{text}");
    assert!(text.contains("older version"), "{text}");
    assert_eq!(out, "");
    let shown = show_as(&admin, "alpha").await;
    assert_eq!(field(&shown, "version"), "2");
    assert_eq!(field(&shown, "prompt"), "hi");
}

#[sqlx::test]
async fn hostile_prompt_files_are_usage_errors_without_a_connection(pool: PgPool) {
    drop(pool);
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let over = "a".repeat(fleet_core::MAX_PROMPT_TEXT_BYTES + 1);
    let bad = [
        "a\rb".to_owned(),
        "a\r\nb".to_owned(),
        "a\0b".to_owned(),
        "a\u{85}b".to_owned(),
        "a\u{2028}b".to_owned(),
        "a\u{2029}b".to_owned(),
        "a\u{202e}b".to_owned(),
        "a\u{1b}[0m".to_owned(),
        over,
    ];
    for text in &bad {
        let path = file(&dir, text);
        let (result, out) = cli(dead, &["profile", "prompt", "alpha", "--file", &path]).await;
        let err = result.unwrap_err();
        assert_eq!(err.exit_code(), 2, "{text:?}");
        assert!(matches!(err, CliError::Usage(_)), "{text:?}");
        assert!(!err.to_string().contains(text.as_str()), "{text:?}");
        assert_eq!(out, "");
    }
}

#[sqlx::test]
async fn a_prompt_at_the_cap_is_accepted_and_a_missing_file_or_directory_fails(pool: PgPool) {
    let admin = serve_admin(pool).await;
    run_as(
        &admin,
        &["profile", "create", "alpha", "--file", "-"],
        ONE.as_bytes(),
    )
    .await
    .0
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let at = file(&dir, &"a".repeat(fleet_core::MAX_PROMPT_TEXT_BYTES));
    run_as(&admin, &["profile", "prompt", "alpha", "--file", &at], b"")
        .await
        .0
        .unwrap();
    let dir_path = dir.path().to_str().unwrap();
    for path in ["/nonexistent/p.txt", dir_path] {
        let (result, out) =
            run_as(&admin, &["profile", "prompt", "alpha", "--file", path], b"").await;
        assert!(result.is_err(), "{path}");
        assert_eq!(out, "");
    }
}

#[sqlx::test]
async fn prompt_of_an_unknown_profile_is_not_found(pool: PgPool) {
    let admin = serve_admin(pool).await;
    let (result, out) = run_as(
        &admin,
        &["profile", "prompt", "missing", "--file", "-"],
        b"x",
    )
    .await;
    assert!(result.unwrap_err().to_string().contains("NotFound"));
    assert_eq!(out, "");
}
