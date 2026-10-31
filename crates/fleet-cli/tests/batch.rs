//! `fleet batch show` against a real in-process server on Postgres. The tests need a
//! Postgres superuser URL in `DATABASE_URL`. They live in their own binary because each one
//! binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::SubmitBatchRequest;
use fleet_server::auth::BearerAuth;
use fleet_server::batches::MAX_BATCH_PROFILES;
use fleet_server::config::Token;
use fleet_server::jobs::MAX_PROMPT_BYTES;
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::transport::server::TcpIncoming;

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const WAIT: Duration = Duration::from_secs(60);

fn serve(store: &Store) -> SocketAddr {
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    );
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(store, &auth).serve_with_incoming(incoming));
    addr
}

async fn cli_as(addr: SocketAddr, token: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    cli_in(addr, token, args, b"").await
}

async fn cli_in(
    addr: SocketAddr,
    token: &str,
    args: &[&str],
    mut stdin: &[u8],
) -> (Result<(), CliError>, String) {
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
            &mut stdin,
            &mut out,
        ),
    )
    .await
    .unwrap();
    (result, String::from_utf8_lossy(&out).into_owned())
}

async fn submitted(pool: &PgPool) -> (Store, String, Vec<String>) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    store
        .create_profile("alpha", r#"{"claude_md":"one"}"#)
        .await
        .unwrap();
    store
        .create_profile("beta", r#"{"claude_md":"two"}"#)
        .await
        .unwrap();
    let reply = store
        .submit_batch(&SubmitBatchRequest {
            idempotency_key: "k1".into(),
            prompt: "fix the bug".into(),
            repo: "https://example.com/org/repo.git".into(),
            base_sha: SHA.into(),
            repeats: 0,
            profiles: vec!["alpha".into(), "beta".into()],
            agent: String::new(),
        })
        .await
        .unwrap();
    (store, reply.batch_id, reply.job_ids)
}

#[sqlx::test]
async fn show_prints_one_column_per_profile_with_dashes_for_the_missing(pool: PgPool) {
    let (store, batch_id, job_ids) = submitted(&pool).await;
    sqlx::query(
        "INSERT INTO job_summary (job_id, turns, tool_calls, complete, missing) \
         VALUES ($1, 4, 0, false, ARRAY['hooks'])",
    )
    .bind(&job_ids[0])
    .execute(&pool)
    .await
    .unwrap();
    for (seq, cmd, dur) in [(1_i32, "cargo build", 2500_i64), (2, "ls", 7)] {
        sqlx::query(
            "INSERT INTO job_event (job_id, seq, ts_ms, kind, tool, dur_ms, cmd) \
             VALUES ($1, $2, 1000, 'tool', 'Bash', $3, $4)",
        )
        .bind(&job_ids[0])
        .bind(seq)
        .bind(dur)
        .bind(cmd)
        .execute(&pool)
        .await
        .unwrap();
    }
    let addr = serve(&store);
    let (result, out) = cli_as(addr, CLIENT, &["batch", "show", &batch_id]).await;
    result.unwrap();
    assert!(out.contains("\nprofile\talpha@1\tbeta@1\n"), "{out}");
    assert!(out.contains("\nturns\t4\t-\n"), "{out}");
    assert!(out.contains("\ntool_calls\t0\t-\n"), "{out}");
    assert!(out.contains("\nmodel\tunknown\tunknown\n"), "{out}");
    assert!(out.contains("\nmissing\thooks\tno summary\n"), "{out}");
    assert!(
        out.contains("commands (alpha@1):\n  2.5s\tcargo build\n  7ms\tls\n"),
        "{out}"
    );
    assert!(out.contains("commands (beta@1):\n  -\n"), "{out}");
}

#[sqlx::test]
async fn show_refuses_an_unknown_batch_a_bad_id_and_the_box_token(pool: PgPool) {
    let (store, batch_id, _) = submitted(&pool).await;
    let addr = serve(&store);
    let (unknown, _) = cli_as(
        addr,
        CLIENT,
        &["batch", "show", "01ARZ3NDEKTSV4RRFFQ69G5FAV"],
    )
    .await;
    assert!(matches!(unknown, Err(CliError::Rpc(s)) if s.code() == tonic::Code::NotFound));
    let (bad, _) = cli_as(addr, CLIENT, &["batch", "show", "bad id"]).await;
    assert!(matches!(bad, Err(CliError::Rpc(s)) if s.code() == tonic::Code::InvalidArgument));
    let (boxed, out) = cli_as(addr, BOX, &["batch", "show", &batch_id]).await;
    assert!(matches!(boxed, Err(CliError::Rpc(s)) if s.code() == tonic::Code::PermissionDenied));
    assert_eq!(out, "");
}

const REPO: &str = "https://example.com/org/repo.git";

async fn migrated(pool: &PgPool) -> Store {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    for (name, body) in [
        ("alpha", r#"{"claude_md":"one"}"#),
        ("beta", r#"{"claude_md":"two"}"#),
    ] {
        store.create_profile(name, body).await.unwrap();
    }
    store
}

fn submit_args<'a>(prompt: &'a str, base: &'a str, profiles: &'a str) -> Vec<&'a str> {
    vec![
        "batch",
        "submit",
        "--prompt",
        prompt,
        "--repo",
        REPO,
        "--base",
        base,
        "--profiles",
        profiles,
    ]
}

fn line<'a>(out: &'a str, key: &str) -> &'a str {
    out.lines()
        .find_map(|l| l.strip_prefix(&format!("{key}: ")))
        .unwrap()
}

#[sqlx::test]
async fn submit_prints_the_batch_and_one_job_per_profile_pinned_at_the_sha(pool: PgPool) {
    let store = migrated(&pool).await;
    let addr = serve(&store);
    let mut args = submit_args("fix it", SHA, "alpha,beta");
    args.extend(["--idempotency-key", "k-submit"]);
    let (result, out) = cli_as(addr, CLIENT, &args).await;
    result.unwrap();
    assert_eq!(line(&out, "created"), "yes");
    let batch_id = line(&out, "batch");
    let jobs: Vec<&str> = out.lines().filter(|l| l.starts_with("job: ")).collect();
    assert_eq!(jobs.len(), 2, "{out}");
    assert!(jobs[0].starts_with("job: alpha\t"), "{out}");
    assert!(jobs[1].starts_with("job: beta\t"), "{out}");
    let (shown, table) = cli_as(addr, CLIENT, &["batch", "show", batch_id]).await;
    shown.unwrap();
    assert!(table.contains("\nprofile\talpha@1\tbeta@1\n"), "{table}");
    let stored: (String, bool) = sqlx::query_as("SELECT base_ref, open_pr FROM jobs LIMIT 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stored, (SHA.to_owned(), false));
}

#[sqlx::test]
async fn the_same_key_returns_the_stored_batch_and_a_new_key_makes_a_new_one(pool: PgPool) {
    let store = migrated(&pool).await;
    let addr = serve(&store);
    let mut keyed = submit_args("fix it", SHA, "alpha,beta");
    keyed.extend(["--idempotency-key", "k-same"]);
    let (first, one) = cli_as(addr, CLIENT, &keyed).await;
    first.unwrap();
    let (again, two) = cli_as(addr, CLIENT, &keyed).await;
    again.unwrap();
    assert_eq!(line(&two, "created"), "no");
    assert_eq!(line(&two, "batch"), line(&one, "batch"));
    let mut other = submit_args("fix it", SHA, "alpha,beta");
    other.extend(["--idempotency-key", "k-other"]);
    let (third, three) = cli_as(addr, CLIENT, &other).await;
    third.unwrap();
    assert_ne!(line(&three, "batch"), line(&one, "batch"));
}

#[sqlx::test]
async fn without_a_key_each_submit_is_a_new_batch(pool: PgPool) {
    let store = migrated(&pool).await;
    let addr = serve(&store);
    let args = submit_args("fix it", SHA, "alpha");
    let (first, one) = cli_as(addr, CLIENT, &args).await;
    first.unwrap();
    let (second, two) = cli_as(addr, CLIENT, &args).await;
    second.unwrap();
    assert_eq!(line(&two, "created"), "yes");
    assert_ne!(line(&one, "batch"), line(&two, "batch"));
}

#[sqlx::test]
async fn a_dash_prompt_reads_stdin(pool: PgPool) {
    let store = migrated(&pool).await;
    let addr = serve(&store);
    let args = submit_args("-", SHA, "alpha");
    let (result, out) = cli_in(addr, CLIENT, &args, b"from stdin").await;
    result.unwrap();
    let (shown, _) = cli_as(addr, CLIENT, &["batch", "show", line(&out, "batch")]).await;
    shown.unwrap();
    let prompt: (String,) = sqlx::query_as("SELECT prompt FROM batch")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(prompt.0, "from stdin");
}

#[sqlx::test]
async fn the_server_still_refuses_an_unknown_profile_and_the_box_token(pool: PgPool) {
    let store = migrated(&pool).await;
    let addr = serve(&store);
    let (unknown, out) = cli_as(addr, CLIENT, &submit_args("p", SHA, "alpha,nope")).await;
    assert!(
        matches!(unknown, Err(CliError::Rpc(s)) if s.code() == tonic::Code::NotFound
        || s.code() == tonic::Code::InvalidArgument)
    );
    assert_eq!(out, "");
    let (boxed, _) = cli_as(addr, BOX, &submit_args("p", SHA, "alpha")).await;
    assert!(matches!(boxed, Err(CliError::Rpc(s)) if s.code() == tonic::Code::PermissionDenied));
    let batches: (i64,) = sqlx::query_as("SELECT count(*) FROM batch")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(batches.0, 0);
}

async fn usage(args: &[&str], stdin: &[u8]) -> String {
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (result, out) = cli_in(addr, CLIENT, args, stdin).await;
    assert_eq!(out, "");
    let Err(CliError::Usage(message)) = result else {
        unreachable!("expected a usage error");
    };
    message
}

#[tokio::test]
async fn a_bad_sha_is_a_usage_error_before_any_connection() {
    let upper = SHA.to_uppercase();
    for bad in [
        "main",
        "0123",
        upper.as_str(),
        "0123456789abcdef0123456789abcdef0123456",
        "0123456789abcdef0123456789abcdef012345678",
        "0123456789abcdef0123456789abcdef0123456g",
    ] {
        usage(&submit_args("p", bad, "alpha"), b"").await;
    }
}

#[tokio::test]
async fn a_bad_profile_list_is_a_usage_error_before_any_connection() {
    let seventeen = (0..=MAX_BATCH_PROFILES)
        .map(|i| format!("p{i}"))
        .collect::<Vec<_>>()
        .join(",");
    for bad in ["", "a,,b", "a,a", ",a", "a,", seventeen.as_str()] {
        usage(&submit_args("p", SHA, bad), b"").await;
    }
    let sixteen = seventeen.rsplit_once(',').unwrap().0.to_owned();
    let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (result, _) = cli_in(addr, CLIENT, &submit_args("p", SHA, &sixteen), b"").await;
    assert!(matches!(
        result,
        Err(CliError::Connect(_) | CliError::Rpc(_))
    ));
}

#[tokio::test]
async fn an_empty_or_oversize_prompt_is_a_usage_error() {
    usage(&submit_args("  ", SHA, "alpha"), b"").await;
    usage(&submit_args("-", SHA, "alpha"), b"  \n").await;
    let over = vec![b'x'; MAX_PROMPT_BYTES + 1];
    usage(&submit_args("-", SHA, "alpha"), &over).await;
    let long = "y".repeat(MAX_PROMPT_BYTES + 1);
    usage(&submit_args(&long, SHA, "alpha"), b"").await;
}

#[test]
fn the_cli_limits_match_the_server_limits() {
    assert_eq!(fleet_cli::batch::MAX_BATCH_PROFILES, MAX_BATCH_PROFILES);
    assert_eq!(fleet_cli::batch::MAX_PROMPT_BYTES, MAX_PROMPT_BYTES);
}
