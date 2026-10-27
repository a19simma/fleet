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
use fleet_server::config::Token;
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
