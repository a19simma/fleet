//! `fleet catalog` against a real in-process server on Postgres: an admin changes the catalog,
//! a non-admin and the static client token are refused with `admin required`. The tests need a
//! Postgres superuser URL in `DATABASE_URL`. They live in their own binary because each one
//! binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::MAX_CATALOG_CONTENT_BYTES;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::admin::{AdminCommand, run as admin_run};
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::Code;
use tonic::transport::server::TcpIncoming;

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const WAIT: Duration = Duration::from_secs(60);

struct Rig {
    addr: SocketAddr,
    admin: String,
    admin_id: u64,
    plain: String,
    plain_id: u64,
}

async fn token_for(pool: &PgPool, users: &Users, name: &str, admin: bool) -> (u64, String) {
    let id = admin_run(pool, &AdminCommand::CreateUser(name.into()), "op")
        .await
        .unwrap()
        .user_id;
    if admin {
        users.set_admin(id, true).await.unwrap();
    }
    let token = users.create_api_token(id, "t").await.unwrap();
    (
        u64::try_from(id).unwrap(),
        String::from_utf8(token.token.expose().to_vec()).unwrap(),
    )
}

async fn serve(pool: PgPool) -> Rig {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    let (admin_id, admin) = token_for(&pool, &users, "root", true).await;
    let (plain_id, plain) = token_for(&pool, &users, "pat", false).await;
    Rig {
        addr,
        admin,
        admin_id,
        plain,
        plain_id,
    }
}

async fn cli_as(
    addr: SocketAddr,
    token: &str,
    args: &[&str],
    stdin: &[u8],
) -> (Result<(), CliError>, String) {
    let url = format!("http://{addr}");
    let mut full = vec!["fleet", "--server", url.as_str()];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let token = token.to_owned();
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

fn rows(out: &str) -> Vec<Vec<&str>> {
    out.lines().map(|l| l.split('\t').collect()).collect()
}

fn assert_denied(result: Result<(), CliError>) {
    let err = result.unwrap_err();
    assert!(
        matches!(&err, CliError::Rpc(s) if s.code() == Code::PermissionDenied),
        "{err}"
    );
    assert_eq!(err.exit_code(), 1);
    assert_eq!(
        err.to_string(),
        "server error PermissionDenied: admin required"
    );
}

const UPSERT: [&str; 7] = ["catalog", "upsert", "skill", "tdd", "tdd", "--file", "-"];

#[sqlx::test]
async fn an_admin_upserts_lists_enables_and_disables(pool: PgPool) {
    let rig = serve(pool).await;
    let a = &rig.admin;
    let (r, out) = cli_as(rig.addr, a, &UPSERT, b"body one").await;
    r.unwrap();
    assert_eq!(rows(&out), [["tdd", "skill", "tdd", "disabled"]]);
    let node = ["catalog", "upsert", "tool", "node", "node", "--file", "-"];
    let (r, _) = cli_as(rig.addr, a, &node, b"22.1.0").await;
    r.unwrap();
    let (r, out) = cli_as(rig.addr, a, &["catalog", "list"], b"").await;
    r.unwrap();
    assert_eq!(
        rows(&out),
        [
            ["node", "tool", "node", "disabled"],
            ["tdd", "skill", "tdd", "disabled"]
        ],
        "an admin sees disabled items"
    );
    for id in ["tdd", "node"] {
        let (r, out) = cli_as(rig.addr, a, &["catalog", "enable", id], b"").await;
        r.unwrap();
        assert_eq!(rows(&out)[0][3], "enabled");
    }
    let (r, out) = cli_as(rig.addr, a, &["catalog", "list"], b"").await;
    r.unwrap();
    assert_eq!(rows(&out).len(), 2, "{out}");
    let (r, out) = cli_as(rig.addr, a, &["catalog", "list", "--kind", "tool"], b"").await;
    r.unwrap();
    assert_eq!(rows(&out), [["node", "tool", "node", "enabled"]]);
    let (r, out) = cli_as(rig.addr, a, &["catalog", "disable", "tdd"], b"").await;
    r.unwrap();
    assert_eq!(rows(&out), [["tdd", "skill", "tdd", "disabled"]]);
    let (r, out) = cli_as(rig.addr, a, &["catalog", "list", "--kind", "skill"], b"").await;
    r.unwrap();
    assert_eq!(rows(&out), [["tdd", "skill", "tdd", "disabled"]]);
}

#[sqlx::test]
async fn a_non_admin_token_is_refused_and_the_server_is_unchanged(pool: PgPool) {
    let rig = serve(pool).await;
    let a = &rig.admin;
    cli_as(rig.addr, a, &UPSERT, b"body").await.0.unwrap();
    cli_as(rig.addr, a, &["catalog", "enable", "tdd"], b"")
        .await
        .0
        .unwrap();
    let other = [
        "catalog", "upsert", "skill", "other", "other", "--file", "-",
    ];
    for token in [rig.plain.as_str(), CLIENT] {
        let (r, out) = cli_as(rig.addr, token, &other, b"body").await;
        assert_denied(r);
        assert_eq!(out, "");
        let (r, out) = cli_as(rig.addr, token, &["catalog", "disable", "tdd"], b"").await;
        assert_denied(r);
        assert_eq!(out, "");
        let (r, out) = cli_as(rig.addr, token, &["catalog", "enable", "other"], b"").await;
        assert_denied(r);
        assert_eq!(out, "");
    }
    let (r, out) = cli_as(rig.addr, a, &["catalog", "list"], b"").await;
    r.unwrap();
    assert_eq!(rows(&out), [["tdd", "skill", "tdd", "enabled"]]);
    let (r, _) = cli_as(rig.addr, a, &["catalog", "enable", "other"], b"").await;
    let err = r.unwrap_err();
    assert!(
        matches!(&err, CliError::Rpc(s) if s.code() == Code::NotFound),
        "{err}"
    );
}

#[sqlx::test]
async fn a_non_admin_cannot_list(pool: PgPool) {
    let rig = serve(pool).await;
    cli_as(rig.addr, &rig.admin, &UPSERT, b"body")
        .await
        .0
        .unwrap();
    cli_as(rig.addr, &rig.admin, &["catalog", "enable", "tdd"], b"")
        .await
        .0
        .unwrap();
    for token in [rig.plain.as_str(), CLIENT] {
        let (r, out) = cli_as(rig.addr, token, &["catalog", "list"], b"").await;
        assert_denied(r);
        assert_eq!(out, "");
    }
}

#[sqlx::test]
async fn bad_kinds_and_bad_content_are_usage_errors_before_any_request(pool: PgPool) {
    let rig = serve(pool).await;
    let long = "x".repeat(4096);
    let kinds = [
        "",
        "SKILL",
        "Skill",
        " skill",
        "skill ",
        "skill\n",
        "skill\r\n",
        "ski\u{2028}ll",
        "sk\u{85}ill",
        "skill\0",
        "unspecified",
        "skills",
        "sk\u{ff49}ll",
        "skill\u{202e}",
        "../skill",
        long.as_str(),
    ];
    for kind in kinds {
        let (r, out) = cli_as(
            rig.addr,
            &rig.admin,
            &["catalog", "upsert", kind, "tdd", "tdd", "--file", "-"],
            b"body",
        )
        .await;
        let err = r.unwrap_err();
        assert_eq!(err.exit_code(), 2, "{kind:?}");
        assert_eq!(out, "");
        let (r, _) = cli_as(
            rig.addr,
            &rig.admin,
            &["catalog", "list", "--kind", kind],
            b"",
        )
        .await;
        assert_eq!(r.unwrap_err().exit_code(), 2, "{kind:?}");
    }
    let over = "x".repeat(MAX_CATALOG_CONTENT_BYTES + 1);
    for (body, text) in [(&b""[..], "is empty"), (over.as_bytes(), "larger than")] {
        let (r, _) = cli_as(rig.addr, &rig.admin, &UPSERT, body).await;
        let err = r.unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains(text), "{err}");
    }
    let (r, _) = cli_as(rig.addr, &rig.admin, &["catalog", "enable", "tdd"], b"").await;
    assert!(matches!(r.unwrap_err(), CliError::Rpc(s) if s.code() == Code::NotFound));
    let exact = "x".repeat(MAX_CATALOG_CONTENT_BYTES);
    let (r, _) = cli_as(rig.addr, &rig.admin, &UPSERT, exact.as_bytes()).await;
    r.unwrap();
}

#[sqlx::test]
async fn a_missing_file_is_an_io_error(pool: PgPool) {
    let rig = serve(pool).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("none.md");
    let (r, _) = cli_as(
        rig.addr,
        &rig.admin,
        &[
            "catalog",
            "upsert",
            "skill",
            "tdd",
            "TDD",
            "--file",
            path.to_str().unwrap(),
        ],
        b"",
    )
    .await;
    assert!(matches!(r.unwrap_err(), CliError::Io(_)));
}

#[test]
fn every_catalog_form_parses() {
    for args in [
        &["catalog", "list"][..],
        &["catalog", "list", "--kind", "skill"],
        &["catalog", "upsert", "skill", "tdd", "tdd", "--file", "-"],
        &["catalog", "enable", "tdd"],
        &["catalog", "disable", "tdd"],
    ] {
        let mut all = vec!["fleet"];
        all.extend_from_slice(args);
        assert!(Cli::try_parse_from(all).is_ok(), "{args:?}");
    }
    for args in [
        &["catalog"][..],
        &["catalog", "enable"],
        &["catalog", "upsert", "skill"],
        &["catalog", "list", "--kind"],
    ] {
        let mut all = vec!["fleet"];
        all.extend_from_slice(args);
        assert!(Cli::try_parse_from(all).is_err(), "{args:?}");
    }
}

#[test]
fn every_capability_form_parses_and_bad_ones_are_refused() {
    for args in [
        &["user", "cap", "list", "7"][..],
        &["user", "cap", "grant", "7", "profile:tools"],
        &["user", "cap", "revoke", "7", "profile:tools"],
    ] {
        let mut all = vec!["fleet"];
        all.extend_from_slice(args);
        assert!(Cli::try_parse_from(all).is_ok(), "{args:?}");
    }
    for args in [
        &["user", "cap"][..],
        &["user", "cap", "grant", "7"],
        &["user", "cap", "list", "seven"],
    ] {
        let mut all = vec!["fleet"];
        all.extend_from_slice(args);
        assert!(Cli::try_parse_from(all).is_err(), "{args:?}");
    }
}

async fn caps(rig: &Rig, user: u64) -> String {
    let id = user.to_string();
    let (r, out) = cli_as(rig.addr, &rig.admin, &["user", "cap", "list", &id], b"").await;
    r.unwrap();
    out
}

#[sqlx::test]
async fn an_admin_grants_lists_and_revokes_a_capability(pool: PgPool) {
    let rig = serve(pool).await;
    let id = rig.plain_id.to_string();
    let a = &rig.admin;
    assert_eq!(caps(&rig, rig.plain_id).await, "");
    for _ in 0..2 {
        let (r, out) = cli_as(
            rig.addr,
            a,
            &["user", "cap", "grant", &id, "profile:tools"],
            b"",
        )
        .await;
        r.unwrap();
        let rows = rows(&out);
        assert_eq!(rows.len(), 1, "{out}");
        assert_eq!(
            rows[0][..3],
            [
                id.as_str(),
                "profile:tools",
                rig.admin_id.to_string().as_str()
            ]
        );
        assert!(rows[0][3].parse::<u64>().unwrap() > 0);
    }
    assert_eq!(rows(&caps(&rig, rig.plain_id).await).len(), 1);
    let revoke = ["user", "cap", "revoke", &id, "profile:tools"];
    let (r, out) = cli_as(rig.addr, a, &revoke, b"").await;
    r.unwrap();
    assert_eq!(out, format!("revoked\t{id}\tprofile:tools\n"));
    let (r, out) = cli_as(rig.addr, a, &revoke, b"").await;
    r.unwrap();
    assert_eq!(out, format!("not held\t{id}\tprofile:tools\n"));
    assert_eq!(caps(&rig, rig.plain_id).await, "");
}

#[sqlx::test]
async fn a_non_admin_token_cannot_change_capabilities_and_grants_stay(pool: PgPool) {
    let rig = serve(pool).await;
    let id = rig.plain_id.to_string();
    let grant = ["user", "cap", "grant", &id, "profile:tools"];
    cli_as(rig.addr, &rig.admin, &grant, b"").await.0.unwrap();
    let before = caps(&rig, rig.plain_id).await;
    assert_eq!(rows(&before).len(), 1);
    let other = rig.admin_id.to_string();
    let attempts = [
        vec!["user", "cap", "grant", &other, "profile:tools"],
        vec!["user", "cap", "revoke", &id, "profile:tools"],
        vec!["user", "cap", "list", &id],
    ];
    for token in [rig.plain.as_str(), CLIENT] {
        for args in &attempts {
            let (r, out) = cli_as(rig.addr, token, args, b"").await;
            assert_denied(r);
            assert_eq!(out, "", "{args:?}");
        }
    }
    assert_eq!(caps(&rig, rig.plain_id).await, before);
    assert_eq!(caps(&rig, rig.admin_id).await, "");
}

#[sqlx::test]
async fn unknown_targets_and_capabilities_are_server_refusals(pool: PgPool) {
    let rig = serve(pool).await;
    let id = rig.plain_id.to_string();
    let missing = (rig.plain_id + 1000).to_string();
    let too_big = u64::MAX.to_string();
    let a = &rig.admin;
    for (args, code) in [
        (
            vec!["user", "cap", "grant", &missing, "profile:tools"],
            Code::NotFound,
        ),
        (vec!["user", "cap", "list", &missing], Code::NotFound),
        (
            vec!["user", "cap", "revoke", &missing, "profile:tools"],
            Code::NotFound,
        ),
        (
            vec!["user", "cap", "grant", &id, "profile:nothing"],
            Code::InvalidArgument,
        ),
        (
            vec!["user", "cap", "grant", &too_big, "profile:tools"],
            Code::InvalidArgument,
        ),
    ] {
        let (r, out) = cli_as(rig.addr, a, &args, b"").await;
        let err = r.unwrap_err();
        assert!(
            matches!(&err, CliError::Rpc(s) if s.code() == code),
            "{args:?} {err}"
        );
        assert_eq!(err.exit_code(), 1);
        assert_eq!(out, "");
    }
    assert_eq!(caps(&rig, rig.plain_id).await, "");
}
