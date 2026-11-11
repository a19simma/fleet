//! The per-Box token path in the auth layer (ADR-0069). They need a Postgres superuser URL in
//! `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::convert::Infallible;

use fleet_core::BoxName;
use fleet_server::auth::{ADMIN_REQUIRED, BOX_MISMATCH, BearerAuth, BoxCaller};
use fleet_server::config::Token;
use fleet_server::cred::admin::{AdminCommand, run};
use fleet_server::cred::users::{BoxTokenLabel, BoxTokenTtl, Users};
use sqlx::PgPool;
use tonic::Code;
use tonic::body::Body;
use tonic::codegen::http::{HeaderValue, Request, Response};
use tower::{Layer, Service, ServiceExt};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const INGEST: &str = "/fleet.v1.FleetIngest/PushEvents";
const WORKER: &str = "/fleet.v1.FleetWorker/ClaimJob";
const UNAUTH: &str = "missing or invalid bearer token";

fn auth(users: &Users) -> BearerAuth {
    BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone())
}

fn name(n: u32) -> BoxName {
    BoxName::new(&format!("box-{n}")).unwrap()
}

async fn issue(pool: &PgPool, users: &Users, who: &str, n: u32) -> (i64, i64, String) {
    let user = run(pool, &AdminCommand::CreateUser(who.into()), "op")
        .await
        .unwrap()
        .user_id;
    let token = users
        .issue_box_token(
            user,
            &name(n),
            &BoxTokenLabel::new("t").unwrap(),
            BoxTokenTtl::default(),
        )
        .await
        .unwrap();
    (
        user,
        token.id,
        String::from_utf8(token.token.expose().to_vec()).unwrap(),
    )
}

fn bearer(token: &str) -> Vec<u8> {
    format!("Bearer {token}").into_bytes()
}

#[sqlx::test]
async fn a_box_token_yields_a_box_caller_and_no_caller(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (user, token_id, token) = issue(&pool, &users, "alice", 1).await;
    for path in [INGEST, WORKER] {
        let got = auth(&users)
            .resolve(path, Some(&bearer(&token)))
            .await
            .unwrap();
        assert_eq!(got.caller, None, "{path}");
        let box_caller = got.box_caller.unwrap();
        assert_eq!(box_caller.token_id, token_id);
        assert_eq!(box_caller.user_id, user);
        assert_eq!(box_caller.box_name, name(1).as_str());
    }
}

#[sqlx::test]
async fn static_tokens_resolve_with_no_box_caller(pool: PgPool) {
    let users = Users::new(pool.clone());
    let got = auth(&users)
        .resolve(INGEST, Some(&bearer(BOX)))
        .await
        .unwrap();
    assert_eq!(got.box_caller, None);
    let got = auth(&users)
        .resolve("/fleet.v1.FleetJobs/ListJobs", Some(&bearer(CLIENT)))
        .await
        .unwrap();
    assert_eq!(got.box_caller, None);
    assert!(got.caller.is_some());
}

#[sqlx::test]
async fn a_box_token_is_denied_outside_the_box_scope(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (_, _, token) = issue(&pool, &users, "alice", 1).await;
    for path in [
        "/fleet.v1.FleetJobs/ListJobs",
        "/fleet.v1.FleetQuery/ListFleet",
        "/fleet.v1.FleetCredentials/ListCredentials",
        "/fleet.v1.FleetEnvironments/ListEnvironments",
        "/fleet.v1.FleetEdit/DecideEdit",
        "/fleet.v1.FleetWork/ImportWork",
        "/fleet.v1.FleetCatalogAdmin/UpsertCatalogItem",
        "/fleet.v1.FleetHosts/AddHost",
        "/fleet.v1.Unknown/Method",
    ] {
        let err = auth(&users)
            .resolve(path, Some(&bearer(&token)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}");
    }
}

#[sqlx::test]
async fn bad_box_tokens_are_unauthenticated_with_the_usual_text(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (_, token_id, token) = issue(&pool, &users, "alice", 1).await;
    let wrong = format!("fbx_{}", "0".repeat(64));
    let hex = token.strip_prefix("fbx_").unwrap();
    let cases: Vec<(&str, Option<Vec<u8>>)> = vec![
        ("missing", None),
        ("unknown", Some(bearer(&wrong))),
        ("prefix only", Some(bearer("fbx_"))),
        ("short", Some(bearer(&token[..token.len() - 1]))),
        ("long", Some(bearer(&format!("{token}0")))),
        (
            "uppercase",
            Some(bearer(&format!("fbx_{}", hex.to_uppercase()))),
        ),
        ("wrong scheme", Some(format!("bearer {token}").into_bytes())),
        ("no scheme", Some(token.clone().into_bytes())),
        (
            "trailing space",
            Some(format!("Bearer {token} ").into_bytes()),
        ),
        (
            "leading space",
            Some(format!("Bearer  {token}").into_bytes()),
        ),
        (
            "trailing cr",
            Some(format!("Bearer {token}\r").into_bytes()),
        ),
        (
            "trailing nel",
            Some(format!("Bearer {token}\u{85}").into_bytes()),
        ),
        (
            "trailing ls",
            Some(format!("Bearer {token}\u{2028}").into_bytes()),
        ),
        (
            "non ascii",
            Some(format!("Bearer {token}\u{e9}").into_bytes()),
        ),
        ("raw 0xff", Some(b"Bearer \xff\xfe".to_vec())),
        (
            "two tokens",
            Some(format!("Bearer {token} {token}").into_bytes()),
        ),
        ("flt prefix swap", Some(bearer(&format!("flt_{hex}")))),
    ];
    for (shown, header) in cases {
        let err = auth(&users)
            .resolve(INGEST, header.as_deref())
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated, "{shown}");
        assert_eq!(err.message(), UNAUTH, "{shown}");
    }
    sqlx::query("UPDATE box_tokens SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day' WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .unwrap();
    let err = auth(&users)
        .resolve(INGEST, Some(&bearer(&token)))
        .await
        .unwrap_err();
    assert_eq!((err.code(), err.message()), (Code::Unauthenticated, UNAUTH));
    sqlx::query("UPDATE box_tokens SET expires_at = now() + interval '1 day', revoked_at = now() WHERE id = $1")
        .bind(token_id)
        .execute(&pool)
        .await
        .unwrap();
    let err = auth(&users)
        .resolve(INGEST, Some(&bearer(&token)))
        .await
        .unwrap_err();
    assert_eq!((err.code(), err.message()), (Code::Unauthenticated, UNAUTH));
}

#[sqlx::test]
async fn an_api_token_is_not_a_box_token(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (user, _, _) = issue(&pool, &users, "alice", 1).await;
    let api = users.create_api_token(user, "t").await.unwrap();
    let plain = String::from_utf8(api.token.expose().to_vec()).unwrap();
    let got = auth(&users)
        .resolve("/fleet.v1.FleetJobs/ListJobs", Some(&bearer(&plain)))
        .await
        .unwrap();
    assert_eq!(got.box_caller, None);
    assert_eq!(got.caller.unwrap().user_id, user);
    let err = auth(&users)
        .resolve(INGEST, Some(&bearer(&plain)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[test]
fn require_box_matches_exactly() {
    let caller = BoxCaller {
        token_id: 1,
        user_id: 2,
        box_name: name(7).as_str().to_owned(),
    };
    caller.require_box(name(7).as_str()).unwrap();
    for other in [
        name(8).as_str().to_owned(),
        String::new(),
        format!("{} ", name(7).as_str()),
        name(7).as_str().to_uppercase(),
        format!("{}0", name(7).as_str()),
    ] {
        let err = caller.require_box(&other).unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{other:?}");
        assert_eq!(err.message(), BOX_MISMATCH, "{other:?}");
    }
}

#[sqlx::test]
async fn the_layer_inserts_the_box_caller_extension_and_never_a_caller(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (_, _, token) = issue(&pool, &users, "alice", 1).await;
    let probe = tower::service_fn(|request: Request<()>| async move {
        let has_box = request
            .extensions()
            .get::<BoxCaller>()
            .is_some_and(|c| c.user_id != 0);
        let has_caller = request
            .extensions()
            .get::<fleet_server::auth::Caller>()
            .is_some();
        let status = match (has_box, has_caller) {
            (true, false) => 200,
            _ => 500,
        };
        Ok::<_, Infallible>(
            Response::builder()
                .status(status)
                .body(Body::empty())
                .unwrap(),
        )
    });
    let mut service = auth(&users).layer(probe);
    let request = Request::builder()
        .uri(INGEST)
        .header(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        )
        .body(())
        .unwrap();
    let response = service.ready().await.unwrap().call(request).await.unwrap();
    assert_eq!(response.status(), 200);
    let bad = Request::builder()
        .uri(INGEST)
        .header("authorization", "Bearer fbx_nope")
        .body(())
        .unwrap();
    let response = service.ready().await.unwrap().call(bad).await.unwrap();
    assert_eq!(
        response.headers().get("grpc-status").unwrap(),
        &(Code::Unauthenticated as i32).to_string()
    );
}

#[sqlx::test]
async fn a_malformed_box_token_never_reaches_the_database(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (_, _, token) = issue(&pool, &users, "alice", 1).await;
    let hex = token.strip_prefix("fbx_").unwrap().to_owned();
    pool.close().await;
    let malformed: Vec<(&str, Vec<u8>)> = vec![
        ("prefix only", bearer("fbx_")),
        ("short", bearer(&token[..token.len() - 1])),
        ("long", bearer(&format!("{token}0"))),
        ("uppercase", bearer(&format!("fbx_{}", hex.to_uppercase()))),
        ("trailing cr", format!("Bearer {token}\r").into_bytes()),
        ("trailing nel", format!("Bearer {token}\u{85}").into_bytes()),
        ("non ascii", format!("Bearer {token}\u{e9}").into_bytes()),
        ("raw 0xff", b"Bearer fbx_\xff\xfe".to_vec()),
        ("two tokens", format!("Bearer {token} {token}").into_bytes()),
    ];
    for (shown, header) in malformed {
        let err = auth(&users)
            .resolve(INGEST, Some(&header))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated, "{shown}");
        assert_eq!(err.message(), UNAUTH, "{shown}");
    }
    for control in [token, format!("fbx_{}", "0".repeat(64))] {
        let err = auth(&users)
            .resolve(INGEST, Some(&bearer(&control)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unavailable, "well formed {control}");
    }
}

#[sqlx::test]
async fn a_denied_path_does_not_move_last_used_at(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (_, token_id, token) = issue(&pool, &users, "alice", 1).await;
    let last_used = || async {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT last_used_at::text FROM box_tokens WHERE id = $1",
        )
        .bind(token_id)
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    for path in [
        "/fleet.v1.FleetJobs/ListJobs",
        "/fleet.v1.FleetCatalogAdmin/UpsertCatalogItem",
        "/fleet.v1.Unknown/Method",
    ] {
        let err = auth(&users)
            .resolve(path, Some(&bearer(&token)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}");
        let want = if path.contains("CatalogAdmin") {
            ADMIN_REQUIRED
        } else {
            "bearer token not valid for this service"
        };
        assert_eq!(err.message(), want, "{path}");
        assert_eq!(last_used().await, None, "{path}");
    }
    auth(&users)
        .resolve(WORKER, Some(&bearer(&token)))
        .await
        .unwrap();
    assert!(last_used().await.is_some());
}

#[sqlx::test]
async fn a_failed_last_used_update_does_not_fail_authentication(pool: PgPool) {
    let users = Users::new(pool.clone());
    let (user, _, token) = issue(&pool, &users, "alice", 1).await;
    sqlx::raw_sql(
        "CREATE FUNCTION refuse_touch() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'touch refused'; END; $$; \
         CREATE TRIGGER refuse_touch BEFORE UPDATE ON box_tokens \
         FOR EACH ROW EXECUTE FUNCTION refuse_touch();",
    )
    .execute(&pool)
    .await
    .unwrap();
    let touched = sqlx::query("UPDATE box_tokens SET last_used_at = now() WHERE user_id = $1")
        .bind(user)
        .execute(&pool)
        .await;
    assert!(touched.is_err());
    let got = auth(&users)
        .resolve(WORKER, Some(&bearer(&token)))
        .await
        .unwrap();
    assert_eq!(got.box_caller.unwrap().user_id, user);
}
