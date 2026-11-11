//! `FleetBoxTokens` (ADR-0069): auth gating, validation, ownership and the cap. The tests
//! need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::v1::fleet_box_tokens_server::FleetBoxTokens;
use fleet_proto::v1::{IssueBoxTokenRequest, ListBoxTokensRequest, RevokeBoxTokenRequest};
use fleet_server::auth::{BOX_TOKENS_NEED_USER_TOKEN, BearerAuth, Caller};
use fleet_server::config::Token;
use fleet_server::cred::users::{MAX_ACTIVE_BOX_TOKENS, Users};
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::{Code, Request};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const ISSUE: &str = "/fleet.v1.FleetBoxTokens/IssueBoxToken";
const PATHS: [&str; 3] = [
    ISSUE,
    "/fleet.v1.FleetBoxTokens/ListBoxTokens",
    "/fleet.v1.FleetBoxTokens/RevokeBoxToken",
];

fn name(n: u32) -> String {
    format!("box-{n}")
}

fn as_user<T>(user_id: i64, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(Caller {
        user_id,
        is_admin: false,
    });
    request
}

async fn user(pool: &PgPool, username: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(username)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn service(pool: &PgPool) -> FleetService {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    FleetService::new(store)
}

fn issue(box_name: &str, label: &str, ttl_days: u32) -> IssueBoxTokenRequest {
    IssueBoxTokenRequest {
        r#box: box_name.to_owned(),
        label: label.to_owned(),
        ttl_days,
    }
}

fn bearer(token: &str) -> Vec<u8> {
    format!("Bearer {token}").into_bytes()
}

#[sqlx::test]
async fn the_static_client_token_is_refused_with_a_fixed_reason(pool: PgPool) {
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users);
    for path in PATHS {
        let err = auth.resolve(path, Some(&bearer(CLIENT))).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}");
        assert_eq!(err.message(), BOX_TOKENS_NEED_USER_TOKEN, "{path}");
        let err = auth.check(path, Some(&bearer(CLIENT))).unwrap_err();
        assert_eq!(err.message(), BOX_TOKENS_NEED_USER_TOKEN, "{path}");
        let err = auth.resolve(path, Some(&bearer(BOX))).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}");
        assert_ne!(err.message(), BOX_TOKENS_NEED_USER_TOKEN, "{path}");
    }
}

#[sqlx::test]
async fn an_api_token_reaches_the_service_and_a_box_token_does_not(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let api = users.create_api_token(alice, "t").await.unwrap();
    let plain = String::from_utf8(api.token.expose().to_vec()).unwrap();
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    for path in PATHS {
        let got = auth.resolve(path, Some(&bearer(&plain))).await.unwrap();
        assert_eq!(got.caller.unwrap().user_id, alice, "{path}");
    }
    let svc = service(&pool).await;
    let issued = svc
        .issue_box_token(as_user(alice, issue(&name(1), "ci", 0)))
        .await
        .unwrap()
        .into_inner();
    for path in PATHS {
        let err = auth
            .resolve(path, Some(&bearer(&issued.token)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}");
    }
}

#[sqlx::test]
async fn a_handler_without_a_caller_refuses(pool: PgPool) {
    let svc = service(&pool).await;
    let err = svc
        .issue_box_token(Request::new(issue(&name(1), "", 0)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), BOX_TOKENS_NEED_USER_TOKEN);
    let err = svc
        .list_box_tokens(Request::new(ListBoxTokensRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.message(), BOX_TOKENS_NEED_USER_TOKEN);
    let err = svc
        .revoke_box_token(Request::new(RevokeBoxTokenRequest { id: 1 }))
        .await
        .unwrap_err();
    assert_eq!(err.message(), BOX_TOKENS_NEED_USER_TOKEN);
}

#[sqlx::test]
async fn issue_returns_a_working_token_once_and_list_never_shows_it(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let svc = service(&pool).await;
    let issued = svc
        .issue_box_token(as_user(alice, issue(&name(1), "ci", 30)))
        .await
        .unwrap()
        .into_inner();
    assert!(issued.token.starts_with("fbx_"));
    assert_eq!(issued.token.len(), 4 + 64);
    assert_eq!(issued.r#box, name(1));
    let owner = users
        .resolve_box_token(issued.token.as_bytes())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(owner.user_id, alice);
    let listed = svc
        .list_box_tokens(as_user(alice, ListBoxTokensRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.tokens.len(), 1);
    assert_eq!(listed.tokens[0].id, issued.id);
    assert_eq!(listed.tokens[0].label, "ci");
    assert!(!format!("{listed:?}").contains(&issued.token));
}

#[sqlx::test]
async fn hostile_input_is_refused_before_any_row(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let svc = service(&pool).await;
    let long = "x".repeat(65);
    let table = [
        (name(1) + "\n", "", 0),
        (name(1) + " ", "", 0),
        (String::new(), "", 0),
        ("box-".to_owned(), "", 0),
        ("Box-1".to_owned(), "", 0),
        (format!("{}a", name(1)), "", 0),
        ("worker".to_owned(), "", 0),
        ("box-\u{0661}".to_owned(), "", 0),
        (name(1), "a\nb", 0),
        (name(1), "a\r\nb", 0),
        (name(1), "a\u{2028}b", 0),
        (name(1), "a\u{85}b", 0),
        (name(1), "a\0b", 0),
        (name(1), "a\u{202e}b", 0),
        (name(1), long.as_str(), 0),
        (name(1), "", 366),
        (name(1), "", u32::MAX),
    ];
    for (box_name, label, ttl) in table {
        let err = svc
            .issue_box_token(as_user(alice, issue(&box_name, label, ttl)))
            .await
            .unwrap_err();
        assert_eq!(
            err.code(),
            Code::InvalidArgument,
            "{box_name:?} {label:?} {ttl}"
        );
    }
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM box_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    svc.issue_box_token(as_user(alice, issue(&name(1), &"é".repeat(64), 365)))
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_taken_name_does_not_reveal_the_holder(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let svc = service(&pool).await;
    svc.issue_box_token(as_user(alice, issue(&name(1), "", 0)))
        .await
        .unwrap();
    let by_other = svc
        .issue_box_token(as_user(bob, issue(&name(1), "", 0)))
        .await
        .unwrap_err();
    let by_self = svc
        .issue_box_token(as_user(alice, issue(&name(1), "", 0)))
        .await
        .unwrap_err();
    assert_eq!(by_other.code(), Code::AlreadyExists);
    assert_eq!(by_other.message(), by_self.message());
    assert_eq!(by_other.code(), by_self.code());
    assert!(!by_other.message().contains("alice"));
}

#[sqlx::test]
async fn revoke_is_owner_scoped_and_ends_the_token(pool: PgPool) {
    let users = Users::new(pool.clone());
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let svc = service(&pool).await;
    let issued = svc
        .issue_box_token(as_user(alice, issue(&name(1), "", 0)))
        .await
        .unwrap()
        .into_inner();
    let foreign = svc
        .revoke_box_token(as_user(bob, RevokeBoxTokenRequest { id: issued.id }))
        .await
        .unwrap_err();
    let unknown = svc
        .revoke_box_token(as_user(bob, RevokeBoxTokenRequest { id: i64::MAX }))
        .await
        .unwrap_err();
    assert_eq!(foreign.code(), Code::NotFound);
    assert_eq!(foreign.message(), unknown.message());
    assert!(
        users
            .resolve_box_token(issued.token.as_bytes())
            .await
            .unwrap()
            .is_some()
    );
    let listed = svc
        .list_box_tokens(as_user(bob, ListBoxTokensRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.tokens.len(), 0);
    svc.revoke_box_token(as_user(alice, RevokeBoxTokenRequest { id: issued.id }))
        .await
        .unwrap();
    assert!(
        users
            .resolve_box_token(issued.token.as_bytes())
            .await
            .unwrap()
            .is_none()
    );
    let again = svc
        .revoke_box_token(as_user(alice, RevokeBoxTokenRequest { id: issued.id }))
        .await
        .unwrap_err();
    assert_eq!(again.code(), Code::NotFound);
    svc.issue_box_token(as_user(bob, issue(&name(1), "", 0)))
        .await
        .unwrap();
}

#[sqlx::test]
async fn the_cap_is_per_user(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let svc = service(&pool).await;
    let cap = u32::try_from(MAX_ACTIVE_BOX_TOKENS).unwrap();
    for n in 1..=cap {
        svc.issue_box_token(as_user(alice, issue(&name(n), "", 0)))
            .await
            .unwrap();
    }
    let err = svc
        .issue_box_token(as_user(alice, issue(&name(cap + 1), "", 0)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    svc.issue_box_token(as_user(bob, issue(&name(cap + 1), "", 0)))
        .await
        .unwrap();
}
