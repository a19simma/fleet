//! The model allowlist at profile save, job submit and batch submit, over the store and over a
//! real tonic server. The tests need a Postgres superuser URL in `DATABASE_URL`. They live in
//! their own binary because some of them bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_core::MAX_MODEL_BYTES;
use fleet_core::model_allowlist::ModelAllowlist;
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_profiles_client::FleetProfilesClient;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, CreateProfileRequest, GetProfileBlobRequest, SubmitBatchRequest,
    SubmitJobRequest,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::profiles::{self, ProfileContent};
use fleet_server::service::router;
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const REPO: &str = "https://example.com/org/repo.git";
const OPUS: &str = "claude-opus-4-1";
const SONNET: &str = "claude-sonnet-4-5";

fn list(raw: &str) -> ModelAllowlist {
    ModelAllowlist::parse(raw).unwrap()
}

fn profile_json(model: &str) -> String {
    serde_json::json!({ "model": model }).to_string()
}

async fn store_with(pool: PgPool, allowlist: Option<ModelAllowlist>) -> Store {
    let store = Store::new(pool).with_model_allowlist(allowlist);
    store.migrate().await.unwrap();
    store
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn seed(pool: &PgPool, owner: i64, name: &str, model: &str) {
    profiles::create_owned(
        pool,
        Some(owner),
        None,
        name,
        ProfileContent::Json(&profile_json(model)),
    )
    .await
    .unwrap();
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    let sql = match table {
        "profile_version" => "SELECT count(*) FROM profile_version",
        "profile_blob" => "SELECT count(*) FROM profile_blob",
        "jobs" => "SELECT count(*) FROM jobs",
        _ => "SELECT count(*) FROM batch",
    };
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

fn submit(key: &str, profile: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr: true,
        agent: String::new(),
        profile: profile.to_owned(),
        environment: String::new(),
    }
}

fn batch(key: &str, profiles: &[&str]) -> SubmitBatchRequest {
    SubmitBatchRequest {
        idempotency_key: key.to_owned(),
        prompt: "fix the bug".to_owned(),
        repo: REPO.to_owned(),
        base_sha: SHA.to_owned(),
        repeats: 0,
        profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
        agent: String::new(),
    }
}

fn denied(err: &StoreError, model: &str) {
    assert!(matches!(err, StoreError::ModelDenied(_)), "{err}");
    assert_eq!(
        err.to_string(),
        format!("model {model} is not in the allowlist")
    );
}

#[sqlx::test]
async fn save_refuses_a_model_outside_the_list_and_writes_nothing(pool: PgPool) {
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    let alice = user(&pool, "alice").await;
    let err = store
        .create_profile(Some(alice), "p", &profile_json("gpt-5"))
        .await
        .unwrap_err();
    denied(&err, "gpt-5");
    assert_eq!(count(&pool, "profile_version").await, 0);
    assert_eq!(count(&pool, "profile_blob").await, 0);
    store
        .create_profile(Some(alice), "p", &profile_json(OPUS))
        .await
        .unwrap();
    assert_eq!(count(&pool, "profile_version").await, 1);
}

#[sqlx::test]
async fn save_in_toml_form_is_checked_too(pool: PgPool) {
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    let alice = user(&pool, "alice").await;
    let err = store
        .create_profile_content(
            Some(alice),
            "p",
            ProfileContent::Toml("model = \"gpt-5\"\n"),
        )
        .await
        .unwrap_err();
    denied(&err, "gpt-5");
    assert_eq!(count(&pool, "profile_version").await, 0);
}

#[sqlx::test]
async fn update_refuses_a_model_outside_the_list(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    seed(&pool, alice, "p", OPUS).await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM profile")
        .fetch_one(&pool)
        .await
        .unwrap();
    let allow = list(OPUS);
    let err = profiles::update_owned(
        &pool,
        Some(alice),
        Some(&allow),
        id,
        ProfileContent::Json(&profile_json("gpt-5")),
    )
    .await
    .unwrap_err();
    denied(&err, "gpt-5");
    assert_eq!(count(&pool, "profile_version").await, 1);
    profiles::update_owned(
        &pool,
        Some(alice),
        Some(&allow),
        id,
        ProfileContent::Json(&profile_json(OPUS)),
    )
    .await
    .unwrap();
}

#[sqlx::test]
async fn a_profile_with_no_model_passes_a_set_list(pool: PgPool) {
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    let alice = user(&pool, "alice").await;
    store
        .create_profile(Some(alice), "p", r#"{"claude_md":"x"}"#)
        .await
        .unwrap();
    store
        .submit_job_for(Some(alice), &submit("k", "p"))
        .await
        .unwrap();
}

#[sqlx::test]
async fn an_unset_list_applies_no_restriction(pool: PgPool) {
    let store = store_with(pool.clone(), None).await;
    let alice = user(&pool, "alice").await;
    store
        .create_profile(Some(alice), "p", &profile_json("anything-at-all"))
        .await
        .unwrap();
    store
        .submit_job_for(Some(alice), &submit("k", "p"))
        .await
        .unwrap();
    store
        .submit_batch_for(Some(alice), &batch("b", &["p"]))
        .await
        .unwrap();
}

#[sqlx::test]
async fn submit_refuses_a_pinned_model_outside_the_list(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    seed(&pool, alice, "bad", "gpt-5").await;
    seed(&pool, alice, "good", OPUS).await;
    let store = store_with(pool.clone(), Some(list(&format!("{OPUS},{SONNET}")))).await;
    let err = store
        .submit_job_for(Some(alice), &submit("k1", "bad"))
        .await
        .unwrap_err();
    denied(&err, "gpt-5");
    assert_eq!(count(&pool, "jobs").await, 0);
    store
        .submit_job_for(Some(alice), &submit("k2", "good"))
        .await
        .unwrap();
    assert_eq!(count(&pool, "jobs").await, 1);
}

#[sqlx::test]
async fn match_is_exact_and_case_sensitive(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    seed(&pool, alice, "upper", "Claude-Opus-4-1").await;
    seed(&pool, alice, "prefix", "claude-opus").await;
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    for name in ["upper", "prefix"] {
        let err = store
            .submit_job_for(Some(alice), &submit(name, name))
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::ModelDenied(_)), "{name}");
    }
    assert_eq!(count(&pool, "jobs").await, 0);
}

#[sqlx::test]
async fn batch_submit_cannot_bypass_the_list(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    seed(&pool, alice, "good", OPUS).await;
    seed(&pool, alice, "bad", "gpt-5").await;
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    let err = store
        .submit_batch_for(Some(alice), &batch("b1", &["good", "bad"]))
        .await
        .unwrap_err();
    denied(&err, "gpt-5");
    assert_eq!(count(&pool, "jobs").await, 0);
    assert_eq!(count(&pool, "batch").await, 0);
    store
        .submit_batch_for(Some(alice), &batch("b2", &["good"]))
        .await
        .unwrap();
    assert_eq!(count(&pool, "jobs").await, 1);
}

#[sqlx::test]
async fn the_unowned_batch_path_cannot_bypass_the_list(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    seed(&pool, alice, "bad", "gpt-5").await;
    sqlx::query("UPDATE profile SET visibility = 'shared'")
        .execute(&pool)
        .await
        .unwrap();
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    let err = store
        .submit_batch(&batch("b1", &["bad"]))
        .await
        .unwrap_err();
    denied(&err, "gpt-5");
    assert_eq!(count(&pool, "jobs").await, 0);
}

#[sqlx::test]
async fn hostile_model_names_never_reach_the_message_raw(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    let over = "x".repeat(MAX_MODEL_BYTES);
    let table: Vec<(&str, String)> = vec![
        ("cr", "a\rb".into()),
        ("crlf", "a\r\nb".into()),
        ("lf", "a\nb".into()),
        ("nel", "a\u{85}b".into()),
        ("u2028", "a\u{2028}b".into()),
        ("u2029", "a\u{2029}b".into()),
        ("backslash", "a\\b".into()),
        ("tab", "a\tb".into()),
        ("nul", "a\0b".into()),
        ("space", "a b".into()),
        ("non-ascii", "modèle-é".into()),
        ("bidi", "a\u{202e}b".into()),
        ("case", "CLAUDE-OPUS-4-1".into()),
        ("max length", over),
    ];
    let mut reached = 0;
    for (label, model) in table {
        let saved = store
            .create_profile(Some(alice), "p", &profile_json(&model))
            .await;
        let Err(StoreError::ModelDenied(d)) = saved else {
            continue;
        };
        reached += 1;
        let shown = d.to_string();
        assert!(
            !shown
                .chars()
                .any(|c| c.is_control() || "\u{2028}\u{2029}\u{202e}".contains(c)),
            "{label}: {shown:?}"
        );
    }
    assert!(
        reached >= 8,
        "only {reached} hostile names reached the allowlist"
    );
    assert_eq!(count(&pool, "profile_version").await, 0);
}

fn serve(pool: &PgPool, store: &Store) -> SocketAddr {
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(Users::new(pool.clone()));
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(store, &auth).serve_with_incoming(incoming));
    addr
}

fn channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

#[derive(Clone)]
struct Bearer(String);

impl tonic::service::Interceptor for Bearer {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let value = MetadataValue::try_from(format!("Bearer {}", self.0))
            .map_err(|err| Status::internal(err.to_string()))?;
        request.metadata_mut().insert("authorization", value);
        Ok(request)
    }
}

#[sqlx::test]
async fn grpc_maps_a_denied_model_to_permission_denied_naming_it(pool: PgPool) {
    let alice = user(&pool, "alice").await;
    seed(&pool, alice, "bad", "gpt-5").await;
    let store = store_with(pool.clone(), Some(list(OPUS))).await;
    let token = {
        let made = Users::new(pool.clone())
            .create_api_token(alice, "test")
            .await
            .unwrap();
        String::from_utf8(made.token.expose().to_vec()).unwrap()
    };
    let addr = serve(&pool, &store);
    let mut profiles = FleetProfilesClient::with_interceptor(channel(addr), Bearer(token.clone()));
    let err = profiles
        .create_profile(CreateProfileRequest {
            name: "p".to_owned(),
            content_json: profile_json("gpt-5"),
            ..CreateProfileRequest::default()
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "model gpt-5 is not in the allowlist");
    let mut jobs = FleetJobsClient::with_interceptor(channel(addr), Bearer(token));
    let err = jobs.submit_job(submit("k", "bad")).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), "model gpt-5 is not in the allowlist");
}

fn box_name() -> String {
    format!("box-{}", 1)
}

async fn lease_blob(
    pool: &PgPool,
    queued_under: Option<ModelAllowlist>,
    serving_under: Option<ModelAllowlist>,
    profile_json: &str,
) -> Result<fleet_proto::v1::GetProfileBlobReply, Status> {
    let alice = user(pool, "alice").await;
    profiles::create_owned(
        pool,
        Some(alice),
        None,
        "p",
        ProfileContent::Json(profile_json),
    )
    .await
    .unwrap();
    let queue = store_with(pool.clone(), queued_under).await;
    queue
        .submit_job_for(Some(alice), &submit("k", "p"))
        .await
        .unwrap();
    let serving = store_with(pool.clone(), serving_under).await;
    let addr = serve(pool, &serving);
    let mut worker = FleetWorkerClient::with_interceptor(channel(addr), Bearer(BOX.to_owned()));
    let job = worker
        .claim_job(ClaimJobRequest { r#box: box_name() })
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap();
    worker
        .get_profile_blob(GetProfileBlobRequest {
            job_id: job.job_id,
            attempt: job.attempt,
            r#box: box_name(),
        })
        .await
        .map(tonic::Response::into_inner)
}

#[sqlx::test]
async fn blob_serve_refuses_a_job_queued_before_the_list_narrowed(pool: PgPool) {
    let err = lease_blob(&pool, None, Some(list(SONNET)), &profile_json(OPUS))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.message(),
        "model claude-opus-4-1 is not in the allowlist"
    );
}

#[sqlx::test]
async fn blob_serve_refuses_a_job_queued_under_a_wider_list(pool: PgPool) {
    let wide = list(&format!("{OPUS},{SONNET}"));
    let err = lease_blob(&pool, Some(wide), Some(list(SONNET)), &profile_json(OPUS))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.message(),
        "model claude-opus-4-1 is not in the allowlist"
    );
}

#[sqlx::test]
async fn blob_serve_passes_an_allowed_model(pool: PgPool) {
    let json = profile_json(OPUS);
    let reply = lease_blob(&pool, None, Some(list(OPUS)), &json)
        .await
        .unwrap();
    assert_eq!(reply.content, json.as_bytes());
}

#[sqlx::test]
async fn blob_serve_passes_a_profile_with_no_model_under_a_list(pool: PgPool) {
    let json = r#"{"claude_md":"x"}"#;
    let reply = lease_blob(&pool, None, Some(list(OPUS)), json)
        .await
        .unwrap();
    assert_eq!(reply.content, json.as_bytes());
}
