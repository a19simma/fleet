//! The profile environment-key refusal at the wire edge: submit, batch and lease each answer a
//! stored blob with an `environment` key as `INVALID_ARGUMENT` with the distinct message. The
//! tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary because
//! each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_proto::MAX_PROFILE_MESSAGE_BYTES;
use fleet_proto::v1::fleet_batches_client::FleetBatchesClient;
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, GetProfileBlobRequest, SubmitBatchRequest, SubmitJobRequest,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::profiles::ProfileContent;
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const REPO: &str = "https://example.com/org/repo.git";
const MESSAGE: &str = "a profile cannot name an environment";

fn bearer(mut request: Request<()>, token: &str) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {token}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

fn as_box(request: Request<()>) -> Result<Request<()>, Status> {
    bearer(request, BOX)
}

#[derive(Clone)]
struct UserBearer(String);

impl tonic::service::Interceptor for UserBearer {
    fn call(&mut self, request: Request<()>) -> Result<Request<()>, Status> {
        bearer(request, &self.0)
    }
}

async fn user_token(pool: &PgPool) -> UserBearer {
    let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
        .fetch_one(pool)
        .await
        .unwrap();
    let made = Users::new(pool.clone())
        .create_api_token(id, "test")
        .await
        .unwrap();
    UserBearer(String::from_utf8(made.token.expose().to_vec()).unwrap())
}

fn serve(pool: &PgPool, store: &Store) -> Channel {
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(Users::new(pool.clone()));
    let incoming =
        tonic::transport::server::TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(router(store, &auth).serve_with_incoming(incoming));
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

async fn store_with_shared(pool: &PgPool, name: &str) -> Store {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let system: i64 = sqlx::query_scalar("SELECT system_user_id()")
        .fetch_one(pool)
        .await
        .unwrap();
    fleet_server::profiles::create_owned(
        pool,
        Some(system),
        None,
        name,
        ProfileContent::Json(r#"{"claude_md":"x"}"#),
    )
    .await
    .unwrap();
    sqlx::query("UPDATE profile SET visibility = 'shared' WHERE name = $1")
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
    store
}

async fn plant_environment_key(pool: &PgPool, name: &str) {
    let hash: Vec<u8> = sqlx::query_scalar(
        "SELECT v.hash FROM profile p JOIN profile_version v \
         ON v.profile_id = p.id AND v.version = p.latest_version WHERE p.name = $1",
    )
    .bind(name)
    .fetch_one(pool)
    .await
    .unwrap();
    let content = br#"{"claude_md":"x","environment":"prod"}"#.to_vec();
    let mut tx = pool.begin().await.unwrap();
    sqlx::query("SET LOCAL session_replication_role = replica")
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("UPDATE profile_blob SET content = $1, size = octet_length($1) WHERE hash = $2")
        .bind(content)
        .bind(hash)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn job(key: &str, profile: &str) -> SubmitJobRequest {
    SubmitJobRequest {
        idempotency_key: key.to_owned(),
        prompt: "add hello.txt".to_owned(),
        repo: REPO.to_owned(),
        base_ref: "main".to_owned(),
        open_pr: false,
        agent: String::new(),
        profile: profile.to_owned(),
        environment: String::new(),
    }
}

fn batch(key: &str, profile: &str) -> SubmitBatchRequest {
    SubmitBatchRequest {
        idempotency_key: key.to_owned(),
        prompt: "do it".to_owned(),
        repo: REPO.to_owned(),
        base_sha: SHA.to_owned(),
        repeats: 0,
        profiles: vec![profile.to_owned()],
        agent: String::new(),
        environment: String::new(),
    }
}

fn box_name() -> String {
    format!("box-{}", 1)
}

fn assert_refusal(status: &Status) {
    assert_eq!(status.code(), Code::InvalidArgument, "{status}");
    assert_eq!(status.message(), MESSAGE);
}

#[sqlx::test]
async fn submit_answers_a_stored_environment_key_as_invalid_argument(pool: PgPool) {
    let store = store_with_shared(&pool, "alpha").await;
    plant_environment_key(&pool, "alpha").await;
    let token = user_token(&pool).await;
    let mut jobs = FleetJobsClient::with_interceptor(serve(&pool, &store), token);
    let err = jobs.submit_job(job("s", "alpha")).await.unwrap_err();
    assert_refusal(&err);
}

#[sqlx::test]
async fn batch_answers_a_stored_environment_key_as_invalid_argument(pool: PgPool) {
    let store = store_with_shared(&pool, "alpha").await;
    plant_environment_key(&pool, "alpha").await;
    let token = user_token(&pool).await;
    let mut batches = FleetBatchesClient::with_interceptor(serve(&pool, &store), token);
    let err = batches.submit_batch(batch("b", "alpha")).await.unwrap_err();
    assert_refusal(&err);
}

#[sqlx::test]
async fn lease_answers_a_stored_environment_key_as_invalid_argument(pool: PgPool) {
    let store = store_with_shared(&pool, "alpha").await;
    let reply = store.submit_batch(&batch("b", "alpha")).await.unwrap();
    let id = reply.job_ids.first().unwrap().clone();
    let channel = serve(&pool, &store);
    let mut worker = FleetWorkerClient::with_interceptor(channel, as_box)
        .max_decoding_message_size(MAX_PROFILE_MESSAGE_BYTES);
    let job = worker
        .claim_job(ClaimJobRequest { r#box: box_name() })
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap();
    plant_environment_key(&pool, "alpha").await;
    let err = worker
        .get_profile_blob(GetProfileBlobRequest {
            job_id: id,
            attempt: job.attempt,
            r#box: box_name(),
        })
        .await
        .unwrap_err();
    assert_refusal(&err);
}

#[sqlx::test]
async fn an_unknown_profile_name_still_answers_not_found(pool: PgPool) {
    let store = store_with_shared(&pool, "alpha").await;
    plant_environment_key(&pool, "alpha").await;
    let token = user_token(&pool).await;
    let mut jobs = FleetJobsClient::with_interceptor(serve(&pool, &store), token);
    let err = jobs.submit_job(job("u", "missing")).await.unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(err.message(), "profile not found");
}
