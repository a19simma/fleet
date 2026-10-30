//! `FleetBatches` over a real tonic server on a loopback port, plus the batch table checks.
//! The tests need a Postgres superuser URL in `DATABASE_URL`. They live in their own binary
//! because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;

use fleet_proto::v1::fleet_batches_client::FleetBatchesClient;
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::{GetBatchRequest, ListJobsRequest, SubmitBatchRequest};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::service::router;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};

const CLIENT: &str = "test-token-0123456789abcdef0123456789";
const BOX: &str = "box-token-0123456789abcdef0123456789";
const SHA: &str = "0123456789abcdef0123456789abcdef01234567";
const REPO: &str = "https://example.com/org/repo.git";
const ONE: &str = r#"{"claude_md":"one"}"#;
const TWO: &str = r#"{"claude_md":"two"}"#;

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Batches = FleetBatchesClient<InterceptedService<Channel, Interceptor>>;

fn as_client(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, Some(CLIENT))
}

fn as_box(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, Some(BOX))
}

fn anonymous(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, None)
}

fn with_token(mut request: Request<()>, token: Option<&str>) -> Result<Request<()>, Status> {
    if let Some(token) = token {
        let value = MetadataValue::try_from(format!("Bearer {token}"))
            .map_err(|err| Status::internal(err.to_string()))?;
        request.metadata_mut().insert("authorization", value);
    }
    Ok(request)
}

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

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

fn channel(addr: SocketAddr) -> Channel {
    Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy()
}

fn batches(addr: SocketAddr, interceptor: Interceptor) -> Batches {
    FleetBatchesClient::with_interceptor(channel(addr), interceptor)
}

fn request(key: &str, profiles: &[&str]) -> SubmitBatchRequest {
    SubmitBatchRequest {
        idempotency_key: key.to_owned(),
        prompt: "fix the bug".to_owned(),
        repo: REPO.to_owned(),
        base_sha: SHA.to_owned(),
        repeats: 0,
        profiles: profiles.iter().map(|p| (*p).to_owned()).collect(),
    }
}

async fn count(pool: &PgPool, table: &str) -> i64 {
    let sql = match table {
        "batch" => "SELECT count(*) FROM batch",
        _ => "SELECT count(*) FROM jobs",
    };
    sqlx::query_scalar(sql).fetch_one(pool).await.unwrap()
}

async fn two_profiles(store: &Store) {
    store.create_profile("alpha", ONE).await.unwrap();
    store.create_profile("beta", TWO).await.unwrap();
}

#[sqlx::test]
async fn submit_creates_batch_and_jobs_in_profile_order(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let reply = batches(addr, as_client)
        .submit_batch(request("k1", &["beta", "alpha"]))
        .await
        .unwrap()
        .into_inner();
    assert!(reply.created);
    assert_eq!(reply.job_ids.len(), 2);
    assert_eq!(count(&pool, "batch").await, 1);
    let rows: Vec<(String, String, i32, i32)> = sqlx::query_as(
        "SELECT job_id, profile_name, batch_pos, repeat_idx FROM jobs WHERE batch_id = $1 \
         ORDER BY batch_pos",
    )
    .bind(&reply.batch_id)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows[0].0, reply.job_ids[0]);
    assert_eq!(rows[0].1, "beta");
    assert_eq!(rows[1].0, reply.job_ids[1]);
    assert_eq!(rows[1].1, "alpha");
    assert_eq!(rows[0].3, 0);
    let job: (String, String, String, bool, String) =
        sqlx::query_as("SELECT base_ref, repo, state, open_pr, branch FROM jobs WHERE job_id = $1")
            .bind(&reply.job_ids[0])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(job.0, SHA);
    assert_eq!(job.1, REPO);
    assert_eq!(job.2, "QUEUED");
    assert!(!job.3);
    assert_eq!(job.4, format!("swarm/{}", reply.job_ids[0]));
}

#[sqlx::test]
async fn a_failing_second_job_leaves_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    sqlx::query(
        "CREATE FUNCTION fail_beta() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.profile_name = 'beta' THEN RAISE EXCEPTION 'forced'; END IF; RETURN NEW; END; $$",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TRIGGER fail_beta BEFORE INSERT ON jobs FOR EACH ROW EXECUTE FUNCTION fail_beta()",
    )
    .execute(&pool)
    .await
    .unwrap();
    let addr = serve(&store);
    let err = batches(addr, as_client)
        .submit_batch(request("k1", &["alpha", "beta"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
    assert!(!err.message().contains("forced"));
    assert_eq!(count(&pool, "batch").await, 0);
    assert_eq!(count(&pool, "jobs").await, 0);
}

#[sqlx::test]
async fn an_unknown_second_profile_leaves_nothing(pool: PgPool) {
    let store = store(pool.clone()).await;
    store.create_profile("alpha", ONE).await.unwrap();
    let addr = serve(&store);
    let err = batches(addr, as_client)
        .submit_batch(request("k1", &["alpha", "ghost"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(err.message(), "profile not found");
    assert!(!err.message().contains("ghost"));
    assert_eq!(count(&pool, "batch").await, 0);
    assert_eq!(count(&pool, "jobs").await, 0);
}

#[sqlx::test]
async fn resubmit_returns_the_same_batch_and_jobs(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    let first = client
        .submit_batch(request("k1", &["alpha", "beta"]))
        .await
        .unwrap()
        .into_inner();
    let mut repeated = request("k1", &["alpha", "beta"]);
    repeated.repeats = 1;
    let again = client.submit_batch(repeated).await.unwrap().into_inner();
    assert!(first.created);
    assert!(!again.created);
    assert_eq!(again.batch_id, first.batch_id);
    assert_eq!(again.job_ids, first.job_ids);
    assert_eq!(count(&pool, "batch").await, 1);
    assert_eq!(count(&pool, "jobs").await, 2);
}

#[sqlx::test]
async fn resubmit_after_a_new_version_keeps_the_batch(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    let first = client
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap()
        .into_inner();
    store
        .create_profile("alpha", r#"{"claude_md":"three"}"#)
        .await
        .unwrap();
    let again = client
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.batch_id, first.batch_id);
    assert!(!again.created);
}

#[sqlx::test]
async fn same_key_with_other_parameters_is_refused(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    client
        .submit_batch(request("k1", &["alpha", "beta"]))
        .await
        .unwrap();
    let mut prompt = request("k1", &["alpha", "beta"]);
    prompt.prompt = "other".to_owned();
    let mut repo = request("k1", &["alpha", "beta"]);
    repo.repo = "https://example.com/other.git".to_owned();
    let mut sha = request("k1", &["alpha", "beta"]);
    sha.base_sha = "f".repeat(40);
    let others = [
        prompt,
        repo,
        sha,
        request("k1", &["alpha"]),
        request("k1", &["beta", "alpha"]),
        request("k1", &["alpha", "beta", "gamma"]),
    ];
    for other in others {
        let err = client.submit_batch(other).await.unwrap_err();
        assert_eq!(err.code(), Code::AlreadyExists);
        assert_eq!(
            err.message(),
            "idempotency key already used with other parameters"
        );
    }
    assert_eq!(count(&pool, "batch").await, 1);
    assert_eq!(count(&pool, "jobs").await, 2);
}

#[sqlx::test]
async fn repeats_two_is_refused_and_zero_and_one_pass(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    let mut two = request("k2", &["alpha"]);
    two.repeats = 2;
    let err = client.submit_batch(two).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), "repeats above 1 is not supported");
    assert_eq!(count(&pool, "batch").await, 0);
    let mut zero = request("k0", &["alpha"]);
    zero.repeats = 0;
    client.submit_batch(zero).await.unwrap();
    let mut one = request("k1", &["alpha"]);
    one.repeats = 1;
    client.submit_batch(one).await.unwrap();
    let stored: Vec<i32> = sqlx::query_scalar("SELECT repeats FROM batch")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!(stored, vec![1, 1]);
}

#[sqlx::test]
async fn bad_base_sha_is_refused_and_the_check_holds_in_the_database(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    let upper = SHA.to_uppercase();
    let short = SHA[..39].to_owned();
    let long = format!("{SHA}0");
    let non_hex = format!("{}g", &SHA[..39]);
    for bad in [upper, short, long, non_hex] {
        let mut req = request("k1", &["alpha"]);
        req.base_sha.clone_from(&bad);
        let err = client.submit_batch(req).await.unwrap_err();
        assert_eq!(err.code(), Code::InvalidArgument, "{bad}");
        assert_eq!(err.message(), "invalid base sha");
        let direct = sqlx::query(
            "INSERT INTO batch (batch_id, idempotency_key, prompt, repo, base_sha) \
             VALUES ('b', 'k', 'p', 'https://example.com/r', $1)",
        )
        .bind(&bad)
        .execute(&pool)
        .await;
        assert!(direct.is_err(), "{bad}");
    }
    assert_eq!(count(&pool, "batch").await, 0);
}

#[sqlx::test]
async fn the_database_refuses_repeats_above_one(pool: PgPool) {
    let _ = store(pool.clone()).await;
    let direct = sqlx::query(
        "INSERT INTO batch (batch_id, idempotency_key, prompt, repo, base_sha, repeats) \
         VALUES ('b', 'k', 'p', 'https://example.com/r', $1, 2)",
    )
    .bind(SHA)
    .execute(&pool)
    .await;
    assert!(direct.is_err());
}

#[sqlx::test]
async fn unknown_profile_is_not_found_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    let addr = serve(&store);
    let err = batches(addr, as_client)
        .submit_batch(request("k1", &["zzz-private-input"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(err.message(), "profile not found");
    assert_eq!(count(&pool, "batch").await, 0);
}

#[sqlx::test]
async fn bad_lists_and_names_are_refused_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    let err = client
        .submit_batch(request("k1", &["alpha", "alpha"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(err.message(), "duplicate profile in batch");
    let err = client.submit_batch(request("k1", &[])).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let names: Vec<String> = (0..17).map(|n| format!("p{n}")).collect();
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    let err = client.submit_batch(request("k1", &refs)).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    let err = client
        .submit_batch(request("k1", &["zzz private input"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(!err.message().contains("private"));
    let mut bad_repo = request("k1", &["alpha"]);
    bad_repo.repo = "http://example.com/r".to_owned();
    let err = client.submit_batch(bad_repo).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert!(!err.message().contains("example"));
    let mut bad_prompt = request("k1", &["alpha"]);
    bad_prompt.prompt = " ".to_owned();
    let err = client.submit_batch(bad_prompt).await.unwrap_err();
    assert_eq!(err.code(), Code::InvalidArgument);
    assert_eq!(count(&pool, "batch").await, 0);
}

#[sqlx::test]
async fn jobs_stay_pinned_to_the_version_at_submit(pool: PgPool) {
    let store = store(pool.clone()).await;
    let v1 = store.create_profile("alpha", ONE).await.unwrap();
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    let first = client
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap()
        .into_inner();
    let v2 = store.create_profile("alpha", TWO).await.unwrap();
    assert_eq!(v2.version, 2);
    let second = client
        .submit_batch(request("k2", &["alpha"]))
        .await
        .unwrap()
        .into_inner();
    let pin = |id: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_as::<_, (i32, String)>(
                "SELECT profile_version, encode(profile_hash, 'hex') FROM jobs WHERE job_id = $1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    assert_eq!(pin(first.job_ids[0].clone()).await, (1, v1.hash.clone()));
    assert_eq!(pin(second.job_ids[0].clone()).await, (2, v2.hash));
}

#[sqlx::test]
async fn batch_profile_repeat_is_unique(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let reply = batches(addr, as_client)
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap()
        .into_inner();
    let direct = sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, batch_id, repeat_idx, \
         batch_pos, profile_name, profile_version, profile_hash) \
         SELECT 'dup', prompt, repo, base_ref, 'swarm/dup', false, batch_id, repeat_idx, 5, \
         profile_name, profile_version, profile_hash FROM jobs WHERE batch_id = $1",
    )
    .bind(&reply.batch_id)
    .execute(&pool)
    .await;
    assert!(direct.is_err());
    assert_eq!(count(&pool, "jobs").await, 1);
}

#[sqlx::test]
async fn a_job_cannot_pin_a_hash_the_profile_never_held(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let reply = batches(addr, as_client)
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap()
        .into_inner();
    let direct = sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, batch_id, repeat_idx, \
         batch_pos, profile_name, profile_version, profile_hash) \
         SELECT 'bad', prompt, repo, base_ref, 'swarm/bad', false, batch_id, 1, 1, \
         profile_name, profile_version, (SELECT hash FROM profile_version WHERE name = 'beta') \
         FROM jobs WHERE batch_id = $1",
    )
    .bind(&reply.batch_id)
    .execute(&pool)
    .await;
    assert!(direct.is_err());
}

#[sqlx::test]
async fn plain_jobs_keep_working_beside_batch_jobs(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    batches(addr, as_client)
        .submit_batch(request("k1", &["alpha", "beta"]))
        .await
        .unwrap();
    let mut jobs = FleetJobsClient::with_interceptor(channel(addr), as_client);
    let plain = jobs
        .submit_job(fleet_proto::v1::SubmitJobRequest {
            idempotency_key: "plain".to_owned(),
            prompt: "p".to_owned(),
            repo: REPO.to_owned(),
            base_ref: "main".to_owned(),
            open_pr: true,
        })
        .await
        .unwrap()
        .into_inner();
    let listed = jobs
        .list_jobs(ListJobsRequest::default())
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.jobs.len(), 3);
    assert!(listed.jobs.iter().any(|job| job.job_id == plain.job_id));
    let fetched = jobs
        .get_job(fleet_proto::v1::GetJobRequest {
            job_id: listed.jobs[0].job_id.clone(),
        })
        .await
        .unwrap();
    assert_eq!(fetched.into_inner().job_id, listed.jobs[0].job_id);
}

#[sqlx::test]
async fn box_token_is_denied_and_anonymous_is_unauthenticated(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let err = batches(addr, as_box)
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let err = batches(addr, anonymous)
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unauthenticated);
    assert_eq!(count(&pool, "batch").await, 0);
}

#[sqlx::test]
async fn concurrent_submits_with_one_key_make_one_batch(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut tasks = Vec::new();
    for _ in 0..6 {
        tasks.push(tokio::spawn(async move {
            batches(addr, as_client)
                .submit_batch(request("k1", &["alpha", "beta"]))
                .await
                .unwrap()
                .into_inner()
        }));
    }
    let mut replies = Vec::new();
    for task in tasks {
        replies.push(task.await.unwrap());
    }
    assert!(replies.iter().all(|r| r.batch_id == replies[0].batch_id));
    assert_eq!(replies.iter().filter(|r| r.created).count(), 1);
    assert_eq!(count(&pool, "batch").await, 1);
    assert_eq!(count(&pool, "jobs").await, 2);
}

fn get(batch_id: &str) -> GetBatchRequest {
    GetBatchRequest {
        batch_id: batch_id.to_owned(),
    }
}

#[sqlx::test]
async fn get_batch_returns_jobs_in_profile_order_with_summary_and_no_prompt(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let mut client = batches(addr, as_client);
    let made = client
        .submit_batch(request("k1", &["beta", "alpha"]))
        .await
        .unwrap()
        .into_inner();
    sqlx::query(
        "INSERT INTO job_summary (job_id, turns, cost_est_usd, complete, missing) \
         VALUES ($1, 7, 0.25, false, ARRAY['hooks'])",
    )
    .bind(&made.job_ids[1])
    .execute(&pool)
    .await
    .unwrap();
    let got = client
        .get_batch(get(&made.batch_id))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(got.batch_id, made.batch_id);
    assert_eq!(got.prompt, "fix the bug");
    assert_eq!(got.repo, REPO);
    assert_eq!(got.base_sha, SHA);
    assert_eq!(got.repeats, 1);
    assert!(got.created_at_ms > 0);
    let ids: Vec<&str> = got.jobs.iter().map(|j| j.job_id.as_str()).collect();
    assert_eq!(
        ids,
        made.job_ids.iter().map(String::as_str).collect::<Vec<_>>()
    );
    let names: Vec<&str> = got
        .jobs
        .iter()
        .map(|j| j.profile.as_ref().unwrap().name.as_str())
        .collect();
    assert_eq!(names, ["beta", "alpha"]);
    assert!(got.jobs.iter().all(|j| j.prompt.is_empty()));
    assert!(got.jobs[0].summary.is_none());
    let summary = got.jobs[1].summary.as_ref().unwrap();
    assert_eq!(summary.turns, Some(7));
    assert_eq!(summary.tool_calls, None);
    assert!(!summary.complete);
    assert_eq!(summary.missing, ["hooks"]);
}

#[sqlx::test]
async fn get_batch_refuses_unknown_bad_and_wrong_scope_without_echo(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let made = batches(addr, as_client)
        .submit_batch(request("k1", &["alpha"]))
        .await
        .unwrap()
        .into_inner();
    let unknown = batches(addr, as_client)
        .get_batch(get("01ARZ3NDEKTSV4RRFFQ69G5FAV"))
        .await
        .unwrap_err();
    assert_eq!(unknown.code(), Code::NotFound);
    assert_eq!(unknown.message(), "batch not found");
    let bad = batches(addr, as_client)
        .get_batch(get("zzz private input"))
        .await
        .unwrap_err();
    assert_eq!(bad.code(), Code::InvalidArgument);
    assert_eq!(bad.message(), "invalid batch id");
    let boxed = batches(addr, as_box)
        .get_batch(get(&made.batch_id))
        .await
        .unwrap_err();
    assert_eq!(boxed.code(), Code::PermissionDenied);
    let anon = batches(addr, anonymous)
        .get_batch(get(&made.batch_id))
        .await
        .unwrap_err();
    assert_eq!(anon.code(), Code::Unauthenticated);
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn drop_owner_default(pool: &PgPool) {
    sqlx::query("ALTER TABLE jobs ALTER COLUMN user_id DROP DEFAULT")
        .execute(pool)
        .await
        .unwrap();
}

async fn owners(pool: &PgPool, batch_id: &str) -> Vec<(i64, String)> {
    sqlx::query_as("SELECT user_id, agent FROM jobs WHERE batch_id = $1 ORDER BY batch_pos")
        .bind(batch_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn every_batch_job_records_the_owner_and_agent_explicitly(pool: PgPool) {
    let store = store(pool.clone()).await;
    drop_owner_default(&pool).await;
    two_profiles(&store).await;
    let alice = user(&pool, "alice").await;
    let reply = store
        .submit_batch_for(Some(alice), &request("k1", &["alpha", "beta"]))
        .await
        .unwrap();
    let claude = || (alice, "claude".to_owned());
    assert_eq!(
        owners(&pool, &reply.batch_id).await,
        vec![claude(), claude()]
    );
}

#[sqlx::test]
async fn the_legacy_batch_path_stamps_the_bootstrap_user(pool: PgPool) {
    let store = store(pool.clone()).await;
    drop_owner_default(&pool).await;
    two_profiles(&store).await;
    let reply = store
        .submit_batch(&request("k1", &["alpha", "beta"]))
        .await
        .unwrap();
    let boot: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'bootstrap'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let rows = owners(&pool, &reply.batch_id).await;
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|(id, _)| *id == boot));
}

#[sqlx::test]
async fn a_batch_key_stored_for_another_owner_conflicts(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let first = store
        .submit_batch_for(Some(alice), &request("k1", &["alpha", "beta"]))
        .await
        .unwrap();
    let again = store
        .submit_batch_for(Some(alice), &request("k1", &["alpha", "beta"]))
        .await
        .unwrap();
    assert_eq!(first.batch_id, again.batch_id);
    assert!(!again.created);
    let other = store
        .submit_batch_for(Some(bob), &request("k1", &["alpha", "beta"]))
        .await;
    assert!(matches!(
        other,
        Err(fleet_server::store::StoreError::KeyConflict)
    ));
    assert_eq!(count(&pool, "jobs").await, 2);
}

#[sqlx::test]
async fn a_batch_agent_other_than_the_default_conflicts_on_resubmit(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let reply = store
        .submit_batch(&request("k1", &["alpha", "beta"]))
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET agent = 'codex' WHERE batch_id = $1 AND batch_pos = 1")
        .bind(&reply.batch_id)
        .execute(&pool)
        .await
        .unwrap();
    let again = store.submit_batch(&request("k1", &["alpha", "beta"])).await;
    assert!(matches!(
        again,
        Err(fleet_server::store::StoreError::KeyConflict)
    ));
}

#[sqlx::test]
async fn a_client_token_batch_stamps_the_bootstrap_user_over_rpc(pool: PgPool) {
    let store = store(pool.clone()).await;
    two_profiles(&store).await;
    let addr = serve(&store);
    let reply = batches(addr, as_client)
        .submit_batch(request("k1", &["alpha", "beta"]))
        .await
        .unwrap()
        .into_inner();
    let boot: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'bootstrap'")
        .fetch_one(&pool)
        .await
        .unwrap();
    let rows = owners(&pool, &reply.batch_id).await;
    assert!(rows.iter().all(|(id, _)| *id == boot));
}
