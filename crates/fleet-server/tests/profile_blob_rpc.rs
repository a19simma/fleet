//! `FleetWorker.GetProfileBlob` over a real tonic server on a loopback port. The tests need a
//! Postgres superuser URL in `DATABASE_URL`. They live in their own binary because each one
//! binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write;
use std::net::SocketAddr;

use fleet_proto::MAX_PROFILE_MESSAGE_BYTES;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{ClaimJobRequest, GetProfileBlobRequest, Job, SubmitBatchRequest};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::profiles::ProfileContent;
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
const DENIED: &str = "lease does not match";

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Worker = FleetWorkerClient<InterceptedService<Channel, Interceptor>>;

fn as_box(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, BOX)
}

fn as_client(request: Request<()>) -> Result<Request<()>, Status> {
    with_token(request, CLIENT)
}

fn with_token(mut request: Request<()>, token: &str) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {token}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

fn name(n: u32) -> String {
    format!("box-{n}")
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

fn worker(addr: SocketAddr, interceptor: Interceptor) -> Worker {
    FleetWorkerClient::with_interceptor(channel(addr), interceptor)
        .max_decoding_message_size(MAX_PROFILE_MESSAGE_BYTES)
}

async fn shared_with(
    pool: &PgPool,
    name: &str,
    content: ProfileContent<'_>,
) -> fleet_proto::v1::ProfileVersion {
    let system: i64 = sqlx::query_scalar("SELECT system_user_id()")
        .fetch_one(pool)
        .await
        .unwrap();
    let made = fleet_server::profiles::create_owned(pool, Some(system), None, name, content)
        .await
        .unwrap();
    sqlx::query("UPDATE profile SET visibility = 'shared' WHERE owner_user_id = $1 AND name = $2")
        .bind(system)
        .bind(name)
        .execute(pool)
        .await
        .unwrap();
    made
}

async fn shared(pool: &PgPool, name: &str, json: &str) -> fleet_proto::v1::ProfileVersion {
    shared_with(pool, name, ProfileContent::Json(json)).await
}

async fn batch_job(store: &Store, profile: &str) -> String {
    let reply = store
        .submit_batch(&SubmitBatchRequest {
            idempotency_key: format!("key-{profile}"),
            prompt: "fix the bug".to_owned(),
            repo: REPO.to_owned(),
            base_sha: SHA.to_owned(),
            repeats: 0,
            profiles: vec![profile.to_owned()],
            agent: String::new(),
        })
        .await
        .unwrap();
    reply.job_ids.first().unwrap().clone()
}

async fn claim(worker: &mut Worker, box_name: &str) -> Job {
    worker
        .claim_job(ClaimJobRequest {
            r#box: box_name.to_owned(),
        })
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap()
}

fn blob(job_id: &str, attempt: u32, box_name: &str) -> GetProfileBlobRequest {
    GetProfileBlobRequest {
        job_id: job_id.to_owned(),
        attempt,
        r#box: box_name.to_owned(),
    }
}

#[sqlx::test]
async fn the_lease_holder_reads_the_pinned_blob(pool: PgPool) {
    let store = store(pool.clone()).await;
    let created = shared(&pool, "alpha", ONE).await;
    let id = batch_job(&store, "alpha").await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    let pinned = job.profile.unwrap();
    assert_eq!(pinned.name, "alpha");
    assert_eq!(pinned.version, created.version);
    assert_eq!(pinned.hash, created.hash);
    assert!(job.batch_id.is_some());
    let reply = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.content, created.content_json.as_bytes());
    assert_eq!(reply.profile.unwrap(), pinned);
}

const TOOLS_TOML: &str = "[[tools]]\nname = \"node\"\nversion = \"20.11.1\"\n";

#[sqlx::test]
async fn a_job_without_a_profile_carries_none_and_has_no_blob(pool: PgPool) {
    let store = store(pool.clone()).await;
    store
        .submit_job(&fleet_proto::v1::SubmitJobRequest {
            idempotency_key: "plain".to_owned(),
            prompt: "p".to_owned(),
            repo: REPO.to_owned(),
            base_ref: "main".to_owned(),
            open_pr: false,
            agent: String::new(),
            profile: String::new(),
        })
        .await
        .unwrap();
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    assert!(job.profile.is_none());
    assert!(job.batch_id.is_none());
    let err = worker
        .get_profile_blob(blob(&job.job_id, job.attempt, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::NotFound);
    assert_eq!(err.message(), "profile not found");
}

#[sqlx::test]
async fn a_wrong_box_is_denied(pool: PgPool) {
    let store = store(pool.clone()).await;
    shared(&pool, "alpha", ONE).await;
    let id = batch_job(&store, "alpha").await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    let err = worker
        .get_profile_blob(blob(&id, job.attempt, &name(2)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), DENIED);
}

#[sqlx::test]
async fn a_wrong_attempt_is_denied(pool: PgPool) {
    let store = store(pool.clone()).await;
    shared(&pool, "alpha", ONE).await;
    let id = batch_job(&store, "alpha").await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    for attempt in [0, job.attempt + 1, u32::MAX] {
        let err = worker
            .get_profile_blob(blob(&id, attempt, &name(1)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "attempt {attempt}");
        assert_eq!(err.message(), DENIED);
    }
}

#[sqlx::test]
async fn a_missing_job_looks_like_a_wrong_box(pool: PgPool) {
    let store = store(pool.clone()).await;
    let mut worker = worker(serve(&store), as_box);
    let err = worker
        .get_profile_blob(blob("01ARZ3NDEKTSV4RRFFQ69G5FAV", 1, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), DENIED);
}

#[sqlx::test]
async fn a_queued_or_finished_job_has_no_lease(pool: PgPool) {
    let store = store(pool.clone()).await;
    shared(&pool, "alpha", ONE).await;
    let id = batch_job(&store, "alpha").await;
    let mut worker = worker(serve(&store), as_box);
    let err = worker
        .get_profile_blob(blob(&id, 0, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    let job = claim(&mut worker, &name(1)).await;
    sqlx::query(
        "UPDATE jobs SET state = 'RUNNING', lease_expires_at = now() - interval '1 second'",
    )
    .execute(&pool)
    .await
    .unwrap();
    let err = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    sqlx::query("UPDATE jobs SET state = 'FAILED', lease_expires_at = now() + interval '1 hour'")
        .execute(&pool)
        .await
        .unwrap();
    let err = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[sqlx::test]
async fn the_client_token_is_out_of_scope(pool: PgPool) {
    let store = store(pool.clone()).await;
    shared(&pool, "alpha", ONE).await;
    let id = batch_job(&store, "alpha").await;
    let addr = serve(&store);
    let mut holder = worker(addr, as_box);
    let job = claim(&mut holder, &name(1)).await;
    let err = worker(addr, as_client)
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[sqlx::test]
async fn no_hash_or_name_reaches_a_blob(pool: PgPool) {
    let store = store(pool.clone()).await;
    let created = shared(&pool, "alpha", ONE).await;
    batch_job(&store, "alpha").await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    for probe in [created.hash.as_str(), "alpha", ""] {
        let err = worker
            .get_profile_blob(blob(probe, job.attempt, &name(1)))
            .await
            .unwrap_err();
        assert!(
            matches!(err.code(), Code::InvalidArgument | Code::PermissionDenied),
            "probe {probe:?}"
        );
    }
}

#[sqlx::test]
async fn a_pinned_hash_that_does_not_match_the_version_fails_closed(pool: PgPool) {
    let store = store(pool.clone()).await;
    shared(&pool, "alpha", ONE).await;
    shared(&pool, "alpha", TWO).await;
    let id = batch_job(&store, "alpha").await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    sqlx::query(
        "UPDATE jobs SET profile_version = 1, \
         profile_hash = (SELECT v.hash FROM profile_version v JOIN profile p ON p.id = v.profile_id \
         WHERE p.name = 'alpha' AND v.version = 2)",
    )
    .execute(&pool)
    .await
    .unwrap();
    let err = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::Unavailable);
}

fn large_profile() -> String {
    let file = "\n".repeat(200 * 1024);
    let mut files = String::new();
    for index in 0..16 {
        if index > 0 {
            files.push(',');
        }
        write!(
            files,
            r#"{{"path":"f{index}.txt","text":{}}}"#,
            serde_json::to_string(&file).unwrap()
        )
        .unwrap();
    }
    format!(r#"{{"context_files":[{files}]}}"#)
}

#[sqlx::test]
async fn a_blob_over_the_default_client_limit_round_trips(pool: PgPool) {
    let store = store(pool.clone()).await;
    let created = shared(&pool, "big", &large_profile()).await;
    let size = created.content_json.len();
    assert!(size > 4 * 1024 * 1024 && size < MAX_PROFILE_MESSAGE_BYTES);
    let id = batch_job(&store, "big").await;
    let addr = serve(&store);
    let mut raised = worker(addr, as_box);
    let job = claim(&mut raised, &name(1)).await;
    let reply = raised
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.content, created.content_json.as_bytes());
    let mut default = FleetWorkerClient::with_interceptor(channel(addr), as_box);
    let err = default
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::OutOfRange);
}

#[sqlx::test]
async fn the_blob_follows_the_pin_of_either_owner(pool: PgPool) {
    let store = store(pool.clone()).await;
    let alice: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let bob: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ('bob') RETURNING id")
        .fetch_one(&pool)
        .await
        .unwrap();
    for (owner, json) in [(alice, ONE), (bob, TWO)] {
        fleet_server::profiles::create_owned(
            &pool,
            Some(owner),
            None,
            "alpha",
            ProfileContent::Json(json),
        )
        .await
        .unwrap();
    }
    let mut worker = worker(serve(&store), as_box);
    for (n, (owner, json)) in [(alice, ONE), (bob, TWO)].into_iter().enumerate() {
        let request = SubmitBatchRequest {
            idempotency_key: format!("key-{owner}"),
            prompt: "fix the bug".to_owned(),
            repo: REPO.to_owned(),
            base_sha: SHA.to_owned(),
            repeats: 0,
            profiles: vec!["alpha".to_owned()],
            agent: String::new(),
        };
        let id = store
            .submit_batch_for(Some(owner), &request)
            .await
            .unwrap()
            .job_ids
            .remove(0);
        let box_name = name(u32::try_from(n).unwrap() + 1);
        let job = claim(&mut worker, &box_name).await;
        assert_eq!(job.job_id, id);
        let reply = worker
            .get_profile_blob(blob(&id, job.attempt, &box_name))
            .await
            .unwrap()
            .into_inner();
        let expected = fleet_core::Profile::from_json(json.as_bytes())
            .unwrap()
            .canonical_json();
        assert_eq!(reply.content, expected);
    }
}

async fn submitted_job(pool: &PgPool, store: &Store) -> (String, fleet_proto::v1::CatalogItem) {
    let user: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ('ann') RETURNING id")
        .fetch_one(pool)
        .await
        .unwrap();
    fleet_server::profiles::create_owned(
        pool,
        Some(user),
        None,
        "alpha",
        ProfileContent::Json(r#"{"claude_md":"one","selection":[{"item_id":"s2"}]}"#),
    )
    .await
    .unwrap();
    for (id, body) in [("s1", "skill one"), ("s2", "skill two")] {
        sqlx::query(
            "INSERT INTO catalog_items (id, kind, name, content, digest, admin_enabled) \
             VALUES ($1, 'skill', $1, $2, decode(repeat('00', 32), 'hex'), true)",
        )
        .bind(id)
        .bind(body)
        .execute(pool)
        .await
        .unwrap();
    }
    let job = store
        .submit_job_for(
            Some(user),
            &fleet_proto::v1::SubmitJobRequest {
                idempotency_key: "key-1".to_owned(),
                prompt: "fix the bug".to_owned(),
                repo: REPO.to_owned(),
                base_ref: "main".to_owned(),
                open_pr: false,
                agent: String::new(),
                profile: "alpha".to_owned(),
            },
        )
        .await
        .unwrap();
    let item = fleet_core::catalog::CatalogItem::new(
        fleet_core::catalog::CatalogKind::Skill,
        "s1",
        "s1",
        "skill one",
    )
    .unwrap();
    let expected = fleet_proto::v1::CatalogItem {
        id: "s1".to_owned(),
        kind: fleet_proto::v1::CatalogKind::Skill as i32,
        name: "s1".to_owned(),
        content: "skill one".to_owned(),
        digest: item.digest().to_vec(),
        admin_enabled: true,
    };
    (job.job_id, expected)
}

#[sqlx::test]
async fn the_blob_carries_the_frozen_catalog_with_bodies(pool: PgPool) {
    let store = store(pool.clone()).await;
    let (id, expected) = submitted_job(&pool, &store).await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    let reply = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.catalog, vec![expected.clone()]);
    sqlx::query("UPDATE catalog_items SET content = 'edited'")
        .execute(&pool)
        .await
        .unwrap();
    let again = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.catalog, vec![expected]);
}

#[sqlx::test]
async fn a_tampered_snapshot_is_refused_and_never_served(pool: PgPool) {
    let store = store(pool.clone()).await;
    let (id, _) = submitted_job(&pool, &store).await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    for tamper in [
        "UPDATE jobs SET snapshot_catalog = replace(snapshot_catalog::text, 'skill one', 'evil')::jsonb",
        "UPDATE jobs SET snapshot_hash = decode(repeat('11', 32), 'hex')",
    ] {
        sqlx::query(tamper).execute(&pool).await.unwrap();
        let err = worker
            .get_profile_blob(blob(&id, job.attempt, &name(1)))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unavailable, "{tamper}");
        assert!(!err.message().contains("evil"));
    }
}

async fn user_id(pool: &PgPool, name: &str, admin: bool) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username, is_admin) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(admin)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn tools_job(store: &Store, submitter: i64) -> String {
    let request = SubmitBatchRequest {
        idempotency_key: "tools-key".to_owned(),
        prompt: "fix the bug".to_owned(),
        repo: REPO.to_owned(),
        base_sha: SHA.to_owned(),
        repeats: 0,
        profiles: vec!["alpha".to_owned()],
        agent: String::new(),
    };
    store
        .submit_batch_for(Some(submitter), &request)
        .await
        .unwrap()
        .job_ids
        .remove(0)
}

#[sqlx::test]
async fn a_tools_blob_follows_the_live_grant_of_the_job_owner(pool: PgPool) {
    let store = store(pool.clone()).await;
    let root = user_id(&pool, "root", true).await;
    let ann = user_id(&pool, "ann", false).await;
    let system: i64 = sqlx::query_scalar("SELECT system_user_id()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let caps = fleet_server::cred::capability::Capabilities::new(pool.clone());
    let tools = fleet_server::cred::capability::PROFILE_TOOLS;
    caps.grant(root, system, tools).await.unwrap();
    let created = shared_with(&pool, "alpha", ProfileContent::Toml(TOOLS_TOML)).await;
    caps.grant(root, ann, tools).await.unwrap();
    let id = tools_job(&store, ann).await;
    let mut worker = worker(serve(&store), as_box);
    let job = claim(&mut worker, &name(1)).await;
    let reply = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.content, created.content_json.as_bytes());
    assert_eq!(reply.profile.unwrap().hash, created.hash);
    assert!(caps.revoke(root, system, tools).await.unwrap());
    worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap();
    assert!(caps.revoke(root, ann, tools).await.unwrap());
    let err = worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(
        err.message(),
        fleet_server::profiles::ERR_PROFILE_TOOLS_NOT_GRANTED
    );
    assert!(!err.message().contains("node"));
    caps.grant(root, ann, tools).await.unwrap();
    worker
        .get_profile_blob(blob(&id, job.attempt, &name(1)))
        .await
        .unwrap();
}
