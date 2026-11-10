//! `FleetWorker.GetJobEnvironment` (ADR-0067): the fixed denial, the audit rows, the live
//! `env:scripts` and lease locks, the reply cap and secret hiding. The tests need a Postgres
//! superuser URL in `DATABASE_URL` and live in their own binary because they bind sockets.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    clippy::unwrap_in_result,
    reason = "test code asserts by panicking"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::credential::{Secret, fingerprint};
use fleet_core::environment::{
    Delivery, EgressHost, Entry, EntryName, EnvironmentName, EnvironmentSpec, ScriptBody,
    ScriptSpec, SecretSpec, SecretValue,
};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, EnvironmentDelivery, GetJobEnvironmentReply, GetJobEnvironmentRequest, Job,
    SubmitJobRequest,
};
use fleet_proto::{ERR_ENV_INTERNAL, ERR_ENV_LIMIT, ERR_ENV_RELEASE_DENIED};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::seal::FileSealer;
use fleet_server::environments::{EnvironmentService, EnvironmentStore};
use fleet_server::service::router_with_environments;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::server::TcpIncoming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Request, Status};
use tonic_prost::prost::Message;

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const REPO: &str = "https://example.com/org/repo.git";
const MARK: &str = "MARKER-release-secret-k4";
const SHEBANG: &str = "#!/bin/sh\necho a\n";

static NEXT: AtomicUsize = AtomicUsize::new(0);

fn box_a() -> String {
    format!("box-{}", 1)
}

fn box_b() -> String {
    format!("box-{}", 2)
}

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!(
        "fleet-env-release-{}-{}.keys",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let loaded = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    loaded.unwrap()
}

fn store(pool: &PgPool) -> EnvironmentStore {
    EnvironmentStore::new(pool.clone(), Arc::new(sealer()))
}

type Interceptor = fn(Request<()>) -> Result<Request<()>, Status>;
type Worker = FleetWorkerClient<InterceptedService<Channel, Interceptor>>;

fn as_box(mut request: Request<()>) -> Result<Request<()>, Status> {
    let value = MetadataValue::try_from(format!("Bearer {BOX}"))
        .map_err(|err| Status::internal(err.to_string()))?;
    request.metadata_mut().insert("authorization", value);
    Ok(request)
}

struct Rig {
    pool: PgPool,
    core: Store,
    worker: Worker,
    channel: Channel,
    users: Users,
    alice: i64,
    bob: i64,
}

async fn bare_user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn grant(pool: &PgPool, user: i64) {
    sqlx::query(
        "INSERT INTO user_capabilities (user_id, capability, granted_by) VALUES ($1, 'env:scripts', $1)",
    )
    .bind(user)
    .execute(pool)
    .await
    .unwrap();
}

async fn rig_with(pool: PgPool, cap: Option<usize>) -> Rig {
    let core = Store::new(pool.clone());
    core.migrate().await.unwrap();
    let alice = bare_user(&pool, "alice").await;
    let bob = bare_user(&pool, "bob").await;
    grant(&pool, alice).await;
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    let mut environments = store(&pool);
    if let Some(cap) = cap {
        environments = environments.with_reply_cap(cap);
    }
    let service = EnvironmentService::new(environments);
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr: SocketAddr = incoming.local_addr().unwrap();
    tokio::spawn(
        router_with_environments(&core, &auth, None, Some(service)).serve_with_incoming(incoming),
    );
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    Rig {
        pool,
        core,
        worker: FleetWorkerClient::with_interceptor(channel.clone(), as_box),
        channel,
        users,
        alice,
        bob,
    }
}

async fn rig(pool: PgPool) -> Rig {
    rig_with(pool, None).await
}

fn entry_name(raw: &str) -> EntryName {
    EntryName::new(raw).unwrap()
}

fn visible(name: &str, delivery: Delivery) -> Entry {
    Entry::Secret(SecretSpec::new(entry_name(name), true, delivery).unwrap())
}

fn hidden(name: &str) -> Entry {
    Entry::Secret(SecretSpec::with_defaults(entry_name(name)))
}

fn script(name: &str) -> Entry {
    Entry::Script(ScriptSpec::with_defaults(
        entry_name(name),
        ScriptBody::new(SHEBANG).unwrap(),
    ))
}

async fn environment(
    pool: &PgPool,
    owner: i64,
    name: &str,
    entries: Vec<Entry>,
    hosts: &[&str],
) -> (i64, i32) {
    let store = store(pool);
    let id = store
        .create_environment(owner, &EnvironmentName::new(name).unwrap())
        .await
        .unwrap();
    for item in &entries {
        if let Entry::Secret(secret) = item {
            store
                .put_secret(
                    owner,
                    id,
                    secret.name(),
                    &SecretValue::new(format!("{MARK}-{}", secret.name().as_str())).unwrap(),
                )
                .await
                .unwrap();
        }
    }
    let hosts = hosts.iter().map(|h| EgressHost::new(h).unwrap()).collect();
    let saved = store
        .save_version(owner, id, &EnvironmentSpec::new(entries, hosts).unwrap())
        .await
        .unwrap();
    (id, saved.version)
}

impl Rig {
    async fn submit(&self, owner: i64, key: &str) {
        self.core
            .submit_job_for(
                Some(owner),
                &SubmitJobRequest {
                    idempotency_key: key.to_owned(),
                    prompt: "add hello.txt".to_owned(),
                    repo: REPO.to_owned(),
                    base_ref: "main".to_owned(),
                    open_pr: false,
                    agent: String::new(),
                    profile: String::new(),
                    environment: String::new(),
                },
            )
            .await
            .unwrap();
    }

    async fn claim(&mut self) -> Job {
        self.worker
            .claim_job(ClaimJobRequest { r#box: box_a() })
            .await
            .unwrap()
            .into_inner()
            .job
            .unwrap()
    }

    async fn running(&mut self, owner: i64, key: &str, env: Option<(i64, i32)>) -> Job {
        self.submit(owner, key).await;
        if let Some(env) = env {
            sqlx::query(
                "UPDATE jobs SET environment_id = $1, environment_version = $2 WHERE idempotency_key = $3",
            )
            .bind(env.0)
            .bind(env.1)
            .bind(key)
            .execute(&self.pool)
            .await
            .unwrap();
        }
        self.claim().await
    }

    async fn fetch(
        &mut self,
        job: &str,
        attempt: u32,
        box_name: &str,
    ) -> Result<GetJobEnvironmentReply, Status> {
        self.worker
            .get_job_environment(GetJobEnvironmentRequest {
                job_id: job.to_owned(),
                attempt,
                r#box: box_name.to_owned(),
            })
            .await
            .map(tonic::Response::into_inner)
    }

    async fn uses(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM environment_use")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn same_status(left: &Status, right: &Status, cause: &str) {
    assert_eq!(left.code(), right.code(), "{cause}");
    assert_eq!(left.message(), right.message(), "{cause}");
    assert_eq!(left.details(), right.details(), "{cause}");
    assert_eq!(
        left.metadata().clone().into_headers(),
        right.metadata().clone().into_headers(),
        "{cause}"
    );
}

#[sqlx::test]
async fn every_denial_cause_returns_one_byte_identical_status(pool: PgPool) {
    let mut rig = rig(pool).await;
    let (alice, bob) = (rig.alice, rig.bob);
    let secrets = environment(&rig.pool, alice, "plain", vec![hidden("TOKEN")], &[]).await;
    let scripted = environment(
        &rig.pool,
        alice,
        "scripted",
        vec![hidden("TOKEN"), script("setup")],
        &[],
    )
    .await;
    let doomed = environment(&rig.pool, alice, "doomed", vec![hidden("TOKEN")], &[]).await;
    let good = rig.running(alice, "good", Some(secrets)).await;
    let not_running = rig.running(alice, "not-running", Some(secrets)).await;
    let expired = rig.running(alice, "expired", Some(secrets)).await;
    let foreign = rig.running(bob, "foreign", Some(secrets)).await;
    let revoked = rig.running(alice, "revoked", Some(scripted)).await;
    let deleted = rig.running(alice, "deleted", Some(doomed)).await;
    sqlx::query("UPDATE jobs SET state = 'SUCCEEDED' WHERE job_id = $1")
        .bind(&not_running.job_id)
        .execute(&rig.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE job_id = $1")
        .bind(&expired.job_id)
        .execute(&rig.pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&rig.pool)
        .await
        .unwrap();
    store(&rig.pool)
        .delete_environment(alice, doomed.0)
        .await
        .unwrap();

    let reference = rig.fetch("no-such-job", 1, &box_a()).await.unwrap_err();
    assert_eq!(reference.code(), Code::PermissionDenied);
    assert_eq!(reference.message(), ERR_ENV_RELEASE_DENIED);
    assert_eq!(reference.details().len(), 0);
    let causes = [
        ("wrong box", good.job_id.clone(), 1, box_b()),
        ("wrong attempt", good.job_id.clone(), 2, box_a()),
        ("state not running", not_running.job_id.clone(), 1, box_a()),
        ("expired lease", expired.job_id.clone(), 1, box_a()),
        (
            "unknown job",
            "01HZZZZZZZZZZZZZZZZZZZZZZZ".to_owned(),
            1,
            box_a(),
        ),
        ("other user", foreign.job_id.clone(), 1, box_a()),
        ("revoked env:scripts", revoked.job_id.clone(), 1, box_a()),
        ("deleted environment", deleted.job_id.clone(), 1, box_a()),
    ];
    for (cause, job, attempt, box_name) in &causes {
        let status = rig.fetch(job, *attempt, box_name).await.unwrap_err();
        same_status(&status, &reference, cause);
    }
    assert_eq!(rig.uses().await, 0, "a denial wrote an audit row");
    let reply = rig.fetch(&good.job_id, 1, &box_a()).await.unwrap();
    assert_eq!(reply.secrets.len(), 1, "positive control");
    assert_eq!(rig.uses().await, 1);
}

#[sqlx::test]
async fn a_release_returns_the_pin_and_audits_each_secret_on_every_call(pool: PgPool) {
    let mut rig = rig(pool).await;
    let alice = rig.alice;
    let env = environment(
        &rig.pool,
        alice,
        "prod",
        vec![
            hidden("ALPHA"),
            visible("BETA", Delivery::Env),
            visible("GAMMA", Delivery::File),
            script("setup"),
        ],
        &["api.example.com"],
    )
    .await;
    let job = rig.running(alice, "pinned", Some(env)).await;
    assert!(job.has_environment);
    let first = rig.fetch(&job.job_id, 1, &box_a()).await.unwrap();
    assert_eq!(first.environment, "prod");
    assert_eq!(first.version, 1);
    assert_eq!(first.hash.len(), 64);
    assert_eq!(first.egress_hosts, ["api.example.com"]);
    assert_eq!(first.scripts.len(), 1);
    assert_eq!(first.scripts[0].name, "setup");
    assert_eq!(first.scripts[0].body, SHEBANG);
    let got: Vec<_> = first
        .secrets
        .iter()
        .map(|s| {
            (
                s.name.as_str(),
                s.value.clone(),
                s.agent_visible,
                s.delivery,
            )
        })
        .collect();
    let file = EnvironmentDelivery::File as i32;
    let env_delivery = EnvironmentDelivery::Env as i32;
    assert_eq!(
        got,
        [
            ("ALPHA", format!("{MARK}-ALPHA"), false, file),
            ("BETA", format!("{MARK}-BETA"), true, env_delivery),
            ("GAMMA", format!("{MARK}-GAMMA"), true, file),
        ]
    );
    rig.fetch(&job.job_id, 1, &box_a()).await.unwrap();
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, fingerprint FROM environment_use WHERE job_id = $1 AND environment_id = $2 AND version = $3 ORDER BY id",
    )
    .bind(&job.job_id)
    .bind(env.0)
    .bind(env.1)
    .fetch_all(&rig.pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 6);
    let want: Vec<(String, String)> = ["ALPHA", "BETA", "GAMMA"]
        .iter()
        .chain(["ALPHA", "BETA", "GAMMA"].iter())
        .map(|n| {
            (
                (*n).to_owned(),
                fingerprint(&Secret::new(format!("{MARK}-{n}"))),
            )
        })
        .collect();
    assert_eq!(rows, want);
}

#[sqlx::test]
async fn an_empty_environment_leaves_one_null_name_row_and_no_pin_an_empty_reply(pool: PgPool) {
    let mut rig = rig(pool).await;
    let alice = rig.alice;
    let env = environment(&rig.pool, alice, "bare", vec![script("setup")], &[]).await;
    let none = rig.running(alice, "no-pin", None).await;
    assert!(!none.has_environment);
    let reply = rig.fetch(&none.job_id, 1, &box_a()).await.unwrap();
    assert_eq!(reply, GetJobEnvironmentReply::default());
    assert_eq!(rig.uses().await, 0);
    let pinned = rig.running(alice, "bare-pin", Some(env)).await;
    let reply = rig.fetch(&pinned.job_id, 1, &box_a()).await.unwrap();
    assert_eq!(reply.secrets.len(), 0);
    assert_eq!(reply.scripts.len(), 1);
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT name, fingerprint FROM environment_use WHERE job_id = $1")
            .bind(&pinned.job_id)
            .fetch_all(&rig.pool)
            .await
            .unwrap();
    assert_eq!(rows, [(String::new(), String::new())]);
}

#[sqlx::test]
async fn a_failed_audit_insert_returns_no_body_and_no_rows(pool: PgPool) {
    let mut rig = rig(pool).await;
    let alice = rig.alice;
    let env = environment(
        &rig.pool,
        alice,
        "prod",
        vec![hidden("ALPHA"), hidden("BETA")],
        &[],
    )
    .await;
    let job = rig.running(alice, "pinned", Some(env)).await;
    sqlx::raw_sql(
        "CREATE FUNCTION fail_second() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN IF NEW.name = 'BETA' THEN RAISE EXCEPTION 'injected'; END IF; RETURN NEW; END; $$; \
         CREATE TRIGGER fail_second BEFORE INSERT ON environment_use \
         FOR EACH ROW EXECUTE FUNCTION fail_second();",
    )
    .execute(&rig.pool)
    .await
    .unwrap();
    let status = rig.fetch(&job.job_id, 1, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::Internal);
    assert_eq!(status.message(), ERR_ENV_INTERNAL);
    assert!(!format!("{status:?}").contains(MARK));
    assert_eq!(rig.uses().await, 0, "the first row survived the failure");
}

#[sqlx::test]
async fn a_revoke_between_submit_and_lease_is_denied_with_no_use_row(pool: PgPool) {
    let mut rig = rig(pool).await;
    let alice = rig.alice;
    let env = environment(
        &rig.pool,
        alice,
        "scripted",
        vec![hidden("TOKEN"), script("setup")],
        &[],
    )
    .await;
    let granted = rig.running(alice, "granted", Some(env)).await;
    rig.fetch(&granted.job_id, 1, &box_a()).await.unwrap();
    assert_eq!(rig.uses().await, 1, "positive control");
    sqlx::query("DELETE FROM user_capabilities WHERE user_id = $1")
        .bind(alice)
        .execute(&rig.pool)
        .await
        .unwrap();
    let late = rig.running(alice, "late", Some(env)).await;
    let status = rig.fetch(&late.job_id, 1, &box_a()).await.unwrap_err();
    assert_eq!(status.code(), Code::PermissionDenied);
    assert_eq!(status.message(), ERR_ENV_RELEASE_DENIED);
    assert_eq!(rig.uses().await, 1);
}

async fn lock_waiters(pool: &PgPool, table: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
         AND pid <> pg_backend_pid() AND query LIKE '%' || $1 || '%'",
    )
    .bind(table)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn wait_for_lock(pool: &PgPool, table: &str) {
    for _ in 0..100 {
        if lock_waiters(pool, table).await > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the release never waited on {table}");
}

async fn barrier(pool: PgPool, holder_sql: &'static str, table: &str, scripted: bool) {
    let mut rig = rig(pool).await;
    let alice = rig.alice;
    let entries = if scripted {
        vec![hidden("TOKEN"), script("setup")]
    } else {
        vec![hidden("TOKEN")]
    };
    let env = environment(&rig.pool, alice, "held", entries, &[]).await;
    let job = rig.running(alice, "held-job", Some(env)).await;
    let release = store(&rig.pool);
    let mut holder = rig.pool.begin().await.unwrap();
    sqlx::query(holder_sql)
        .bind(alice)
        .bind(&job.job_id)
        .execute(&mut *holder)
        .await
        .unwrap();
    let pending = tokio::spawn({
        let job_id = job.job_id.clone();
        async move { release.release_for_job(&job_id, 1, &box_a()).await }
    });
    wait_for_lock(&rig.pool, table).await;
    assert!(!pending.is_finished(), "the release did not wait");
    holder.commit().await.unwrap();
    let outcome = pending.await.unwrap();
    assert!(outcome.is_err(), "the release used a stale read");
    assert_eq!(rig.uses().await, 0);
}

#[sqlx::test]
async fn the_scripts_check_holds_for_share_and_reads_after_the_lock(pool: PgPool) {
    barrier(
        pool,
        "DELETE FROM user_capabilities WHERE user_id = $1 AND $2::text IS NOT NULL",
        "user_capabilities",
        true,
    )
    .await;
}

#[sqlx::test]
async fn the_lease_check_holds_for_share_and_reads_after_the_lock(pool: PgPool) {
    barrier(
        pool,
        "UPDATE jobs SET state = 'CANCELLED' WHERE job_id = $2 AND $1::bigint IS NOT NULL",
        "jobs",
        false,
    )
    .await;
}

#[sqlx::test]
async fn the_reply_cap_allows_the_exact_size_and_refuses_one_byte_over(pool: PgPool) {
    let mut open = rig(pool.clone()).await;
    let alice = open.alice;
    let env = environment(
        &open.pool,
        alice,
        "sized",
        vec![hidden("ALPHA"), script("setup")],
        &["api.example.com"],
    )
    .await;
    let job = open.running(alice, "sized-job", Some(env)).await;
    let size = open
        .fetch(&job.job_id, 1, &box_a())
        .await
        .unwrap()
        .encoded_len();
    let rows = open.uses().await;
    let service = EnvironmentService::new(store(&pool).with_reply_cap(size));
    let ok = service.job_environment(&job.job_id, 1, &box_a()).await;
    assert_eq!(ok.unwrap().encoded_len(), size);
    assert_eq!(open.uses().await, rows + 1);
    let service = EnvironmentService::new(store(&pool).with_reply_cap(size - 1));
    let status = service
        .job_environment(&job.job_id, 1, &box_a())
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::ResourceExhausted);
    assert_eq!(status.message(), ERR_ENV_LIMIT);
    assert_eq!(open.uses().await, rows + 1, "the refused call left a row");
}

#[sqlx::test]
async fn only_the_box_token_reaches_the_release(pool: PgPool) {
    let mut rig = rig(pool).await;
    let alice = rig.alice;
    let env = environment(&rig.pool, alice, "prod", vec![hidden("TOKEN")], &[]).await;
    let job = rig.running(alice, "pinned", Some(env)).await;
    rig.fetch(&job.job_id, 1, &box_a()).await.unwrap();
    let made = rig.users.create_api_token(alice, "t").await.unwrap();
    let user_token = String::from_utf8(made.token.expose().to_vec()).unwrap();
    for token in [CLIENT.to_owned(), user_token] {
        let mut client = FleetWorkerClient::new(rig.channel.clone());
        let mut request = Request::new(GetJobEnvironmentRequest {
            job_id: job.job_id.clone(),
            attempt: 1,
            r#box: box_a(),
        });
        request.metadata_mut().insert(
            "authorization",
            MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
        );
        let status = client.get_job_environment(request).await.unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied);
        assert!(!status.message().contains(MARK));
    }
    let mut client = FleetWorkerClient::new(rig.channel.clone());
    let status = client
        .get_job_environment(GetJobEnvironmentRequest {
            job_id: job.job_id.clone(),
            attempt: 1,
            r#box: box_a(),
        })
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);
    assert_eq!(rig.uses().await, 1);
}

#[derive(Clone, Default)]
struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn logs() -> &'static LogBuffer {
    static BUFFER: std::sync::OnceLock<LogBuffer> = std::sync::OnceLock::new();
    static INIT: std::sync::Once = std::sync::Once::new();
    let buffer = BUFFER.get_or_init(LogBuffer::default);
    INIT.call_once(|| {
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(buffer.clone())
                .with_max_level(tracing::Level::TRACE)
                .with_ansi(false)
                .without_time()
                .finish(),
        )
        .unwrap();
    });
    buffer
}

#[sqlx::test]
async fn no_log_status_or_debug_output_carries_a_released_value(pool: PgPool) {
    let buffer = logs();
    let mut rig = rig(pool).await;
    let alice = rig.alice;
    let env = environment(&rig.pool, alice, "prod", vec![hidden("TOKEN")], &[]).await;
    let job = rig.running(alice, "pinned", Some(env)).await;
    let ok = rig.fetch(&job.job_id, 1, &box_a()).await.unwrap();
    assert!(ok.secrets[0].value.contains(MARK), "positive control");
    sqlx::raw_sql(
        "CREATE FUNCTION fail_all() RETURNS trigger LANGUAGE plpgsql AS $$ \
         BEGIN RAISE EXCEPTION 'injected'; END; $$; \
         CREATE TRIGGER fail_all BEFORE INSERT ON environment_use \
         FOR EACH ROW EXECUTE FUNCTION fail_all();",
    )
    .execute(&rig.pool)
    .await
    .unwrap();
    let failed = rig.fetch(&job.job_id, 1, &box_a()).await.unwrap_err();
    let denied = rig.fetch("no-such-job", 1, &box_a()).await.unwrap_err();
    let shown = format!("{ok:?} {ok:#?} {failed:?} {denied:?} {:?}", rig.core);
    assert!(!shown.replace("<redacted>", "").contains(MARK), "{shown}");
    let captured = String::from_utf8_lossy(&buffer.0.lock().unwrap()).into_owned();
    assert!(
        captured.contains("environment store call failed"),
        "{captured}"
    );
    assert!(!captured.contains(MARK), "the value reached the logs");
}
