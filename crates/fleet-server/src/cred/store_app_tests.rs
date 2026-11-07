//! Release of a `github_app` credential: the forge partition, the mint outside the transaction
//! and the use rows after a successful mint. The tests run the production capability gate and an
//! [`AppClient`] aimed at a loopback fake. They need a Postgres superuser URL in `DATABASE_URL`.

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fleet_core::credential::{BotIdentity, CredentialKind, CredentialShape, Secret};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::app_jwt::AppKey;
use super::app_mint::{AppClient, Limits};
use super::app_policy::AppPolicy;
use super::capability::Capabilities;
use super::seal::FileSealer;
use super::store::{AppLane, CredentialStore, DENIED_DEDUPE_SECS, StoreError};
use crate::store::Store;

const PAT: &str = "github_pat_11ABCDEFG0abcdefghijklmnop";
const ANT: &str = "sk-ant-api03-abcdefghijklmnopqrstuv";
const TOKEN: &str = "ghs_testtoken0123456789";
const CAP: &str = "forge:github_app";
const INSTALLATION: u64 = 4242;
const BOT_NAME: &str = "fleet-bot[bot]";
const BOT_EMAIL: &str = "12345+fleet-bot[bot]@users.noreply.github.com";
const STATIC: CredentialShape = CredentialShape::StaticSecret;
const JOB: &str = "01JJOBAPP00000000000000000";

static FILES: AtomicUsize = AtomicUsize::new(0);

fn rfc3339(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap();
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn good_body() -> String {
    format!(
        r#"{{"token":"{TOKEN}","expires_at":"{}","permissions":{{"contents":"write","pull_requests":"write","checks":"read","statuses":"read","metadata":"read"}},"repositories":[{{"id":1,"name":"widget","full_name":"o/widget"}}]}}"#,
        rfc3339(now() + 3600)
    )
}

fn http(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

struct Fake {
    addr: std::net::SocketAddr,
    seen: Arc<Mutex<Vec<String>>>,
    hook_ok: Arc<Mutex<Vec<bool>>>,
    held: Arc<Mutex<Vec<sqlx::pool::PoolConnection<sqlx::Postgres>>>>,
    app: Arc<Mutex<(&'static str, String)>>,
    inst: Arc<Mutex<(&'static str, String)>>,
}

fn installation_json(id: u64, app_id: u64, login: &str, suspended: &str) -> String {
    format!(
        r#"{{"id":{id},"app_id":{app_id},"account":{{"login":"{login}"}},"suspended_at":{suspended}}}"#
    )
}

fn policy(installations: &str, repos: &str) -> AppPolicy {
    AppPolicy::parse("o", Some(installations), Some(repos)).unwrap()
}

fn open_policy() -> AppPolicy {
    policy("4242", "o/*")
}

impl Fake {
    fn first_mint(&self) -> String {
        self.requests()
            .into_iter()
            .find(|r| r.starts_with("POST "))
            .unwrap()
    }

    fn lookups(&self) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.starts_with("GET /app/installations/"))
            .count()
    }

    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
    }

    fn revokes(&self) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.starts_with("DELETE "))
            .count()
    }

    fn mints(&self) -> usize {
        self.requests()
            .iter()
            .filter(|r| r.starts_with("POST "))
            .count()
    }
}

async fn read_request(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await.unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&buf).into_owned();
        if let Some((head, body)) = text.split_once("\r\n\r\n") {
            let want = head
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            if body.len() >= want {
                break;
            }
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

async fn fake(mint_status: &'static str, hook: Option<(PgPool, &'static str)>) -> Fake {
    fake_with(mint_status, "204 No Content", hook, None).await
}

async fn fake_with(
    mint_status: &'static str,
    revoke_status: &'static str,
    hook: Option<(PgPool, &'static str)>,
    hold_job_lock: Option<PgPool>,
) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let hook_ok = Arc::new(Mutex::new(Vec::new()));
    let held = Arc::new(Mutex::new(Vec::new()));
    let app = Arc::new(Mutex::new(("200 OK", r#"{"id":12345}"#.to_owned())));
    let inst = Arc::new(Mutex::new((
        "200 OK",
        installation_json(INSTALLATION, 12345, "o", "null"),
    )));
    let revokes = Arc::new(AtomicUsize::new(0));
    let (seen_task, hook_task, held_task) =
        (Arc::clone(&seen), Arc::clone(&hook_ok), Arc::clone(&held));
    let (app_task, revokes_task) = (Arc::clone(&app), Arc::clone(&revokes));
    let inst_task = Arc::clone(&inst);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (app, revokes) = (Arc::clone(&app_task), Arc::clone(&revokes_task));
            let inst = Arc::clone(&inst_task);
            let (seen, ok_log, hook, parked, gate) = (
                Arc::clone(&seen_task),
                Arc::clone(&hook_task),
                hook.clone(),
                Arc::clone(&held_task),
                hold_job_lock.clone(),
            );
            tokio::spawn(async move {
                let request = read_request(&mut stream).await;
                let is_mint = request.starts_with("POST ");
                let is_app = request.starts_with("GET /app ");
                let is_inst = request.starts_with("GET /app/installations/");
                seen.lock().unwrap().push(request);
                let reply = if is_inst {
                    let (status, body) = inst.lock().unwrap().clone();
                    http(status, &body)
                } else if is_app {
                    let (status, body) = app.lock().unwrap().clone();
                    http(status, &body)
                } else if is_mint {
                    if let Some((pool, sql)) = hook {
                        let mut conn = pool.acquire().await.unwrap();
                        sqlx::query("SET lock_timeout = '500ms'")
                            .execute(&mut *conn)
                            .await
                            .unwrap();
                        let done = sqlx::query(sql).execute(&mut *conn).await.is_ok();
                        ok_log.lock().unwrap().push(done);
                    }
                    if let Some(pool) = gate {
                        let mut conn = pool.acquire().await.unwrap();
                        sqlx::query("BEGIN").execute(&mut *conn).await.unwrap();
                        sqlx::query("SELECT 1 FROM jobs FOR UPDATE")
                            .execute(&mut *conn)
                            .await
                            .unwrap();
                        parked.lock().unwrap().push(conn);
                    }
                    if mint_status.starts_with("201") {
                        http(mint_status, &good_body())
                    } else {
                        http(mint_status, "")
                    }
                } else if revoke_status == "HANG_FIRST" {
                    if revokes.fetch_add(1, Ordering::SeqCst) == 0 {
                        tokio::time::sleep(Duration::from_secs(3600)).await;
                    }
                    http("500 Internal Server Error", "")
                } else {
                    http(revoke_status, "")
                };
                let _ = stream.write_all(reply.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    Fake {
        addr,
        seen,
        hook_ok,
        held,
        app,
        inst,
    }
}

fn app_key() -> AppKey {
    let pem = openssl::rsa::Rsa::generate(2048)
        .unwrap()
        .private_key_to_pem()
        .unwrap();
    let path = std::env::temp_dir().join(format!(
        "fleet-app-lane-{}-{}.pem",
        std::process::id(),
        FILES.fetch_add(1, Ordering::Relaxed)
    ));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&pem).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let key = AppKey::load(&path);
    std::fs::remove_file(&path).unwrap();
    key.unwrap()
}

struct World {
    pool: PgPool,
    caps: Capabilities,
    creds: CredentialStore,
    alice: i64,
    admin: i64,
}

async fn user(pool: &PgPool, name: &str, admin: bool) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username, is_admin) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(admin)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn world(pool: PgPool, lane: Option<AppClient>) -> World {
    world_with(pool, lane, open_policy()).await
}

async fn world_with(pool: PgPool, lane: Option<AppClient>, policy: AppPolicy) -> World {
    world_limited(pool, lane, policy, None).await
}

async fn world_limited(
    pool: PgPool,
    lane: Option<AppClient>,
    policy: AppPolicy,
    limit: Option<usize>,
) -> World {
    Store::new(pool.clone()).migrate().await.unwrap();
    let path = std::env::temp_dir().join(format!(
        "fleet-app-lane-{}-{}.keys",
        std::process::id(),
        FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let sealer = Arc::new(sealer.unwrap());
    let mut creds = match limit {
        Some(limit) => CredentialStore::with_limit(pool.clone(), sealer, limit),
        None => CredentialStore::new(pool.clone(), sealer),
    };
    if let Some(client) = lane {
        let bot = BotIdentity::new(BOT_NAME, BOT_EMAIL).unwrap();
        creds = creds.with_github_app(AppLane::new(
            app_key(),
            "12345".to_owned(),
            client,
            bot,
            policy.clone(),
        ));
    }
    World {
        caps: Capabilities::new(pool.clone()),
        alice: user(&pool, "alice", false).await,
        admin: user(&pool, "root", true).await,
        creds,
        pool,
    }
}

impl World {
    async fn put(&self, kind: CredentialKind, value: &str) {
        self.creds
            .put(
                self.alice,
                kind,
                STATIC,
                Secret::new(value.into()),
                None,
                None,
            )
            .await
            .unwrap();
    }

    async fn seed(&self, with_cap: bool) {
        self.caps.grant(self.admin, self.alice, CAP).await.unwrap();
        self.put(CredentialKind::GithubApp, &INSTALLATION.to_string())
            .await;
        self.put(CredentialKind::GithubPat, PAT).await;
        self.put(CredentialKind::AnthropicApiKey, ANT).await;
        if !with_cap {
            self.caps.revoke(self.admin, self.alice, CAP).await.unwrap();
        }
        sqlx::query(
            "INSERT INTO jobs (job_id, idempotency_key, prompt, repo, base_ref, branch, open_pr, state, attempt, box, \
             lease_expires_at, user_id, agent) \
             VALUES ($1, 'k', 'p', 'o/widget', 'main', 'b', false, 'RUNNING', 1, 'alpha', now() + interval '1 hour', $2, 'claude')",
        )
        .bind(JOB)
        .bind(self.alice)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn uses(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM credential_use")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn client(fake: &Fake) -> AppClient {
    AppClient::plain(fake.addr, Limits::default())
}

#[sqlx::test]
async fn the_app_wins_over_the_pat_and_the_reply_carries_the_token(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let released = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    let mut kinds: Vec<_> = released.iter().map(|c| c.kind.wire_name()).collect();
    kinds.sort_unstable();
    assert_eq!(kinds, ["anthropic_api_key", "github_app"]);
    let app = released
        .iter()
        .find(|c| c.kind == CredentialKind::GithubApp)
        .unwrap();
    assert_eq!(app.value.expose(), TOKEN.as_bytes());
    assert_eq!(fake.mints(), 1);
    let request = &fake.first_mint();
    assert!(
        request.starts_with("POST /app/installations/4242/access_tokens "),
        "{request}"
    );
    assert!(
        request.contains(r#""repositories":["widget"]"#),
        "{request}"
    );
    assert_eq!(w.uses().await, 2);
    let bearer = request
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .starts_with("authorization:")
                .then(|| l.to_owned())
        })
        .unwrap();
    let payload = bearer.rsplit('.').nth(1).unwrap();
    let mut padded = payload.replace('-', "+").replace('_', "/");
    while !padded.len().is_multiple_of(4) {
        padded.push('=');
    }
    let claims = String::from_utf8(openssl::base64::decode_block(&padded).unwrap()).unwrap();
    assert!(claims.ends_with(r#""iss":"12345"}"#), "{claims}");
    let used: Vec<String> = sqlx::query_scalar(
        "SELECT c.kind FROM credential_use u JOIN credentials c ON c.id = u.credential_id ORDER BY 1",
    )
    .fetch_all(&w.pool)
    .await
    .unwrap();
    assert_eq!(used, ["anthropic_api_key", "github_app"]);
}

#[sqlx::test]
async fn without_the_capability_the_job_fails_with_the_fixed_error_and_never_uses_the_pat(
    pool: PgPool,
) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(false).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::CapabilityDenied), "{err:?}");
    assert_eq!(
        err.to_string(),
        "credential kind needs a capability the user lacks"
    );
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_failed_mint_is_one_fixed_error_and_writes_no_use_row(pool: PgPool) {
    let fake = fake("500 Internal Server Error", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintFailed), "{err:?}");
    assert_eq!(err.to_string(), fleet_proto::PRECONDITION_APP_MINT);
    assert_eq!(fake.mints(), 1);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_server_without_the_lane_fails_closed_and_never_uses_the_pat(pool: PgPool) {
    let w = world(pool, None).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintFailed), "{err:?}");
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_wrong_lease_makes_zero_mint_calls(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    for (attempt, boxed) in [(1, "beta"), (2, "alpha"), (9, "zeta")] {
        let err = w
            .creds
            .release_for_job(JOB, attempt, boxed)
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::LeaseDenied), "{err:?}");
    }
    let err = w
        .creds
        .release_for_job("01JNOSUCHJOB0000000000000", 1, "alpha")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::LeaseDenied), "{err:?}");
    sqlx::query("UPDATE jobs SET lease_expires_at = now() - interval '1 minute'")
        .execute(&w.pool)
        .await
        .unwrap();
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::LeaseDenied), "{err:?}");
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn the_mint_runs_after_the_transaction_commits(pool: PgPool) {
    let probe = fake(
        "201 Created",
        Some((pool.clone(), "UPDATE jobs SET prompt = prompt")),
    )
    .await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    assert_eq!(*probe.hook_ok.lock().unwrap(), [true]);
}

#[sqlx::test]
async fn a_lease_lost_during_the_mint_revokes_the_token_and_writes_no_use_row(pool: PgPool) {
    let probe = fake(
        "201 Created",
        Some((
            pool.clone(),
            "UPDATE jobs SET lease_expires_at = now() - interval '1 minute'",
        )),
    )
    .await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::LeaseDenied), "{err:?}");
    assert_eq!(w.uses().await, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = probe.requests();
    assert!(
        seen.iter()
            .any(|r| r.starts_with("DELETE /installation/token ")),
        "{seen:?}"
    );
}

#[sqlx::test]
async fn a_capability_revoked_during_the_mint_revokes_the_token_and_writes_no_use_row(
    pool: PgPool,
) {
    let probe = fake(
        "201 Created",
        Some((
            pool.clone(),
            "DELETE FROM user_capabilities WHERE capability = 'forge:github_app'",
        )),
    )
    .await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::CapabilityDenied), "{err:?}");
    assert_eq!(w.uses().await, 0);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        probe
            .requests()
            .iter()
            .any(|r| r.starts_with("DELETE /installation/token "))
    );
}

#[sqlx::test]
async fn an_expired_app_credential_fails_expired_without_a_mint_or_the_pat(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query(
        "UPDATE credentials SET expires_at = now() - interval '1 day' WHERE kind = 'github_app'",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::Expired), "{err:?}");
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 0);
}

#[test]
fn the_repository_name_is_the_last_path_segment_without_git() {
    use super::store::repo_name;
    assert_eq!(repo_name("o/widget"), "widget");
    assert_eq!(repo_name("https://example.com/org/repo.git"), "repo");
    assert_eq!(repo_name("o/widget/"), "widget");
    assert_eq!(repo_name("widget"), "widget");
}

#[sqlx::test]
async fn a_user_without_the_app_credential_still_gets_the_pat(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query("DELETE FROM credentials WHERE kind = 'github_app'")
        .execute(&w.pool)
        .await
        .unwrap();
    let released = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    assert!(released.iter().any(|c| c.kind == CredentialKind::GithubPat));
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 2);
}

#[sqlx::test]
async fn the_service_maps_a_failed_mint_to_the_fixed_precondition(pool: PgPool) {
    let fake = fake("500 Internal Server Error", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let status = service.job_credentials(JOB, 1, "alpha").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_APP_MINT);
}

#[sqlx::test]
async fn the_service_sends_the_token_under_the_installation_token_kind(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let reply = service.job_credentials(JOB, 1, "alpha").await.unwrap();
    let mut kinds: Vec<_> = reply.credentials.iter().map(|c| c.kind.as_str()).collect();
    kinds.sort_unstable();
    assert_eq!(kinds, ["anthropic_api_key", "github_installation_token"]);
    let token = reply
        .credentials
        .iter()
        .find(|c| c.kind == fleet_proto::GITHUB_INSTALLATION_TOKEN_KIND)
        .unwrap();
    assert_eq!(token.value, TOKEN);
    let want_ms = (now() + 3600) * 1000;
    let got_ms = token.expires_at_ms.unwrap();
    assert!(got_ms.abs_diff(want_ms) < 60_000, "{got_ms} {want_ms}");
    let identity = token.git_identity.as_ref().unwrap();
    assert_eq!(identity.name, BOT_NAME);
    assert_eq!(identity.email, BOT_EMAIL);
    let agent = reply
        .credentials
        .iter()
        .find(|c| c.kind == "anthropic_api_key")
        .unwrap();
    assert_eq!(agent.expires_at_ms, None);
    assert_eq!(agent.git_identity, None);
}

#[sqlx::test]
async fn a_pat_release_carries_no_expiry_and_no_identity(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query("DELETE FROM credentials WHERE kind = 'github_app'")
        .execute(&w.pool)
        .await
        .unwrap();
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let reply = service.job_credentials(JOB, 1, "alpha").await.unwrap();
    assert_eq!(reply.credentials.len(), 2);
    for credential in &reply.credentials {
        assert_eq!(credential.expires_at_ms, None, "{}", credential.kind);
        assert_eq!(credential.git_identity, None, "{}", credential.kind);
    }
}

#[sqlx::test]
async fn a_user_holding_github_app_without_the_capability_fails_the_job_and_never_gets_the_pat(
    pool: PgPool,
) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(false).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let status = service.job_credentials(JOB, 1, "alpha").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        status.message(),
        super::capability::ERR_CAPABILITY_NOT_GRANTED
    );
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 0);
    let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM credentials ORDER BY 1")
        .fetch_all(&w.pool)
        .await
        .unwrap();
    assert!(kinds.iter().any(|k| k == "github_pat"));
    assert!(kinds.iter().any(|k| k == "github_app"));
}

async fn app_id(w: &World) -> u64 {
    let id: i64 = sqlx::query_scalar("SELECT id FROM credentials WHERE kind = 'github_app'")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    u64::try_from(id).unwrap()
}

#[sqlx::test]
async fn verify_mints_once_revokes_and_the_reply_holds_no_token(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::VerifyCredentialRequest {
        id: app_id(&w).await,
    };
    let reply = service.verify(w.alice, &request).await.unwrap();
    assert!(reply.valid);
    assert_eq!(reply.login, None);
    assert_eq!(reply.expires_at_ms, None);
    assert!(!format!("{reply:?}").contains(TOKEN));
    assert_eq!(fake.mints(), 1);
    let request = &fake.first_mint();
    assert!(
        request.contains(r#""repositories":["widget"]"#),
        "{request}"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while !fake
        .requests()
        .iter()
        .any(|r| r.starts_with("DELETE /installation/token "))
    {
        assert!(
            tokio::time::Instant::now() < deadline,
            "no revoke within 5 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn verify_reports_invalid_when_the_mint_fails_and_holds_no_token(pool: PgPool) {
    let fake = fake("500 Internal Server Error", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::VerifyCredentialRequest {
        id: app_id(&w).await,
    };
    let reply = service.verify(w.alice, &request).await.unwrap();
    assert!(!reply.valid);
    assert_eq!(fake.mints(), 1);
}

#[sqlx::test]
async fn verify_without_the_capability_mints_nothing(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(false).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::VerifyCredentialRequest {
        id: app_id(&w).await,
    };
    let status = service.verify(w.alice, &request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(
        status.message(),
        super::capability::ERR_CAPABILITY_NOT_GRANTED
    );
    assert_eq!(fake.mints(), 0);
}

#[sqlx::test]
async fn verify_without_a_job_repository_fails_the_precondition_and_mints_nothing(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query("DELETE FROM jobs")
        .execute(&w.pool)
        .await
        .unwrap();
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::VerifyCredentialRequest {
        id: app_id(&w).await,
    };
    let status = service.verify(w.alice, &request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_NO_VERIFY_REPO);
    assert_eq!(fake.mints(), 0);
}

#[sqlx::test]
async fn verify_scopes_the_mint_to_the_most_recent_job_repository(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query(
        "INSERT INTO jobs (job_id, idempotency_key, prompt, repo, base_ref, branch, open_pr, state, user_id, agent, created_at) \
         VALUES ('01JJOBAPP00000000000000001', 'k2', 'p', 'o/gadget', 'main', 'b', false, 'QUEUED', $1, 'claude', now() + interval '1 hour')",
    )
    .bind(w.alice)
    .execute(&w.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO jobs (job_id, idempotency_key, prompt, repo, base_ref, branch, open_pr, state, user_id, agent, created_at) \
         VALUES ('01JJOBAPP00000000000000002', 'k3', 'p', 'o/foreign', 'main', 'b', false, 'QUEUED', $1, 'claude', now() + interval '2 hours')",
    )
    .bind(w.admin)
    .execute(&w.pool)
    .await
    .unwrap();
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::VerifyCredentialRequest {
        id: app_id(&w).await,
    };
    service.verify(w.alice, &request).await.unwrap();
    let mint = &fake.first_mint();
    assert!(mint.contains(r#""repositories":["gadget"]"#), "{mint}");
}

#[sqlx::test]
async fn verify_for_another_user_is_not_found_and_mints_nothing(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::VerifyCredentialRequest {
        id: app_id(&w).await,
    };
    let status = service.verify(w.admin, &request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
    assert_eq!(fake.mints(), 0);
}

struct NoGithub;

#[tonic::async_trait]
impl super::github::GithubApi for NoGithub {
    async fn user(
        &self,
        _token: &Secret,
    ) -> Result<super::github::GithubUser, super::github::GithubError> {
        Err(super::github::GithubError::Unavailable)
    }
}

const SECOND_JOB: &str = "01JJOBAPP00000000000000001";

type Row = (String, Option<String>);

impl World {
    fn capped(mut self, cap: u32) -> Self {
        self.creds = self.creds.with_mint_cap(cap);
        self
    }

    async fn rows(&self) -> Vec<Row> {
        sqlx::query_as("SELECT outcome, reason FROM github_app_mint ORDER BY id")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn outcomes(&self) -> Vec<String> {
        self.rows().await.into_iter().map(|(o, _)| o).collect()
    }

    async fn second_job(&self) {
        sqlx::query(
            "INSERT INTO jobs (job_id, idempotency_key, prompt, repo, base_ref, branch, open_pr, state, attempt, box, \
             lease_expires_at, user_id, agent) \
             VALUES ($1, 'k2', 'p', 'o/widget', 'main', 'b2', false, 'RUNNING', 1, 'alpha', now() + interval '1 hour', $2, 'claude')",
        )
        .bind(SECOND_JOB)
        .bind(self.alice)
        .execute(&self.pool)
        .await
        .unwrap();
    }
}

async fn eventually<F, Fut>(what: &str, mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if probe().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[sqlx::test]
async fn a_mint_writes_an_attempt_row_then_a_minted_row_with_the_expiry(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    assert_eq!(w.outcomes().await, ["attempt", "minted"]);
    let json: Vec<String> = sqlx::query_scalar(
        "SELECT (to_jsonb(t) - 'id' - 'mint_id' - 'attempt_id' - 'at' - 'expires_at' - 'credential_id')::text \
         FROM github_app_mint t ORDER BY id",
    )
    .fetch_all(&w.pool)
    .await
    .unwrap();
    let want = |outcome: &str| {
        serde_json::json!({
            "job_id": JOB,
            "repo": "o/widget",
            "installation_id": "4242",
            "requested_permissions": "contents:write,pull_requests:write,checks:read,statuses:read",
            "outcome": outcome,
            "reason": null,
            "scope": "job",
        })
    };
    let got: Vec<serde_json::Value> = json
        .iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    assert_eq!(got, [want("attempt"), want("minted")]);
    let linked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM github_app_mint m JOIN github_app_mint a ON a.attempt_id = m.attempt_id \
         AND a.outcome = 'attempt' AND a.mint_id = a.attempt_id \
         WHERE m.outcome = 'minted' AND m.mint_id <> m.attempt_id",
    )
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(linked, 1);
    let credential: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM github_app_mint m JOIN credentials c ON c.id = m.credential_id \
         WHERE c.kind = 'github_app'",
    )
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(credential, 2);
    let expiry_ok: Vec<(String, Option<bool>)> = sqlx::query_as(
        "SELECT outcome, expires_at BETWEEN now() + interval '55 minutes' AND now() + interval '65 minutes' \
         FROM github_app_mint ORDER BY id",
    )
    .fetch_all(&w.pool)
    .await
    .unwrap();
    assert_eq!(
        expiry_ok,
        [
            ("attempt".to_owned(), None),
            ("minted".to_owned(), Some(true))
        ]
    );
}

#[sqlx::test]
async fn each_refresh_is_its_own_audited_mint_and_use(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    for _ in 0..3 {
        w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    }
    assert_eq!(fake.mints(), 3);
    assert_eq!(w.uses().await, 6);
    assert_eq!(
        w.outcomes().await,
        [
            "attempt", "minted", "attempt", "minted", "attempt", "minted"
        ]
    );
    let distinct: i64 =
        sqlx::query_scalar("SELECT count(DISTINCT attempt_id) FROM github_app_mint")
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert_eq!(distinct, 3);
}

#[sqlx::test]
async fn the_cap_allows_cap_mints_and_refuses_the_next_with_a_denied_row(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(3);
    w.seed(true).await;
    for n in 1..=3 {
        w.creds
            .release_for_job(JOB, 1, "alpha")
            .await
            .unwrap_or_else(|e| panic!("mint {n}: {e:?}"));
    }
    assert_eq!(fake.mints(), 3);
    assert_eq!(w.uses().await, 6);
    for _ in 0..2 {
        let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
        assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
        assert_eq!(err.to_string(), fleet_proto::PRECONDITION_APP_MINT_CAP);
        assert_ne!(
            err.to_string(),
            fleet_proto::PRECONDITION_APP_MINT.to_owned()
        );
    }
    assert_eq!(fake.mints(), 3);
    assert_eq!(w.uses().await, 6);
    let rows = w.rows().await;
    assert_eq!(rows.len(), 7);
    assert_eq!(
        rows[6..],
        [("denied".to_owned(), Some("job mint cap".to_owned()))]
    );
    let attempts = rows.iter().filter(|(o, _)| o == "attempt").count();
    assert_eq!(attempts, 3);
}

#[sqlx::test]
async fn the_cap_of_one_refuses_the_second_release_and_the_cap_of_two_the_third(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    let w = w.capped(2);
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), 2);
}

#[sqlx::test]
async fn a_cap_of_zero_never_mints(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(0);
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn the_cap_is_per_job(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    w.second_job().await;
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    w.creds
        .release_for_job(SECOND_JOB, 1, "alpha")
        .await
        .unwrap();
    let err = w
        .creds
        .release_for_job(SECOND_JOB, 1, "alpha")
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), 2);
}

#[sqlx::test]
async fn failed_mints_spend_the_cap(pool: PgPool) {
    let fake = fake("500 Internal Server Error", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(2);
    w.seed(true).await;
    for _ in 0..2 {
        let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
        assert!(matches!(err, StoreError::MintFailed), "{err:?}");
    }
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), 2);
    assert_eq!(
        w.rows().await,
        [
            ("attempt".to_owned(), None),
            ("failed".to_owned(), Some("mint failed".to_owned())),
            ("attempt".to_owned(), None),
            ("failed".to_owned(), Some("mint failed".to_owned())),
            ("denied".to_owned(), Some("job mint cap".to_owned())),
        ]
    );
}

#[sqlx::test]
async fn concurrent_releases_cannot_both_slip_under_the_cap(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    let (a, b, c, d) = tokio::join!(
        w.creds.release_for_job(JOB, 1, "alpha"),
        w.creds.release_for_job(JOB, 1, "alpha"),
        w.creds.release_for_job(JOB, 1, "alpha"),
        w.creds.release_for_job(JOB, 1, "alpha"),
    );
    let results = <[_; 4]>::from((a, b, c, d));
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::MintCapReached)))
            .count(),
        3
    );
    assert_eq!(fake.mints(), 1);
    let attempts = w
        .outcomes()
        .await
        .iter()
        .filter(|o| *o == "attempt")
        .count();
    assert_eq!(attempts, 1);
}

#[sqlx::test]
async fn the_service_maps_the_cap_to_its_own_fixed_precondition(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    service.job_credentials(JOB, 1, "alpha").await.unwrap();
    let status = service.job_credentials(JOB, 1, "alpha").await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_APP_MINT_CAP);
}

#[sqlx::test]
async fn a_wrong_lease_and_a_pat_release_write_no_mint_rows(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let _ = w.creds.release_for_job(JOB, 1, "beta").await.unwrap_err();
    assert_eq!(w.rows().await, []);
    sqlx::query("DELETE FROM credentials WHERE kind = 'github_app'")
        .execute(&w.pool)
        .await
        .unwrap();
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    assert_eq!(w.rows().await, []);
}

#[sqlx::test]
async fn a_lease_lost_during_the_mint_audits_denied_then_revoked(pool: PgPool) {
    let probe = fake(
        "201 Created",
        Some((
            pool.clone(),
            "UPDATE jobs SET lease_expires_at = now() - interval '1 minute'",
        )),
    )
    .await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::LeaseDenied), "{err:?}");
    assert_eq!(
        w.rows().await,
        [
            ("attempt".to_owned(), None),
            (
                "denied".to_owned(),
                Some("lease lost after mint".to_owned())
            ),
            ("revoked".to_owned(), None),
        ]
    );
    assert_eq!(probe.revokes(), 1);
}

#[sqlx::test]
async fn a_capability_revoked_during_the_mint_audits_denied_then_revoked(pool: PgPool) {
    let probe = fake(
        "201 Created",
        Some((
            pool.clone(),
            "DELETE FROM user_capabilities WHERE capability = 'forge:github_app'",
        )),
    )
    .await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::CapabilityDenied), "{err:?}");
    assert_eq!(
        w.rows().await,
        [
            ("attempt".to_owned(), None),
            (
                "denied".to_owned(),
                Some("capability gone after mint".to_owned())
            ),
            ("revoked".to_owned(), None),
        ]
    );
}

#[sqlx::test]
async fn a_revoke_the_provider_refuses_is_audited_as_revoke_failed(pool: PgPool) {
    let probe = fake_with(
        "201 Created",
        "500 Internal Server Error",
        Some((
            pool.clone(),
            "UPDATE jobs SET lease_expires_at = now() - interval '1 minute'",
        )),
        None,
    )
    .await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::LeaseDenied), "{err:?}");
    let rows = w.rows().await;
    assert_eq!(
        rows[2],
        (
            "revoke_failed".to_owned(),
            Some("revoke refused".to_owned())
        )
    );
    assert_eq!(rows.len(), 3);
}

#[sqlx::test]
async fn a_release_dropped_after_the_mint_revokes_the_token(pool: PgPool) {
    let probe = fake_with("201 Created", "204 No Content", None, Some(pool.clone())).await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    let release = tokio::time::timeout(
        Duration::from_millis(1500),
        w.creds.release_for_job(JOB, 1, "alpha"),
    )
    .await;
    assert!(release.is_err(), "the release finished instead of hanging");
    assert_eq!(probe.mints(), 1);
    eventually("the guard to revoke the token", || async {
        probe.revokes() == 1
    })
    .await;
    probe.held.lock().unwrap().clear();
    eventually("the revoked row", || async {
        w.outcomes().await == ["attempt", "revoked"]
    })
    .await;
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_release_that_completes_never_revokes(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(fake.revokes(), 0);
}

#[sqlx::test]
async fn the_audit_table_stays_insert_only_for_the_release_path(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    let blocked = sqlx::query("UPDATE github_app_mint SET reason = 'x'")
        .execute(&w.pool)
        .await;
    assert!(blocked.is_err());
    let blocked = sqlx::query("DELETE FROM github_app_mint")
        .execute(&w.pool)
        .await;
    assert!(blocked.is_err());
}

#[sqlx::test]
async fn a_release_waits_on_the_credential_row_lock_before_it_counts(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM credentials WHERE kind = 'github_app' FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let blocked = tokio::time::timeout(
        Duration::from_millis(700),
        w.creds.release_for_job(JOB, 1, "alpha"),
    )
    .await;
    assert!(blocked.is_err(), "the release did not wait on the row lock");
    assert_eq!(fake.mints(), 0);
    holder.rollback().await.unwrap();
    w.creds.release_for_job(JOB, 1, "alpha").await.unwrap();
    assert_eq!(fake.mints(), 1);
}

const OTHER_JOB: &str = "01JJOBAPP00000000000000002";

impl World {
    async fn credential_of(&self, user_id: i64) -> i64 {
        sqlx::query_scalar("SELECT id FROM credentials WHERE user_id = $1 AND kind = 'github_app'")
            .bind(user_id)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn plant_attempts(&self, user_id: i64, count: i64, age_secs: i64) {
        let credential = self.credential_of(user_id).await;
        for _ in 0..count {
            sqlx::query(
                "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
                 installation_id, requested_permissions, outcome, at) \
                 SELECT u, u, $1, $2, 'o/widget', '1', 'contents:write', 'attempt', \
                 now() - $3::bigint * interval '1 second' FROM (SELECT gen_random_uuid() AS u) f",
            )
            .bind(credential)
            .bind(OTHER_JOB)
            .bind(age_secs)
            .execute(&self.pool)
            .await
            .unwrap();
        }
    }

    async fn bob(&self) -> i64 {
        let bob = user(&self.pool, "bob", false).await;
        self.caps.grant(self.admin, bob, CAP).await.unwrap();
        self.creds
            .put(
                bob,
                CredentialKind::GithubApp,
                STATIC,
                Secret::new(INSTALLATION.to_string()),
                None,
                None,
            )
            .await
            .unwrap();
        bob
    }

    fn rate_limited(self, limit: u32) -> Self {
        Self {
            creds: self.creds.with_user_mint_limit(limit),
            ..self
        }
    }

    async fn release_outcome(&self) -> Result<(), StoreError> {
        self.creds
            .release_for_job(JOB, 1, "alpha")
            .await
            .map(|_| ())
    }
}

const LIMIT: u32 = 3;

async fn limited_world(pool: PgPool, fake: &Fake) -> World {
    let w = world(pool, Some(client(fake))).await.rate_limited(LIMIT);
    w.seed(true).await;
    w
}

#[sqlx::test]
async fn the_user_limit_admits_a_release_at_limit_minus_one_prior_attempts(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    w.plant_attempts(w.alice, i64::from(LIMIT) - 1, 0).await;
    w.release_outcome().await.unwrap();
    assert_eq!(fake.mints(), 1);
}

#[sqlx::test]
async fn the_user_limit_refuses_at_the_limit_with_a_denied_row_and_no_pat(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    w.plant_attempts(w.alice, i64::from(LIMIT), 0).await;
    let err = w.release_outcome().await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(err.to_string(), fleet_proto::PRECONDITION_APP_MINT_CAP);
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 0);
    let denied: Vec<Row> = w
        .rows()
        .await
        .into_iter()
        .filter(|(o, _)| o == "denied")
        .collect();
    assert_eq!(
        denied,
        [("denied".to_owned(), Some("user mint rate".to_owned()))]
    );
}

#[sqlx::test]
async fn the_user_limit_refuses_above_the_limit(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    w.plant_attempts(w.alice, i64::from(LIMIT) + 1, 0).await;
    let err = w.release_outcome().await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), 0);
}

#[sqlx::test]
async fn real_releases_reach_the_user_limit_then_stop(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    for _ in 0..LIMIT {
        w.release_outcome().await.unwrap();
    }
    let err = w.release_outcome().await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), usize::try_from(LIMIT).unwrap());
}

#[sqlx::test]
async fn another_users_attempts_do_not_count(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    let bob = w.bob().await;
    w.plant_attempts(bob, i64::from(LIMIT) + 5, 0).await;
    w.release_outcome().await.unwrap();
    assert_eq!(fake.mints(), 1);
}

#[sqlx::test]
async fn attempts_older_than_a_minute_do_not_count_and_younger_ones_do(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    w.plant_attempts(w.alice, i64::from(LIMIT) + 5, 60).await;
    w.release_outcome().await.unwrap();
    w.plant_attempts(w.alice, i64::from(LIMIT), 59).await;
    let err = w.release_outcome().await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), 1);
}

#[sqlx::test]
async fn only_attempt_rows_count_toward_the_user_limit(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    let credential = w.credential_of(w.alice).await;
    for outcome in ["denied", "failed", "minted"] {
        for _ in 0..LIMIT {
            sqlx::query(
                "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
                 installation_id, requested_permissions, outcome) \
                 SELECT u, u, $1, $2, 'o/widget', '1', 'contents:write', $3 \
                 FROM (SELECT gen_random_uuid() AS u) f",
            )
            .bind(credential)
            .bind(OTHER_JOB)
            .bind(outcome)
            .execute(&w.pool)
            .await
            .unwrap();
        }
    }
    w.release_outcome().await.unwrap();
}

#[sqlx::test]
async fn repeated_denials_at_a_limit_write_one_denied_row_within_the_dedupe_window(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    w.plant_attempts(w.alice, i64::from(LIMIT), 0).await;
    for _ in 0..3 {
        w.release_outcome().await.unwrap_err();
    }
    let denied = w.outcomes().await;
    assert_eq!(denied.iter().filter(|o| *o == "denied").count(), 1);
}

#[sqlx::test]
async fn a_zero_dedupe_window_writes_every_denial(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let mut w = limited_world(pool, &fake).await;
    w.creds = w.creds.with_denied_dedupe_secs(0);
    w.plant_attempts(w.alice, i64::from(LIMIT), 0).await;
    for _ in 0..3 {
        w.release_outcome().await.unwrap_err();
    }
    let denied = w.outcomes().await;
    assert_eq!(denied.iter().filter(|o| *o == "denied").count(), 3);
}

#[sqlx::test]
async fn a_denied_row_older_than_the_dedupe_window_is_written_again(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await;
    w.plant_attempts(w.alice, i64::from(LIMIT), 0).await;
    let credential = w.credential_of(w.alice).await;
    sqlx::query(
        "INSERT INTO github_app_mint (mint_id, attempt_id, credential_id, job_id, repo, \
         installation_id, requested_permissions, outcome, reason, at) \
         SELECT u, u, $1, $2, 'o/widget', '1', 'contents:write', 'denied', 'user mint rate', \
         now() - $3::bigint * interval '1 second' FROM (SELECT gen_random_uuid() AS u) f",
    )
    .bind(credential)
    .bind(JOB)
    .bind(DENIED_DEDUPE_SECS + 10)
    .execute(&w.pool)
    .await
    .unwrap();
    w.release_outcome().await.unwrap_err();
    let denied = w.outcomes().await;
    assert_eq!(denied.iter().filter(|o| *o == "denied").count(), 2);
}

#[sqlx::test]
async fn a_denied_row_of_another_reason_does_not_hide_the_denial(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = limited_world(pool, &fake).await.capped(0);
    w.release_outcome().await.unwrap_err();
    let w = w.capped(34).rate_limited(0);
    w.release_outcome().await.unwrap_err();
    let reasons: Vec<_> = w.rows().await.into_iter().filter_map(|(_, r)| r).collect();
    assert_eq!(reasons, ["job mint cap", "user mint rate"]);
}

async fn verify_reply(w: &World) -> Result<fleet_proto::v1::VerifyCredentialReply, tonic::Status> {
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::VerifyCredentialRequest {
        id: app_id(w).await,
    };
    service.verify(w.alice, &request).await
}

#[sqlx::test]
async fn verify_audits_an_attempt_a_minted_row_and_a_revoked_row_under_the_latest_job(
    pool: PgPool,
) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    assert!(verify_reply(&w).await.unwrap().valid);
    assert_eq!(w.outcomes().await, ["attempt", "minted", "revoked"]);
    let jobs: Vec<String> = sqlx::query_scalar("SELECT DISTINCT job_id FROM github_app_mint")
        .fetch_all(&w.pool)
        .await
        .unwrap();
    assert_eq!(jobs, [JOB]);
    let expiring: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM github_app_mint WHERE outcome = 'minted' AND expires_at IS NOT NULL",
    )
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(expiring, 1);
    assert_eq!(w.uses().await, 0);
}

#[sqlx::test]
async fn a_failed_verify_mint_audits_an_attempt_then_failed(pool: PgPool) {
    let fake = fake("500 Internal Server Error", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    assert!(!verify_reply(&w).await.unwrap().valid);
    assert_eq!(
        w.rows().await,
        [
            ("attempt".to_owned(), None),
            ("failed".to_owned(), Some("mint failed".to_owned())),
        ]
    );
}

#[sqlx::test]
async fn failed_verify_mints_do_not_spend_the_job_cap(pool: PgPool) {
    let fake = fake("500 Internal Server Error", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    assert!(!verify_reply(&w).await.unwrap().valid);
    assert!(!verify_reply(&w).await.unwrap().valid);
    assert_eq!(fake.mints(), 2);
}

#[sqlx::test]
async fn verify_obeys_the_user_rate_limit_with_a_denied_row_and_no_mint(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.rate_limited(2);
    w.seed(true).await;
    w.plant_attempts(w.alice, 2, 0).await;
    let status = verify_reply(&w).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_APP_MINT_CAP);
    assert_eq!(fake.mints(), 0);
    assert_eq!(
        w.rows().await.last().cloned(),
        Some(("denied".to_owned(), Some("user mint rate".to_owned())))
    );
}

#[sqlx::test]
async fn verify_probes_never_spend_the_job_cap(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    for _ in 0..3 {
        assert!(verify_reply(&w).await.unwrap().valid);
    }
    w.release_outcome().await.unwrap();
    assert_eq!(fake.mints(), 4);
    let scopes: Vec<String> = sqlx::query_scalar("SELECT scope FROM github_app_mint ORDER BY id")
        .fetch_all(&w.pool)
        .await
        .unwrap();
    let mut want = vec!["probe"; 9];
    want.extend(["job", "job"]);
    assert_eq!(scopes, want);
}

#[sqlx::test]
async fn a_probe_works_when_the_latest_job_already_holds_its_cap(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.capped(1);
    w.seed(true).await;
    w.release_outcome().await.unwrap();
    assert!(verify_reply(&w).await.unwrap().valid);
    let err = w.release_outcome().await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
}

#[sqlx::test]
async fn verify_probes_count_toward_the_user_rate_for_probes_and_releases(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.rate_limited(2);
    w.seed(true).await;
    assert!(verify_reply(&w).await.unwrap().valid);
    assert!(verify_reply(&w).await.unwrap().valid);
    let status = verify_reply(&w).await.unwrap_err();
    assert_eq!(status.message(), fleet_proto::PRECONDITION_APP_MINT_CAP);
    let err = w.release_outcome().await.unwrap_err();
    assert!(matches!(err, StoreError::MintCapReached), "{err:?}");
    assert_eq!(fake.mints(), 2);
    assert_eq!(
        w.rows().await.last().cloned(),
        Some(("denied".to_owned(), Some("user mint rate".to_owned())))
    );
}

#[sqlx::test]
async fn a_probe_denial_is_not_hidden_by_a_job_denial_of_the_same_reason(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.rate_limited(1);
    w.seed(true).await;
    w.release_outcome().await.unwrap();
    w.release_outcome().await.unwrap_err();
    verify_reply(&w).await.unwrap_err();
    let scopes: Vec<String> = sqlx::query_scalar(
        "SELECT scope FROM github_app_mint WHERE outcome = 'denied' ORDER BY id",
    )
    .fetch_all(&w.pool)
    .await
    .unwrap();
    assert_eq!(scopes, ["job", "probe"]);
}

#[sqlx::test]
async fn a_user_with_no_job_gets_no_probe_row(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query("DELETE FROM jobs")
        .execute(&w.pool)
        .await
        .unwrap();
    let status = verify_reply(&w).await.unwrap_err();
    assert_eq!(status.message(), fleet_proto::PRECONDITION_NO_VERIFY_REPO);
    assert_eq!(w.rows().await.len(), 0);
}

#[sqlx::test]
async fn tombstoned_credentials_do_not_count_toward_the_per_user_limit(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_limited(pool, Some(client(&fake)), open_policy(), Some(2)).await;
    w.caps.grant(w.admin, w.alice, CAP).await.unwrap();
    w.put(CredentialKind::GithubPat, PAT).await;
    w.put(CredentialKind::AnthropicApiKey, ANT).await;
    sqlx::query("UPDATE credentials SET tombstoned_at = now() WHERE kind = 'github_pat'")
        .execute(&w.pool)
        .await
        .unwrap();
    w.creds
        .put(
            w.alice,
            CredentialKind::GithubApp,
            STATIC,
            Secret::new(INSTALLATION.to_string()),
            None,
            None,
        )
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_verify_whose_revoke_is_refused_is_invalid_and_audited(pool: PgPool) {
    let fake = fake_with("201 Created", "500 Internal Server Error", None, None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    assert!(!verify_reply(&w).await.unwrap().valid);
    assert_eq!(w.outcomes().await, ["attempt", "minted", "revoke_failed"]);
}

async fn tombstoned_world(pool: PgPool) -> (World, Fake, i64) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    w.release_outcome().await.unwrap();
    let id = i64::try_from(app_id(&w).await).unwrap();
    (w, fake, id)
}

#[sqlx::test]
async fn deleting_a_minted_app_credential_tombstones_it_and_keeps_the_history(pool: PgPool) {
    let (w, _fake, id) = tombstoned_world(pool).await;
    let deleted = w.creds.delete(w.alice, id).await;
    assert!(deleted.is_ok(), "{deleted:?}");
    let tombstoned: bool =
        sqlx::query_scalar("SELECT tombstoned_at IS NOT NULL FROM credentials WHERE id = $1")
            .bind(id)
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert!(tombstoned);
    let listed = w.creds.list(w.alice).await.unwrap();
    assert!(listed.iter().all(|c| c.kind != CredentialKind::GithubApp));
    assert_eq!(w.outcomes().await, ["attempt", "minted"]);
    let again = w.creds.delete(w.alice, id).await;
    assert!(matches!(again, Err(StoreError::NotFound)), "{again:?}");
}

#[sqlx::test]
async fn deleting_a_minted_app_credential_through_the_service_succeeds(pool: PgPool) {
    let (w, _fake, id) = tombstoned_world(pool).await;
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::DeleteCredentialRequest {
        id: u64::try_from(id).unwrap(),
    };
    let reply = service.delete(w.alice, &request).await;
    assert!(reply.is_ok(), "{reply:?}");
}

#[sqlx::test]
async fn deleting_an_app_credential_without_history_removes_the_row(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let id = i64::try_from(app_id(&w).await).unwrap();
    w.creds.delete(w.alice, id).await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials WHERE id = $1")
        .bind(id)
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[sqlx::test]
async fn deleting_a_pat_still_removes_the_row(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let id: i64 = sqlx::query_scalar("SELECT id FROM credentials WHERE kind = 'github_pat'")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    w.creds.delete(w.alice, id).await.unwrap();
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials WHERE id = $1")
        .bind(id)
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
}

#[sqlx::test]
async fn a_put_onto_a_tombstoned_row_is_refused_and_leaves_the_row_untouched(pool: PgPool) {
    let (w, _fake, id) = tombstoned_world(pool).await;
    w.creds.delete(w.alice, id).await.unwrap();
    let before: (String, Vec<u8>) =
        sqlx::query_as("SELECT fingerprint, ciphertext FROM credentials WHERE id = $1")
            .bind(id)
            .fetch_one(&w.pool)
            .await
            .unwrap();
    let err = w
        .creds
        .put(
            w.alice,
            CredentialKind::GithubApp,
            STATIC,
            Secret::new("777".to_owned()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Tombstoned), "{err:?}");
    let after: (String, Vec<u8>, bool) = sqlx::query_as(
        "SELECT fingerprint, ciphertext, tombstoned_at IS NOT NULL FROM credentials WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!((after.0, after.1), before);
    assert!(after.2);
}

#[sqlx::test]
async fn a_put_onto_any_tombstoned_kind_is_refused(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query("UPDATE credentials SET tombstoned_at = now() WHERE kind = 'github_pat'")
        .execute(&w.pool)
        .await
        .unwrap();
    let err = w
        .creds
        .put(
            w.alice,
            CredentialKind::GithubPat,
            STATIC,
            Secret::new(PAT.to_owned()),
            None,
            None,
        )
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Tombstoned), "{err:?}");
}

#[sqlx::test]
async fn the_service_maps_a_tombstoned_put_to_its_fixed_precondition(pool: PgPool) {
    let (w, _fake, id) = tombstoned_world(pool).await;
    w.creds.delete(w.alice, id).await.unwrap();
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::PutCredentialRequest {
        kind: "github_app".to_owned(),
        shape: "static_secret".to_owned(),
        value: INSTALLATION.to_string(),
        expires_at_ms: None,
    };
    let status = service.put(w.alice, request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        status.message(),
        fleet_proto::PRECONDITION_CREDENTIAL_TOMBSTONED
    );
}

#[sqlx::test]
async fn a_release_cancelled_during_the_revoke_still_audits_revoke_failed(pool: PgPool) {
    let fake = fake_with(
        "201 Created",
        "HANG_FIRST",
        Some((
            pool.clone(),
            "UPDATE jobs SET lease_expires_at = now() - interval '1 minute'",
        )),
        None,
    )
    .await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let cancelled = tokio::time::timeout(
        Duration::from_millis(1500),
        w.creds.release_for_job(JOB, 1, "alpha"),
    )
    .await;
    assert!(
        cancelled.is_err(),
        "the release finished instead of hanging"
    );
    eventually("the revoke_failed row after the cancel", || async {
        w.outcomes().await.contains(&"revoke_failed".to_owned())
    })
    .await;
    assert_eq!(fake.revokes(), 2);
}

#[sqlx::test]
async fn the_rate_window_is_measured_from_the_count_not_from_the_transaction_start(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await.rate_limited(1);
    w.seed(true).await;
    w.plant_attempts(w.alice, 1, 58).await;
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM credentials WHERE kind = 'github_app' FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let creds = w.creds.clone();
    let release = tokio::spawn(async move { creds.release_for_job(JOB, 1, "alpha").await });
    tokio::time::sleep(Duration::from_secs(3)).await;
    holder.rollback().await.unwrap();
    let outcome = release.await.unwrap();
    assert!(outcome.is_ok(), "{:?}", outcome.err());
    assert_eq!(fake.mints(), 1);
}

#[sqlx::test]
async fn a_credential_tombstoned_during_the_mint_revokes_the_token_and_writes_no_use_row(
    pool: PgPool,
) {
    let probe = fake(
        "201 Created",
        Some((
            pool.clone(),
            "UPDATE credentials SET tombstoned_at = now() WHERE kind = 'github_app'",
        )),
    )
    .await;
    let w = world(pool, Some(client(&probe))).await;
    w.seed(true).await;
    let err = w.release_outcome().await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound), "{err:?}");
    assert_eq!(
        w.rows().await,
        [
            ("attempt".to_owned(), None),
            (
                "denied".to_owned(),
                Some("credential gone after mint".to_owned())
            ),
            ("revoked".to_owned(), None),
        ]
    );
    assert_eq!(w.uses().await, 0);
}

struct LogBuffer(Arc<Mutex<Vec<u8>>>);

impl Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_guard_dropped_without_a_runtime_logs_the_unrevoked_token() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let guard = runtime.block_on(async {
        let pool = PgPool::connect_lazy("postgres://u:p@127.0.0.1:1/none").unwrap();
        let bot = BotIdentity::new(BOT_NAME, BOT_EMAIL).unwrap();
        let lane = AppLane::new(
            app_key(),
            "12345".to_owned(),
            AppClient::plain("127.0.0.1:1".parse().unwrap(), Limits::default()),
            bot,
            open_policy(),
        );
        super::store::armed_guard_for_test(
            lane,
            pool,
            super::app_mint::InstallationToken::for_test(TOKEN, 1),
        )
    });
    let logged = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&logged);
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || LogBuffer(Arc::clone(&sink)))
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, || drop(guard));
    let text = String::from_utf8(logged.lock().unwrap().clone()).unwrap();
    assert!(text.contains("ERROR"), "{text}");
    assert!(text.contains("attempt-under-test"), "{text}");
    assert!(!text.contains(TOKEN), "{text}");
}

fn bare_lane(fake: &Fake) -> AppLane {
    let bot = BotIdentity::new(BOT_NAME, BOT_EMAIL).unwrap();
    AppLane::new(
        app_key(),
        "12345".to_owned(),
        client(fake),
        bot,
        open_policy(),
    )
}

#[tokio::test]
async fn the_app_id_check_matches_mismatches_and_degrades_to_unchecked() {
    use super::store::AppIdCheck;
    let fake = fake("201 Created", None).await;
    let lane = bare_lane(&fake);
    assert_eq!(lane.check_app_id().await, AppIdCheck::Match);
    *fake.app.lock().unwrap() = ("200 OK", r#"{"id":999}"#.to_owned());
    assert_eq!(lane.check_app_id().await, AppIdCheck::Mismatch);
    *fake.app.lock().unwrap() = ("500 Internal Server Error", String::new());
    assert_eq!(lane.check_app_id().await, AppIdCheck::Unchecked);
    *fake.app.lock().unwrap() = ("200 OK", "not json".to_owned());
    assert_eq!(lane.check_app_id().await, AppIdCheck::Unchecked);
}

const INSTALLATION_REASON: &str = "installation not on allowlist";
const BINDING_REASON: &str = "installation binding refused";
const REPO_REASON: &str = "repository not allowed";

async fn refused_release(w: &World, fake: &Fake, want: &str, rows: Vec<Row>) {
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert_eq!(err.to_string(), want, "{err:?}");
    assert_eq!(fake.mints(), 0);
    assert_eq!(w.uses().await, 0);
    assert_eq!(w.rows().await, rows);
}

#[sqlx::test]
async fn an_installation_off_the_allowlist_is_refused_before_any_call(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_with(pool, Some(client(&fake)), policy("9999", "o/*")).await;
    w.seed(true).await;
    refused_release(
        &w,
        &fake,
        fleet_proto::PRECONDITION_APP_INSTALLATION,
        vec![("denied".to_owned(), Some(INSTALLATION_REASON.to_owned()))],
    )
    .await;
    assert_eq!(fake.lookups(), 0);
}

#[sqlx::test]
async fn the_default_policy_allows_no_installation_and_no_repository(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_with(
        pool,
        Some(client(&fake)),
        AppPolicy::parse("o", None, None).unwrap(),
    )
    .await;
    w.seed(true).await;
    refused_release(
        &w,
        &fake,
        fleet_proto::PRECONDITION_APP_INSTALLATION,
        vec![("denied".to_owned(), Some(INSTALLATION_REASON.to_owned()))],
    )
    .await;
}

#[sqlx::test]
async fn a_repository_off_the_allowlist_is_refused_before_any_call(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_with(pool, Some(client(&fake)), policy("4242", "o/other")).await;
    w.seed(true).await;
    refused_release(
        &w,
        &fake,
        fleet_proto::PRECONDITION_APP_REPO,
        vec![("denied".to_owned(), Some(REPO_REASON.to_owned()))],
    )
    .await;
    assert_eq!(fake.lookups(), 0);
}

#[sqlx::test]
async fn a_job_repository_with_another_owner_is_refused(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    sqlx::query("UPDATE jobs SET repo = 'evil/widget'")
        .execute(&w.pool)
        .await
        .unwrap();
    refused_release(
        &w,
        &fake,
        fleet_proto::PRECONDITION_APP_REPO,
        vec![("denied".to_owned(), Some(REPO_REASON.to_owned()))],
    )
    .await;
}

#[sqlx::test]
async fn a_hostile_job_repository_is_refused_and_audited_within_the_column_cap(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let long = format!("o/{}", "a".repeat(400));
    for hostile in [
        "o/widget\r",
        "o/widget\n",
        "o\\widget",
        "u:p@o/widget",
        "o//widget",
        "o/",
        "o/wïdget",
        long.as_str(),
    ] {
        sqlx::query("UPDATE jobs SET repo = $1")
            .bind(hostile)
            .execute(&w.pool)
            .await
            .unwrap();
        let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
        assert!(matches!(err, StoreError::RepoDenied), "{hostile:?} {err:?}");
    }
    assert_eq!(fake.mints(), 0);
}

async fn binding_refused(pool: PgPool, body: String) {
    let fake = fake("201 Created", None).await;
    *fake.inst.lock().unwrap() = ("200 OK", body);
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::InstallationDenied), "{err:?}");
    assert_eq!(fake.mints(), 0);
    assert_eq!(fake.lookups(), 1);
    assert_eq!(w.uses().await, 0);
    assert_eq!(
        w.rows().await,
        [
            ("attempt".to_owned(), None),
            ("denied".to_owned(), Some(BINDING_REASON.to_owned())),
        ]
    );
}

#[sqlx::test]
async fn a_suspended_installation_mints_nothing(pool: PgPool) {
    binding_refused(
        pool,
        installation_json(INSTALLATION, 12345, "o", "\"2026-01-01T00:00:00Z\""),
    )
    .await;
}

#[sqlx::test]
async fn an_installation_of_another_app_mints_nothing(pool: PgPool) {
    binding_refused(pool, installation_json(INSTALLATION, 99, "o", "null")).await;
}

#[sqlx::test]
async fn an_installation_of_another_account_mints_nothing(pool: PgPool) {
    binding_refused(pool, installation_json(INSTALLATION, 12345, "evil", "null")).await;
}

#[sqlx::test]
async fn an_installation_reply_with_another_id_mints_nothing(pool: PgPool) {
    binding_refused(pool, installation_json(1, 12345, "o", "null")).await;
}

#[sqlx::test]
async fn a_failed_installation_lookup_is_a_failed_mint_and_mints_nothing(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    *fake.inst.lock().unwrap() = ("404 Not Found", String::new());
    let w = world(pool, Some(client(&fake))).await;
    w.seed(true).await;
    let err = w.creds.release_for_job(JOB, 1, "alpha").await.unwrap_err();
    assert!(matches!(err, StoreError::MintFailed), "{err:?}");
    assert_eq!(fake.mints(), 0);
    assert_eq!(
        w.rows().await,
        [
            ("attempt".to_owned(), None),
            ("failed".to_owned(), Some("mint failed".to_owned())),
        ]
    );
}

#[sqlx::test]
async fn verify_refuses_an_off_list_installation_and_a_bad_binding_without_a_mint(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_with(pool, Some(client(&fake)), policy("9999", "o/*")).await;
    w.seed(true).await;
    let status = verify_reply(&w).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_APP_INSTALLATION);
    assert_eq!(fake.mints(), 0);
}

#[sqlx::test]
async fn verify_refuses_an_off_list_repository_without_a_mint(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_with(pool, Some(client(&fake)), policy("4242", "o/other")).await;
    w.seed(true).await;
    let status = verify_reply(&w).await.unwrap_err();
    assert_eq!(status.message(), fleet_proto::PRECONDITION_APP_REPO);
    assert_eq!(fake.mints(), 0);
}

#[sqlx::test]
async fn put_vets_the_installation_against_the_allowlist_and_the_binding(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_with(pool, Some(client(&fake)), policy("4242", "o/*")).await;
    w.caps.grant(w.admin, w.alice, CAP).await.unwrap();
    let id = |n: u64| Secret::new(n.to_string());
    w.creds
        .vet_installation(w.alice, &id(INSTALLATION))
        .await
        .unwrap();
    let err = w.creds.vet_installation(w.alice, &id(7)).await.unwrap_err();
    assert!(matches!(err, StoreError::InstallationDenied), "{err:?}");
    assert_eq!(fake.lookups(), 1);
    *fake.inst.lock().unwrap() = (
        "200 OK",
        installation_json(INSTALLATION, 12345, "evil", "null"),
    );
    let err = w
        .creds
        .vet_installation(w.alice, &id(INSTALLATION))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::InstallationDenied), "{err:?}");
}

#[sqlx::test]
async fn the_service_put_refuses_an_off_list_installation_with_the_fixed_message(pool: PgPool) {
    let fake = fake("201 Created", None).await;
    let w = world_with(pool, Some(client(&fake)), policy("9999", "o/*")).await;
    w.caps.grant(w.admin, w.alice, CAP).await.unwrap();
    let service = super::CredentialService::new(w.creds.clone(), Arc::new(NoGithub));
    let request = fleet_proto::v1::PutCredentialRequest {
        kind: "github_app".to_owned(),
        shape: "static_secret".to_owned(),
        value: INSTALLATION.to_string(),
        expires_at_ms: None,
    };
    let status = service.put(w.alice, request).await.unwrap_err();
    assert_eq!(status.code(), tonic::Code::FailedPrecondition);
    assert_eq!(status.message(), fleet_proto::PRECONDITION_APP_INSTALLATION);
    assert_eq!(fake.lookups(), 0);
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
}
