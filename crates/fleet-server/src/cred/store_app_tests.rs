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
use super::capability::Capabilities;
use super::seal::FileSealer;
use super::store::{AppLane, CredentialStore, StoreError};
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
}

impl Fake {
    fn requests(&self) -> Vec<String> {
        self.seen.lock().unwrap().clone()
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let hook_ok = Arc::new(Mutex::new(Vec::new()));
    let (seen_task, hook_task) = (Arc::clone(&seen), Arc::clone(&hook_ok));
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (seen, hook_ok, hook) =
                (Arc::clone(&seen_task), Arc::clone(&hook_task), hook.clone());
            tokio::spawn(async move {
                let request = read_request(&mut stream).await;
                let is_mint = request.starts_with("POST ");
                seen.lock().unwrap().push(request);
                let reply = if is_mint {
                    if let Some((pool, sql)) = hook {
                        let mut conn = pool.acquire().await.unwrap();
                        sqlx::query("SET lock_timeout = '500ms'")
                            .execute(&mut *conn)
                            .await
                            .unwrap();
                        let done = sqlx::query(sql).execute(&mut *conn).await.is_ok();
                        hook_ok.lock().unwrap().push(done);
                    }
                    if mint_status.starts_with("201") {
                        http(mint_status, &good_body())
                    } else {
                        http(mint_status, "")
                    }
                } else {
                    http("204 No Content", "")
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
    Store::new(pool.clone()).migrate().await.unwrap();
    let path = std::env::temp_dir().join(format!(
        "fleet-app-lane-{}-{}.keys",
        std::process::id(),
        FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let mut creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
    if let Some(client) = lane {
        let bot = BotIdentity::new(BOT_NAME, BOT_EMAIL).unwrap();
        creds = creds.with_github_app(AppLane::new(app_key(), "12345".to_owned(), client, bot));
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
    let request = &fake.requests()[0];
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
    let request = &fake.requests()[0];
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
    let mint = &fake.requests()[0];
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
