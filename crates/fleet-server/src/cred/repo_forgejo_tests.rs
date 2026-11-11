//! A Forgejo repository through the registry: the stored `forgejo_pat` is opened for the exact
//! `(user, host)`, an expired one is ignored, and the check reaches the forge with it. The tests
//! need a Postgres superuser URL in `DATABASE_URL`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use fleet_core::credential::{CredentialKind, CredentialShape, Secret};
use fleet_proto::v1::AddRepoRequest;
use sqlx::PgPool;

use super::forge_verify::{ForgejoVerifier, PgHostDirectory};
use super::https::{FetchError, ForgeGet, ForgeReply, ForgeTransport};
use super::repo_api::RepoService;
use super::repo_store::RepoStore;
use super::repo_verify::RepoVerifiers;
use super::seal::FileSealer;
use super::store::CredentialStore;
use crate::config::{Forge, RepoHosts};
use crate::store::Store;

const TOKEN: &str = "0123456789abcdef0123456789abcdef01234567";
const HOST: &str = "git.example.org";
const OTHER: &str = "git.other.org";

static FILES: AtomicUsize = AtomicUsize::new(0);

struct Echo {
    seen: std::sync::Mutex<Vec<(String, String)>>,
    flags: std::sync::Mutex<Vec<(bool, Vec<std::net::IpAddr>)>>,
}

#[tonic::async_trait]
impl ForgeTransport for Echo {
    async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
        let auth = request.authorization.map_or_else(String::new, |value| {
            String::from_utf8_lossy(value.as_bytes()).into_owned()
        });
        self.flags
            .lock()
            .unwrap()
            .push((request.allow_private, request.approved_ips.to_vec()));
        self.seen
            .lock()
            .unwrap()
            .push((request.host.to_owned(), auth));
        Ok(ForgeReply {
            status: hyper::StatusCode::OK,
            body: br#"{"permissions":{"push":true}}"#.to_vec(),
            location: None,
        })
    }
}

struct World {
    pool: PgPool,
    creds: CredentialStore,
    repos: RepoService,
    echo: Arc<Echo>,
    user: i64,
}

async fn world(pool: PgPool) -> World {
    Store::new(pool.clone()).migrate().await.unwrap();
    let path = std::env::temp_dir().join(format!(
        "fleet-repo-forgejo-{}-{}.keys",
        std::process::id(),
        FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
    for host in [HOST, OTHER] {
        sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
            .bind(host)
            .execute(&pool)
            .await
            .unwrap();
    }
    let user: i64 = sqlx::query_scalar("SELECT bootstrap_user_id()")
        .fetch_one(&pool)
        .await
        .unwrap();
    let echo = Arc::new(Echo {
        seen: std::sync::Mutex::new(Vec::new()),
        flags: std::sync::Mutex::new(Vec::new()),
    });
    let directory = Arc::new(PgHostDirectory::new(pool.clone()));
    let forgejo = ForgejoVerifier::new(echo.clone(), directory.clone());
    let verifiers = RepoVerifiers::new(RepoHosts::parse("").unwrap())
        .with(Forge::Forgejo, Arc::new(forgejo))
        .with_directory(directory);
    let repos = RepoService::new(
        RepoStore::new(pool.clone(), creds.clone()),
        Arc::new(verifiers),
    );
    World {
        pool,
        creds,
        repos,
        echo,
        user,
    }
}

async fn put(w: &World, host: &str) {
    w.creds
        .put_for_host(
            w.user,
            host,
            CredentialKind::ForgejoPat,
            CredentialShape::StaticSecret,
            Secret::new(TOKEN.to_owned()),
            None,
            None,
        )
        .await
        .unwrap();
}

async fn add(w: &World, repo: &str) -> Result<fleet_proto::v1::RepoInfo, tonic::Status> {
    w.repos
        .add(
            w.user,
            &AddRepoRequest {
                repo: repo.to_owned(),
            },
        )
        .await
}

#[sqlx::test]
async fn repo_add_verifies_a_forgejo_repo_with_the_users_pat(pool: PgPool) {
    let w = world(pool).await;
    put(&w, HOST).await;
    let info = add(&w, "git.example.org/Octo/Hello").await.unwrap();
    assert_eq!(info.forge_kind, "forgejo");
    assert_eq!(info.path, "octo/hello");
    assert_eq!(info.push, Some(true));
    assert_eq!(
        *w.echo.seen.lock().unwrap(),
        vec![(HOST.to_owned(), format!("token {TOKEN}"))]
    );
}

#[sqlx::test]
async fn a_pat_for_another_host_is_never_sent(pool: PgPool) {
    let w = world(pool).await;
    put(&w, OTHER).await;
    let err = add(&w, "git.example.org/o/r").await.unwrap_err();
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL);
    assert!(w.echo.seen.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn an_expired_pat_is_no_credential_without_a_request(pool: PgPool) {
    let w = world(pool).await;
    put(&w, HOST).await;
    sqlx::query("UPDATE credentials SET expires_at = now() - interval '1 minute' WHERE host = $1")
        .bind(HOST)
        .execute(&w.pool)
        .await
        .unwrap();
    let err = add(&w, "git.example.org/o/r").await.unwrap_err();
    assert_eq!(err.message(), fleet_proto::PRECONDITION_REPO_NO_CREDENTIAL);
    assert!(w.echo.seen.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn a_host_without_a_row_is_not_allowed_host(pool: PgPool) {
    let w = world(pool).await;
    put(&w, HOST).await;
    let err = add(&w, "git.unlisted.org/o/r").await.unwrap_err();
    assert_eq!(
        err.message(),
        fleet_proto::PRECONDITION_REPO_NOT_ALLOWED_HOST
    );
    assert!(w.echo.seen.lock().unwrap().is_empty());
}

#[sqlx::test]
async fn the_approved_addresses_of_the_row_reach_the_transport(pool: PgPool) {
    let w = world(pool).await;
    put(&w, HOST).await;
    sqlx::query(
        "UPDATE git_hosts SET allow_private = true, approved_ips = ARRAY['192.168.3.1'::inet] \
         WHERE host = $1",
    )
    .bind(HOST)
    .execute(&w.pool)
    .await
    .unwrap();
    add(&w, "git.example.org/o/r").await.unwrap();
    let ip: std::net::IpAddr = "192.168.3.1".parse().unwrap();
    assert_eq!(*w.echo.flags.lock().unwrap(), vec![(true, vec![ip])]);
}
