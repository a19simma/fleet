//! fleet-server: serves the Fleet gRPC API and a plain health endpoint.

use std::io::Write as _;
use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use fleet_server::auth::BearerAuth;
use fleet_server::config::{
    Config, CredentialsState, Forge, UpdateRepo, exposed_binds, is_loopback,
};
use fleet_server::cred::admin::{AdminError, SETUP_CODE_TTL_HOURS, parse_args, run as run_admin};
use fleet_server::cred::app_mint::AppClient;
use fleet_server::cred::github::HttpsGithub;
use fleet_server::cred::limiter::Limiter;
use fleet_server::cred::password::BootstrapPassword;
use fleet_server::cred::pinned::PinnedHttps;
use fleet_server::cred::release::ReleaseFetcher;
use fleet_server::cred::repo_store::RepoStore;
use fleet_server::cred::repo_verify::{GithubVerifier, RepoVerifiers};
use fleet_server::cred::store::{AppIdCheck, AppLane, CredentialStore};
use fleet_server::cred::{CredentialService, RepoService, Users};
use fleet_server::reaper::{DEFAULT_REAP_PERIOD, run_reaper};
use fleet_server::retention::run_retention;
use fleet_server::service::{UpdateRelay, serve_with_credentials};
use fleet_server::store::Store;
use fleet_server::supervise::{BoxError, supervise};
use fleet_server::update_feed::{FeedCache, FeedPoller, FeedSource, ReleaseFeed, SystemJitter};
use fleet_server::web::{Web, WebAuth};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tonic::transport::server::TcpIncoming;
use tracing_subscriber::EnvFilter;

const MAX_CONNECTIONS: u32 = 10;
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
const STATEMENT_TIMEOUT_MS: &str = "10000";

async fn termination() {
    let terminate = async {
        match signal(SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if let Err(err) = result {
                tracing::error!(%err, "cannot listen for SIGINT");
                std::future::pending::<()>().await;
            }
        }
        () = terminate => {}
    }
}

async fn stopped(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

fn build_web(
    config: &Config,
    pool: &sqlx::PgPool,
    users: &Users,
    credentials: Option<CredentialService>,
    store: Store,
    password: BootstrapPassword,
) -> Result<Web, BoxError> {
    let Some(origin) = config.web_origin.as_deref() else {
        tracing::warn!("FLEET_WEB_ORIGIN is unset: web login is off");
        return Ok(Web::new());
    };
    let auth = WebAuth::new(
        pool.clone(),
        users.clone(),
        origin,
        config.web_rp_id.as_deref(),
    )?
    .with_bootstrap(
        password,
        Arc::new(Limiter::system()),
        config.trusted_proxy_hops,
    );
    Ok(Web::with_console(auth, credentials, store))
}

async fn bootstrap_password(config: &Config, users: &Users) -> Result<BootstrapPassword, BoxError> {
    let Some(plain) = config.bootstrap_password.as_ref() else {
        return Ok(BootstrapPassword::disarmed());
    };
    if !users.bootstrap_password_armed().await? {
        tracing::info!("FLEET_BOOTSTRAP_PASSWORD is ignored: setup is already closed");
        return Ok(BootstrapPassword::disarmed());
    }
    let password = BootstrapPassword::from_plaintext(plain.expose().to_owned()).await?;
    tracing::info!("the bootstrap password is armed for the first admin");
    Ok(password)
}

async fn credential_service(
    config: &Config,
    pool: &sqlx::PgPool,
    github_app: Option<AppLane>,
) -> Result<Option<CredentialService>, BoxError> {
    let rows_exist: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM credentials)")
        .fetch_one(pool)
        .await?;
    let state = CredentialsState::resolve(config.master_key_file.as_deref(), rows_exist)?;
    let CredentialsState::Enabled(sealer) = state else {
        tracing::info!("{}", CredentialsState::DISABLED_NOTICE);
        return Ok(None);
    };
    tracing::info!("credential master key loaded");
    let github = HttpsGithub::new()?;
    let mut store = CredentialStore::new(pool.clone(), sealer);
    if let Some(lane) = github_app {
        store = store.with_github_app(lane);
    }
    let transport = PinnedHttps::system()?;
    let github_verifier = GithubVerifier::new(Arc::new(transport), Some(Arc::new(store.clone())));
    let verifiers = RepoVerifiers::new(config.repo_hosts.clone())
        .with(Forge::Github, Arc::new(github_verifier));
    let repos = RepoService::new(
        RepoStore::new(pool.clone(), store.clone()),
        Arc::new(verifiers),
    );
    Ok(Some(
        CredentialService::new(store, Arc::new(github)).with_repos(repos),
    ))
}

/// Starts the release feed poller when `repo` is set and returns the cache it fills with its task.
/// `make_source` runs only then. The poll loop runs inside the task, so a slow first fetch never
/// delays readiness, and the task ends when `stop_rx` holds `true`.
///
/// # Errors
///
/// Returns the error of `make_source`.
fn spawn_update_feed(
    repo: Option<&UpdateRepo>,
    interval: Duration,
    stop_rx: watch::Receiver<bool>,
    make_source: impl FnOnce(&UpdateRepo) -> Result<Arc<dyn FeedSource>, BoxError>,
) -> Result<Option<(FeedCache, JoinHandle<()>)>, BoxError> {
    let Some(repo) = repo else {
        return Ok(None);
    };
    let source = make_source(repo)?;
    let cache = FeedCache::new();
    let poller = FeedPoller::new(source, cache.clone(), interval, Arc::new(SystemJitter));
    tracing::info!(%repo, "release feed polling started");
    Ok(Some((cache, poller.spawn(stop_rx))))
}

async fn join_feed(task: Option<JoinHandle<()>>) {
    if let Some(task) = task
        && let Err(err) = task.await
    {
        tracing::error!(panicked = err.is_panic(), "release feed task died");
    }
}

/// The relay for `config`: the feed when `FLEET_UPDATE_REPO` is set, else the file source.
fn update_relay(
    config: &Config,
    stop_rx: watch::Receiver<bool>,
) -> Result<(UpdateRelay, Option<JoinHandle<()>>), BoxError> {
    let feed = spawn_update_feed(
        config.update_repo.as_ref(),
        config.update_poll,
        stop_rx,
        release_source,
    )?;
    Ok(match feed {
        Some((cache, task)) => (UpdateRelay::from_feed(cache), Some(task)),
        None => (UpdateRelay::new(config.update_manifest.clone()), None),
    })
}

fn release_source(repo: &UpdateRepo) -> Result<Arc<dyn FeedSource>, BoxError> {
    let fetcher = ReleaseFetcher::new(Arc::new(PinnedHttps::system()?));
    Ok(Arc::new(ReleaseFeed::new(fetcher, repo.clone())))
}

fn configured_store(pool: sqlx::PgPool, config: &Config) -> Store {
    Store::new(pool)
        .with_max_ci_retries(config.max_ci_retries)
        .with_model_allowlist(config.model_allowlist.clone())
}

async fn log_setup_path(users: &Users) -> Result<(), BoxError> {
    if let Some(code) = users.issue_setup_code().await? {
        tracing::warn!(
            setup_path = %format!("/setup/{}", String::from_utf8_lossy(code.expose())),
            "no users exist: open this path on the server's public address to create the admin; it works once and changes on restart"
        );
    }
    Ok(())
}

async fn load_github_app(config: &Config) -> Result<Option<AppLane>, BoxError> {
    let Some(app) = config.github_app.as_ref() else {
        return Ok(None);
    };
    let key = app
        .load_key()
        .map_err(|err| format!("FLEET_GITHUB_APP_KEY_FILE: {err}"))?;
    tracing::info!("github app key loaded");
    let lane = AppLane::new(
        key,
        app.app_id_text(),
        AppClient::new()?,
        app.bot.clone(),
        app.policy.clone(),
    );
    match lane.check_app_id().await {
        AppIdCheck::Mismatch => {
            Err("FLEET_GITHUB_APP_KEY_FILE: the key does not belong to FLEET_GITHUB_APP_ID".into())
        }
        AppIdCheck::Match => Ok(Some(lane)),
        AppIdCheck::Unchecked => {
            tracing::warn!("github app id check skipped: GitHub could not be reached");
            Ok(Some(lane))
        }
    }
}

async fn run() -> Result<(), BoxError> {
    let config = Config::from_env()?;
    let github_app = load_github_app(&config).await?;
    let options = PgConnectOptions::from_str(config.database_url.expose())?
        .options([("statement_timeout", STATEMENT_TIMEOUT_MS)]);
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(options)
        .await?;
    let store = configured_store(pool.clone(), &config);
    store.migrate().await?;

    let credential_service = credential_service(&config, &pool, github_app).await?;

    let users = Users::new(pool.clone());
    log_setup_path(&users).await?;

    let password = bootstrap_password(&config, &users).await?;
    let web = build_web(
        &config,
        &pool,
        &users,
        credential_service.clone(),
        store.clone(),
        password,
    )?;

    if !is_loopback(&config.listen) {
        tracing::warn!(
            listen = %config.listen,
            "FLEET_LISTEN is not a loopback address and the gRPC listener is plaintext h2c; keep it behind a TLS-terminating gateway"
        );
    }
    if let Some((var, addr)) = exposed_binds(&config.listen, &config.health_listen)
        .into_iter()
        .find(|(var, _)| *var == "FLEET_HEALTH_LISTEN")
    {
        tracing::warn!(
            listen = %addr,
            "{var} is not a loopback address; the health listener is reachable off the host"
        );
    }
    let grpc = TcpIncoming::from(TcpListener::bind(config.listen).await?);
    let health = TcpListener::bind(config.health_listen).await?;
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        grpc = %config.listen,
        health = %config.health_listen,
        "fleet-server started"
    );

    let (stop_tx, stop_rx) = watch::channel(false);
    let stop_tx = Arc::new(stop_tx);
    let signal_stop = Arc::clone(&stop_tx);
    tokio::spawn(async move {
        termination().await;
        tracing::info!("shutdown requested");
        signal_stop.send_replace(true);
    });

    let reaper = tokio::spawn(run_reaper(
        store.clone(),
        DEFAULT_REAP_PERIOD,
        stop_rx.clone(),
        None,
    ));
    let retention = tokio::spawn(run_retention(
        store.clone(),
        config.retention,
        config.retention_interval,
        stop_rx.clone(),
        None,
    ));
    let (update, feed_task) = update_relay(&config, stop_rx.clone())?;
    let auth = BearerAuth::new(&config.token, config.client_token.as_ref()).with_users(users);
    let grpc_server = async {
        serve_with_credentials(
            &store,
            &auth,
            web,
            credential_service,
            update,
            grpc,
            stopped(stop_rx.clone()),
        )
        .await
        .map_err(BoxError::from)
    };
    let health_server = async {
        let app = Router::new().route("/healthz", get(|| async { "ok" }));
        axum::serve(health, app)
            .with_graceful_shutdown(stopped(stop_rx.clone()))
            .await
            .map_err(BoxError::from)
    };
    let served = async { tokio::try_join!(grpc_server, health_server).map(|_| ()) };
    let result = supervise(served, reaper, &stop_tx).await;
    if let Err(err) = retention.await {
        tracing::error!(panicked = err.is_panic(), "retention task died");
    }
    join_feed(feed_task).await;
    result?;
    tracing::info!("fleet-server stopped");
    Ok(())
}

async fn admin(args: &[String]) -> Result<(), AdminError> {
    let cmd = parse_args(args)?;
    let url = std::env::var("FLEET_DATABASE_URL").map_err(|_| AdminError::MissingDatabaseUrl)?;
    let options = PgConnectOptions::from_str(&url)?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(options)
        .await?;
    let operator = std::env::var("USER")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    let done = run_admin(&pool, &cmd, &operator).await?;
    let report = match (&done.setup_code, done.admin) {
        (Some(code), _) => format!(
            "user: {}\npasskeys removed: {}\nsessions revoked: {}\napi tokens revoked: {}\nsetup code: {}\nthe code works once and expires in {} hours\n",
            done.username,
            done.passkeys_removed,
            done.sessions_revoked,
            done.tokens_revoked,
            String::from_utf8_lossy(code.expose()),
            SETUP_CODE_TTL_HOURS
        ),
        (None, flag) => format!(
            "user: {}\nadmin: {}\n",
            done.username,
            flag.unwrap_or(false)
        ),
    };
    std::io::stdout()
        .write_all(report.as_bytes())
        .map_err(|_| AdminError::Output)
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some((first, rest)) = args.split_first()
        && first == "admin"
    {
        return match admin(rest).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("fleet-server admin: {err}");
                ExitCode::from(err.exit_code())
            }
        };
    }
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!(%err, "fleet-server failed");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "0123456789abcdef0123456789abcdef";

    fn config(allowlist: Option<&'static str>) -> Config {
        Config::from_lookup(|var| match var {
            "FLEET_DATABASE_URL" => Some("postgres://h/db".to_owned()),
            "FLEET_TOKEN" => Some(TOKEN.to_owned()),
            "FLEET_MODEL_ALLOWLIST" => allowlist.map(str::to_owned),
            _ => None,
        })
        .unwrap()
    }

    struct Counting(Arc<std::sync::atomic::AtomicUsize>);

    #[tonic::async_trait]
    impl FeedSource for Counting {
        async fn fetch_pair(
            &self,
        ) -> Result<(Vec<u8>, Vec<u8>), fleet_server::cred::release::ReleaseRefusal> {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((b"{\"seq\":1}".to_vec(), b"sig".to_vec()))
        }
    }

    #[tokio::test]
    async fn the_feed_poller_starts_only_when_the_repo_is_set() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let built = Arc::new(AtomicUsize::new(0));
        let (stop_tx, stop_rx) = watch::channel(false);
        let make = |built: &Arc<AtomicUsize>, calls: &Arc<AtomicUsize>| {
            let (built, calls) = (Arc::clone(built), Arc::clone(calls));
            move |_: &UpdateRepo| -> Result<Arc<dyn FeedSource>, BoxError> {
                built.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(Counting(calls)))
            }
        };
        let none = spawn_update_feed(
            None,
            Duration::from_secs(60),
            stop_rx.clone(),
            make(&built, &calls),
        )
        .unwrap();
        assert!(none.is_none());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(built.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let repo = UpdateRepo::parse("acme/fleet").unwrap();
        let (cache, task) = spawn_update_feed(
            Some(&repo),
            Duration::from_secs(60),
            stop_rx,
            make(&built, &calls),
        )
        .unwrap()
        .unwrap();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while cache.current().is_none() {
            assert!(tokio::time::Instant::now() < deadline);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(built.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        stop_tx.send_replace(true);
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn a_source_that_cannot_be_built_fails_startup() {
        let (_stop_tx, stop_rx) = watch::channel(false);
        let repo = UpdateRepo::parse("acme/fleet").unwrap();
        let err = spawn_update_feed(Some(&repo), Duration::from_secs(60), stop_rx, |_| {
            Err("no tls".into())
        })
        .map(|_| ())
        .unwrap_err();
        assert_eq!(err.to_string(), "no tls");
    }

    #[sqlx::test]
    async fn the_configured_store_carries_the_model_allowlist(pool: sqlx::PgPool) {
        let set = configured_store(pool.clone(), &config(Some("claude-opus-4-1")));
        assert_eq!(
            set.model_allowlist().map(|l| l.entries().to_vec()),
            Some(vec!["claude-opus-4-1".to_owned()])
        );
        assert_eq!(
            configured_store(pool, &config(None)).model_allowlist(),
            None
        );
    }
}
