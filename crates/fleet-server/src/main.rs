//! fleet-server: serves the Fleet gRPC API and a plain health endpoint.

use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::routing::get;
use fleet_server::auth::BearerAuth;
use fleet_server::config::{Config, CredentialsState, exposed_binds, is_loopback};
use fleet_server::reaper::{DEFAULT_REAP_PERIOD, run_reaper};
use fleet_server::retention::run_retention;
use fleet_server::service::router;
use fleet_server::store::Store;
use fleet_server::supervise::{BoxError, supervise};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
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

async fn run() -> Result<(), BoxError> {
    let config = Config::from_env()?;
    let options = PgConnectOptions::from_str(config.database_url.expose())?
        .options([("statement_timeout", STATEMENT_TIMEOUT_MS)]);
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(options)
        .await?;
    let store = Store::new(pool.clone()).with_max_ci_retries(config.max_ci_retries);
    store.migrate().await?;

    let rows_exist: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM credentials)")
        .fetch_one(&pool)
        .await?;
    let credentials = CredentialsState::resolve(config.master_key_file.as_deref(), rows_exist)?;
    if credentials.is_enabled() {
        tracing::info!("credential master key loaded");
    } else {
        tracing::info!("{}", CredentialsState::DISABLED_NOTICE);
    }

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
    let auth = BearerAuth::new(&config.token, config.client_token.as_ref());
    let grpc_server = async {
        router(&store, &auth)
            .serve_with_incoming_shutdown(grpc, stopped(stop_rx.clone()))
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
    result?;
    tracing::info!("fleet-server stopped");
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
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
