use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fleet_core::{HookAllowlist, Identity, Redactor};
use sd_notify::NotifyState;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio::time::{Interval, MissedTickBehavior};

use crate::Error;
use crate::app::{AppState, hook_router, hook_socket_router, socket_router};
use crate::config::Config;
use crate::events::Limits;
use crate::heartbeat::Heartbeat;
use crate::http1::{Failure, roundtrip};
use crate::jobenv::group_id;
use crate::jobs::{self, JobPoller};
use crate::managed_settings;
use crate::store::Store;
use crate::system::read_identity;
use crate::systemd;
use crate::toolhook::HookHub;

const DEFAULT_WATCHDOG_PERIOD: Duration = Duration::from_secs(20);
const MIN_WATCHDOG_PERIOD: Duration = Duration::from_millis(1);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const JOBS_GRACE: Duration = Duration::from_secs(15);
const MAX_HEALTH_TIMEOUT: Duration = Duration::from_secs(3);

/// Process signal streams for the daemon.
///
/// Register them before any other startup work so a signal that arrives early is held
/// instead of killing the process mid-start.
#[derive(Debug)]
pub struct Signals {
    term: Signal,
    int: Signal,
    hup: Signal,
}

impl Signals {
    /// Registers handlers for `SIGTERM`, `SIGINT` and `SIGHUP`.
    ///
    /// # Errors
    ///
    /// Fails when a handler cannot be installed.
    pub fn register() -> Result<Self, Error> {
        Ok(Self {
            term: signal(SignalKind::terminate()).map_err(Error::Runtime)?,
            int: signal(SignalKind::interrupt()).map_err(Error::Runtime)?,
            hup: signal(SignalKind::hangup()).map_err(Error::Runtime)?,
        })
    }

    /// Resolves on `SIGTERM` or `SIGINT`. `SIGHUP` is logged and ignored, since fleetd
    /// has no config reload.
    pub async fn terminated(mut self) {
        loop {
            tokio::select! {
                _ = self.term.recv() => return,
                _ = self.int.recv() => return,
                _ = self.hup.recv() => tracing::info!("SIGHUP ignored"),
            }
        }
    }
}

/// Binds the unix socket at `path` with mode 0600.
///
/// An existing file at `path` is removed only when it is a socket that refuses
/// connections, which marks it as left behind by a dead process.
///
/// # Errors
///
/// Fails when `path` holds anything but a stale socket, the old file cannot be removed,
/// the bind fails or the mode cannot be set.
pub fn bind_socket(path: &Path) -> Result<UnixListener, Error> {
    bind_with(path, 0o600, None)
}

/// Binds the hook socket at `path` with mode 0660 and group `gid`, when one is given.
///
/// Stale-socket handling is that of [`bind_socket`]. The group is set before the mode, so
/// the socket is never group-writable under the wrong group.
///
/// # Errors
///
/// Fails like [`bind_socket`], or when the group cannot be set.
pub fn bind_hook_socket(path: &Path, gid: Option<u32>) -> Result<UnixListener, Error> {
    bind_with(path, 0o660, gid)
}

fn bind_with(path: &Path, mode: u32, gid: Option<u32>) -> Result<UnixListener, Error> {
    let io = |source| Error::Io {
        path: path.to_owned(),
        source,
    };
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.file_type().is_socket() {
                return Err(io(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "path exists and is not a socket",
                )));
            }
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                return Err(io(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    "another process is listening on the socket",
                )));
            }
            std::fs::remove_file(path).map_err(io)?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(io(err)),
    }
    let listener = UnixListener::bind(path).map_err(io)?;
    if let Some(gid) = gid {
        std::os::unix::fs::chown(path, None, Some(gid)).map_err(io)?;
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io)?;
    Ok(listener)
}

fn hook_group(config: &Config) -> Result<Option<u32>, Error> {
    let Some(spec) = config.hook_socket_group.as_deref() else {
        return Ok(None);
    };
    let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
    group_id(spec, &groups)
        .map(Some)
        .ok_or(Error::InvalidValue {
            name: "hook_socket_group",
            value: spec.to_owned(),
        })
}

fn load_redactor(config: &Config) -> Result<Redactor, Error> {
    match std::fs::read_to_string(&config.secrets_file.path) {
        Ok(text) => {
            let redactor = Redactor::from_env_file(&text);
            for key in redactor.skipped_keys() {
                tracing::warn!(key, "secret too short or trivial, not redacted");
            }
            tracing::info!(
                secrets = redactor.len(),
                skipped = ?redactor.skipped_keys(),
                "redaction loaded"
            );
            Ok(redactor)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !config.secrets_file.required => {
            tracing::warn!(path = %config.secrets_file.path.display(), "no secrets file, redaction disabled");
            Ok(Redactor::default())
        }
        Err(source) => Err(Error::Io {
            path: config.secrets_file.path.clone(),
            source,
        }),
    }
}

type ListenerExit = (&'static str, std::io::Result<()>);

fn serve(
    tasks: &mut JoinSet<ListenerExit>,
    name: &'static str,
    server: impl Future<Output = std::io::Result<()>> + Send + 'static,
) {
    tasks.spawn(async move { (name, server.await) });
}

fn listener_exit(joined: Result<ListenerExit, JoinError>) -> Result<(), Error> {
    let (name, cause) = match joined {
        Ok((name, Ok(()))) => (
            name,
            std::io::Error::other("listener ended before shutdown"),
        ),
        Ok((name, Err(err))) => (name, err),
        Err(err) => ("listener", std::io::Error::other(err)),
    };
    tracing::error!(%cause, listener = name, "listener stopped, exiting");
    Err(Error::Runtime(cause))
}

async fn wait_for(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

async fn exited(
    slot: &mut Option<JoinHandle<()>>,
    name: &'static str,
) -> Result<ListenerExit, JoinError> {
    let Some(handle) = slot.as_mut() else {
        return std::future::pending().await;
    };
    let joined = handle.await;
    *slot = None;
    joined.map(|()| (name, Ok(())))
}

async fn first_exit(
    tasks: &mut JoinSet<ListenerExit>,
    poller: &mut Option<JoinHandle<()>>,
    heartbeat: &mut Option<JoinHandle<()>>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    tokio::select! {
        () = shutdown => Ok(()),
        Some(joined) = tasks.join_next() => listener_exit(joined),
        joined = exited(poller, "poller") => listener_exit(joined),
        joined = exited(heartbeat, "heartbeat") => listener_exit(joined),
    }
}

/// A listener the watchdog checks with a real `GET /healthz`.
#[derive(Debug, Clone)]
enum Listener {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

async fn healthz_ok(stream: impl AsyncRead + AsyncWrite + Unpin) -> std::io::Result<bool> {
    let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    match roundtrip(stream, request).await {
        Ok(response) => Ok(response.status == 200 && response.body.trim() == "ok"),
        Err(Failure::NotSent) => Err(std::io::Error::other("healthz request was not sent")),
        Err(Failure::Unanswered(err)) => Err(err),
    }
}

impl Listener {
    async fn healthy(&self, timeout: Duration) -> bool {
        let check = async {
            match self {
                Self::Tcp(addr) => healthz_ok(TcpStream::connect(addr).await?).await,
                Self::Unix(path) => healthz_ok(UnixStream::connect(path).await?).await,
            }
        };
        match tokio::time::timeout(timeout, check).await {
            Ok(Ok(true)) => true,
            Ok(Ok(false)) => {
                tracing::warn!(listener = ?self, "healthz did not answer 200 ok");
                false
            }
            Ok(Err(err)) => {
                tracing::warn!(%err, listener = ?self, "healthz round trip failed");
                false
            }
            Err(_) => {
                tracing::warn!(listener = ?self, "healthz round trip timed out");
                false
            }
        }
    }
}

async fn all_healthy(listeners: &[Listener], timeout: Duration) -> bool {
    let mut checks = JoinSet::new();
    for listener in listeners {
        let listener = listener.clone();
        checks.spawn(async move { listener.healthy(timeout).await });
    }
    let mut healthy = true;
    while let Some(done) = checks.join_next().await {
        healthy &= done.unwrap_or(false);
    }
    healthy
}

fn watchdog_interval(period: Duration) -> Interval {
    let mut tick = tokio::time::interval(period);
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    tick
}

async fn watchdog(listeners: Vec<Listener>, period: Duration, ping: impl Fn()) {
    let timeout = probe_timeout(period);
    let mut tick = watchdog_interval(period);
    loop {
        tick.tick().await;
        if all_healthy(&listeners, timeout).await {
            ping();
        } else {
            tracing::error!("a listener failed its healthz check, withholding watchdog ping");
        }
    }
}

fn watchdog_period() -> Duration {
    period_for(sd_notify::watchdog_enabled())
}

fn period_for(limit: Option<Duration>) -> Duration {
    limit
        .map_or(DEFAULT_WATCHDOG_PERIOD, |limit| limit / 2)
        .max(MIN_WATCHDOG_PERIOD)
}

/// The health probe budget for a watchdog `period`: at most 3 seconds and always half
/// the period or less, so a probe ends before the next tick is due.
fn probe_timeout(period: Duration) -> Duration {
    MAX_HEALTH_TIMEOUT.min(period / 2)
}

/// Runs the daemon until `shutdown` resolves or a listener ends.
///
/// Opens the queue, binds the loopback listener and the unix socket, sends `READY=1`,
/// then pings the systemd watchdog every half `WatchdogSec`. Each tick makes one
/// `GET /healthz` round trip to each listener and sends `WATCHDOG=1` only when every
/// listener answers 200 within half the watchdog period, capped at 3 seconds. On
/// shutdown it stops the listeners, aborting any that outlast a 10 second grace period,
/// checkpoints the WAL and removes the socket file. While `FLEET_SERVER_URL` is set it
/// also sends a heartbeat every 30 seconds with `FLEET_TOKEN` as the bearer token, and a
/// job poller claims one job at a time. On shutdown the poller stops the running job's
/// process group and the runner reports it `FAILED`, within 15 seconds. The unit's
/// `TimeoutStopSec=15` equals that grace, so systemd can send `SIGKILL` before the final
/// report and cleanup finish. A bad URL or token disables the poller with a warning.
///
/// # Errors
///
/// Fails on config, queue or bind errors at startup. Fails after cleanup when a
/// listener, the job poller or the heartbeat ends before `shutdown`, so the process exits
/// non-zero.
pub async fn run(config: Config, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
    run_with_env(config, &|name| std::env::var(name).ok(), shutdown).await
}

/// Runs the daemon like [`run`], reading `FLEET_SERVER_URL` and `FLEET_TOKEN` through `env`.
///
/// # Errors
///
/// Fails like [`run`].
pub async fn run_with_env(
    config: Config,
    env: &(dyn Fn(&str) -> Option<String> + Sync),
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let identity = read_identity(config.box_name.as_deref());
    tracing::info!(box_name = %identity.box_name, boot_id = %identity.boot_id, "starting");
    let redactor = load_redactor(&config)?;
    let store = Store::open(
        &config.db_path,
        Limits {
            max_bytes: config.queue_max_bytes,
            max_age: config.queue_max_age,
        },
    )
    .await?;
    let heartbeat = match Heartbeat::from_env(env) {
        Ok(target) => target,
        Err(err) => {
            tracing::warn!(%err, "heartbeat disabled");
            None
        }
    };
    let hub = HookHub::new();
    let jobs = match jobs::build(
        &config,
        env,
        &identity.box_name,
        redactor.clone(),
        hub.clone(),
    ) {
        Ok(poller) => poller,
        Err(err) => {
            tracing::warn!(%err, "job poller disabled");
            None
        }
    };
    run_with_hub(
        config,
        store,
        identity,
        redactor,
        heartbeat,
        jobs,
        hub,
        Path::new(systemd::DEFAULT_RUN_DIR),
        Path::new(managed_settings::DEFAULT_PATH),
        shutdown,
    )
    .await
}

type Bound = (TcpListener, SocketAddr, UnixListener, Option<UnixListener>);

async fn bind_all(config: &Config) -> Result<Bound, Error> {
    let gid = hook_group(config)?;
    let tcp = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, config.http_port)))
        .await
        .map_err(Error::Runtime)?;
    let tcp_addr = tcp.local_addr().map_err(Error::Runtime)?;
    let socket = bind_socket(&config.socket_path)?;
    let hook = match config.hook_socket.as_deref() {
        Some(path) => match bind_hook_socket(path, gid) {
            Ok(listener) => Some(listener),
            Err(err) => {
                let _ = std::fs::remove_file(&config.socket_path);
                return Err(err);
            }
        },
        None => None,
    };
    Ok((tcp, tcp_addr, socket, hook))
}

#[cfg(test)]
async fn run_with_store(
    config: Config,
    store: Store,
    identity: Identity,
    redactor: Redactor,
    heartbeat: Option<Heartbeat>,
    jobs: Option<JobPoller>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    run_with_hub(
        config,
        store,
        identity,
        redactor,
        heartbeat,
        jobs,
        HookHub::new(),
        Path::new(systemd::DEFAULT_RUN_DIR),
        Path::new(managed_settings::DEFAULT_PATH),
        shutdown,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    reason = "one call site wires the shared pieces together"
)]
async fn run_with_hub(
    config: Config,
    store: Store,
    identity: Identity,
    redactor: Redactor,
    heartbeat: Option<Heartbeat>,
    jobs: Option<JobPoller>,
    hub: Arc<HookHub>,
    run_root: &Path,
    managed_settings: &Path,
    shutdown: impl Future<Output = ()>,
) -> Result<(), Error> {
    let (tcp, tcp_addr, socket, hook_socket) = match bind_all(&config).await {
        Ok(bound) => bound,
        Err(err) => {
            if let Err(close_err) = store.clone().close().await {
                tracing::warn!(%close_err, "closing the queue after a failed bind failed");
            }
            return Err(err);
        }
    };
    systemd::sweep_stale_runs(&config, run_root).await;
    managed_settings::audit(managed_settings);
    let heartbeat_identity = identity.clone();
    let state = AppState::with_hub(
        store.clone(),
        identity,
        HookAllowlist::new(config.hook_events.iter().cloned()),
        redactor,
        config.dedupe_window,
        hub,
    );

    tracing::info!(addr = %tcp_addr, socket = %config.socket_path.display(), "listening");

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tasks = JoinSet::new();
    serve(
        &mut tasks,
        "tcp",
        axum::serve(tcp, hook_router(state.clone()))
            .with_graceful_shutdown(wait_for(stop_rx.clone()))
            .into_future(),
    );
    serve(
        &mut tasks,
        "socket",
        axum::serve(socket, socket_router(state.clone()))
            .with_graceful_shutdown(wait_for(stop_rx.clone()))
            .into_future(),
    );
    if let Some(listener) = hook_socket {
        serve(
            &mut tasks,
            "hook socket",
            axum::serve(listener, hook_socket_router(state))
                .with_graceful_shutdown(wait_for(stop_rx.clone()))
                .into_future(),
        );
    }
    let mut poller = jobs.map(|poller| tokio::spawn(poller.run(wait_for(stop_rx.clone()))));
    let mut heartbeat = heartbeat.map(|target| {
        tokio::spawn(target.run(heartbeat_identity, store.clone(), wait_for(stop_rx)))
    });
    let mut probed = vec![
        Listener::Tcp(tcp_addr),
        Listener::Unix(config.socket_path.clone()),
    ];
    probed.extend(config.hook_socket.iter().cloned().map(Listener::Unix));
    let dog = tokio::spawn(watchdog(probed, watchdog_period(), || {
        let _ = sd_notify::notify(&[NotifyState::Watchdog]);
    }));
    let _ = sd_notify::notify(&[NotifyState::Ready]);

    let outcome = first_exit(&mut tasks, &mut poller, &mut heartbeat, shutdown).await;
    tracing::info!("shutting down");
    let _ = sd_notify::notify(&[NotifyState::Stopping]);
    dog.abort();
    let _ = stop_tx.send(true);
    if let Some(poller) = poller.as_mut()
        && tokio::time::timeout(JOBS_GRACE, &mut *poller)
            .await
            .is_err()
    {
        poller.abort();
    }
    if let Some(heartbeat) = heartbeat.as_mut()
        && tokio::time::timeout(SHUTDOWN_GRACE, &mut *heartbeat)
            .await
            .is_err()
    {
        heartbeat.abort();
    }
    let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        tracing::warn!("listeners did not drain in time, aborting them");
        tasks.abort_all();
    }
    let _ = std::fs::remove_file(&config.socket_path);
    if let Some(path) = &config.hook_socket {
        let _ = std::fs::remove_file(path);
    }
    let closed = store.close().await;
    let result = outcome.and(closed);
    if result.is_ok() {
        tracing::info!("stopped");
    }
    result
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::routing::get;
    use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
    use fleet_proto::v1::{HeartbeatReply, HeartbeatRequest, PushEventsReply, PushEventsRequest};
    use tempfile::TempDir;

    use super::*;

    fn app() -> Router {
        Router::new().route("/healthz", get(|| async { "ok" }))
    }

    async fn serve_tcp() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app()).await;
        });
        (addr, task)
    }

    async fn closed_addr() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        listener.local_addr().unwrap()
    }

    async fn pings_within(listeners: Vec<Listener>, wait: Duration) -> usize {
        let count = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        let dog = tokio::spawn(watchdog(listeners, Duration::from_millis(20), move || {
            seen.fetch_add(1, Ordering::SeqCst);
        }));
        tokio::time::sleep(wait).await;
        dog.abort();
        count.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn tick_pings_when_every_listener_answers() {
        let dir = TempDir::new().unwrap();
        let (addr, _tcp) = serve_tcp().await;
        let path = dir.path().join("s.sock");
        let unix = UnixListener::bind(&path).unwrap();
        let _sock = tokio::spawn(async move {
            let _ = axum::serve(unix, app()).await;
        });
        let listeners = vec![Listener::Tcp(addr), Listener::Unix(path)];
        assert!(all_healthy(&listeners, Duration::from_secs(1)).await);
        assert!(pings_within(listeners, Duration::from_millis(300)).await >= 1);
    }

    #[tokio::test]
    async fn tick_withholds_when_a_listener_is_closed() {
        let (addr, _tcp) = serve_tcp().await;
        let dead = closed_addr().await;
        let listeners = vec![Listener::Tcp(addr), Listener::Tcp(dead)];
        assert!(!all_healthy(&listeners, Duration::from_secs(1)).await);
        assert_eq!(pings_within(listeners, Duration::from_millis(300)).await, 0);
    }

    #[tokio::test]
    async fn tick_withholds_when_the_listener_answers_something_else() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _task = tokio::spawn(async move {
            let _ = axum::serve(listener, Router::new()).await;
        });
        assert!(!all_healthy(&[Listener::Tcp(addr)], Duration::from_secs(1)).await);
    }

    #[test]
    fn probe_timeout_stays_below_every_period() {
        let limits = [
            None,
            Some(Duration::from_millis(2)),
            Some(Duration::from_secs(1)),
            Some(Duration::from_secs(30)),
            Some(Duration::from_secs(600)),
        ];
        for limit in limits {
            let period = period_for(limit);
            assert!(probe_timeout(period) < period, "{limit:?}");
            assert!(probe_timeout(period) <= MAX_HEALTH_TIMEOUT);
        }
    }

    #[tokio::test]
    async fn the_watchdog_interval_delays_missed_ticks() {
        let tick = watchdog_interval(Duration::from_millis(20));
        assert_eq!(tick.missed_tick_behavior(), MissedTickBehavior::Delay);
    }

    async fn exit_of(poller: Option<JoinHandle<()>>, heartbeat: Option<JoinHandle<()>>) -> bool {
        let mut tasks = JoinSet::new();
        let (mut poller, mut heartbeat) = (poller, heartbeat);
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            first_exit(
                &mut tasks,
                &mut poller,
                &mut heartbeat,
                std::future::pending(),
            ),
        )
        .await;
        matches!(outcome, Ok(Err(Error::Runtime(_)))) && poller.is_none() && heartbeat.is_none()
    }

    #[tokio::test(start_paused = true)]
    async fn a_poller_that_ends_before_shutdown_is_fatal() {
        assert!(exit_of(Some(tokio::spawn(async {})), None).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_heartbeat_that_ends_before_shutdown_is_fatal() {
        assert!(exit_of(None, Some(tokio::spawn(async {}))).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_panicking_poller_is_fatal() {
        let task = tokio::spawn(async { panic!("poller panic") });
        assert!(exit_of(Some(task), None).await);
    }

    #[tokio::test(start_paused = true)]
    async fn a_running_poller_and_heartbeat_do_not_end_the_wait() {
        let mut tasks = JoinSet::new();
        let mut poller = Some(tokio::spawn(std::future::pending()));
        let mut heartbeat = Some(tokio::spawn(std::future::pending()));
        let outcome = first_exit(&mut tasks, &mut poller, &mut heartbeat, async {}).await;
        assert!(outcome.is_ok());
        assert!(poller.is_some() && heartbeat.is_some());
    }

    #[tokio::test(start_paused = true)]
    async fn a_stalled_tick_is_not_followed_by_catch_up_ticks() {
        let period = Duration::from_millis(60);
        let mut tick = watchdog_interval(period);
        tick.tick().await;
        tokio::time::sleep(Duration::from_secs(5)).await;
        tick.tick().await;
        let started = tokio::time::Instant::now();
        tick.tick().await;
        assert_eq!(started.elapsed(), period);
    }

    #[tokio::test(start_paused = true)]
    async fn a_listener_that_never_answers_is_probed_once_per_period()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&accepted);
        let _slow = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                seen.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _held = stream;
                    std::future::pending::<()>().await;
                });
            }
        });
        let pings = pings_within(vec![Listener::Tcp(addr)], Duration::from_secs(10)).await;
        assert_eq!(pings, 0);
        let probes = accepted.load(Ordering::SeqCst);
        assert!((50..=501).contains(&probes), "{probes}");
        Ok(())
    }

    fn test_config(dir: &TempDir, port: u16) -> Result<Config, Error> {
        let file = format!(
            "http_port = {port}\nsocket_path = \"{}\"\n",
            dir.path().join("fleetd.sock").display()
        );
        Config::resolve(Some(&file), &|_| None)
    }

    async fn open_store(dir: &TempDir) -> Result<Store, Error> {
        Store::open(
            &dir.path().join("q.db"),
            Limits {
                max_bytes: u64::MAX,
                max_age: Duration::from_secs(60),
            },
        )
        .await
    }

    fn test_identity() -> Identity {
        Identity {
            box_name: "alpha".into(),
            hostname: "host".into(),
            machine_id: "machine".into(),
            boot_id: "boot".into(),
        }
    }

    #[tokio::test]
    async fn a_taken_port_fails_startup_and_closes_the_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = taken.local_addr()?.port();
        let store = open_store(&dir).await?;
        let result = run_with_store(
            test_config(&dir, port)?,
            store.clone(),
            test_identity(),
            Redactor::default(),
            None,
            None,
            std::future::pending(),
        )
        .await;
        assert!(matches!(result, Err(Error::Runtime(_))), "{result:?}");
        assert!(store.is_closed());
        Ok(())
    }

    #[tokio::test]
    async fn a_socket_bind_failure_closes_the_store() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let store = open_store(&dir).await?;
        let mut config = test_config(&dir, 0)?;
        config.socket_path = dir.path().join("missing").join("fleetd.sock");
        let result = run_with_store(
            config,
            store.clone(),
            test_identity(),
            Redactor::default(),
            None,
            None,
            std::future::pending(),
        )
        .await;
        assert!(result.is_err());
        assert!(store.is_closed());
        Ok(())
    }

    const GROUPS: &str = "root:x:0:\nfleet-work:x:996:agent,fleet-job\nbroken:x:abc:\n";

    #[test]
    fn group_id_takes_a_number_or_a_name_from_the_group_file() {
        assert_eq!(group_id("1234", GROUPS), Some(1234));
        assert_eq!(group_id("fleet-work", GROUPS), Some(996));
        assert_eq!(group_id("root", GROUPS), Some(0));
        assert_eq!(group_id("fleet", GROUPS), None);
        assert_eq!(group_id("broken", GROUPS), None);
        assert_eq!(group_id("nobody", ""), None);
    }

    #[tokio::test]
    async fn the_hook_socket_is_0660_and_takes_the_group() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::MetadataExt;

        let dir = TempDir::new()?;
        let plain = dir.path().join("plain.sock");
        let _plain = bind_hook_socket(&plain, None)?;
        assert_eq!(std::fs::metadata(&plain)?.mode() & 0o777, 0o660);
        let gid = rustix::process::getegid().as_raw();
        let grouped = dir.path().join("grouped.sock");
        let _grouped = bind_hook_socket(&grouped, Some(gid))?;
        let meta = std::fs::metadata(&grouped)?;
        assert_eq!((meta.mode() & 0o777, meta.gid()), (0o660, gid));
        let main = dir.path().join("main.sock");
        let _main = bind_socket(&main)?;
        assert_eq!(std::fs::metadata(&main)?.mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn an_unknown_hook_group_is_a_startup_error() -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let mut config = test_config(&dir, 0)?;
        config.hook_socket_group = Some("no-such-group-zz9".to_owned());
        assert!(matches!(
            hook_group(&config),
            Err(Error::InvalidValue {
                name: "hook_socket_group",
                ..
            })
        ));
        config.hook_socket_group = None;
        assert!(matches!(hook_group(&config), Ok(None)));
        Ok(())
    }

    #[tokio::test]
    async fn a_hook_socket_bind_failure_removes_the_main_socket_and_closes_the_store()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let store = open_store(&dir).await?;
        let mut config = test_config(&dir, 0)?;
        config.hook_socket = Some(dir.path().join("missing").join("hook.sock"));
        let result = run_with_store(
            config.clone(),
            store.clone(),
            test_identity(),
            Redactor::default(),
            None,
            None,
            std::future::pending(),
        )
        .await;
        assert!(result.is_err());
        assert!(store.is_closed());
        assert!(!config.socket_path.exists());
        Ok(())
    }

    const FAKE_SYSTEMCTL: &str = "#!/bin/sh\necho \"$@\" >> \"$(dirname \"$0\")/calls.log\"\nprintf 'ActiveState=inactive\\nSubState=dead\\nResult=success\\nExecMainCode=0\\nExecMainStatus=0\\n'\n";

    fn fake_systemctl() -> &'static Path {
        use std::os::unix::fs::PermissionsExt;
        static DIR: std::sync::OnceLock<TempDir> = std::sync::OnceLock::new();
        let dir = DIR.get_or_init(|| {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("systemctl");
            std::fs::write(&path, FAKE_SYSTEMCTL).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            dir
        });
        dir.path()
    }

    #[tokio::test]
    async fn a_failed_bind_sweeps_no_run_dir_and_issues_no_systemctl_call()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let ctl = fake_systemctl();
        let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = taken.local_addr()?.port();
        let run_root = dir.path().join("run");
        let stale = run_root.join("job1");
        std::fs::create_dir_all(&stale)?;
        let mut config = test_config(&dir, port)?;
        config.agent_launcher = crate::config::AgentLauncher::Systemd;
        config.systemctl_path = ctl.join("systemctl");
        let store = open_store(&dir).await?;
        let result = run_with_hub(
            config,
            store,
            test_identity(),
            Redactor::default(),
            None,
            None,
            HookHub::new(),
            &run_root,
            Path::new(managed_settings::DEFAULT_PATH),
            std::future::pending(),
        )
        .await;
        assert!(matches!(result, Err(Error::Runtime(_))), "{result:?}");
        assert!(stale.exists());
        assert!(!ctl.join("calls.log").exists());
        Ok(())
    }

    #[derive(Clone, Default)]
    struct LogSink(Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogSink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[tokio::test]
    async fn startup_warns_when_the_managed_settings_hold_http_hooks()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let settings = dir.path().join("managed-settings.json");
        std::fs::write(
            &settings,
            r#"{"hooks":{"Stop":[{"hooks":[{"type":"http","url":"http://127.0.0.1:7071/x"}]}]}}"#,
        )?;
        let sink = LogSink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let store = open_store(&dir).await?;
        let result = run_with_hub(
            test_config(&dir, 0)?,
            store,
            test_identity(),
            Redactor::default(),
            None,
            None,
            HookHub::new(),
            &dir.path().join("run"),
            &settings,
            tokio::time::sleep(Duration::from_millis(200)),
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        let out = String::from_utf8(sink.0.lock().unwrap().clone())?;
        assert!(out.contains("WARN") && out.contains("http hooks"), "{out}");
        Ok(())
    }

    async fn status_of(path: &Path, request: &str) -> Result<u16, Box<dyn std::error::Error>> {
        let stream = UnixStream::connect(path).await?;
        let response = roundtrip(stream, request.as_bytes())
            .await
            .map_err(|_| "no response")?;
        Ok(response.status)
    }

    #[tokio::test]
    async fn the_hook_socket_serves_only_hook_routes_and_is_removed_at_shutdown()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let store = open_store(&dir).await?;
        let mut config = test_config(&dir, 0)?;
        let hook = dir.path().join("hook.sock");
        config.hook_socket = Some(hook.clone());
        let main = config.socket_path.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let daemon = tokio::spawn(run_with_store(
            config,
            store,
            test_identity(),
            Redactor::default(),
            None,
            None,
            async {
                let _ = stopped.await;
            },
        ));
        let mut waited = 0;
        while !(hook.exists() && main.exists()) && waited < 500 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            waited += 1;
        }
        let post = |path: &str| {
            format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
        };
        let get = "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        assert_eq!(status_of(&hook, &post("/event")).await?, 404);
        assert_eq!(status_of(&hook, get).await?, 200);
        assert_eq!(status_of(&hook, &post("/hook/PostToolUse")).await?, 200);
        assert_eq!(status_of(&main, &post("/event")).await?, 400);
        let _ = stop.send(());
        daemon.await??;
        assert!(!hook.exists());
        assert!(!main.exists());
        Ok(())
    }

    struct Counter(tokio::sync::mpsc::UnboundedSender<()>);

    #[tonic::async_trait]
    impl FleetIngest for Counter {
        async fn push_events(
            &self,
            _request: tonic::Request<PushEventsRequest>,
        ) -> Result<tonic::Response<PushEventsReply>, tonic::Status> {
            Err(tonic::Status::unimplemented("unused"))
        }

        async fn heartbeat(
            &self,
            _request: tonic::Request<HeartbeatRequest>,
        ) -> Result<tonic::Response<HeartbeatReply>, tonic::Status> {
            let _ = self.0.send(());
            Ok(tonic::Response::new(HeartbeatReply { next_in_s: 30 }))
        }
    }

    #[tokio::test]
    async fn a_server_target_spawns_the_heartbeat_and_shutdown_stops_it_first()
    -> Result<(), Box<dyn std::error::Error>> {
        let wide = Duration::from_secs(5);
        let (beats, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let incoming =
            tonic::transport::server::TcpIncoming::bind((Ipv4Addr::LOCALHOST, 0).into())?;
        let addr = incoming.local_addr()?;
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FleetIngestServer::new(Counter(beats)))
                .serve_with_incoming(incoming),
        );
        let target = Heartbeat::new(&format!("http://{addr}"), "runtime-token-0123456789")?
            .with_period(Duration::from_millis(100));
        let dir = TempDir::new()?;
        let store = open_store(&dir).await?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_with_store(
            test_config(&dir, 0)?,
            store.clone(),
            test_identity(),
            Redactor::default(),
            Some(target),
            None,
            async move {
                let _ = stopped.await;
            },
        ));
        for _ in 0..2 {
            tokio::time::timeout(wide, rx.recv())
                .await?
                .ok_or("stub closed")?;
        }
        let _ = stop.send(());
        tokio::time::timeout(wide, task).await???;
        assert!(store.is_closed());
        while rx.try_recv().is_ok() {}
        let late = tokio::time::timeout(Duration::from_millis(500), rx.recv()).await;
        assert!(
            late.is_err(),
            "heartbeat sent after run_with_store returned"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_listener_finishing_is_the_fatal_exit() {
        let mut tasks = JoinSet::new();
        serve(&mut tasks, "tcp", async { Ok(()) });
        let outcome = first_exit(&mut tasks, &mut None, &mut None, std::future::pending()).await;
        assert!(matches!(outcome, Err(Error::Runtime(_))));
    }

    #[tokio::test]
    async fn shutdown_without_a_listener_exit_is_clean() {
        let mut tasks = JoinSet::new();
        serve(&mut tasks, "tcp", std::future::pending());
        assert!(
            first_exit(&mut tasks, &mut None, &mut None, async {})
                .await
                .is_ok()
        );
    }
}
