use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use fleet_core::{HookAllowlist, Redactor};
use sd_notify::NotifyState;
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinError, JoinHandle};

use crate::Error;
use crate::app::{AppState, hook_router, socket_router};
use crate::config::Config;
use crate::events::Limits;
use crate::store::Store;
use crate::system::read_identity;

const DEFAULT_WATCHDOG_PERIOD: Duration = Duration::from_secs(20);
const MIN_WATCHDOG_PERIOD: Duration = Duration::from_millis(1);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
const STALL_LIMIT: Duration = Duration::from_secs(30);
const PROBE_PERIOD: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_SLICE: Duration = Duration::from_secs(10);

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
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    Ok(listener)
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

fn serve_task(
    server: impl Future<Output = std::io::Result<()>> + Send + 'static,
) -> JoinHandle<std::io::Result<()>> {
    tokio::spawn(server)
}

fn listener_exit(
    name: &'static str,
    joined: Result<std::io::Result<()>, JoinError>,
) -> Result<(), Error> {
    let cause = match joined {
        Ok(Ok(())) => std::io::Error::other("listener ended before shutdown"),
        Ok(Err(err)) => err,
        Err(err) => std::io::Error::other(err),
    };
    tracing::error!(%cause, listener = name, "listener stopped, exiting");
    Err(Error::Runtime(cause))
}

async fn wait_for(mut rx: watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

/// Progress counter that a supervised task bumps on each loop turn.
///
/// Clones share one counter. The [`Supervisor`] flags a task whose counter stops moving.
#[derive(Debug, Clone, Default)]
pub struct Progress(Arc<AtomicU64>);

impl Progress {
    /// Creates a counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that the task made progress.
    pub fn bump(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Sleeps for `total` in slices of at most 10 seconds, bumping `progress` before each
/// slice and once after the last, so a long backoff does not look like a stall.
pub async fn sleep_beating(total: Duration, progress: &Progress) {
    let deadline = tokio::time::Instant::now() + total;
    loop {
        progress.bump();
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return;
        }
        tokio::time::sleep(left.min(MAX_SLICE)).await;
    }
}

#[derive(Debug)]
struct Tracked {
    name: &'static str,
    progress: Progress,
    seen: u64,
    advanced_at: tokio::time::Instant,
    handle: Option<AbortHandle>,
}

/// The set of tasks whose liveness gates the systemd watchdog.
///
/// A task is healthy while its [`Progress`] advanced within the last 30 seconds and, when
/// it has a handle, the task has not finished.
#[derive(Debug, Default)]
pub struct Supervisor {
    tasks: Vec<Tracked>,
}

impl Supervisor {
    /// Creates an empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a task. Its 30 second window starts now. Pass the task's abort handle to
    /// treat an early exit as unhealthy.
    pub fn register(
        &mut self,
        name: &'static str,
        progress: &Progress,
        handle: Option<AbortHandle>,
    ) {
        self.tasks.push(Tracked {
            name,
            progress: progress.clone(),
            seen: progress.get(),
            advanced_at: tokio::time::Instant::now(),
            handle,
        });
    }

    /// Names of the tasks that are stalled or finished at `now`. Empty means healthy.
    pub fn unhealthy(&mut self, now: tokio::time::Instant) -> Vec<&'static str> {
        let mut bad = Vec::new();
        for task in &mut self.tasks {
            let count = task.progress.get();
            if count != task.seen {
                task.seen = count;
                task.advanced_at = now;
            }
            let finished = task.handle.as_ref().is_some_and(AbortHandle::is_finished);
            if finished || now.saturating_duration_since(task.advanced_at) > STALL_LIMIT {
                bad.push(task.name);
            }
        }
        bad
    }
}

#[derive(Debug, Clone)]
enum Probe {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl Probe {
    async fn connect(&self) -> std::io::Result<()> {
        match self {
            Self::Tcp(addr) => TcpStream::connect(addr).await.map(drop),
            Self::Unix(path) => UnixStream::connect(path).await.map(drop),
        }
    }
}

async fn probe_loop(target: Probe, progress: Progress) {
    let mut tick = tokio::time::interval(PROBE_PERIOD);
    loop {
        tick.tick().await;
        match tokio::time::timeout(PROBE_TIMEOUT, target.connect()).await {
            Ok(Ok(())) => progress.bump(),
            Ok(Err(err)) => tracing::warn!(%err, probe = ?target, "listener probe failed"),
            Err(_) => tracing::warn!(probe = ?target, "listener probe timed out"),
        }
    }
}

async fn watchdog(mut supervisor: Supervisor) {
    let period = sd_notify::watchdog_enabled()
        .map_or(DEFAULT_WATCHDOG_PERIOD, |limit| limit / 2)
        .max(MIN_WATCHDOG_PERIOD);
    let mut tick = tokio::time::interval(period);
    loop {
        tick.tick().await;
        let bad = supervisor.unhealthy(tokio::time::Instant::now());
        if bad.is_empty() {
            let _ = sd_notify::notify(&[NotifyState::Watchdog]);
        } else {
            tracing::error!(tasks = ?bad, "task stalled or ended, withholding watchdog ping");
        }
    }
}

/// Runs the daemon until `shutdown` resolves or a listener ends.
///
/// Opens the queue, binds the loopback listener and the unix socket, sends `READY=1`,
/// then pings the systemd watchdog while every supervised task advances. Each listener is
/// probed by a connection to its own address every 10 seconds. On shutdown it stops the
/// listeners, aborting any that outlast a 10 second grace period, checkpoints the WAL
/// and removes the socket file.
///
/// # Errors
///
/// Fails on config, queue or bind errors at startup. Fails after cleanup when a
/// listener ends before `shutdown`, so the process exits non-zero.
pub async fn run(config: Config, shutdown: impl Future<Output = ()>) -> Result<(), Error> {
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
    let state = AppState::new(
        store.clone(),
        identity,
        HookAllowlist::new(config.hook_events.iter().cloned()),
        redactor,
        config.dedupe_window,
    );

    let tcp = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, config.http_port)))
        .await
        .map_err(Error::Runtime)?;
    let tcp_addr = tcp.local_addr().map_err(Error::Runtime)?;
    let socket = bind_socket(&config.socket_path)?;
    tracing::info!(addr = ?tcp.local_addr().ok(), socket = %config.socket_path.display(), "listening");

    let (stop_tx, stop_rx) = watch::channel(false);
    let mut tcp_task = serve_task(
        axum::serve(tcp, hook_router(state.clone()))
            .with_graceful_shutdown(wait_for(stop_rx.clone()))
            .into_future(),
    );
    let mut socket_task = serve_task(
        axum::serve(socket, socket_router(state))
            .with_graceful_shutdown(wait_for(stop_rx))
            .into_future(),
    );
    let tcp_progress = Progress::new();
    let socket_progress = Progress::new();
    let mut supervisor = Supervisor::new();
    supervisor.register("tcp", &tcp_progress, Some(tcp_task.abort_handle()));
    supervisor.register("socket", &socket_progress, Some(socket_task.abort_handle()));
    let probes = [
        tokio::spawn(probe_loop(Probe::Tcp(tcp_addr), tcp_progress)),
        tokio::spawn(probe_loop(
            Probe::Unix(config.socket_path.clone()),
            socket_progress,
        )),
    ];
    let dog = tokio::spawn(watchdog(supervisor));
    let _ = sd_notify::notify(&[NotifyState::Ready]);

    let mut tcp_done = false;
    let mut socket_done = false;
    let outcome = tokio::select! {
        () = shutdown => Ok(()),
        joined = &mut tcp_task => {
            tcp_done = true;
            listener_exit("tcp", joined)
        }
        joined = &mut socket_task => {
            socket_done = true;
            listener_exit("socket", joined)
        }
    };
    tracing::info!("shutting down");
    let _ = sd_notify::notify(&[NotifyState::Stopping]);
    dog.abort();
    for probe in &probes {
        probe.abort();
    }
    let _ = stop_tx.send(true);
    let drained = tokio::time::timeout(SHUTDOWN_GRACE, async {
        if !tcp_done {
            let _ = (&mut tcp_task).await;
        }
        if !socket_done {
            let _ = (&mut socket_task).await;
        }
    })
    .await;
    if drained.is_err() {
        tracing::warn!("listeners did not drain in time, aborting them");
        tcp_task.abort();
        socket_task.abort();
    }
    let _ = std::fs::remove_file(&config.socket_path);
    let closed = store.close().await;
    let result = outcome.and(closed);
    if result.is_ok() {
        tracing::info!("stopped");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Instant, advance, sleep};

    async fn step(by: Duration) {
        advance(by).await;
        tokio::task::yield_now().await;
    }

    #[tokio::test(start_paused = true)]
    async fn beating_task_stays_healthy() {
        let progress = Progress::new();
        let beat = progress.clone();
        let task = tokio::spawn(async move {
            loop {
                beat.bump();
                sleep(Duration::from_secs(5)).await;
            }
        });
        let mut sup = Supervisor::new();
        sup.register("beater", &progress, Some(task.abort_handle()));
        for _ in 0..30 {
            step(Duration::from_secs(10)).await;
            assert_eq!(sup.unhealthy(Instant::now()), Vec::<&str>::new());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_task_is_flagged_after_thirty_seconds() {
        let progress = Progress::new();
        let beat = progress.clone();
        let task = tokio::spawn(async move {
            beat.bump();
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        let mut sup = Supervisor::new();
        sup.register("stalled", &progress, Some(task.abort_handle()));
        step(Duration::from_secs(1)).await;
        assert_eq!(sup.unhealthy(Instant::now()), Vec::<&str>::new());
        step(Duration::from_secs(28)).await;
        assert_eq!(sup.unhealthy(Instant::now()), Vec::<&str>::new());
        step(Duration::from_secs(2)).await;
        assert_eq!(sup.unhealthy(Instant::now()), vec!["stalled"]);
    }

    #[tokio::test(start_paused = true)]
    async fn one_stalled_task_taints_the_set() {
        let good = Progress::new();
        let bad = Progress::new();
        let beat = good.clone();
        let task = tokio::spawn(async move {
            loop {
                beat.bump();
                sleep(Duration::from_secs(5)).await;
            }
        });
        let mut sup = Supervisor::new();
        sup.register("good", &good, Some(task.abort_handle()));
        sup.register("bad", &bad, None);
        step(Duration::from_secs(31)).await;
        assert_eq!(sup.unhealthy(Instant::now()), vec!["bad"]);
    }

    #[tokio::test(start_paused = true)]
    async fn finished_task_is_flagged_at_once() {
        let progress = Progress::new();
        let task = tokio::spawn(async {});
        let mut sup = Supervisor::new();
        sup.register("gone", &progress, Some(task.abort_handle()));
        step(Duration::from_millis(1)).await;
        assert_eq!(sup.unhealthy(Instant::now()), vec!["gone"]);
    }

    #[tokio::test(start_paused = true)]
    async fn long_backoff_sleep_keeps_the_task_healthy() {
        let progress = Progress::new();
        let beat = progress.clone();
        let task = tokio::spawn(async move {
            sleep_beating(Duration::from_secs(300), &beat).await;
        });
        let mut sup = Supervisor::new();
        sup.register("backoff", &progress, Some(task.abort_handle()));
        for _ in 0..29 {
            step(Duration::from_secs(10)).await;
            assert_eq!(sup.unhealthy(Instant::now()), Vec::<&str>::new());
        }
    }
}
