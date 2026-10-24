use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use fleet_core::{HookAllowlist, Redactor};
use sd_notify::NotifyState;
use tokio::net::{TcpListener, UnixListener};
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::sync::watch;
use tokio::task::{AbortHandle, JoinError, JoinHandle};

use crate::Error;
use crate::app::{AppState, hook_router, socket_router};
use crate::config::Config;
use crate::queue::{Limits, Queue};
use crate::system::read_identity;

const DEFAULT_WATCHDOG_PERIOD: Duration = Duration::from_secs(20);
const MIN_WATCHDOG_PERIOD: Duration = Duration::from_millis(1);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

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
            tracing::info!("redaction loaded");
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

async fn watchdog(listeners: Vec<AbortHandle>) {
    let period = sd_notify::watchdog_enabled()
        .map_or(DEFAULT_WATCHDOG_PERIOD, |limit| limit / 2)
        .max(MIN_WATCHDOG_PERIOD);
    let mut tick = tokio::time::interval(period);
    loop {
        tick.tick().await;
        if listeners.iter().all(|handle| !handle.is_finished()) {
            let _ = sd_notify::notify(&[NotifyState::Watchdog]);
        } else {
            tracing::error!("listener task ended, withholding watchdog ping");
        }
    }
}

/// Runs the daemon until `shutdown` resolves or a listener ends.
///
/// Opens the queue, binds the loopback listener and the unix socket, sends `READY=1`,
/// then pings the systemd watchdog while both listeners live. On shutdown it stops the
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
    let queue = Queue::open(
        &config.db_path,
        Limits {
            max_bytes: config.queue_max_bytes,
            max_age: config.queue_max_age,
        },
    )
    .await?;
    let state = AppState::new(
        queue.clone(),
        identity,
        HookAllowlist::new(config.hook_events.iter().cloned()),
        redactor,
        config.dedupe_window,
    );

    let tcp = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, config.http_port)))
        .await
        .map_err(Error::Runtime)?;
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
    let dog = tokio::spawn(watchdog(vec![
        tcp_task.abort_handle(),
        socket_task.abort_handle(),
    ]));
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
    let closed = queue.close().await;
    outcome.and(closed)
}
