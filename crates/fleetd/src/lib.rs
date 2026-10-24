//! fleetd: the per-box Fleet daemon.
//!
//! Hooks and local tools post events. fleetd normalizes and redacts them, then commits
//! each to a SQLite queue before it answers.

mod app;
mod config;
mod dump;
mod error;
mod queue;
mod runtime;
mod system;

pub use app::{AppState, hook_router, socket_router};
pub use config::{Config, DEFAULT_CONFIG_PATH, DEFAULT_SECRETS_PATH, SecretsFile};
pub use dump::dump;
pub use error::Error;
pub use queue::{Enqueued, Limits, OVERFLOW_KIND, Queue, QueuedEvent};
pub use runtime::{Signals, bind_socket, run};
pub use system::{fresh_id, now_ms, read_identity};
