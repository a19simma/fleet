//! fleetd: the per-box Fleet daemon.
//!
//! Hooks and local tools post events. fleetd normalizes and redacts them, then commits
//! each to a SQLite queue before it answers.

mod app;
mod config;
mod dump;
mod error;
pub mod events;
mod runtime;
mod store;
mod system;

pub use app::{AppState, hook_router, socket_router};
pub use config::{Config, DEFAULT_CONFIG_PATH, DEFAULT_SECRETS_PATH, SecretsFile};
pub use dump::dump;
pub use error::Error;
pub use events::{Enqueued, Limits, OVERFLOW_KIND, QueuedEvent};
pub use runtime::{Progress, Signals, Supervisor, bind_socket, run, sleep_beating};
pub use store::Store;
pub use system::{fresh_id, now_ms, read_identity};
