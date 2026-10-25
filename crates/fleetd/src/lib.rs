//! fleetd: the per-box Fleet daemon.
//!
//! Hooks and local tools post events. fleetd normalizes and redacts them, then commits
//! each to a SQLite queue before it answers.
//!
//! While `FLEET_SERVER_URL` and `FLEET_TOKEN` are set, the daemon also runs jobs: [`poller`]
//! claims them, [`workspace`] prepares git worktrees, and [`runner`] runs the agent as a child
//! process, then pushes the branch and opens the pull request. The push's `GIT_ASKPASS` is
//! `fleetd askpass` ([`askpass`]).

pub mod agent_config;
mod app;
pub mod askpass;
pub mod backoff;
mod config;
mod dump;
mod error;
pub mod events;
pub mod forwarder;
mod group;
pub mod heartbeat;
mod hook;
pub mod http1;
mod jobs;
pub mod poller;
mod proc;
pub mod runner;
mod runtime;
mod store;
mod system;
pub mod transport;
pub mod workspace;

pub use app::{AppState, hook_router, socket_router};
pub use config::{Config, DEFAULT_CONFIG_PATH, DEFAULT_SECRETS_PATH, SecretsFile};
pub use dump::dump;
pub use error::Error;
pub use events::{Enqueued, Limits, OVERFLOW_KIND, QueuedEvent};
pub use hook::{forward_hook, run_hook};
pub use runtime::{Signals, bind_socket, run, run_with_env};
pub use store::Store;
pub use system::{fresh_id, now_ms, read_identity};
