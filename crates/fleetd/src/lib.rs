//! fleetd: the per-box Fleet daemon.
//!
//! Hooks and local tools post events. fleetd normalizes and redacts them, then commits
//! each to a SQLite queue before it answers.
//!
//! While `FLEET_SERVER_URL` and `FLEET_TOKEN` are set, the daemon also runs jobs: [`poller`]
//! claims them, [`workspace`] prepares git worktrees, and [`runner`] runs the agent as a child
//! process, then pushes the branch and opens the pull request. Each run also reports tool events
//! and a summary parsed from the agent's output ([`telemetry`]). The push's `GIT_ASKPASS` is
//! `fleetd askpass` ([`askpass`]).

pub mod agent_config;
pub mod agent_exec;
mod app;
pub mod askpass;
pub mod backoff;
pub mod broker;
mod config;
pub mod connect_proxy;
mod dump;
mod error;
pub mod events;
mod feed;
pub mod fetch;
pub mod fetch_policy;
pub mod fetch_service;
pub mod floor;
pub mod forge;
pub mod forwarder;
mod group;
pub mod heartbeat;
mod hook;
pub mod http1;
pub mod jobenv;
mod jobs;
pub mod jobsock;
pub mod netguard;
pub mod phase;
pub mod poller;
mod proc;
pub mod profile_apply;
pub mod publish;
pub mod runner;
mod runtime;
mod store;
pub mod stuck;
mod system;
pub mod systemd;
pub mod telemetry;
pub mod toolhook;
pub mod transport;
pub mod workspace;

pub use app::{AppState, hook_router, hook_socket_router, socket_router};
pub use config::{AgentLauncher, Config, DEFAULT_CONFIG_PATH, DEFAULT_SECRETS_PATH, SecretsFile};
pub use dump::dump;
pub use error::Error;
pub use events::{Enqueued, Limits, OVERFLOW_KIND, QueuedEvent};
pub use hook::{forward_hook, run_hook};
#[doc(hidden)]
pub use jobs::{BrokerWiring, DaemonRunner, DynBroker, JobServices, job_services_with};
pub use runtime::{Signals, bind_hook_socket, bind_socket, run, run_with_env};
pub use store::Store;
pub use system::{fresh_id, now_ms, read_identity};
pub use toolhook::{HookHub, ToolReport};
