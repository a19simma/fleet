//! The Fleet server: Postgres storage and the session projection behind the gRPC services.

pub mod auth;
pub mod batches;
pub mod catalog;
pub mod config;
pub mod cred;
pub mod environments;
pub mod hosts;
pub mod jobs;
pub mod profiles;
pub mod projection;
pub mod reaper;
pub mod retention;
pub mod service;
pub mod stats;
pub mod store;
pub mod supervise;
pub mod telemetry;
pub mod timing;
pub mod update_feed;
pub mod web;
