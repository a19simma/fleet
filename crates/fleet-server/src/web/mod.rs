//! The browser UI: Topcoat pages served on the gRPC port.
//!
//! ADR 0041 picks Topcoat and dispatch by content type and path. Tonic owns the accept
//! loop and the connection settings, so the web stack inherits its keepalive, request
//! timeout and graceful shutdown. [`Dispatch`] sends gRPC calls to the authenticated tonic
//! routes and every other request to the Topcoat router, then stamps the security headers.

mod dispatch;
mod pages;

pub use dispatch::{Dispatch, GRPC_PREFIX, harden};
pub use pages::{HOME_MARKER, STYLE_CSS, STYLE_PATH, Web};
