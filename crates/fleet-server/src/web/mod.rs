//! The browser UI: Topcoat pages served on the gRPC port.
//!
//! ADR 0041 picks Topcoat and dispatch by content type and path. [`serve`] owns the accept
//! loop so HTTP/1 clients get a header-read timeout. [`Dispatch`] sends gRPC calls to the
//! authenticated tonic routes and every other request to the Topcoat router, behind
//! [`CatchPanic`], then stamps the security headers. [`WebAuth`] holds passkey login and
//! sessions (ADR 0042). The work tracker pages live in `work` (ADR 0064).

mod capabilities;
mod catalog;
mod clientip;
mod credentials;
mod dispatch;
mod jobs;
mod layout;
mod pages;
mod panic;
mod passkeys;
mod profiles;
mod repos;
mod serve;
mod timing;
mod tokens;
mod work;

pub use clientip::{MAX_FORWARDED_BYTES, MAX_TRUSTED_HOPS, UNKNOWN, client_ip};
pub use dispatch::{Dispatch, GRPC_PREFIX, harden};
pub use jobs::MAX_RENDER_BYTES;
pub use pages::{
    HOME_MARKER, MAX_BODY_BYTES, NAV_FOCUS_JS, PASSKEY_JS, SCRIPT_PATH, STYLE_CSS, STYLE_PATH, Web,
};
pub use panic::CatchPanic;
pub use passkeys::{
    AuthError, NewSession, SESSION_COOKIE, SESSION_IDLE_SECS, SESSION_TTL_SECS, SessionInfo,
    WebAuth,
};
pub use serve::{HEADER_READ_TIMEOUT, serve};
