//! Bearer token check, applied once as a tower layer around the whole gRPC router.
//!
//! Two tokens, scoped by gRPC path: the box token covers `FleetIngest` and `FleetWorker`,
//! the client token covers `FleetQuery`, `FleetJobs`, `FleetProfiles`, `FleetBatches` and
//! `FleetCredentials`. Any other path
//! is denied.
//!
//! With a [`Users`] store the layer also resolves the caller: a per-user API token maps to its
//! user, `FLEET_CLIENT_TOKEN` maps to the `bootstrap` user, and the result rides the request
//! as a [`Caller`] extension. The box token carries no user.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use fleet_core::constant_time_eq;
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::http::{HeaderValue, Request, Response};
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};

use crate::config::{Secret, Token};
use crate::cred::Users;

const INGEST: &str = "/fleet.v1.FleetIngest/";
const WORKER: &str = "/fleet.v1.FleetWorker/";
const QUERY: &str = "/fleet.v1.FleetQuery/";
const JOBS: &str = "/fleet.v1.FleetJobs/";
const JUDGE: &str = "/fleet.v1.FleetJudge/";
const PROFILES: &str = "/fleet.v1.FleetProfiles/";
const BATCHES: &str = "/fleet.v1.FleetBatches/";
const CREDENTIALS: &str = "/fleet.v1.FleetCredentials/";

/// The user a request acts as, set by [`BearerAuth`] on every client-scope request when it has a
/// [`Users`] store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller {
    /// The user's row id.
    pub user_id: i64,
}

/// Which token a request carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Box,
    Client,
}

/// Requires `authorization: Bearer <token>` on every request, whatever the gRPC path.
///
/// The whole header value is compared with [`constant_time_eq`], so a wrong scheme, a
/// wrong token and a header with non-ASCII bytes all fail the same way. A valid token
/// that does not cover the path gets `PERMISSION_DENIED`. Without a client token,
/// `FleetJobs`, `FleetProfiles` and `FleetBatches` are closed to everyone.
#[derive(Debug, Clone)]
pub struct BearerAuth {
    box_token: Secret,
    client_token: Option<Secret>,
    users: Option<Users>,
}

impl BearerAuth {
    /// Builds a check for the box token and an optional client token.
    pub fn new(box_token: &Token, client_token: Option<&Token>) -> Self {
        let header = |token: &Token| Secret::new(format!("Bearer {}", token.expose()));
        Self {
            box_token: header(box_token),
            client_token: client_token.map(header),
            users: None,
        }
    }

    /// Adds user resolution: API tokens authenticate as their user and the client token as
    /// the `bootstrap` user.
    #[must_use]
    pub fn with_users(mut self, users: Users) -> Self {
        self.users = Some(users);
        self
    }

    fn scope_of(&self, header: &[u8]) -> Option<Scope> {
        let is_box = constant_time_eq(header, self.box_token.expose().as_bytes());
        let is_client = self
            .client_token
            .as_ref()
            .is_some_and(|token| constant_time_eq(header, token.expose().as_bytes()));
        if is_box {
            Some(Scope::Box)
        } else if is_client {
            Some(Scope::Client)
        } else {
            None
        }
    }

    /// Allow-lists paths per scope: the box token takes `FleetIngest` and `FleetWorker`,
    /// the client token takes `FleetQuery`, `FleetJobs`, `FleetJudge`, `FleetProfiles`,
    /// `FleetBatches` and `FleetCredentials`.
    /// Every other path is denied.
    fn allows(scope: Scope, path: &str) -> bool {
        match scope {
            Scope::Box => path.starts_with(INGEST) || path.starts_with(WORKER),
            Scope::Client => {
                path.starts_with(QUERY)
                    || path.starts_with(JOBS)
                    || path.starts_with(JUDGE)
                    || path.starts_with(PROFILES)
                    || path.starts_with(BATCHES)
                    || path.starts_with(CREDENTIALS)
            }
        }
    }

    /// Checks the token first, then the path scope.
    ///
    /// # Errors
    ///
    /// Returns `UNAUTHENTICATED` when the header is missing or matches no token, and
    /// `PERMISSION_DENIED` when it matches a token whose scope excludes `path`.
    pub fn check(&self, path: &str, header: Option<&[u8]>) -> Result<(), Status> {
        let scope = self
            .scope_of(header.unwrap_or_default())
            .ok_or_else(|| Status::unauthenticated("missing or invalid bearer token"))?;
        if Self::allows(scope, path) {
            Ok(())
        } else {
            Err(Status::permission_denied(
                "bearer token not valid for this service",
            ))
        }
    }
}

impl BearerAuth {
    /// Authenticates a request and resolves its caller.
    ///
    /// A value that matches neither static token is looked up as an API token when a
    /// [`Users`] store is set. The caller is `None` for the box token and when no store is set.
    ///
    /// # Errors
    ///
    /// Returns `UNAUTHENTICATED` for a missing, unknown or revoked token, `PERMISSION_DENIED`
    /// when the scope excludes `path`, and `UNAVAILABLE` when the user lookup fails.
    pub async fn authenticate(
        &self,
        path: &str,
        header: Option<&[u8]>,
    ) -> Result<Option<Caller>, Status> {
        let header = header.unwrap_or_default();
        let unavailable = |_| Status::unavailable("user lookup unavailable");
        let (scope, caller) = match self.scope_of(header) {
            Some(Scope::Box) => (Scope::Box, None),
            Some(Scope::Client) => (Scope::Client, None),
            None => {
                let users = self.users.as_ref();
                let token = header.strip_prefix(b"Bearer ");
                let found = match (users, token) {
                    (Some(users), Some(token)) => {
                        users.authenticate(token).await.map_err(unavailable)?
                    }
                    _ => None,
                };
                let user_id = found
                    .ok_or_else(|| Status::unauthenticated("missing or invalid bearer token"))?;
                (Scope::Client, Some(Caller { user_id }))
            }
        };
        if !Self::allows(scope, path) {
            return Err(Status::permission_denied(
                "bearer token not valid for this service",
            ));
        }
        if let (Scope::Client, None, Some(users)) = (scope, caller, self.users.as_ref()) {
            let user_id = users.bootstrap_user().await.map_err(unavailable)?;
            return Ok(Some(Caller { user_id }));
        }
        Ok(caller)
    }
}

impl<S> Layer<S> for BearerAuth {
    type Service = AuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AuthService {
            inner,
            auth: self.clone(),
        }
    }
}

/// The service [`BearerAuth`] wraps around a router.
#[derive(Debug, Clone)]
pub struct AuthService<S> {
    inner: S,
    auth: BearerAuth,
}

type AuthFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

impl<S, B> Service<Request<B>> for AuthService<S>
where
    S: Service<Request<B>, Response = Response<Body>, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = AuthFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        let auth = self.auth.clone();
        let spare = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, spare);
        Box::pin(async move {
            let header = request
                .headers()
                .get("authorization")
                .map(HeaderValue::as_bytes);
            match auth.authenticate(request.uri().path(), header).await {
                Ok(caller) => {
                    if let Some(caller) = caller {
                        request.extensions_mut().insert(caller);
                    }
                    inner.call(request).await
                }
                Err(status) => {
                    let peer = request
                        .extensions()
                        .get::<TcpConnectInfo>()
                        .and_then(TcpConnectInfo::remote_addr);
                    let code = status.code();
                    tracing::warn!(
                        ?peer,
                        ?code,
                        "rejected request: unauthenticated or out of scope"
                    );
                    Ok(status.into_http())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::*;

    const SECRET: &str = "secret-0123456789abcdef0123456789";
    const PATH: &str = "/fleet.v1.FleetIngest/PushEvents";

    fn auth() -> Result<BearerAuth, String> {
        let token = Token::new(SECRET.into()).map_err(|err| err.to_string())?;
        Ok(BearerAuth::new(&token, None))
    }

    #[test]
    fn right_token_passes() -> Result<(), String> {
        let header = format!("Bearer {SECRET}");
        auth()?
            .check(PATH, Some(header.as_bytes()))
            .map_err(|status| status.to_string())
    }

    #[test]
    fn missing_wrong_and_malformed_fail() -> Result<(), String> {
        let cases: [Option<Vec<u8>>; 7] = [
            None,
            Some(b"Bearer wrong".to_vec()),
            Some(SECRET.as_bytes().to_vec()),
            Some(format!("bearer {SECRET}").into_bytes()),
            Some(format!("Bearer {SECRET} ").into_bytes()),
            Some("Bearer s\u{e9}cret".as_bytes().to_vec()),
            Some(b"Bearer \xff\xfe".to_vec()),
        ];
        let auth = auth()?;
        for case in cases {
            let status = auth
                .check(PATH, case.as_deref())
                .err()
                .ok_or_else(|| format!("{case:?} passed"))?;
            assert_eq!(status.code(), Code::Unauthenticated, "{case:?}");
        }
        Ok(())
    }
}
