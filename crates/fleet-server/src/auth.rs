//! Bearer token check, applied once as a tower layer around the whole gRPC router.

use std::convert::Infallible;
use std::future::{Future, ready};
use std::pin::Pin;
use std::task::{Context, Poll};

use fleet_core::constant_time_eq;
use tonic::Status;
use tonic::body::Body;
use tonic::codegen::http::{HeaderValue, Request, Response};
use tonic::transport::server::TcpConnectInfo;
use tower::{Layer, Service};

use crate::config::{Secret, Token};

/// Requires `authorization: Bearer <token>` on every request, whatever the gRPC path.
///
/// The whole header value is compared with [`constant_time_eq`], so a wrong scheme, a
/// wrong token and a header with non-ASCII bytes all fail the same way.
#[derive(Debug, Clone)]
pub struct BearerAuth {
    expected: Secret,
}

impl BearerAuth {
    /// Builds a check for `token`.
    pub fn new(token: &Token) -> Self {
        Self {
            expected: Secret::new(format!("Bearer {}", token.expose())),
        }
    }

    /// The header value a request to `path` must carry.
    ///
    /// Every path takes the one box token today. Choosing the token per service path
    /// changes only this function.
    fn required(&self, _path: &str) -> &Secret {
        &self.expected
    }

    /// Checks `header` against the token `path` requires.
    ///
    /// # Errors
    ///
    /// Returns `UNAUTHENTICATED` when the header is missing or does not match.
    pub fn check(&self, path: &str, header: Option<&[u8]>) -> Result<(), Status> {
        let given = header.unwrap_or_default();
        if constant_time_eq(given, self.required(path).expose().as_bytes()) {
            Ok(())
        } else {
            Err(Status::unauthenticated("missing or invalid bearer token"))
        }
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
    S: Service<Request<B>, Response = Response<Body>, Error = Infallible>,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = AuthFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let header = request
            .headers()
            .get("authorization")
            .map(HeaderValue::as_bytes);
        match self.auth.check(request.uri().path(), header) {
            Ok(()) => Box::pin(self.inner.call(request)),
            Err(status) => {
                let peer = request
                    .extensions()
                    .get::<TcpConnectInfo>()
                    .and_then(TcpConnectInfo::remote_addr);
                tracing::warn!(?peer, "rejected request with a bad bearer token");
                Box::pin(ready(Ok(status.into_http())))
            }
        }
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
        Ok(BearerAuth::new(&token))
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
