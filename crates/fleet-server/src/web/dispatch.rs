//! One service for both stacks: gRPC goes to tonic, everything else to Topcoat.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, Request, Response};
use tonic::body::Body;
use tower::{Service, ServiceExt};

use super::pages::Web;
use super::panic::CatchPanic;

/// Path prefix shared by every gRPC service the server registers.
pub const GRPC_PREFIX: &str = "/fleet.v1.";

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; \
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

const HEADERS: [(HeaderName, &str); 5] = [
    (CONTENT_SECURITY_POLICY, CSP),
    (X_FRAME_OPTIONS, "DENY"),
    (X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (REFERRER_POLICY, "no-referrer"),
    (CACHE_CONTROL, "no-store"),
];

/// Sets the security headers on a web response, replacing any value a handler chose.
///
/// Every web response is `no-store`, which covers the credential routes and keeps
/// session pages out of shared caches.
pub fn harden<B>(response: &mut Response<B>) {
    for (name, value) in HEADERS {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
}

pub(super) fn is_grpc<B>(request: &Request<B>) -> bool {
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    content_type.starts_with("application/grpc") && request.uri().path().starts_with(GRPC_PREFIX)
}

/// Routes a request to the gRPC stack or the web stack.
///
/// A request goes to gRPC when its content type starts with `application/grpc` and its
/// path starts with [`GRPC_PREFIX`]. A gRPC content type on any other path reaches the web
/// router and gets its 404.
#[derive(Clone)]
pub struct Dispatch<G> {
    grpc: G,
    web: CatchPanic<WebService>,
}

#[derive(Clone)]
struct WebService(Web);

impl Service<Request<Body>> for WebService {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = DispatchFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let web = self.0.clone();
        Box::pin(async move {
            let response = web
                .router()
                .handle(request.map(topcoat::router::Body::new))
                .await;
            Ok(response.map(Body::new))
        })
    }
}

impl<G> Dispatch<G> {
    /// Pairs the authenticated gRPC service with the web router.
    pub const fn new(grpc: G, web: Web) -> Self {
        Self {
            grpc,
            web: CatchPanic::new(WebService(web)),
        }
    }
}

type DispatchFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

impl<G> Service<Request<Body>> for Dispatch<G>
where
    G: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    G::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = DispatchFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.grpc.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        if is_grpc(&request) {
            let spare = self.grpc.clone();
            let mut grpc = std::mem::replace(&mut self.grpc, spare);
            return Box::pin(async move { grpc.call(request).await });
        }
        let mut web = self.web.clone();
        Box::pin(async move {
            let mut response = web.ready().await?.call(request).await?;
            harden(&mut response);
            Ok(response)
        })
    }
}
