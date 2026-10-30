//! A tower service that turns a panic in the wrapped service into a 500 response.

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::http::{Request, Response, StatusCode};
use tonic::body::Body;
use tower::Service;

/// Runs each call on its own task, so a panic ends that request with a 500 and nothing else.
///
/// The connection, the listener and every other request keep running. The panic payload
/// is never sent to the client.
#[derive(Clone)]
pub struct CatchPanic<S> {
    inner: S,
}

impl<S> CatchPanic<S> {
    /// Wraps `inner`.
    pub const fn new(inner: S) -> Self {
        Self { inner }
    }
}

type PanicFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

fn internal_error() -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

impl<S, B> Service<Request<B>> for CatchPanic<S>
where
    S: Service<Request<B>, Response = Response<Body>, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
    B: Send + 'static,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = PanicFuture;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let spare = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, spare);
        Box::pin(async move {
            let task = tokio::spawn(async move { inner.call(request).await });
            match task.await {
                Ok(result) => result,
                Err(err) => {
                    tracing::error!(panicked = err.is_panic(), "web request task failed");
                    Ok(internal_error())
                }
            }
        })
    }
}
