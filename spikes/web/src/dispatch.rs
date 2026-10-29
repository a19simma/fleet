//! One listener, two stacks: gRPC requests go to tonic, everything else to Topcoat.

use std::convert::Infallible;
use std::future::Future;
use std::sync::Arc;

use http_body_util::BodyExt;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::body::{Bytes, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::service::{Service, service_fn};
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tonic::service::Routes;
use topcoat::router::RouterService;
use tower::ServiceExt;

/// Boxed response body shared by both stacks.
pub type BoxBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;

/// Fully qualified name of the gRPC health service.
pub const HEALTH_SERVICE: &str = "grpc.health.v1.Health";

/// Both stacks plus the routing rule between them.
#[derive(Clone)]
pub struct Dispatch {
    web: RouterService,
    grpc: Routes,
    grpc_prefix: Arc<str>,
}

impl Dispatch {
    /// Routes requests with an `application/grpc` content type and a path under
    /// `/{grpc_service}/` to `grpc`, and every other request to `web`.
    #[must_use]
    pub fn new(web: RouterService, grpc: Routes, grpc_service: &str) -> Self {
        Self {
            web,
            grpc,
            grpc_prefix: format!("/{grpc_service}/").into(),
        }
    }

    fn is_grpc(&self, request: &Request<Incoming>) -> bool {
        let content_type = request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        content_type.starts_with("application/grpc")
            && request.uri().path().starts_with(&*self.grpc_prefix)
    }

    async fn handle(self, request: Request<Incoming>) -> Result<Response<BoxBody>, Infallible> {
        if self.is_grpc(&request) {
            let response = self.grpc.oneshot(request).await?;
            Ok(response.map(|b| b.map_err(Into::into).boxed_unsync()))
        } else {
            let response = self.web.call(request).await?;
            Ok(response.map(|b| b.map_err(Into::into).boxed_unsync()))
        }
    }
}

/// Serves `dispatch` on `listener` until `shutdown` resolves.
///
/// # Errors
///
/// Returns the I/O error from accepting a connection.
pub async fn serve(
    listener: TcpListener,
    dispatch: Dispatch,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let stream = tokio::select! {
            accepted = listener.accept() => accepted?.0,
            () = &mut shutdown => return Ok(()),
        };
        let dispatch = dispatch.clone();
        tokio::spawn(async move {
            let service = service_fn(move |request| dispatch.clone().handle(request));
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
