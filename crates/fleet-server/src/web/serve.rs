//! The accept loop for the shared port.
//!
//! Tonic's own loop sets no HTTP/1 header-read timeout, so a client that opens a connection
//! and trickles a request head holds it open for good. This loop drives hyper's auto builder
//! directly with a timer and `header_read_timeout`, and carries over the connection limits
//! the tonic server set: concurrent streams, keepalive pings, a request timeout and a cap on
//! concurrent requests per connection.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::http::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::service::TowerToHyperService;
use tokio::sync::Semaphore;
use tonic::body::Body;
use tonic::codegen::tokio_stream::StreamExt;
use tonic::codegen::{Body as HttpBody, Bytes};
use tonic::transport::server::{Connected, TcpConnectInfo, TcpIncoming};
use tower::{Service, ServiceExt};

use super::dispatch::is_grpc;

/// How long a client may take to send a complete HTTP/1 request head.
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const REQUESTS_PER_CONNECTION: usize = 8;
const MAX_CONCURRENT_STREAMS: u32 = 32;

type LimitFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

#[derive(Clone)]
struct Connection<S> {
    inner: S,
    permits: Arc<Semaphore>,
    peer: Option<TcpConnectInfo>,
}

fn grpc_timeout(value: &str) -> Option<Duration> {
    let (digits, unit) = value.split_at(value.len().checked_sub(1)?);
    if digits.is_empty() || digits.len() > 8 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    match unit {
        "H" => Some(Duration::from_secs(n * 3600)),
        "M" => Some(Duration::from_secs(n * 60)),
        "S" => Some(Duration::from_secs(n)),
        "m" => Some(Duration::from_millis(n)),
        "u" => Some(Duration::from_micros(n)),
        "n" => Some(Duration::from_nanos(n)),
        _ => None,
    }
}

fn effective_timeout<B>(request: &Request<B>, grpc: bool) -> Duration {
    let requested = grpc
        .then(|| request.headers().get("grpc-timeout"))
        .flatten()
        .and_then(|value| value.to_str().ok())
        .and_then(grpc_timeout);
    requested.map_or(REQUEST_TIMEOUT, |t| t.min(REQUEST_TIMEOUT))
}

impl<S, B> Service<Request<B>> for Connection<S>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
    B: HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = LimitFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let mut request = request.map(Body::new);
        if let Some(peer) = &self.peer {
            request.extensions_mut().insert(peer.clone());
        }
        let grpc = is_grpc(&request);
        let limit = effective_timeout(&request, grpc);
        let permits = Arc::clone(&self.permits);
        let mut inner = self.inner.clone();
        Box::pin(async move {
            let Ok(_permit) = permits.acquire_owned().await else {
                return Ok(timed_out(grpc));
            };
            let call = async move { inner.ready().await?.call(request).await };
            tokio::time::timeout(limit, call)
                .await
                .unwrap_or_else(|_| Ok(timed_out(grpc)))
        })
    }
}

fn timed_out(grpc: bool) -> Response<Body> {
    if grpc {
        return tonic::Status::deadline_exceeded("request timed out").into_http();
    }
    let mut response = Response::new(Body::empty());
    *response.status_mut() = axum::http::StatusCode::GATEWAY_TIMEOUT;
    response
}

/// Serves `service` on `incoming` until `shutdown` resolves, then drains open connections.
///
/// HTTP/1 clients must send a full request head within `header_read_timeout` or lose the
/// connection.
///
/// # Errors
///
/// Returns no error today; the signature leaves room for fatal accept failures.
pub async fn serve<S>(
    service: S,
    mut incoming: TcpIncoming,
    shutdown: impl Future<Output = ()>,
    header_read_timeout: Duration,
) -> io::Result<()>
where
    S: Service<Request<Body>, Response = Response<Body>, Error = Infallible>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(header_read_timeout);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(KEEPALIVE_INTERVAL))
        .max_concurrent_streams(MAX_CONCURRENT_STREAMS);
    let graceful = GracefulShutdown::new();
    let mut shutdown = pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => break,
            accepted = incoming.next() => match accepted {
                Some(Ok(stream)) => {
                    let connection = Connection {
                        inner: service.clone(),
                        permits: Arc::new(Semaphore::new(REQUESTS_PER_CONNECTION)),
                        peer: Some(stream.connect_info()),
                    };
                    let builder = builder.clone();
                    let io = TokioIo::new(stream);
                    let watcher = graceful.watcher();
                    tokio::spawn(async move {
                        let served =
                            builder.serve_connection(io, TowerToHyperService::new(connection));
                        if let Err(err) = watcher.watch(served).await {
                            tracing::debug!(%err, "connection ended with an error");
                        }
                    });
                }
                Some(Err(err)) => tracing::debug!(%err, "accept failed"),
                None => break,
            },
        }
    }
    graceful.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::http::header::CONTENT_TYPE;
    use tokio::net::{TcpListener, TcpStream};
    use tower::service_fn;

    use super::*;

    const PATH: &str = "/fleet.v1.FleetJobs/GetStats";

    fn grpc_request(timeout: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder()
            .uri(PATH)
            .header(CONTENT_TYPE, "application/grpc");
        if let Some(timeout) = timeout {
            builder = builder.header("grpc-timeout", timeout);
        }
        builder.body(Body::empty()).unwrap()
    }

    fn connection<S>(inner: S, peer: Option<TcpConnectInfo>) -> Connection<S> {
        Connection {
            inner,
            permits: Arc::new(Semaphore::new(1)),
            peer,
        }
    }

    #[test]
    fn grpc_timeout_header_parses_every_unit_and_rejects_junk() {
        assert_eq!(grpc_timeout("5S"), Some(Duration::from_secs(5)));
        assert_eq!(grpc_timeout("2M"), Some(Duration::from_secs(120)));
        assert_eq!(grpc_timeout("1H"), Some(Duration::from_secs(3600)));
        assert_eq!(grpc_timeout("200m"), Some(Duration::from_millis(200)));
        assert_eq!(grpc_timeout("7u"), Some(Duration::from_micros(7)));
        assert_eq!(grpc_timeout("9n"), Some(Duration::from_nanos(9)));
        assert_eq!(grpc_timeout("S"), None);
        assert_eq!(grpc_timeout(""), None);
        assert_eq!(grpc_timeout("5x"), None);
        assert_eq!(grpc_timeout("-5S"), None);
        assert_eq!(grpc_timeout("123456789S"), None);
    }

    #[test]
    fn effective_timeout_is_the_smaller_of_header_and_cap() {
        let tight = grpc_request(Some("2S"));
        assert_eq!(effective_timeout(&tight, true), Duration::from_secs(2));
        let loose = grpc_request(Some("1H"));
        assert_eq!(effective_timeout(&loose, true), REQUEST_TIMEOUT);
        let none = grpc_request(None);
        assert_eq!(effective_timeout(&none, true), REQUEST_TIMEOUT);
        assert_eq!(effective_timeout(&tight, false), REQUEST_TIMEOUT);
    }

    #[tokio::test]
    async fn a_short_grpc_timeout_header_cuts_the_call_short() {
        let stuck = service_fn(|_: Request<Body>| async {
            tokio::time::sleep(Duration::from_secs(120)).await;
            Ok::<_, Infallible>(Response::new(Body::empty()))
        });
        let mut conn = connection(stuck, None);
        let reply = tokio::time::timeout(
            Duration::from_secs(10),
            conn.call(grpc_request(Some("200m"))),
        )
        .await
        .expect("header deadline was ignored")
        .unwrap();
        let status = tonic::Status::from_header_map(reply.headers()).unwrap();
        assert_eq!(status.code(), tonic::Code::DeadlineExceeded);
    }

    #[tokio::test]
    async fn the_peer_address_reaches_the_request_extensions() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let client_addr = client.local_addr().unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        let seen = service_fn(|request: Request<Body>| async move {
            let peer = request
                .extensions()
                .get::<TcpConnectInfo>()
                .and_then(TcpConnectInfo::remote_addr);
            let mut response = Response::new(Body::empty());
            if let Some(peer) = peer {
                response
                    .headers_mut()
                    .insert("x-peer", peer.to_string().parse().unwrap());
            }
            Ok::<_, Infallible>(response)
        });
        let mut conn = connection(seen, Some(accepted.connect_info()));
        let reply = conn.call(grpc_request(None)).await.unwrap();
        let peer = reply.headers().get("x-peer").unwrap().to_str().unwrap();
        assert_eq!(peer, client_addr.to_string());
    }
}
