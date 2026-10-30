//! The web pages share the gRPC port: both stacks answer on one listener, the stylesheet is
//! compiled in, security headers are stamped and unknown routes get a 404.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::GetStatsRequest;
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::service::serve_with_web_timeout;
use fleet_server::store::Store;
use fleet_server::web::{CatchPanic, HEADER_READ_TIMEOUT, HOME_MARKER, STYLE_CSS, STYLE_PATH, Web};
use sqlx::postgres::PgPoolOptions;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::Code;
use tonic::transport::Endpoint;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);

struct Harness {
    addr: SocketAddr,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start() -> Self {
        Self::start_with(HEADER_READ_TIMEOUT).await
    }

    async fn start_with(header_read_timeout: Duration) -> Self {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://nobody@127.0.0.1:1/none")
            .unwrap();
        let store = Store::new(pool);
        let auth = BearerAuth::new(
            &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            serve_with_web_timeout(
                &store,
                &auth,
                Web::new(),
                TcpIncoming::from(listener),
                async {
                    let _ = rx.await;
                },
                header_read_timeout,
            )
            .await
        });
        Self {
            addr,
            stop: Some(stop),
            task,
        }
    }

    async fn get(&self, path: &str) -> (String, String) {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = String::new();
        tokio::time::timeout(WAIT, stream.read_to_string(&mut raw))
            .await
            .unwrap()
            .unwrap();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        (head.to_owned(), body.to_owned())
    }

    async fn finish(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

#[tokio::test]
async fn one_port_serves_grpc_and_pages() {
    let h = Harness::start().await;
    let (head, body) = h.get("/").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(body.contains(HOME_MARKER), "{body}");

    let channel = Endpoint::from_shared(format!("http://{}", h.addr))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let status = FleetJobsClient::new(channel)
        .get_stats(GetStatsRequest::default())
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Unauthenticated);
    h.finish().await;
}

#[tokio::test]
async fn stylesheet_is_embedded_in_the_binary() {
    let h = Harness::start().await;
    let (head, body) = h.get(STYLE_PATH).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header(&head, "content-type"), Some("text/css"));
    assert_eq!(body, STYLE_CSS);
    h.finish().await;
}

#[tokio::test]
async fn pages_carry_security_headers_and_no_store() {
    let h = Harness::start().await;
    for path in ["/", STYLE_PATH, "/nowhere"] {
        let (head, _) = h.get(path).await;
        assert_eq!(header(&head, "x-frame-options"), Some("DENY"), "{path}");
        assert_eq!(header(&head, "cache-control"), Some("no-store"), "{path}");
        assert_eq!(
            header(&head, "x-content-type-options"),
            Some("nosniff"),
            "{path}"
        );
        let csp = header(&head, "content-security-policy").unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "{path}: {csp}");
        assert!(csp.contains("default-src 'self'"), "{path}: {csp}");
    }
    h.finish().await;
}

#[tokio::test]
async fn unknown_route_is_404() {
    let h = Harness::start().await;
    let (head, _) = h.get("/no/such/page").await;
    assert!(head.starts_with("HTTP/1.1 404"), "{head}");
    h.finish().await;
}

#[tokio::test]
async fn slow_header_client_is_disconnected() {
    let h = Harness::start_with(Duration::from_secs(1)).await;
    let mut stream = TcpStream::connect(h.addr).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        .await
        .unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .expect("server kept a stalled header connection open")
        .unwrap_or(0);
    assert!(!String::from_utf8_lossy(&raw).contains("200 OK"));
    let (head, _) = h.get("/").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    h.finish().await;
}

#[tokio::test]
async fn a_panicking_handler_answers_500_and_the_service_survives() {
    use axum::http::{Request, Response, StatusCode};
    use std::convert::Infallible;
    use tonic::body::Body;
    use tower::{Service, ServiceExt, service_fn};

    let inner = service_fn(|request: Request<Body>| async move {
        assert!(request.uri().path() != "/boom", "handler failed");
        Ok::<_, Infallible>(Response::new(Body::empty()))
    });
    let mut service = CatchPanic::new(inner);
    let boom = Request::builder().uri("/boom").body(Body::empty()).unwrap();
    let response = service.ready().await.unwrap().call(boom).await.unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let fine = Request::builder().uri("/ok").body(Body::empty()).unwrap();
    let response = service.ready().await.unwrap().call(fine).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
