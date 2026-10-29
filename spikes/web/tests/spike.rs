//! End-to-end checks: coexistence, embedded asset, passkey, negative content types.

use std::net::SocketAddr;
use std::time::Duration;

use reqwest::{Client, StatusCode};
use tokio::sync::oneshot;
use tonic::service::Routes;
use tonic_health::pb::HealthCheckRequest;
use tonic_health::pb::health_check_response::ServingStatus;
use tonic_health::pb::health_client::HealthClient;
use topcoat::router::RouterService;
use url::Url;
use web_spike::dispatch::{Dispatch, HEALTH_SERVICE, serve};
use web_spike::passkey::Passkeys;
use web_spike::web::{HOME_MARKER, STYLE_CSS, STYLE_PATH, router};
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;
use webauthn_rs::prelude::{
    CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse,
};

const WAIT: Duration = Duration::from_secs(20);

struct Harness {
    addr: SocketAddr,
    origin: String,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let origin = format!("http://localhost:{}", addr.port());
        let passkeys = Passkeys::new(&Url::parse(&origin).unwrap()).unwrap();
        let (reporter, health) = tonic_health::server::health_reporter();
        reporter
            .set_service_status("", tonic_health::ServingStatus::Serving)
            .await;
        let dispatch = Dispatch::new(
            RouterService::new(router(passkeys, &origin)),
            Routes::new(health),
            HEALTH_SERVICE,
        );
        let (stop, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(serve(listener, dispatch, async {
            let _ = rx.await;
        }));
        Self {
            addr,
            origin,
            stop: Some(stop),
            task,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.addr)
    }

    async fn finish(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let joined = tokio::time::timeout(WAIT, self.task).await.unwrap();
        joined.unwrap().unwrap();
    }
}

async fn bounded<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(WAIT, future).await.unwrap()
}

#[tokio::test]
async fn coexistence_grpc_health_and_web_page_on_one_port() {
    let h = Harness::start().await;

    let channel = bounded(
        tonic::transport::Channel::from_shared(format!("http://{}", h.addr))
            .unwrap()
            .connect(),
    )
    .await
    .unwrap();
    let mut client = HealthClient::new(channel);
    let reply = bounded(client.check(HealthCheckRequest {
        service: String::new(),
    }))
    .await
    .unwrap()
    .into_inner();
    assert_eq!(reply.status(), ServingStatus::Serving);

    let page = bounded(reqwest::get(h.url("/"))).await.unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.version(), reqwest::Version::HTTP_11);
    let body = bounded(page.text()).await.unwrap();
    assert!(body.contains(HOME_MARKER), "{body}");
    assert!(body.contains(STYLE_PATH), "{body}");

    h.finish().await;
}

#[tokio::test]
async fn embedded_asset_is_served_from_the_binary() {
    let h = Harness::start().await;
    let response = bounded(reqwest::get(h.url(STYLE_PATH))).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/css");
    assert_eq!(bounded(response.text()).await.unwrap(), STYLE_CSS);
    assert_ne!(STYLE_CSS, "");
    h.finish().await;
}

async fn post_json<T: serde::Serialize>(
    client: &Client,
    h: &Harness,
    path: &str,
    body: &T,
) -> reqwest::Response {
    bounded(
        client
            .post(h.url(path))
            .header("origin", &h.origin)
            .json(body)
            .send(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn passkey_register_and_login_with_software_authenticator() {
    let h = Harness::start().await;
    let client = Client::new();
    let origin = Url::parse(&h.origin).unwrap();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let name = serde_json::json!({ "name": "alice" });

    let started = post_json(&client, &h, "/passkey/register/start", &name).await;
    assert_eq!(started.status(), StatusCode::OK);
    let challenge: CreationChallengeResponse = bounded(started.json()).await.unwrap();
    let credential: RegisterPublicKeyCredential = authenticator
        .do_registration(origin.clone(), challenge)
        .unwrap();
    let finished = post_json(
        &client,
        &h,
        "/passkey/register/finish",
        &serde_json::json!({ "name": "alice", "credential": credential }),
    )
    .await;
    assert_eq!(finished.status(), StatusCode::OK);

    let started = post_json(&client, &h, "/passkey/login/start", &name).await;
    assert_eq!(started.status(), StatusCode::OK);
    let challenge: RequestChallengeResponse = bounded(started.json()).await.unwrap();
    let assertion: PublicKeyCredential =
        authenticator.do_authentication(origin, challenge).unwrap();
    let finished = post_json(
        &client,
        &h,
        "/passkey/login/finish",
        &serde_json::json!({ "name": "alice", "credential": assertion }),
    )
    .await;
    assert_eq!(finished.status(), StatusCode::OK);
    let ok: serde_json::Value = bounded(finished.json()).await.unwrap();
    assert_eq!(ok["ok"], true);

    let replay = post_json(
        &client,
        &h,
        "/passkey/login/finish",
        &serde_json::json!({ "name": "alice", "credential": assertion }),
    )
    .await;
    assert_eq!(replay.status(), StatusCode::BAD_REQUEST);

    let unknown = post_json(
        &client,
        &h,
        "/passkey/login/start",
        &serde_json::json!({ "name": "mallory" }),
    )
    .await;
    assert_eq!(unknown.status(), StatusCode::BAD_REQUEST);

    h.finish().await;
}

#[tokio::test]
async fn grpc_content_type_on_web_routes_gets_4xx_and_server_survives() {
    let h = Harness::start().await;
    let client = Client::builder().http2_prior_knowledge().build().unwrap();

    for path in ["/", "/passkey/register/start", "/static/style.css"] {
        let response = bounded(
            client
                .post(h.url(path))
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(vec![0u8; 5])
                .send(),
        )
        .await
        .unwrap();
        assert!(
            response.status().is_client_error(),
            "{path}: {}",
            response.status()
        );
    }

    let wrong_type = bounded(
        client
            .post(h.url(&format!("/{HEALTH_SERVICE}/Check")))
            .header("content-type", "application/json")
            .body("{}")
            .send(),
    )
    .await
    .unwrap();
    assert!(
        wrong_type.status().is_client_error(),
        "{}",
        wrong_type.status()
    );

    let text_on_json_route = bounded(
        Client::new()
            .post(h.url("/passkey/register/start"))
            .header("origin", &h.origin)
            .header("content-type", "text/plain")
            .body("alice")
            .send(),
    )
    .await
    .unwrap();
    assert!(
        text_on_json_route.status().is_client_error(),
        "{}",
        text_on_json_route.status()
    );

    let still_up = bounded(reqwest::get(h.url("/"))).await.unwrap();
    assert_eq!(still_up.status(), StatusCode::OK);
    assert!(!h.task.is_finished());

    h.finish().await;
}
