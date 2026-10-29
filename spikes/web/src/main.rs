use std::net::SocketAddr;

use tonic::service::Routes;
use topcoat::router::RouterService;
use url::Url;
use web_spike::dispatch::{Dispatch, HEALTH_SERVICE, serve};
use web_spike::passkey::Passkeys;
use web_spike::web::router;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let addr: SocketAddr = std::env::var("ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".to_owned())
        .parse()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let bound = listener.local_addr()?;
    let origin = format!("http://localhost:{}", bound.port());
    let passkeys = Passkeys::new(&Url::parse(&origin).map_err(std::io::Error::other)?)
        .map_err(std::io::Error::other)?;
    let (reporter, health) = tonic_health::server::health_reporter();
    reporter
        .set_service_status("", tonic_health::ServingStatus::Serving)
        .await;
    let dispatch = Dispatch::new(
        RouterService::new(router(passkeys, &origin)),
        Routes::new(health),
        HEALTH_SERVICE,
    );
    serve(listener, dispatch, std::future::pending()).await
}
