//! fleetd: the per-box Fleet daemon. Serves a loopback health endpoint.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::process::ExitCode;

use axum::Router;
use axum::routing::get;
use clap::Parser;
use tokio::net::TcpListener;

const DEFAULT_PORT: u16 = 7071;
const PORT_VAR: &str = "FLEETD_PORT";

#[derive(Parser)]
#[command(version, about = "Per-box Fleet daemon")]
struct Cli;

#[derive(Debug)]
enum Error {
    Port(String),
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Port(raw) => write!(f, "invalid {PORT_VAR} value: {raw:?}"),
            Self::Io(err) => write!(f, "io error: {err}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

fn parse_port(raw: Option<&str>) -> Result<u16, Error> {
    raw.map_or(Ok(DEFAULT_PORT), |value| {
        value.parse().map_err(|_| Error::Port(value.to_owned()))
    })
}

async fn healthz() -> &'static str {
    "ok"
}

fn router() -> Router {
    Router::new().route("/healthz", get(healthz))
}

async fn serve() -> Result<(), Error> {
    let port = parse_port(std::env::var(PORT_VAR).ok().as_deref())?;
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await?;
    axum::serve(listener, router()).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    Cli::parse();
    match serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("fleetd: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let response = router()
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[test]
    fn port_defaults_and_parses() {
        assert_eq!(parse_port(None).unwrap(), 7071);
        assert_eq!(parse_port(Some("8080")).unwrap(), 8080);
        assert!(parse_port(Some("nope")).is_err());
    }
}
