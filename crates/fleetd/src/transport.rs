//! Endpoint setup shared by the poller and heartbeat channels.

use std::time::Duration;

use tonic::transport::{Certificate, ClientTlsConfig, Endpoint};

/// Longest a connection attempt may take, TLS handshake included.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Builds an endpoint for `url` with [`CONNECT_TIMEOUT`] applied.
///
/// An `https` URL gets TLS with the bundled webpki roots, plus `ca_pem` when given. An
/// `http` URL stays plaintext and ignores `ca_pem`.
///
/// # Errors
///
/// Fails when `url` is not a valid endpoint or the TLS config is rejected.
pub(crate) fn endpoint(
    url: &str,
    ca_pem: Option<&[u8]>,
) -> Result<Endpoint, tonic::transport::Error> {
    let endpoint = Endpoint::from_shared(url.to_owned())?.connect_timeout(CONNECT_TIMEOUT);
    if endpoint.uri().scheme_str() != Some("https") {
        return Ok(endpoint);
    }
    let mut tls = ClientTlsConfig::new().with_webpki_roots();
    if let Some(pem) = ca_pem {
        tls = tls.ca_certificate(Certificate::from_pem(pem));
    }
    endpoint.tls_config(tls)
}
