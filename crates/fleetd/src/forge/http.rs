//! The production [`Http`] seam: one HTTPS request to one host over a pinned dial.
//!
//! The host is fixed at construction. Each call resolves it once, checks every answer and dials
//! only a checked address, with the host name as TLS SNI and `Host` header. An answer is allowed
//! when it is public, or when an admin approved it for this host. No redirect is followed, no
//! proxy is used and no environment variable is read. The body is capped at [`MAX_BODY_BYTES`]
//! and one deadline covers the whole call.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use fleet_core::host::HostName;
use fleet_forge::{Http, HttpError, HttpRequest, HttpResponse, MAX_BODY_BYTES, Method};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes};
use hyper::header::{ACCEPT_ENCODING, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, HOST};
use hyper::header::{HeaderName, HeaderValue, USER_AGENT};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::fetch::{Dialer, Resolver, SystemResolver, TcpDialer, webpki_tls_config};
use crate::netguard::is_public_address;

/// The longest one request may take, DNS and body included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// The longest the connect step may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const PORT: u16 = 443;

struct AbortOnDrop(JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An [`Http`] seam that talks to one host with the pinned dial described in the module docs.
#[derive(Debug)]
pub struct PinnedHttp<R = SystemResolver, D = TcpDialer> {
    host: HostName,
    approved: Vec<IpAddr>,
    resolver: R,
    dialer: D,
    tls: Arc<ClientConfig>,
}

impl PinnedHttp {
    /// The production seam for `host`: system DNS, plain TCP, webpki roots. `approved` lists the
    /// non-public addresses an admin allowed for this host.
    #[must_use]
    pub fn system(host: HostName, approved: Vec<IpAddr>) -> Self {
        Self::new(
            host,
            approved,
            SystemResolver,
            TcpDialer,
            webpki_tls_config(),
        )
    }
}

impl<R: Resolver, D: Dialer> PinnedHttp<R, D> {
    /// A seam over the given resolver, dialer and TLS config.
    #[must_use]
    pub const fn new(
        host: HostName,
        approved: Vec<IpAddr>,
        resolver: R,
        dialer: D,
        tls: Arc<ClientConfig>,
    ) -> Self {
        Self {
            host,
            approved,
            resolver,
            dialer,
            tls,
        }
    }

    fn permits(&self, ip: IpAddr) -> bool {
        is_public_address(ip) || self.approved.contains(&ip)
    }

    async fn addresses(&self) -> Result<Vec<IpAddr>, HttpError> {
        let name = self.host.as_str();
        let ips = match name.parse::<IpAddr>() {
            Ok(ip) => vec![ip],
            Err(_) => self
                .resolver
                .resolve(name)
                .await
                .map_err(|_| HttpError::Reset)?,
        };
        if ips.is_empty() {
            return Err(HttpError::Reset);
        }
        if !ips.iter().all(|ip| self.permits(*ip)) {
            return Err(HttpError::HostRefused);
        }
        Ok(ips)
    }

    async fn exchange(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        let ips = self.addresses().await?;
        let tcp = timeout(CONNECT_TIMEOUT, async {
            for ip in &ips {
                if let Ok(stream) = self.dialer.dial(SocketAddr::new(*ip, PORT)).await {
                    return Some(stream);
                }
            }
            None
        })
        .await
        .map_err(|_| HttpError::Timeout)?
        .ok_or(HttpError::Reset)?;
        let name = ServerName::try_from(self.host.as_str().to_owned())
            .map_err(|_| HttpError::HostRefused)?;
        let tls = TlsConnector::from(Arc::clone(&self.tls))
            .connect(name, tcp)
            .await
            .map_err(|_| HttpError::Reset)?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(64 * 1024)
            .handshake::<_, Full<Bytes>>(hyper_util::rt::TokioIo::new(tls))
            .await
            .map_err(|_| HttpError::Reset)?;
        let _driver = AbortOnDrop(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let response = sender
            .send_request(build(&self.host, request)?)
            .await
            .map_err(|_| HttpError::Reset)?;
        read(response).await
    }
}

fn build(host: &HostName, request: HttpRequest) -> Result<hyper::Request<Full<Bytes>>, HttpError> {
    let method = match request.method {
        Method::Get => hyper::Method::GET,
        Method::Post => hyper::Method::POST,
    };
    let mut builder = hyper::Request::builder()
        .method(method)
        .uri(request.path.as_str())
        .header(HOST, host.as_str())
        .header(USER_AGENT, "fleetd-forge")
        .header(ACCEPT_ENCODING, "identity")
        .header(CONNECTION, "close");
    for (name, value) in &request.headers {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| HttpError::HostRefused)?;
        if matches!(name, HOST | CONNECTION | ACCEPT_ENCODING | CONTENT_LENGTH) {
            continue;
        }
        let value = HeaderValue::from_str(value).map_err(|_| HttpError::HostRefused)?;
        builder = builder.header(name, value);
    }
    builder
        .body(Full::new(Bytes::from(request.body)))
        .map_err(|_| HttpError::HostRefused)
}

async fn read(response: hyper::Response<hyper::body::Incoming>) -> Result<HttpResponse, HttpError> {
    let status = response.status().as_u16();
    let headers = response.headers();
    if headers
        .get_all(CONTENT_ENCODING)
        .iter()
        .any(|value| !value.as_bytes().eq_ignore_ascii_case(b"identity"))
    {
        return Err(HttpError::Reset);
    }
    let kept: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(name, value)| {
            Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
        })
        .collect();
    let mut body = response.into_body();
    if body
        .size_hint()
        .exact()
        .is_some_and(|declared| declared > MAX_BODY_BYTES as u64)
    {
        return Err(HttpError::BodyTooLarge);
    }
    let mut buf = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| HttpError::Reset)?;
        if let Some(data) = frame.data_ref() {
            if buf.len() + data.len() > MAX_BODY_BYTES {
                return Err(HttpError::BodyTooLarge);
            }
            buf.extend_from_slice(data);
        }
    }
    Ok(HttpResponse {
        status,
        headers: kept,
        body: buf,
    })
}

impl<R: Resolver, D: Dialer> Http for PinnedHttp<R, D> {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, HttpError> {
        if request.host != self.host {
            return Err(HttpError::HostRefused);
        }
        timeout(REQUEST_TIMEOUT, self.exchange(request))
            .await
            .map_err(|_| HttpError::Timeout)?
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use rustls::RootCertStore;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::fetch::tls_config_with_roots;

    const NAME: &str = "git.example.test";
    const PUBLIC: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const PRIVATE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
    const OUTER: Duration = Duration::from_secs(20);

    type Seen = Arc<Mutex<Vec<(Option<String>, String)>>>;

    struct Answers(Vec<IpAddr>);

    impl Resolver for Answers {
        fn resolve(&self, _: &str) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send {
            std::future::ready(Ok(self.0.clone()))
        }
    }

    struct Local {
        port: u16,
        dialed: Mutex<Vec<SocketAddr>>,
    }

    impl Dialer for Arc<Local> {
        async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
            self.dialed
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(addr);
            TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)).await
        }
    }

    struct Server {
        local: Arc<Local>,
        roots: RootCertStore,
        seen: Seen,
    }

    fn dialed(server: &Server) -> Vec<SocketAddr> {
        server
            .local
            .dialed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn requests(server: &Server) -> Vec<(Option<String>, String)> {
        server
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn reply(status: &str, headers: &[(&str, &str)], body: &[u8], declared: usize) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status}\r\n").into_bytes();
        for (name, value) in headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(
            format!("content-length: {declared}\r\nconnection: close\r\n\r\n").as_bytes(),
        );
        out.extend_from_slice(body);
        out
    }

    async fn serve(bytes: Vec<u8>) -> Server {
        let key = rcgen::generate_simple_self_signed(vec![NAME.to_owned()]).expect("cert");
        let der = key.cert.der().clone();
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).expect("root");
        let private =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(der.to_vec())], private)
            .expect("server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let seen: Seen = Arc::default();
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let bytes = bytes.clone();
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let sni = tls.get_ref().1.server_name().map(str::to_owned);
                    let mut head = Vec::new();
                    let mut chunk = [0_u8; 1024];
                    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                        match tls.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => head.extend_from_slice(&chunk[..n]),
                        }
                    }
                    log.lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((sni, String::from_utf8_lossy(&head).into_owned()));
                    let _ = tls.write_all(&bytes).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Server {
            local: Arc::new(Local {
                port,
                dialed: Mutex::default(),
            }),
            roots,
            seen,
        }
    }

    fn host() -> HostName {
        HostName::normalise(NAME).expect("test host is valid")
    }

    fn seam(
        server: &Server,
        answers: Vec<IpAddr>,
        approved: Vec<IpAddr>,
    ) -> PinnedHttp<Answers, Arc<Local>> {
        PinnedHttp::new(
            host(),
            approved,
            Answers(answers),
            Arc::clone(&server.local),
            tls_config_with_roots(server.roots.clone()),
        )
    }

    fn get(host: HostName, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method: Method::Get,
            host,
            path: "/api/v1/repos/o/r".to_owned(),
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: Vec::new(),
        }
    }

    async fn call(
        http: &PinnedHttp<Answers, Arc<Local>>,
        request: HttpRequest,
    ) -> Result<HttpResponse, HttpError> {
        timeout(OUTER, http.send(request))
            .await
            .expect("outer timeout")
    }

    fn public() -> Vec<IpAddr> {
        vec![IpAddr::V4(PUBLIC)]
    }

    fn ok() -> Vec<u8> {
        reply("200 OK", &[("x-kept", "1")], b"hi", 2)
    }

    #[tokio::test]
    async fn the_request_dials_the_checked_address_on_443_with_sni_and_fixed_headers() {
        let server = serve(ok()).await;
        let http = seam(&server, public(), Vec::new());
        let got = call(
            &http,
            get(
                host(),
                &[
                    ("authorization", "token t0k3n"),
                    ("host", "evil.example"),
                    ("content-length", "99"),
                    ("connection", "keep-alive"),
                    ("accept-encoding", "gzip"),
                ],
            ),
        )
        .await
        .expect("call succeeds");
        assert_eq!(got.status, 200);
        assert_eq!(got.body, b"hi");
        assert!(got.headers.iter().any(|(n, v)| n == "x-kept" && v == "1"));
        assert_eq!(dialed(&server), [SocketAddr::new(IpAddr::V4(PUBLIC), 443)]);
        let seen = requests(&server);
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.as_deref(), Some(NAME));
        let head = seen[0].1.to_ascii_lowercase();
        assert!(
            head.starts_with("get /api/v1/repos/o/r http/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains(&format!("host: {NAME}\r\n")), "{head}");
        assert!(head.contains("user-agent: fleetd-forge\r\n"), "{head}");
        assert!(head.contains("accept-encoding: identity\r\n"), "{head}");
        assert!(head.contains("connection: close\r\n"), "{head}");
        assert!(head.contains("authorization: token t0k3n\r\n"), "{head}");
        for dropped in ["evil.example", "content-length: 99", "keep-alive", "gzip"] {
            assert!(!head.contains(dropped), "{dropped} in {head}");
        }
    }

    #[tokio::test]
    async fn a_request_for_another_host_is_refused_before_any_dial() {
        let server = serve(ok()).await;
        let http = seam(&server, public(), Vec::new());
        let other = HostName::normalise("other.example.test").expect("host");
        assert_eq!(
            call(&http, get(other, &[])).await.err(),
            Some(HttpError::HostRefused)
        );
        assert_eq!(dialed(&server), Vec::new());
    }

    #[tokio::test]
    async fn a_private_answer_is_refused_unless_approved_for_the_host() {
        let server = serve(ok()).await;
        let private = IpAddr::V4(PRIVATE);
        let http = seam(&server, vec![private], Vec::new());
        assert_eq!(
            call(&http, get(host(), &[])).await.err(),
            Some(HttpError::HostRefused)
        );
        assert_eq!(dialed(&server), Vec::new());
        let mixed = seam(&server, vec![IpAddr::V4(PUBLIC), private], Vec::new());
        assert_eq!(
            call(&mixed, get(host(), &[])).await.err(),
            Some(HttpError::HostRefused)
        );
        assert_eq!(dialed(&server), Vec::new());
        let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6));
        let wrong = seam(&server, vec![private], vec![other]);
        assert_eq!(
            call(&wrong, get(host(), &[])).await.err(),
            Some(HttpError::HostRefused)
        );
        let approved = seam(&server, vec![private], vec![private]);
        assert!(call(&approved, get(host(), &[])).await.is_ok());
        assert_eq!(dialed(&server), [SocketAddr::new(private, 443)]);
    }

    #[tokio::test]
    async fn a_redirect_is_returned_and_never_followed() {
        let server = serve(reply(
            "302 Found",
            &[("location", "https://evil.example/x")],
            b"",
            0,
        ))
        .await;
        let http = seam(&server, public(), Vec::new());
        let got = call(&http, get(host(), &[])).await.expect("call succeeds");
        assert_eq!(got.status, 302);
        assert_eq!(requests(&server).len(), 1);
        assert_eq!(dialed(&server).len(), 1);
    }

    #[tokio::test]
    async fn a_body_over_the_cap_fails_closed_declared_or_streamed() {
        let big = vec![b'a'; MAX_BODY_BYTES + 1];
        let declared = serve(reply("200 OK", &[], &big, big.len())).await;
        let http = seam(&declared, public(), Vec::new());
        assert_eq!(
            call(&http, get(host(), &[])).await.err(),
            Some(HttpError::BodyTooLarge)
        );
        let at_cap = vec![b'a'; MAX_BODY_BYTES];
        let exact = serve(reply("200 OK", &[], &at_cap, at_cap.len())).await;
        let http = seam(&exact, public(), Vec::new());
        let got = call(&http, get(host(), &[]))
            .await
            .expect("at cap succeeds");
        assert_eq!(got.body.len(), MAX_BODY_BYTES);
    }

    #[tokio::test]
    async fn a_compressed_reply_is_refused() {
        let server = serve(reply("200 OK", &[("content-encoding", "gzip")], b"hi", 2)).await;
        let http = seam(&server, public(), Vec::new());
        assert_eq!(
            call(&http, get(host(), &[])).await.err(),
            Some(HttpError::Reset)
        );
        let identity = serve(reply(
            "200 OK",
            &[("content-encoding", "identity")],
            b"hi",
            2,
        ))
        .await;
        let http = seam(&identity, public(), Vec::new());
        assert!(call(&http, get(host(), &[])).await.is_ok());
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_fails_the_handshake() {
        let server = serve(ok()).await;
        let http = PinnedHttp::new(
            HostName::normalise("wrong.example.test").expect("host"),
            Vec::new(),
            Answers(public()),
            Arc::clone(&server.local),
            tls_config_with_roots(server.roots.clone()),
        );
        let request = get(
            HostName::normalise("wrong.example.test").expect("host"),
            &[],
        );
        assert_eq!(call(&http, request).await.err(), Some(HttpError::Reset));
    }

    #[test]
    fn permits_is_public_or_approved() {
        let http = PinnedHttp::system(host(), vec![IpAddr::V4(PRIVATE)]);
        assert!(http.permits(IpAddr::V4(PUBLIC)));
        assert!(http.permits(IpAddr::V4(PRIVATE)));
        assert!(!http.permits(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!http.permits(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 6))));
    }
}
