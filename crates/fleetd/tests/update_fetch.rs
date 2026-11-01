//! The production archive fetcher against a loopback TLS server: binary bodies, redirects that
//! leave the allow-list refused before any connection, the hop and size caps, and a stalled body.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::format_collect,
    reason = "test code asserts by panicking"
)]

use std::future::Future;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::tools::Version;
use fleetd::fetch::{Dialer, Resolver, tls_config_with_roots};
use fleetd::fetch_policy::{FetchCaps, FetchPolicy, HostPattern};
use fleetd::update::{
    ArchiveFetcher, MAX_ARCHIVE_REDIRECTS, PolicyArchiveFetcher, Stager, Target, archive_caps,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

const PUBLIC: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
const NAMES: [&str; 3] = ["a.example.test", "b.example.test", "evil.example.test"];
const OUTER: Duration = Duration::from_secs(30);

type Handler = Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>;

struct Fixed;

impl Resolver for Fixed {
    fn resolve(&self, _host: &str) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send {
        std::future::ready(Ok(vec![IpAddr::V4(PUBLIC)]))
    }
}

struct Loopback {
    port: u16,
    dialed: Mutex<Vec<SocketAddr>>,
}

struct Dial(Arc<Loopback>);

impl Dialer for Dial {
    async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        self.0.dialed.lock().unwrap().push(addr);
        TcpStream::connect((Ipv4Addr::LOCALHOST, self.0.port)).await
    }
}

struct Server {
    loopback: Arc<Loopback>,
    roots: RootCertStore,
}

impl Server {
    fn dials(&self) -> usize {
        self.loopback.dialed.lock().unwrap().len()
    }
}

async fn serve(handler: Handler, hold_open: bool) -> Server {
    let key = rcgen::generate_simple_self_signed(NAMES.map(str::to_owned).to_vec()).unwrap();
    let der = key.cert.der().clone();
    let mut roots = RootCertStore::empty();
    roots.add(der.clone()).unwrap();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![CertificateDer::from(der.to_vec())], private)
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut chunk = [0_u8; 1024];
                while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&chunk[..n]),
                    }
                }
                let reply = handler(&String::from_utf8_lossy(&head));
                let _ = tls.write_all(&reply).await;
                let _ = tls.flush().await;
                if hold_open {
                    std::future::pending::<()>().await;
                }
                let _ = tls.shutdown().await;
            });
        }
    });
    Server {
        loopback: Arc::new(Loopback {
            port,
            dialed: Mutex::default(),
        }),
        roots,
    }
}

fn response(status: &str, headers: &[(&str, String)], declared: usize, body: &[u8]) -> Vec<u8> {
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

fn archive(body: &[u8]) -> Handler {
    let body = body.to_vec();
    Arc::new(move |_| {
        response(
            "200 OK",
            &[("content-type", "application/gzip".to_owned())],
            body.len(),
            &body,
        )
    })
}

fn redirect_to(location: &str) -> Handler {
    let location = location.to_owned();
    Arc::new(move |_| response("302 Found", &[("location", location.clone())], 0, b""))
}

fn allow() -> Vec<HostPattern> {
    ["a.example.test", "b.example.test"]
        .iter()
        .map(|name| HostPattern::parse(name).unwrap())
        .collect()
}

fn caps() -> FetchCaps {
    FetchCaps {
        connect_timeout: Duration::from_secs(5),
        total_timeout: Duration::from_secs(20),
        ..archive_caps()
    }
}

fn fetcher_with(server: &Server, caps: FetchCaps) -> PolicyArchiveFetcher<Fixed, Dial> {
    PolicyArchiveFetcher::with_parts(
        tokio::runtime::Handle::current(),
        FetchPolicy::Allowlist(allow()),
        caps,
        Fixed,
        Dial(Arc::clone(&server.loopback)),
        tls_config_with_roots(server.roots.clone()),
    )
}

async fn download(
    fetcher: PolicyArchiveFetcher<Fixed, Dial>,
    url: &str,
) -> io::Result<(String, Vec<u8>)> {
    let url = url.to_owned();
    let job = tokio::task::spawn_blocking(move || {
        let response = fetcher.get(&url)?;
        let mut body = Vec::new();
        let mut reader = response.body;
        reader.read_to_end(&mut body)?;
        Ok((response.final_url, body))
    });
    tokio::time::timeout(OUTER, job)
        .await
        .expect("outer timeout")
        .unwrap()
}

fn text(err: &io::Error) -> String {
    err.to_string()
}

fn binary() -> Vec<u8> {
    (0..=255_u8).cycle().take(200_000).collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_binary_body_arrives_intact_with_its_final_url() {
    let body = binary();
    let server = serve(archive(&body), false).await;
    let fetcher = fetcher_with(&server, caps());
    let (final_url, got) = download(fetcher, "https://a.example.test/fleetd.tar.gz")
        .await
        .unwrap();
    assert_eq!(final_url, "https://a.example.test/");
    assert_eq!(got, body);
    assert_eq!(server.dials(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_on_list_redirect_is_followed_and_reported_in_the_final_url() {
    let body = binary();
    let inner = archive(&body);
    let handler: Handler = Arc::new(move |head| {
        if head.contains("fleetd-first") {
            response(
                "302 Found",
                &[("location", "https://b.example.test/real".to_owned())],
                0,
                b"",
            )
        } else {
            inner(head)
        }
    });
    let server = serve(handler, false).await;
    let fetcher = fetcher_with(&server, caps());
    let (final_url, got) = download(fetcher, "https://a.example.test/fleetd-first")
        .await
        .unwrap();
    assert_eq!(final_url, "https://b.example.test/");
    assert_eq!(got, body);
    assert_eq!(server.dials(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirects_off_the_list_or_to_bad_schemes_are_refused_without_a_second_connection() {
    let targets = [
        "https://evil.example.test/x",
        "https://93.184.216.34/x",
        "https://10.0.0.5/x",
        "https://[2606:2800:220:1::1]/x",
        "http://b.example.test/x",
        "ftp://b.example.test/x",
        "//evil.example.test/x",
        "https://b.example.test:8443/x",
        "https://b.example.test@evil.example.test/x",
        "https://evil.example.test%2eb.example.test/x",
    ];
    for target in targets {
        let server = serve(redirect_to(target), false).await;
        let fetcher = fetcher_with(&server, caps());
        let err = download(fetcher, "https://a.example.test/fleetd.tar.gz")
            .await
            .unwrap_err();
        let why = text(&err);
        assert!(
            why.starts_with("redirect refused") || why == "fetch host not permitted",
            "{target}: {why}"
        );
        assert_eq!(server.dials(), 1, "{target}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_first_url_off_the_list_never_connects() {
    let server = serve(archive(b"x"), false).await;
    let fetcher = fetcher_with(&server, caps());
    let err = download(fetcher, "https://evil.example.test/fleetd.tar.gz")
        .await
        .unwrap_err();
    assert_eq!(text(&err), "fetch host not permitted");
    assert_eq!(server.dials(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_redirect_loop_stops_at_the_named_hop_cap() {
    let server = serve(redirect_to("https://b.example.test/loop"), false).await;
    let fetcher = fetcher_with(&server, caps());
    let err = download(fetcher, "https://a.example.test/loop")
        .await
        .unwrap_err();
    assert_eq!(text(&err), "fetch too many redirects");
    assert_eq!(server.dials(), usize::from(MAX_ARCHIVE_REDIRECTS) + 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_body_one_byte_over_the_cap_is_refused_and_the_cap_itself_passes() {
    let cap = 4096_u64;
    let small = FetchCaps {
        max_body_bytes: cap,
        max_decoded_bytes: cap,
        ..caps()
    };
    let at_cap = vec![7_u8; 4096];
    let server = serve(archive(&at_cap), false).await;
    let (_, got) = download(fetcher_with(&server, small), "https://a.example.test/a")
        .await
        .unwrap();
    assert_eq!(got.len(), 4096);

    let over = vec![7_u8; 4097];
    let declared = serve(archive(&over), false).await;
    let err = download(fetcher_with(&declared, small), "https://a.example.test/a")
        .await
        .unwrap_err();
    assert_eq!(text(&err), "fetch body too large");

    let undeclared: Handler = Arc::new(move |_| {
        let mut out = b"HTTP/1.1 200 OK\r\nconnection: close\r\n\r\n".to_vec();
        out.extend_from_slice(&vec![7_u8; 4097]);
        out
    });
    let server = serve(undeclared, false).await;
    let err = download(fetcher_with(&server, small), "https://a.example.test/a")
        .await
        .unwrap_err();
    assert_eq!(text(&err), "fetch body too large");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_body_ends_at_the_injected_deadline() {
    let partial: Handler = Arc::new(|_| {
        response(
            "200 OK",
            &[("content-type", "application/gzip".to_owned())],
            1000,
            &[1_u8; 10],
        )
    });
    let server = serve(partial, true).await;
    let quick = FetchCaps {
        total_timeout: Duration::from_secs(1),
        ..caps()
    };
    let started = std::time::Instant::now();
    let err = download(fetcher_with(&server, quick), "https://a.example.test/a")
        .await
        .unwrap_err();
    assert_eq!(text(&err), "fetch timed out");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_status_error_and_a_content_encoding_are_refused() {
    let missing: Handler = Arc::new(|_| response("404 Not Found", &[], 0, b""));
    let server = serve(missing, false).await;
    let err = download(fetcher_with(&server, caps()), "https://a.example.test/a")
        .await
        .unwrap_err();
    assert_eq!(text(&err), "fetch status 404");

    let encoded: Handler = Arc::new(|_| {
        response(
            "200 OK",
            &[("content-encoding", "gzip".to_owned())],
            1,
            b"x",
        )
    });
    let server = serve(encoded, false).await;
    let err = download(fetcher_with(&server, caps()), "https://a.example.test/a")
        .await
        .unwrap_err();
    assert_eq!(text(&err), "fetch content encoding refused");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_stager_stages_a_download_through_the_policy_fetcher() {
    let body = binary();
    let server = serve(archive(&body), false).await;
    let fetcher = fetcher_with(&server, caps());
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).unwrap();
    let target = Target {
        sha256: Sha256::digest(&body)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
        size: body.len() as u64,
        url: Some("https://a.example.test/fleetd.tar.gz".to_owned()),
    };
    let staged = tokio::task::spawn_blocking(move || {
        Stager::new(&bin, allow(), &fetcher).stage(&Version::new("1.2.3").unwrap(), &target)
    });
    let path = tokio::time::timeout(OUTER, staged)
        .await
        .expect("outer timeout")
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(path).unwrap(), body);
}
