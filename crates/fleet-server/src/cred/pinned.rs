//! The SSRF-safe forge connector (ADR-0059, Security rules).
//!
//! [`PinnedHttps`] checks the host string, resolves it once, vets every address with
//! [`is_vetted`], dials one vetted address and runs TLS with the hostname for SNI and
//! certificate verification. It follows no redirect and reads at most [`MAX_BODY_BYTES`].
//! Vetting runs on every call and nothing is cached.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use http_body_util::Empty;
use hyper::Request;
use hyper::body::Bytes;
use hyper::header::{ACCEPT, AUTHORIZATION, HOST, USER_AGENT};
use rustls::ClientConfig;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use super::https::{
    FetchError, ForgeGet, ForgeReply, ForgeTransport, MAX_LOCATION_BYTES, TlsError, read_capped,
    send, tls_config,
};

/// The only port dialled in v1.
pub const FORGE_PORT: u16 = 443;

/// Largest accepted forge response body. A longer body fails closed.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Most addresses one lookup may return. A longer list fails closed.
pub const MAX_ADDRESSES: usize = 64;

/// Time allowed to dial and finish the TLS handshake.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

const MAX_HOST_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

fn alibaba_metadata() -> Ipv4Addr {
    Ipv4Addr::new(100, 100, 100, 200)
}

fn aws_metadata_v4() -> Ipv4Addr {
    Ipv4Addr::new(169, 254, 169, 254)
}

fn aws_metadata_v6() -> Ipv6Addr {
    Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)
}

/// Whether `ip` is a cloud metadata address. It is refused whatever `allow_private` says.
pub fn is_metadata(ip: IpAddr) -> bool {
    match unmap(ip) {
        IpAddr::V4(v4) => v4 == aws_metadata_v4() || v4 == alibaba_metadata(),
        IpAddr::V6(v6) => v6 == aws_metadata_v6(),
    }
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

/// Whether `ip` is an RFC 1918 or unique-local `fc00::/7` address, read through IPv4-mapping.
pub fn is_private_range(ip: IpAddr) -> bool {
    match unmap(ip) {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.segments()[0] & 0xfe00 == 0xfc00,
    }
}

/// Whether the forge may be dialled at `ip`.
///
/// The rule is global unicast, not a blocklist. An IPv4-mapped IPv6 address is judged as its
/// IPv4 address. Metadata addresses, loopback, link-local, unspecified, CGNAT `100.64/10`,
/// multicast, broadcast, reserved and documentation ranges, NAT64 `64:ff9b::/96` and 6to4
/// `2002::/16` are always refused. An RFC 1918 or unique-local `fc00::/7` address passes only
/// when `allow_private` is set and `approved_ips` holds that address.
pub fn is_vetted(ip: IpAddr, allow_private: bool, approved_ips: &[IpAddr]) -> bool {
    if is_metadata(ip) {
        return false;
    }
    if is_private_range(ip) {
        let wanted = unmap(ip);
        return allow_private && approved_ips.iter().any(|a| unmap(*a) == wanted);
    }
    match unmap(ip) {
        IpAddr::V4(v4) => vet_v4(v4),
        IpAddr::V6(v6) => vet_v6(v6),
    }
}

fn vet_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    let refused = a == 0
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113);
    !refused
}

fn vet_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    let global_unicast = s[0] & 0xe000 == 0x2000;
    let sixto4 = s[0] == 0x2002;
    let protocol_assignments = s[0] == 0x2001 && s[1] < 0x0200;
    let documentation = (s[0] == 0x2001 && s[1] == 0x0db8) || (s[0] == 0x3fff && s[1] < 0x1000);
    global_unicast && !sixto4 && !protocol_assignments && !documentation
}

/// Checks every address. One refused address, an empty list or a list over [`MAX_ADDRESSES`]
/// fails the whole call. Returns the first address to dial.
///
/// # Errors
///
/// Returns [`FetchError::Blocked`] when any address fails [`is_vetted`] and
/// [`FetchError::Unavailable`] when the list is empty.
pub fn vet_all(
    addrs: &[IpAddr],
    allow_private: bool,
    approved_ips: &[IpAddr],
) -> Result<IpAddr, FetchError> {
    if addrs.len() > MAX_ADDRESSES {
        return Err(FetchError::Blocked);
    }
    if addrs
        .iter()
        .any(|ip| !is_vetted(*ip, allow_private, approved_ips))
    {
        return Err(FetchError::Blocked);
    }
    addrs.first().copied().ok_or(FetchError::Unavailable)
}

/// Whether `host` is a lowercase ASCII DNS name.
///
/// Labels use `a-z`, `0-9` and `-` and neither start nor end with `-`, with no trailing dot. The
/// last label starts with a letter, which refuses IPv4 in every numeric form.
pub fn is_dns_host(host: &str) -> bool {
    if host.len() > MAX_HOST_BYTES {
        return false;
    }
    let labels_ok = host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= MAX_LABEL_BYTES
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    let letter_tld = host
        .rsplit('.')
        .next()
        .is_some_and(|tld| tld.starts_with(|c: char| c.is_ascii_lowercase()));
    labels_ok && letter_tld
}

/// Looks a host name up. Tests replace it with a fake.
#[tonic::async_trait]
pub trait Resolve: Send + Sync {
    /// Every address `host` resolves to.
    ///
    /// # Errors
    ///
    /// Returns the lookup error.
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>;
}

/// The system resolver.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

#[tonic::async_trait]
impl Resolve for SystemResolver {
    async fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>> {
        let found = tokio::net::lookup_host((host, FORGE_PORT)).await?;
        Ok(found
            .take(MAX_ADDRESSES + 1)
            .map(|addr| addr.ip())
            .collect())
    }
}

/// Opens the TCP connection to a vetted address. Tests replace it with a fake.
#[tonic::async_trait]
pub trait Dial: Send + Sync {
    /// Connects to `addr`.
    ///
    /// # Errors
    ///
    /// Returns the connect error.
    async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream>;
}

/// The system dialer.
#[derive(Debug, Clone, Copy, Default)]
pub struct TcpDial;

#[tonic::async_trait]
impl Dial for TcpDial {
    async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
        TcpStream::connect(addr).await
    }
}

/// The real [`ForgeTransport`].
pub struct PinnedHttps<R, D> {
    resolver: R,
    dialer: D,
    tls: Arc<ClientConfig>,
}

impl<R, D> std::fmt::Debug for PinnedHttps<R, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinnedHttps(..)")
    }
}

impl PinnedHttps<SystemResolver, TcpDial> {
    /// The production connector: system DNS, plain TCP and the bundled web roots.
    ///
    /// # Errors
    ///
    /// Returns [`TlsError`] when the TLS stack cannot be set up.
    pub fn system() -> Result<Self, TlsError> {
        Ok(Self::new(SystemResolver, TcpDial, tls_config()?))
    }
}

impl<R: Resolve, D: Dial> PinnedHttps<R, D> {
    /// A connector over the given resolver, dialer and TLS config.
    pub fn new(resolver: R, dialer: D, tls: Arc<ClientConfig>) -> Self {
        Self {
            resolver,
            dialer,
            tls,
        }
    }
}

/// The one `Location` value of a 3xx reply, `None` when absent. Several headers, a non-UTF-8
/// value or one over [`MAX_LOCATION_BYTES`] fail closed.
fn single_location(headers: &hyper::HeaderMap) -> Result<Option<String>, FetchError> {
    let mut values = headers.get_all(hyper::header::LOCATION).iter().take(2);
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || first.as_bytes().len() > MAX_LOCATION_BYTES {
        return Err(FetchError::Unavailable);
    }
    std::str::from_utf8(first.as_bytes())
        .map(|text| Some(text.to_owned()))
        .map_err(|_| FetchError::Unavailable)
}

#[tonic::async_trait]
impl<R: Resolve, D: Dial> ForgeTransport for PinnedHttps<R, D> {
    async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
        if !is_dns_host(request.host) {
            return Err(FetchError::Blocked);
        }
        let addrs = self
            .resolver
            .resolve(request.host)
            .await
            .map_err(|_| FetchError::Unavailable)?;
        let ip =
            vet_all(&addrs, request.allow_private, request.approved_ips).inspect_err(|err| {
                tracing::warn!(host = request.host, error = %err, "forge address refused");
            })?;
        let name =
            ServerName::try_from(request.host.to_owned()).map_err(|_| FetchError::Blocked)?;
        let wire = Request::builder()
            .uri(request.path)
            .header(HOST, request.host)
            .header(USER_AGENT, "fleet-server")
            .header(ACCEPT, request.accept);
        let wire = match request.authorization {
            Some(value) => wire.header(AUTHORIZATION, value.clone()),
            None => wire,
        }
        .body(Empty::<Bytes>::new())
        .map_err(|_| FetchError::Unavailable)?;
        let connected = async {
            let tcp = self.dialer.dial(SocketAddr::new(ip, FORGE_PORT)).await?;
            TlsConnector::from(Arc::clone(&self.tls))
                .connect(name, tcp)
                .await
        };
        let tls = timeout(CONNECT_TIMEOUT, connected)
            .await
            .map_err(|_| FetchError::Unavailable)?
            .map_err(|_| FetchError::Unavailable)?;
        let (response, _guard) = send(tls, wire).await.map_err(|_| FetchError::Unavailable)?;
        let status = response.status();
        if status.is_redirection() {
            let location = single_location(response.headers())?;
            return Ok(ForgeReply {
                status,
                body: Vec::new(),
                location,
            });
        }
        let body = read_capped(response.into_body(), MAX_BODY_BYTES)
            .await
            .map_err(|err| match err {
                super::https::BodyError::TooLarge => FetchError::TooLarge,
                super::https::BodyError::Stream => FetchError::Unavailable,
            })?;
        Ok(ForgeReply {
            status,
            body: body.to_vec(),
            location: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::{RootCertStore, ServerConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;
    use crate::cred::https::tls_config_with_roots;

    const PUBLIC: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const HOST_NAME: &str = "forge.test";

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    fn v6(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn every_always_refused_class_is_refused_even_with_allow_private() {
        let refused = [
            ("loopback", v4(127, 0, 0, 1)),
            ("loopback high", v4(127, 255, 255, 254)),
            ("unspecified", v4(0, 0, 0, 0)),
            ("this network", v4(0, 1, 2, 3)),
            ("link-local", v4(169, 254, 1, 1)),
            ("aws metadata", v4(169, 254, 169, 254)),
            ("alibaba metadata", v4(100, 100, 100, 200)),
            ("cgnat low", v4(100, 64, 0, 1)),
            ("cgnat high", v4(100, 127, 255, 254)),
            ("protocol assignments", v4(192, 0, 0, 8)),
            ("oracle metadata", v4(192, 0, 0, 192)),
            ("test-net-1", v4(192, 0, 2, 1)),
            ("6to4 relay", v4(192, 88, 99, 1)),
            ("benchmarking", v4(198, 18, 0, 1)),
            ("benchmarking high", v4(198, 19, 255, 254)),
            ("test-net-2", v4(198, 51, 100, 1)),
            ("test-net-3", v4(203, 0, 113, 1)),
            ("multicast", v4(224, 0, 0, 1)),
            ("reserved", v4(240, 0, 0, 1)),
            ("broadcast", v4(255, 255, 255, 255)),
            ("v6 loopback", v6("::1")),
            ("v6 unspecified", v6("::")),
            ("v6 link-local", v6("fe80::1")),
            ("v6 link-local top", v6("febf::1")),
            ("v6 multicast", v6("ff02::1")),
            ("aws v6 metadata", v6("fd00:ec2::254")),
            ("nat64", v6("64:ff9b::808:808")),
            ("nat64 private", v6("64:ff9b::a00:1")),
            ("6to4", v6("2002:808:808::1")),
            ("6to4 loopback", v6("2002:7f00:1::1")),
            ("protocol assignments high", v6("2001:1ff::1")),
            ("teredo", v6("2001:0:4136:e378:8000:63bf:3fff:fdd2")),
            ("documentation", v6("2001:db8::1")),
            ("documentation 3fff", v6("3fff::1")),
            ("documentation 3fff top", v6("3fff:fff:ffff::1")),
            ("ipv4 compatible", v6("::808:808")),
            ("mapped loopback", v6("::ffff:127.0.0.1")),
            ("mapped metadata", v6("::ffff:169.254.169.254")),
            (
                "mapped alibaba",
                IpAddr::V6(alibaba_metadata().to_ipv6_mapped()),
            ),
            (
                "mapped cgnat",
                IpAddr::V6(Ipv4Addr::new(100, 64, 0, 1).to_ipv6_mapped()),
            ),
            ("mapped broadcast", v6("::ffff:255.255.255.255")),
            ("mapped unspecified", v6("::ffff:0.0.0.0")),
            ("mapped link-local", v6("::ffff:169.254.1.1")),
        ];
        for (name, ip) in refused {
            for allow_private in [false, true] {
                for approved in [&[][..], &[ip][..]] {
                    assert!(
                        !is_vetted(ip, allow_private, approved),
                        "{name} {ip} {allow_private}"
                    );
                }
            }
        }
    }

    #[test]
    fn private_ranges_need_allow_private() {
        let private = [
            v4(10, 0, 0, 1),
            v4(10, 255, 255, 254),
            v4(172, 16, 0, 1),
            v4(172, 31, 255, 254),
            v4(192, 168, 0, 1),
            v6("fc00::1"),
            v6("fd12:3456::1"),
            v6("::ffff:10.0.0.1"),
            v6("::ffff:192.168.1.1"),
        ];
        for ip in private {
            assert!(!is_vetted(ip, false, &[]), "{ip}");
            assert!(!is_vetted(ip, false, &[ip]), "{ip}");
            assert!(!is_vetted(ip, true, &[]), "{ip}");
            assert!(is_vetted(ip, true, &[ip]), "{ip}");
        }
    }

    #[test]
    fn public_addresses_pass_and_range_edges_hold() {
        let public = [
            v4(93, 184, 216, 34),
            v4(1, 1, 1, 1),
            v4(100, 63, 255, 255),
            v4(100, 128, 0, 1),
            v4(172, 15, 255, 254),
            v4(172, 32, 0, 1),
            v4(169, 253, 1, 1),
            v4(169, 255, 1, 1),
            v4(198, 17, 0, 1),
            v4(198, 20, 0, 1),
            v4(223, 255, 255, 254),
            v4(192, 0, 1, 1),
            v4(192, 88, 98, 1),
            v4(192, 88, 100, 1),
            v4(198, 51, 99, 1),
            v4(198, 51, 101, 1),
            v4(203, 0, 112, 1),
            v4(203, 0, 114, 1),
            v4(11, 0, 0, 1),
            v6("2606:4700:4700::1111"),
            v6("2001:4860:4860::8888"),
            v6("2001:200::1"),
            v6("2003::1"),
            v6("3000::1"),
            v6("3fff:1000::1"),
            v6("2001:db9::1"),
            v6("::ffff:93.184.216.34"),
        ];
        for ip in public {
            assert!(is_vetted(ip, false, &[]), "{ip}");
            assert!(is_vetted(ip, true, &[]), "{ip}");
        }
    }

    #[test]
    fn metadata_addresses_are_named() {
        assert!(is_metadata(v4(169, 254, 169, 254)));
        assert!(is_metadata(v4(100, 100, 100, 200)));
        assert!(is_metadata(v6("fd00:ec2::254")));
        assert!(is_metadata(v6("::ffff:169.254.169.254")));
        assert!(!is_metadata(v4(169, 254, 169, 253)));
        assert!(!is_metadata(v4(100, 100, 100, 201)));
        assert!(!is_metadata(v6("fd00:ec2::255")));
    }

    #[test]
    fn one_refused_address_fails_the_whole_list() {
        let good = v4(93, 184, 216, 34);
        assert_eq!(vet_all(&[good], false, &[]), Ok(good));
        assert_eq!(vet_all(&[good, good], false, &[]), Ok(good));
        for bad in [v4(127, 0, 0, 1), v6("::ffff:127.0.0.1"), v4(10, 0, 0, 1)] {
            assert_eq!(vet_all(&[good, bad], false, &[]), Err(FetchError::Blocked));
            assert_eq!(vet_all(&[bad, good], false, &[]), Err(FetchError::Blocked));
        }
        assert_eq!(vet_all(&[], false, &[]), Err(FetchError::Unavailable));
        assert_eq!(
            vet_all(&[good, v4(10, 0, 0, 1)], true, &[v4(10, 0, 0, 1)]),
            Ok(good),
            "an approved private address passes beside a public one"
        );
        assert_eq!(
            vet_all(&[good, v4(127, 0, 0, 1)], true, &[v4(127, 0, 0, 1)]),
            Err(FetchError::Blocked)
        );
    }

    #[test]
    fn the_address_list_is_capped() {
        let good = v4(93, 184, 216, 34);
        assert_eq!(vet_all(&vec![good; MAX_ADDRESSES], false, &[]), Ok(good));
        assert_eq!(
            vet_all(&vec![good; MAX_ADDRESSES + 1], false, &[]),
            Err(FetchError::Blocked)
        );
    }

    #[test]
    fn host_length_limits_hold_at_the_boundary() {
        let at = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(at.len(), 253);
        assert!(is_dns_host(&at));
        assert!(!is_dns_host(&format!("{at}d")));
        assert!(is_dns_host(&format!("{}.test", "a".repeat(63))));
        assert!(!is_dns_host(&format!("{}.test", "a".repeat(64))));
    }

    #[test]
    fn the_hostile_host_table_is_refused_before_any_lookup() {
        let long_label = format!("{}.test", "a".repeat(64));
        let long_host = format!("{}.test", ["a"; 130].join("."));
        let hostile = [
            "",
            ".",
            "a..b",
            ".a.test",
            "a.test.",
            "127.0.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "[::1]",
            "::1",
            "::ffff:127.0.0.1",
            "2130706433",
            "0x7f.1",
            "1.2.3.4.5",
            "forge.test:443",
            "user@forge.test",
            "user:pw@forge.test",
            "forge.test/path",
            "forge.test\\path",
            "forge.test?x",
            "forge.test#x",
            "forge.test\r\nX: y",
            "forge.test\n",
            "forge.test\r",
            "forge\u{85}.test",
            "forge\u{2028}.test",
            "forge .test",
            " forge.test",
            "forge.test ",
            "forge\t.test",
            "FORGE.test",
            "Forge.Test",
            "forge_x.test",
            "-forge.test",
            "forge-.test",
            "f\u{f6}rge.test",
            "xn--\u{e9}.test",
            "\u{ff10}.test",
            "0x7f000001",
            "a.0x7f000001",
            "0X7F.1",
            "1.1.1.0x",
            long_label.as_str(),
            long_host.as_str(),
        ];
        for host in hostile {
            assert!(!is_dns_host(host), "{host:?}");
        }
        for ok in [
            "forge.test",
            "api.github.com",
            "a",
            "a-b.c0.example",
            "xn--bcher-kva.example",
        ] {
            assert!(is_dns_host(ok), "{ok}");
        }
    }

    struct Fixed(io::Result<Vec<IpAddr>>);

    #[tonic::async_trait]
    impl Resolve for Fixed {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            match &self.0 {
                Ok(list) => Ok(list.clone()),
                Err(err) => Err(io::Error::new(err.kind(), "lookup failed")),
            }
        }
    }

    #[derive(Clone)]
    struct Aim {
        local: SocketAddr,
        dialled: Arc<Mutex<Vec<SocketAddr>>>,
    }

    #[tonic::async_trait]
    impl Dial for Aim {
        async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
            self.dialled.lock().unwrap().push(addr);
            TcpStream::connect(self.local).await
        }
    }

    struct Forge {
        aim: Aim,
        roots: RootCertStore,
        seen: Arc<Mutex<Vec<String>>>,
        accepted: Arc<AtomicUsize>,
    }

    async fn forge(cert_name: &str, reply: Vec<u8>, only_tls12: bool) -> Forge {
        let key = rcgen::generate_simple_self_signed(vec![cert_name.to_owned()]).unwrap();
        let der = key.cert.der().clone();
        let mut roots = RootCertStore::empty();
        roots.add(der.clone()).unwrap();
        let signing =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()));
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = ServerConfig::builder_with_provider(provider);
        let builder = if only_tls12 {
            builder
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
        } else {
            builder.with_safe_default_protocol_versions().unwrap()
        };
        let config = builder
            .with_no_client_auth()
            .with_single_cert(vec![der], signing)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(AtomicUsize::new(0));
        let (log, count) = (Arc::clone(&seen), Arc::clone(&accepted));
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else {
                    return;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let (acceptor, reply, log) = (acceptor.clone(), reply.clone(), Arc::clone(&log));
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let mut buf = vec![0_u8; 8192];
                    let n = tls.read(&mut buf).await.unwrap_or(0);
                    log.lock()
                        .unwrap()
                        .push(String::from_utf8_lossy(&buf[..n]).into_owned());
                    let _ = tls.write_all(&reply).await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        Forge {
            aim: Aim {
                local,
                dialled: Arc::new(Mutex::new(Vec::new())),
            },
            roots,
            seen,
            accepted,
        }
    }

    fn http(status: &str, extra: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn connector(list: Vec<IpAddr>, f: &Forge) -> PinnedHttps<Fixed, Aim> {
        PinnedHttps::new(
            Fixed(Ok(list)),
            f.aim.clone(),
            tls_config_with_roots(f.roots.clone()).unwrap(),
        )
    }

    async fn get(
        c: &PinnedHttps<Fixed, Aim>,
        host: &str,
        private: bool,
    ) -> Result<ForgeReply, FetchError> {
        get_approved(c, host, private, &[]).await
    }

    async fn get_approved<R: Resolve, D: Dial>(
        c: &PinnedHttps<R, D>,
        host: &str,
        private: bool,
        approved: &[IpAddr],
    ) -> Result<ForgeReply, FetchError> {
        let auth = crate::cred::https::bearer_header(b"s3cret-token").unwrap();
        c.get(&ForgeGet {
            host,
            path: "/repos/acme/widget",
            allow_private: private,
            approved_ips: approved,
            authorization: Some(&auth),
            accept: "application/json",
        })
        .await
    }

    #[tokio::test]
    async fn it_dials_the_vetted_address_and_sends_the_request() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        let reply = get(&c, HOST_NAME, false).await.unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, b"{}");
        assert_eq!(
            *f.aim.dialled.lock().unwrap(),
            vec![SocketAddr::new(IpAddr::V4(PUBLIC), 443)]
        );
        let request = f.seen.lock().unwrap().join("");
        assert!(
            request.starts_with("GET /repos/acme/widget HTTP/1.1\r\n"),
            "{request}"
        );
        assert!(request.contains("host: forge.test\r\n"), "{request}");
        assert!(
            request.contains("authorization: Bearer s3cret-token\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_tls_12_only_forge_is_reachable() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), true).await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        assert_eq!(get(&c, HOST_NAME, false).await.unwrap().status, 200);
    }

    #[tokio::test]
    async fn the_certificate_must_match_the_hostname() {
        let f = forge("other.test", http("200 OK", "", b"{}"), false).await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        assert_eq!(
            get(&c, HOST_NAME, false).await,
            Err(FetchError::Unavailable)
        );
        assert!(f.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_untrusted_certificate_is_refused() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let c = PinnedHttps::new(
            Fixed(Ok(vec![IpAddr::V4(PUBLIC)])),
            f.aim.clone(),
            tls_config_with_roots(RootCertStore::empty()).unwrap(),
        );
        assert_eq!(
            get(&c, HOST_NAME, false).await,
            Err(FetchError::Unavailable)
        );
        assert!(f.seen.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn one_bad_address_dials_nothing() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        for bad in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            v6("::ffff:169.254.169.254"),
            v4(10, 0, 0, 1),
            v4(100, 64, 0, 1),
        ] {
            for list in [
                vec![bad],
                vec![IpAddr::V4(PUBLIC), bad],
                vec![bad, IpAddr::V4(PUBLIC)],
            ] {
                let c = connector(list, &f);
                assert_eq!(
                    get(&c, HOST_NAME, false).await,
                    Err(FetchError::Blocked),
                    "{bad}"
                );
            }
        }
        assert!(f.aim.dialled.lock().unwrap().is_empty());
        assert_eq!(f.accepted.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn allow_private_admits_private_and_never_loopback() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let c = connector(vec![v4(10, 1, 2, 3)], &f);
        let approved = [v4(10, 1, 2, 3)];
        assert_eq!(
            get_approved(&c, HOST_NAME, true, &approved)
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            *f.aim.dialled.lock().unwrap(),
            vec![SocketAddr::new(v4(10, 1, 2, 3), 443)]
        );
        for bad in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            v4(169, 254, 169, 254),
            v4(100, 100, 100, 200),
        ] {
            let c = connector(vec![bad], &f);
            assert_eq!(
                get_approved(&c, HOST_NAME, true, &[bad]).await,
                Err(FetchError::Blocked),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn lookup_failure_and_empty_answers_are_unavailable() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let tls = tls_config_with_roots(f.roots.clone()).unwrap();
        let failing = PinnedHttps::new(
            Fixed(Err(io::Error::other("x"))),
            f.aim.clone(),
            Arc::clone(&tls),
        );
        assert_eq!(
            get_via(&failing, HOST_NAME).await,
            Err(FetchError::Unavailable)
        );
        let empty = PinnedHttps::new(Fixed(Ok(Vec::new())), f.aim.clone(), tls);
        assert_eq!(
            get_via(&empty, HOST_NAME).await,
            Err(FetchError::Unavailable)
        );
    }

    async fn get_via<R: Resolve, D: Dial>(
        c: &PinnedHttps<R, D>,
        host: &str,
    ) -> Result<ForgeReply, FetchError> {
        let auth = crate::cred::https::bearer_header(b"t").unwrap();
        c.get(&ForgeGet {
            host,
            path: "/",
            allow_private: false,
            approved_ips: &[],
            authorization: Some(&auth),
            accept: "application/json",
        })
        .await
    }

    #[tokio::test]
    async fn a_hostile_host_is_refused_without_a_lookup() {
        struct Never;
        #[tonic::async_trait]
        impl Resolve for Never {
            async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
                panic!("resolved a hostile host");
            }
        }
        let f = forge(HOST_NAME, Vec::new(), false).await;
        let c = PinnedHttps::new(
            Never,
            f.aim.clone(),
            tls_config_with_roots(f.roots.clone()).unwrap(),
        );
        for host in [
            "127.0.0.1",
            "forge.test:443",
            "user@forge.test",
            "FORGE.test",
            "",
        ] {
            assert_eq!(
                get_via(&c, host).await,
                Err(FetchError::Blocked),
                "{host:?}"
            );
        }
    }

    struct Stall;

    #[tonic::async_trait]
    impl Dial for Stall {
        async fn dial(&self, _: SocketAddr) -> io::Result<TcpStream> {
            std::future::pending().await
        }
    }

    #[tokio::test]
    async fn a_dial_that_never_connects_is_unavailable_within_the_connect_timeout() {
        let c = PinnedHttps::new(
            Fixed(Ok(vec![IpAddr::V4(PUBLIC)])),
            Stall,
            tls_config_with_roots(RootCertStore::empty()).unwrap(),
        );
        let started = std::time::Instant::now();
        let got = timeout(Duration::from_secs(30), get_via(&c, HOST_NAME)).await;
        assert_eq!(got.ok(), Some(Err(FetchError::Unavailable)));
        assert!(started.elapsed() < CONNECT_TIMEOUT * 4);
    }

    #[tokio::test]
    async fn a_redirect_is_returned_unread_and_never_followed() {
        let body = vec![b'x'; 1024];
        let f = forge(
            HOST_NAME,
            http("302 Found", "location: https://evil.test/x\r\n", &body),
            false,
        )
        .await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        let reply = get(&c, HOST_NAME, false).await.unwrap();
        assert_eq!(reply.status, 302);
        assert_eq!(reply.body.len(), 0);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(f.seen.lock().unwrap().len(), 1);
        assert_eq!(f.aim.dialled.lock().unwrap().len(), 1);
    }

    async fn redirect_get(reply: Vec<u8>) -> Result<ForgeReply, FetchError> {
        let f = forge(HOST_NAME, reply, false).await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        get(&c, HOST_NAME, false).await
    }

    #[tokio::test]
    async fn a_redirect_location_is_captured_and_still_not_followed() {
        let f = forge(
            HOST_NAME,
            http("302 Found", "location: https://evil.test/x\r\n", b"zz"),
            false,
        )
        .await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        let reply = get(&c, HOST_NAME, false).await.unwrap();
        assert_eq!(reply.status, 302);
        assert_eq!(reply.location.as_deref(), Some("https://evil.test/x"));
        assert_eq!(reply.body.len(), 0);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(f.seen.lock().unwrap().len(), 1);
        assert_eq!(f.aim.dialled.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn location_is_absent_on_non_redirects_and_on_a_bare_redirect() {
        let ok = redirect_get(http("200 OK", "location: https://a.test/\r\n", b"{}")).await;
        assert_eq!(ok.unwrap().location, None);
        let bare = redirect_get(http("302 Found", "", b"")).await.unwrap();
        assert_eq!(bare.location, None);
    }

    fn location_of(len: usize) -> Vec<u8> {
        let value = format!(
            "https://a.test/{}",
            "p".repeat(len - "https://a.test/".len())
        );
        assert_eq!(value.len(), len);
        http("302 Found", &format!("location: {value}\r\n"), b"")
    }

    #[tokio::test]
    async fn a_location_of_2048_bytes_is_kept_and_2049_is_unavailable() {
        let at = redirect_get(location_of(MAX_LOCATION_BYTES)).await.unwrap();
        assert_eq!(at.location.map(|l| l.len()), Some(MAX_LOCATION_BYTES));
        assert_eq!(
            redirect_get(location_of(MAX_LOCATION_BYTES + 1)).await,
            Err(FetchError::Unavailable)
        );
    }

    #[tokio::test]
    async fn a_non_utf8_location_fails_closed() {
        let mut reply = b"HTTP/1.1 302 Found\r\ncontent-length: 0\r\nconnection: close\r\nlocation: https://a.test/".to_vec();
        reply.extend_from_slice(&[0xff, 0xfe]);
        reply.extend_from_slice(b"\r\n\r\n");
        assert_eq!(redirect_get(reply).await, Err(FetchError::Unavailable));
    }

    #[tokio::test]
    async fn several_location_headers_fail_closed() {
        let reply = http(
            "302 Found",
            "location: https://a.test/1\r\nlocation: https://a.test/2\r\n",
            b"",
        );
        assert_eq!(redirect_get(reply).await, Err(FetchError::Unavailable));
    }

    #[tokio::test]
    async fn no_authorization_header_is_sent_without_one_and_accept_is_the_callers() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        c.get(&ForgeGet {
            host: HOST_NAME,
            path: "/x",
            allow_private: false,
            approved_ips: &[],
            authorization: None,
            accept: "application/octet-stream",
        })
        .await
        .unwrap();
        let request = f.seen.lock().unwrap().join("").to_ascii_lowercase();
        assert!(!request.contains("authorization"), "{request}");
        assert!(
            request.contains("accept: application/octet-stream\r\n"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_body_over_the_cap_fails_and_one_at_the_cap_reads() {
        let over = forge(
            HOST_NAME,
            http("200 OK", "", &vec![b'a'; MAX_BODY_BYTES + 1]),
            false,
        )
        .await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &over);
        assert_eq!(get(&c, HOST_NAME, false).await, Err(FetchError::TooLarge));
        let at = forge(
            HOST_NAME,
            http("200 OK", "", &vec![b'a'; MAX_BODY_BYTES]),
            false,
        )
        .await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &at);
        assert_eq!(
            get(&c, HOST_NAME, false).await.unwrap().body.len(),
            MAX_BODY_BYTES
        );
    }

    #[tokio::test]
    async fn a_chunked_body_over_the_cap_fails_too() {
        let mut reply =
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_vec();
        let chunk = vec![b'a'; MAX_BODY_BYTES / 2 + 1];
        for _ in 0..2 {
            reply.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
            reply.extend_from_slice(&chunk);
            reply.extend_from_slice(b"\r\n");
        }
        reply.extend_from_slice(b"0\r\n\r\n");
        let f = forge(HOST_NAME, reply, false).await;
        let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
        assert_eq!(get(&c, HOST_NAME, false).await, Err(FetchError::TooLarge));
    }

    struct Script {
        answers: Mutex<Vec<Vec<IpAddr>>>,
        calls: Arc<AtomicUsize>,
    }

    impl Script {
        fn new(answers: Vec<Vec<IpAddr>>) -> (Self, Arc<AtomicUsize>) {
            let calls = Arc::new(AtomicUsize::new(0));
            let script = Self {
                answers: Mutex::new(answers),
                calls: Arc::clone(&calls),
            };
            (script, calls)
        }
    }

    #[tonic::async_trait]
    impl Resolve for Script {
        async fn resolve(&self, _: &str) -> io::Result<Vec<IpAddr>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut answers = self.answers.lock().unwrap();
            if answers.len() > 1 {
                Ok(answers.remove(0))
            } else {
                Ok(answers.first().cloned().unwrap_or_default())
            }
        }
    }

    fn scripted(
        answers: Vec<Vec<IpAddr>>,
        f: &Forge,
    ) -> (PinnedHttps<Script, Aim>, Arc<AtomicUsize>) {
        let (script, calls) = Script::new(answers);
        let c = PinnedHttps::new(
            script,
            f.aim.clone(),
            tls_config_with_roots(f.roots.clone()).unwrap(),
        );
        (c, calls)
    }

    #[tokio::test]
    async fn an_approved_private_address_is_dialled_and_an_unapproved_one_is_not() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let approved = [v4(10, 1, 2, 3)];
        let c = connector(vec![v4(10, 1, 2, 3)], &f);
        assert_eq!(
            get_approved(&c, HOST_NAME, false, &approved).await,
            Err(FetchError::Blocked)
        );
        assert_eq!(
            get_approved(&c, HOST_NAME, true, &[]).await,
            Err(FetchError::Blocked)
        );
        assert!(f.aim.dialled.lock().unwrap().is_empty());
        assert_eq!(
            get_approved(&c, HOST_NAME, true, &approved)
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(f.aim.dialled.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_approved_host_that_moves_to_a_new_private_address_is_refused() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let approved = [v4(192, 168, 3, 1)];
        let (c, _) = scripted(vec![vec![v4(192, 168, 3, 1)], vec![v4(192, 168, 3, 2)]], &f);
        assert_eq!(
            get_approved(&c, HOST_NAME, true, &approved)
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(
            get_approved(&c, HOST_NAME, true, &approved).await,
            Err(FetchError::Blocked)
        );
        assert_eq!(f.aim.dialled.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_mixed_set_with_one_unapproved_private_record_is_refused() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let approved = [v4(10, 0, 0, 5)];
        let public = IpAddr::V4(PUBLIC);
        let lists = [
            vec![public, v4(10, 0, 0, 6)],
            vec![v4(10, 0, 0, 6), public],
            vec![v4(10, 0, 0, 5), v4(10, 0, 0, 6)],
            vec![v4(10, 0, 0, 5), v4(127, 0, 0, 1)],
            vec![v4(10, 0, 0, 5), v4(169, 254, 169, 254)],
            vec![v4(10, 0, 0, 5), v4(169, 254, 1, 1)],
            vec![v4(10, 0, 0, 5), v6("::1")],
        ];
        for list in lists {
            let c = connector(list.clone(), &f);
            assert_eq!(
                get_approved(&c, HOST_NAME, true, &approved).await,
                Err(FetchError::Blocked),
                "{list:?}"
            );
        }
        assert!(f.aim.dialled.lock().unwrap().is_empty());
        let ok = connector(vec![public, v4(10, 0, 0, 5)], &f);
        assert_eq!(
            get_approved(&ok, HOST_NAME, true, &approved)
                .await
                .unwrap()
                .status,
            200
        );
    }

    #[tokio::test]
    async fn a_public_host_with_a_private_record_is_refused_even_when_that_address_is_listed() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let c = connector(vec![IpAddr::V4(PUBLIC), v4(10, 0, 0, 5)], &f);
        assert_eq!(
            get_approved(&c, HOST_NAME, false, &[v4(10, 0, 0, 5)]).await,
            Err(FetchError::Blocked)
        );
        assert!(f.aim.dialled.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_approved_address_written_in_mapped_form_matches_its_v4_record() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let mapped = [v6("::ffff:10.0.0.5")];
        let c = connector(vec![v4(10, 0, 0, 5)], &f);
        assert_eq!(
            get_approved(&c, HOST_NAME, true, &mapped)
                .await
                .unwrap()
                .status,
            200
        );
        let c = connector(vec![v6("::ffff:10.0.0.5")], &f);
        assert_eq!(
            get_approved(&c, HOST_NAME, true, &[v4(10, 0, 0, 5)])
                .await
                .unwrap()
                .status,
            200
        );
    }

    #[tokio::test]
    async fn vetting_reruns_on_every_call_and_the_dial_uses_the_vetted_address() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let (c, calls) = scripted(
            vec![
                vec![IpAddr::V4(PUBLIC)],
                vec![v4(169, 254, 169, 254)],
                vec![IpAddr::V4(PUBLIC)],
            ],
            &f,
        );
        assert_eq!(
            get_approved(&c, HOST_NAME, false, &[])
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            get_approved(&c, HOST_NAME, false, &[]).await,
            Err(FetchError::Blocked)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            get_approved(&c, HOST_NAME, false, &[])
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert_eq!(
            *f.aim.dialled.lock().unwrap(),
            vec![SocketAddr::new(IpAddr::V4(PUBLIC), 443); 2]
        );
    }

    #[tokio::test]
    async fn a_rebind_after_the_vet_cannot_change_the_dialled_address() {
        let f = forge(HOST_NAME, http("200 OK", "", b"{}"), false).await;
        let (c, calls) = scripted(vec![vec![IpAddr::V4(PUBLIC)], vec![v4(127, 0, 0, 1)]], &f);
        assert_eq!(
            get_approved(&c, HOST_NAME, false, &[])
                .await
                .unwrap()
                .status,
            200
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            *f.aim.dialled.lock().unwrap(),
            vec![SocketAddr::new(IpAddr::V4(PUBLIC), 443)]
        );
    }

    #[tokio::test]
    async fn a_redirect_to_an_internal_address_is_never_followed() {
        for status in [
            "301 Moved Permanently",
            "302 Found",
            "307 Temporary Redirect",
            "308 Permanent Redirect",
        ] {
            for target in [
                "http://169.254.169.254/latest/meta-data/",
                "https://127.0.0.1/admin",
                "https://[::1]/",
                "https://internal.test/x",
            ] {
                let f = forge(
                    HOST_NAME,
                    http(status, &format!("location: {target}\r\n"), b"moved"),
                    false,
                )
                .await;
                let c = connector(vec![IpAddr::V4(PUBLIC)], &f);
                let reply = get(&c, HOST_NAME, false).await.unwrap();
                assert!(reply.status.is_redirection(), "{status}");
                assert_eq!(reply.location.as_deref(), Some(target));
                assert_eq!(reply.body.len(), 0);
                tokio::time::sleep(Duration::from_millis(100)).await;
                assert_eq!(f.accepted.load(Ordering::SeqCst), 1, "{status} {target}");
                assert_eq!(f.seen.lock().unwrap().len(), 1);
                assert_eq!(f.aim.dialled.lock().unwrap().len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn a_redirect_with_authorization_sends_no_second_request_even_for_an_approved_host() {
        let f = forge(
            HOST_NAME,
            http(
                "307 Temporary Redirect",
                "location: https://other.test/x\r\n",
                b"",
            ),
            false,
        )
        .await;
        let approved = [v4(10, 0, 0, 5)];
        let c = connector(vec![v4(10, 0, 0, 5)], &f);
        let reply = get_approved(&c, HOST_NAME, true, &approved).await.unwrap();
        assert_eq!(reply.status, 307);
        tokio::time::sleep(Duration::from_millis(100)).await;
        let seen = f.seen.lock().unwrap().clone();
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen.iter()
                .filter(|r| r.contains("authorization: Bearer"))
                .count(),
            1
        );
        assert_eq!(f.aim.dialled.lock().unwrap().len(), 1);
    }
}
