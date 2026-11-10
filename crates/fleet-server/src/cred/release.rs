//! The redirect-following fetcher of the release feed (ADR-0060, ADR-0061).
//!
//! [`ReleaseFetcher`] calls a [`ForgeTransport`] once per hop and decides whether to follow a
//! redirect. Every `Location` is untrusted: it is scanned, parsed with the `url` crate and vetted
//! against a host allowlist before any request is made for it. No `Authorization` header is ever
//! sent. A refusal is a [`ReleaseRefusal`], a closed enum that echoes none of the input, and a
//! signed asset URL query never reaches an error or a log line.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use hyper::StatusCode;
use tokio::time::timeout;
use url::{Host, ParseError, Url};

use super::https::{FetchError, ForgeGet, ForgeTransport, MAX_LOCATION_BYTES};

/// Most redirects one download follows. A further redirect is [`ReleaseRefusal::TooManyHops`].
pub const MAX_RELEASE_HOPS: usize = 3;

/// The time one whole fetch, every hop included, may take.
pub const RELEASE_CYCLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The only host of the first hop.
pub const FIRST_HOP_HOST: &str = fleet_proto::UPDATE_FIRST_HOP_HOST;

/// The asset hosts a redirect may name, besides the first-hop host [`FIRST_HOP_HOST`]. Exact names only.
pub const REDIRECT_HOSTS: [&str; 2] = fleet_proto::UPDATE_REDIRECT_HOSTS;

const ACCEPT: &str = "application/octet-stream";

/// Why a release fetch failed. No variant carries input from the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// The redirect had no `Location`.
    MissingLocation,
    /// The `Location` is over [`MAX_LOCATION_BYTES`].
    LocationTooLong,
    /// The `Location` holds a control character, NEL included.
    ControlCharacter,
    /// The `Location` holds whitespace, U+2028 included.
    Whitespace,
    /// The `Location` holds a backslash.
    Backslash,
    /// The `Location` is a relative reference, or the first-hop path does not start with a
    /// single `/`.
    Relative,
    /// The `Location` is a protocol-relative `//host/path`.
    ProtocolRelative,
    /// The `Location` is not parseable as a URL.
    Unparseable,
    /// The scheme is not `https`.
    Scheme,
    /// The URL carries userinfo.
    Userinfo,
    /// The host is empty.
    EmptyHost,
    /// The host is an IPv4 or IPv6 literal.
    IpLiteral,
    /// The host ends with a dot.
    TrailingDot,
    /// The `Location` holds a non-ASCII character.
    NonAscii,
    /// The URL names a port other than the default.
    Port,
    /// The URL carries a fragment.
    Fragment,
    /// The host is not on the allowlist for this hop.
    HostNotAllowed,
    /// The URL was visited earlier in the chain.
    Loop,
    /// More redirects than the hop cap.
    TooManyHops,
    /// The final status is not 200.
    BadStatus,
    /// The body is over the cap.
    TooLarge,
    /// The cycle outran its timeout.
    Timeout,
    /// The transport refused the address.
    Blocked,
    /// The transport could not reach the host.
    Unavailable,
}

impl ReleaseRefusal {
    /// Every variant, so tests can enumerate the closed set.
    pub const ALL: [Self; 24] = [
        Self::MissingLocation,
        Self::LocationTooLong,
        Self::ControlCharacter,
        Self::Whitespace,
        Self::Backslash,
        Self::Relative,
        Self::ProtocolRelative,
        Self::Unparseable,
        Self::Scheme,
        Self::Userinfo,
        Self::EmptyHost,
        Self::IpLiteral,
        Self::TrailingDot,
        Self::NonAscii,
        Self::Port,
        Self::Fragment,
        Self::HostNotAllowed,
        Self::Loop,
        Self::TooManyHops,
        Self::BadStatus,
        Self::TooLarge,
        Self::Timeout,
        Self::Blocked,
        Self::Unavailable,
    ];
}

impl std::fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::MissingLocation => "redirect without location",
            Self::LocationTooLong => "location over the cap",
            Self::ControlCharacter => "location holds a control character",
            Self::Whitespace => "location holds whitespace",
            Self::Backslash => "location holds a backslash",
            Self::Relative => "location is relative",
            Self::ProtocolRelative => "location is protocol-relative",
            Self::Unparseable => "location is not a url",
            Self::Scheme => "location scheme is not https",
            Self::Userinfo => "location holds userinfo",
            Self::EmptyHost => "location host is empty",
            Self::IpLiteral => "location host is an ip literal",
            Self::TrailingDot => "location host ends with a dot",
            Self::NonAscii => "location holds a non-ascii character",
            Self::Port => "location port is not the default",
            Self::Fragment => "location holds a fragment",
            Self::HostNotAllowed => "location host is not allowed",
            Self::Loop => "redirect loop",
            Self::TooManyHops => "too many redirects",
            Self::BadStatus => "final status is not 200",
            Self::TooLarge => "body over the cap",
            Self::Timeout => "release fetch timed out",
            Self::Blocked => "release address refused",
            Self::Unavailable => "release host unavailable",
        })
    }
}

impl std::error::Error for ReleaseRefusal {}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Target {
    host: String,
    path: String,
}

fn scan(raw: &str) -> Result<(), ReleaseRefusal> {
    if raw.len() > MAX_LOCATION_BYTES {
        return Err(ReleaseRefusal::LocationTooLong);
    }
    if raw.chars().any(char::is_control) {
        return Err(ReleaseRefusal::ControlCharacter);
    }
    if raw.chars().any(char::is_whitespace) {
        return Err(ReleaseRefusal::Whitespace);
    }
    if raw.contains('\\') {
        return Err(ReleaseRefusal::Backslash);
    }
    if !raw.is_ascii() {
        return Err(ReleaseRefusal::NonAscii);
    }
    if raw.starts_with("//") {
        return Err(ReleaseRefusal::ProtocolRelative);
    }
    Ok(())
}

fn vet_location(raw: &str) -> Result<Target, ReleaseRefusal> {
    scan(raw)?;
    let url = Url::parse(raw).map_err(|err| match err {
        ParseError::RelativeUrlWithoutBase => ReleaseRefusal::Relative,
        ParseError::EmptyHost => ReleaseRefusal::EmptyHost,
        ParseError::InvalidIpv4Address | ParseError::InvalidIpv6Address => {
            ReleaseRefusal::IpLiteral
        }
        _ => ReleaseRefusal::Unparseable,
    })?;
    if url.scheme() != "https" {
        return Err(ReleaseRefusal::Scheme);
    }
    if !url.username().is_empty() || url.password().is_some() || raw.contains('@') {
        return Err(ReleaseRefusal::Userinfo);
    }
    let host = match url.host() {
        None => return Err(ReleaseRefusal::EmptyHost),
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err(ReleaseRefusal::IpLiteral),
        Some(Host::Domain(name)) => name,
    };
    if host.is_empty() {
        return Err(ReleaseRefusal::EmptyHost);
    }
    if host.ends_with('.') {
        return Err(ReleaseRefusal::TrailingDot);
    }
    if url.port().is_some() {
        return Err(ReleaseRefusal::Port);
    }
    if url.fragment().is_some() {
        return Err(ReleaseRefusal::Fragment);
    }
    let path = url.query().map_or_else(
        || url.path().to_owned(),
        |query| format!("{}?{query}", url.path()),
    );
    Ok(Target {
        host: host.to_owned(),
        path,
    })
}

fn redirect_host_allowed(host: &str) -> bool {
    host == FIRST_HOP_HOST || REDIRECT_HOSTS.contains(&host)
}

/// Downloads a release asset through redirects, with every hop vetted.
pub struct ReleaseFetcher {
    transport: Arc<dyn ForgeTransport>,
    max_hops: usize,
    cycle_timeout: Duration,
}

impl ReleaseFetcher {
    /// A fetcher with the ADR limits.
    pub fn new(transport: Arc<dyn ForgeTransport>) -> Self {
        Self::with_limits(transport, MAX_RELEASE_HOPS, RELEASE_CYCLE_TIMEOUT)
    }

    /// A fetcher with explicit limits, so tests can shrink them.
    pub fn with_limits(
        transport: Arc<dyn ForgeTransport>,
        max_hops: usize,
        cycle_timeout: Duration,
    ) -> Self {
        Self {
            transport,
            max_hops,
            cycle_timeout,
        }
    }

    /// Fetches `path` on [`FIRST_HOP_HOST`], following redirects, and returns the body of the
    /// final 200 reply when it is at most `cap` bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseRefusal`] when a hop is refused, the chain is too long or loops, the
    /// final status is not 200, the body is over `cap` or the cycle times out.
    pub async fn fetch(&self, path: &str, cap: usize) -> Result<Vec<u8>, ReleaseRefusal> {
        timeout(self.cycle_timeout, self.run(path, cap))
            .await
            .map_err(|_| ReleaseRefusal::Timeout)?
    }

    /// Fetches the manifest, capped at [`fleet_proto::MAX_MANIFEST_BYTES`].
    ///
    /// # Errors
    ///
    /// As [`Self::fetch`].
    pub async fn fetch_manifest(&self, path: &str) -> Result<Vec<u8>, ReleaseRefusal> {
        self.fetch(path, fleet_proto::MAX_MANIFEST_BYTES).await
    }

    /// Fetches the signature, capped at [`fleet_proto::MAX_SIGNATURE_BYTES`].
    ///
    /// # Errors
    ///
    /// As [`Self::fetch`].
    pub async fn fetch_signature(&self, path: &str) -> Result<Vec<u8>, ReleaseRefusal> {
        self.fetch(path, fleet_proto::MAX_SIGNATURE_BYTES).await
    }

    async fn run(&self, path: &str, cap: usize) -> Result<Vec<u8>, ReleaseRefusal> {
        if !path.starts_with('/') || path.starts_with("//") {
            return Err(ReleaseRefusal::Relative);
        }
        scan(path)?;
        if path.contains('#') {
            return Err(ReleaseRefusal::Fragment);
        }
        let mut target = Target {
            host: FIRST_HOP_HOST.to_owned(),
            path: path.to_owned(),
        };
        let mut visited = HashSet::new();
        visited.insert(target.clone());
        let mut hops = 0;
        loop {
            let request = ForgeGet {
                host: &target.host,
                path: &target.path,
                allow_private: false,
                approved_ips: &[],
                authorization: None,
                accept: ACCEPT,
            };
            let reply = self
                .transport
                .get(&request)
                .await
                .map_err(|err| match err {
                    FetchError::Blocked => ReleaseRefusal::Blocked,
                    FetchError::Unavailable => ReleaseRefusal::Unavailable,
                    FetchError::TooLarge => ReleaseRefusal::TooLarge,
                })?;
            tracing::debug!(
                hop = hops,
                status = reply.status.as_u16(),
                host = %target.host,
                "release hop"
            );
            if reply.status == StatusCode::OK {
                if reply.body.len() > cap {
                    return Err(ReleaseRefusal::TooLarge);
                }
                return Ok(reply.body);
            }
            if !matches!(reply.status.as_u16(), 301 | 302 | 303 | 307 | 308) {
                return Err(ReleaseRefusal::BadStatus);
            }
            if hops >= self.max_hops {
                return Err(ReleaseRefusal::TooManyHops);
            }
            let location = reply.location.ok_or(ReleaseRefusal::MissingLocation)?;
            let next = vet_location(&location)?;
            if !redirect_host_allowed(&next.host) {
                return Err(ReleaseRefusal::HostNotAllowed);
            }
            if !visited.insert(next.clone()) {
                return Err(ReleaseRefusal::Loop);
            }
            hops += 1;
            target = next;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::cred::https::ForgeReply;

    const OBJ: &str = "https://objects.githubusercontent.com";
    const FIRST: &str = "/o/r/releases/latest/download/manifest.json";

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Seen {
        host: String,
        path: String,
        authorization: bool,
        accept: String,
        allow_private: bool,
    }

    struct Fake {
        replies: Mutex<VecDeque<Result<ForgeReply, FetchError>>>,
        seen: Mutex<Vec<Seen>>,
        delay: Duration,
    }

    impl Fake {
        fn new(replies: Vec<ForgeReply>) -> Arc<Self> {
            Self::slow(replies, Duration::ZERO)
        }

        fn failing(error: FetchError) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(VecDeque::from([Err(error)])),
                seen: Mutex::new(Vec::new()),
                delay: Duration::ZERO,
            })
        }

        fn slow(replies: Vec<ForgeReply>, delay: Duration) -> Arc<Self> {
            Arc::new(Self {
                replies: Mutex::new(replies.into_iter().map(Ok).collect()),
                seen: Mutex::new(Vec::new()),
                delay,
            })
        }

        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
    }

    #[tonic::async_trait]
    impl ForgeTransport for Fake {
        async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
            self.seen.lock().unwrap().push(Seen {
                host: request.host.to_owned(),
                path: request.path.to_owned(),
                authorization: request.authorization.is_some(),
                accept: request.accept.to_owned(),
                allow_private: request.allow_private,
            });
            tokio::time::sleep(self.delay).await;
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(Err(FetchError::Unavailable))
        }
    }

    fn redirect(status: u16, location: &str) -> ForgeReply {
        ForgeReply {
            status: StatusCode::from_u16(status).unwrap(),
            body: Vec::new(),
            location: Some(location.to_owned()),
        }
    }

    fn ok(body: &[u8]) -> ForgeReply {
        ForgeReply {
            status: StatusCode::OK,
            body: body.to_vec(),
            location: None,
        }
    }

    async fn run(fake: &Arc<Fake>) -> Result<Vec<u8>, ReleaseRefusal> {
        ReleaseFetcher::new(fake.clone()).fetch(FIRST, 1024).await
    }

    #[tokio::test]
    async fn release_hostile_locations_are_refused_with_no_request() {
        let long = format!("{OBJ}/{}", "a".repeat(MAX_LOCATION_BYTES));
        let table: Vec<(String, ReleaseRefusal)> = vec![
            ("/relative/path".into(), ReleaseRefusal::Relative),
            ("relative".into(), ReleaseRefusal::Relative),
            (
                "//objects.githubusercontent.com/x".into(),
                ReleaseRefusal::ProtocolRelative,
            ),
            (
                "http://objects.githubusercontent.com/x".into(),
                ReleaseRefusal::Scheme,
            ),
            (
                "https://github.com@evil.example/".into(),
                ReleaseRefusal::Userinfo,
            ),
            (
                "https://u:p@objects.githubusercontent.com/x".into(),
                ReleaseRefusal::Userinfo,
            ),
            (
                "https:\\\\objects.githubusercontent.com\\x".into(),
                ReleaseRefusal::Backslash,
            ),
            (format!("{OBJ}/x\r"), ReleaseRefusal::ControlCharacter),
            (
                format!("{OBJ}/x\r\nHost: evil"),
                ReleaseRefusal::ControlCharacter,
            ),
            (format!("{OBJ}/x\u{85}"), ReleaseRefusal::ControlCharacter),
            (format!("{OBJ}/x\u{2028}"), ReleaseRefusal::Whitespace),
            (format!(" {OBJ}/x"), ReleaseRefusal::Whitespace),
            (format!("{OBJ}/a b"), ReleaseRefusal::Whitespace),
            ("https://[::1]/x".into(), ReleaseRefusal::IpLiteral),
            (
                "https://[2606:50c0:8000::154]/x".into(),
                ReleaseRefusal::IpLiteral,
            ),
            ("https://127.0.0.1/x".into(), ReleaseRefusal::IpLiteral),
            (
                "https://185.199.108.154/x".into(),
                ReleaseRefusal::IpLiteral,
            ),
            (
                "https://objects.githubusercontent.com./x".into(),
                ReleaseRefusal::TrailingDot,
            ),
            (
                "https://objects.githubusercontent.com:444/x".into(),
                ReleaseRefusal::Port,
            ),
            (
                "https://obj\u{e9}cts.githubusercontent.com/x".into(),
                ReleaseRefusal::NonAscii,
            ),
            ("https://".into(), ReleaseRefusal::EmptyHost),
            ("https://:443/x".into(), ReleaseRefusal::EmptyHost),
            (long, ReleaseRefusal::LocationTooLong),
            (format!("{OBJ}/x#frag"), ReleaseRefusal::Fragment),
            (format!("{OBJ}/x?sig=SECRET#frag"), ReleaseRefusal::Fragment),
            (
                "https://evil.example/x".into(),
                ReleaseRefusal::HostNotAllowed,
            ),
            (
                "https://evil.objects.githubusercontent.com/x".into(),
                ReleaseRefusal::HostNotAllowed,
            ),
            (
                "https://githubusercontent.com/x".into(),
                ReleaseRefusal::HostNotAllowed,
            ),
        ];
        for (location, reason) in table {
            let fake = Fake::new(vec![redirect(302, &location), ok(b"never")]);
            let got = run(&fake).await;
            assert_eq!(got, Err(reason), "location {location:?}");
            let seen = fake.seen();
            assert_eq!(seen.len(), 1, "location {location:?} was requested");
            assert_eq!(seen[0].host, FIRST_HOP_HOST);
        }
    }

    #[tokio::test]
    async fn release_follows_every_redirect_status_to_a_200() {
        for status in [301, 302, 303, 307, 308] {
            let fake = Fake::new(vec![
                redirect(status, &format!("{OBJ}/a?sig=SECRET")),
                redirect(status, "https://release-assets.githubusercontent.com/b"),
                ok(b"body"),
            ]);
            assert_eq!(run(&fake).await, Ok(b"body".to_vec()), "status {status}");
            let seen = fake.seen();
            assert_eq!(seen.len(), 3);
            assert_eq!(seen[0].host, "github.com");
            assert_eq!(seen[0].path, FIRST);
            assert_eq!(seen[1].host, "objects.githubusercontent.com");
            assert_eq!(seen[1].path, "/a?sig=SECRET");
            assert_eq!(seen[2].host, "release-assets.githubusercontent.com");
            for hop in seen {
                assert!(!hop.authorization);
                assert!(!hop.allow_private);
                assert_eq!(hop.accept, "application/octet-stream");
            }
        }
    }

    #[tokio::test]
    async fn release_host_case_is_folded_before_matching() {
        let fake = Fake::new(vec![
            redirect(302, "https://OBJECTS.GithubUserContent.com/a"),
            ok(b"x"),
        ]);
        assert_eq!(run(&fake).await, Ok(b"x".to_vec()));
        assert_eq!(fake.seen()[1].host, "objects.githubusercontent.com");
    }

    #[tokio::test]
    async fn release_hop_cap_allows_three_and_refuses_the_fourth() {
        let three = Fake::new(vec![
            redirect(302, &format!("{OBJ}/1")),
            redirect(302, &format!("{OBJ}/2")),
            redirect(302, &format!("{OBJ}/3")),
            ok(b"x"),
        ]);
        assert_eq!(run(&three).await, Ok(b"x".to_vec()));
        let four = Fake::new(vec![
            redirect(302, &format!("{OBJ}/1")),
            redirect(302, &format!("{OBJ}/2")),
            redirect(302, &format!("{OBJ}/3")),
            redirect(302, &format!("{OBJ}/4")),
            ok(b"never"),
        ]);
        assert_eq!(run(&four).await, Err(ReleaseRefusal::TooManyHops));
        assert_eq!(four.seen().len(), 4);
    }

    #[tokio::test]
    async fn release_hop_cap_honours_a_shrunk_value() {
        let one = Fake::new(vec![redirect(302, &format!("{OBJ}/1")), ok(b"x")]);
        let fetcher = ReleaseFetcher::with_limits(one, 1, RELEASE_CYCLE_TIMEOUT);
        assert_eq!(fetcher.fetch(FIRST, 8).await, Ok(b"x".to_vec()));
        let two = Fake::new(vec![
            redirect(302, &format!("{OBJ}/1")),
            redirect(302, &format!("{OBJ}/2")),
            ok(b"never"),
        ]);
        let fetcher = ReleaseFetcher::with_limits(two.clone(), 1, RELEASE_CYCLE_TIMEOUT);
        assert_eq!(
            fetcher.fetch(FIRST, 8).await,
            Err(ReleaseRefusal::TooManyHops)
        );
        assert_eq!(two.seen().len(), 2);
    }

    #[tokio::test]
    async fn release_self_loop_and_cycle_are_refused() {
        let own = Fake::new(vec![
            redirect(302, &format!("{OBJ}/a")),
            redirect(302, &format!("{OBJ}/a")),
            ok(b"never"),
        ]);
        assert_eq!(run(&own).await, Err(ReleaseRefusal::Loop));
        assert_eq!(own.seen().len(), 2);
        let cycle = Fake::new(vec![
            redirect(302, &format!("{OBJ}/a")),
            redirect(302, &format!("{OBJ}/b")),
            redirect(302, &format!("{OBJ}/a")),
            ok(b"never"),
        ]);
        assert_eq!(run(&cycle).await, Err(ReleaseRefusal::Loop));
        assert_eq!(cycle.seen().len(), 3);
    }

    #[tokio::test]
    async fn release_final_status_must_be_200() {
        for status in [201, 204, 206, 404, 500] {
            let fake = Fake::new(vec![ForgeReply {
                status: StatusCode::from_u16(status).unwrap(),
                body: b"x".to_vec(),
                location: None,
            }]);
            assert_eq!(run(&fake).await, Err(ReleaseRefusal::BadStatus), "{status}");
        }
        let bare = Fake::new(vec![ForgeReply {
            status: StatusCode::FOUND,
            body: Vec::new(),
            location: None,
        }]);
        assert_eq!(run(&bare).await, Err(ReleaseRefusal::MissingLocation));
        let not_modified = Fake::new(vec![redirect(304, &format!("{OBJ}/a"))]);
        assert_eq!(run(&not_modified).await, Err(ReleaseRefusal::BadStatus));
        assert_eq!(not_modified.seen().len(), 1);
    }

    #[tokio::test]
    async fn release_body_cap_honours_a_shrunk_value() {
        let at = Fake::new(vec![ok(b"abcd")]);
        let fetcher = ReleaseFetcher::new(at);
        assert_eq!(fetcher.fetch(FIRST, 4).await, Ok(b"abcd".to_vec()));
        let over = Fake::new(vec![ok(b"abcde")]);
        let fetcher = ReleaseFetcher::new(over);
        assert_eq!(fetcher.fetch(FIRST, 4).await, Err(ReleaseRefusal::TooLarge));
    }

    #[tokio::test]
    async fn release_manifest_and_signature_caps_come_from_proto() {
        let manifest = Fake::new(vec![ok(&vec![b' '; fleet_proto::MAX_MANIFEST_BYTES])]);
        let got = ReleaseFetcher::new(manifest).fetch_manifest(FIRST).await;
        assert_eq!(got.unwrap().len(), fleet_proto::MAX_MANIFEST_BYTES);
        let manifest = Fake::new(vec![ok(&vec![b' '; fleet_proto::MAX_MANIFEST_BYTES + 1])]);
        let got = ReleaseFetcher::new(manifest).fetch_manifest(FIRST).await;
        assert_eq!(got, Err(ReleaseRefusal::TooLarge));
        let sig = Fake::new(vec![ok(&vec![b'x'; fleet_proto::MAX_SIGNATURE_BYTES])]);
        let got = ReleaseFetcher::new(sig).fetch_signature(FIRST).await;
        assert_eq!(got.unwrap().len(), fleet_proto::MAX_SIGNATURE_BYTES);
        let sig = Fake::new(vec![ok(&vec![b'x'; fleet_proto::MAX_SIGNATURE_BYTES + 1])]);
        let got = ReleaseFetcher::new(sig).fetch_signature(FIRST).await;
        assert_eq!(got, Err(ReleaseRefusal::TooLarge));
    }

    #[tokio::test]
    async fn release_transport_errors_map_to_refusals() {
        for (error, reason) in [
            (FetchError::Blocked, ReleaseRefusal::Blocked),
            (FetchError::Unavailable, ReleaseRefusal::Unavailable),
            (FetchError::TooLarge, ReleaseRefusal::TooLarge),
        ] {
            let fake = Fake::failing(error);
            assert_eq!(run(&fake).await, Err(reason));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn release_cycle_timeout_covers_the_whole_chain() {
        let hung = Fake::slow(vec![ok(b"x")], Duration::from_secs(60));
        assert_eq!(run(&hung).await, Err(ReleaseRefusal::Timeout));
        let slow_ok = Fake::slow(vec![ok(b"x")], Duration::from_secs(4));
        let fetcher = ReleaseFetcher::with_limits(slow_ok, 3, Duration::from_secs(5));
        assert_eq!(fetcher.fetch(FIRST, 8).await, Ok(b"x".to_vec()));
        let two_hops = Fake::slow(
            vec![redirect(302, &format!("{OBJ}/a")), ok(b"x")],
            Duration::from_secs(4),
        );
        let fetcher = ReleaseFetcher::with_limits(two_hops, 3, Duration::from_secs(5));
        assert_eq!(fetcher.fetch(FIRST, 8).await, Err(ReleaseRefusal::Timeout));
    }

    #[test]
    fn release_refusal_all_lists_every_variant_once() {
        let exhaustive = |reason: ReleaseRefusal| match reason {
            ReleaseRefusal::MissingLocation
            | ReleaseRefusal::LocationTooLong
            | ReleaseRefusal::ControlCharacter
            | ReleaseRefusal::Whitespace
            | ReleaseRefusal::Backslash
            | ReleaseRefusal::Relative
            | ReleaseRefusal::ProtocolRelative
            | ReleaseRefusal::Unparseable
            | ReleaseRefusal::Scheme
            | ReleaseRefusal::Userinfo
            | ReleaseRefusal::EmptyHost
            | ReleaseRefusal::IpLiteral
            | ReleaseRefusal::TrailingDot
            | ReleaseRefusal::NonAscii
            | ReleaseRefusal::Port
            | ReleaseRefusal::Fragment
            | ReleaseRefusal::HostNotAllowed
            | ReleaseRefusal::Loop
            | ReleaseRefusal::TooManyHops
            | ReleaseRefusal::BadStatus
            | ReleaseRefusal::TooLarge
            | ReleaseRefusal::Timeout
            | ReleaseRefusal::Blocked
            | ReleaseRefusal::Unavailable => {}
        };
        for reason in ReleaseRefusal::ALL {
            exhaustive(reason);
        }
        let unique: HashSet<String> = ReleaseRefusal::ALL
            .iter()
            .map(|reason| format!("{reason:?}"))
            .collect();
        assert_eq!(unique.len(), ReleaseRefusal::ALL.len());
    }

    #[tokio::test]
    async fn release_follows_the_real_github_chain_shape() {
        let fake = Fake::new(vec![
            redirect(
                302,
                "https://github.com/o/r/releases/download/v1.2.3/manifest.json",
            ),
            redirect(
                302,
                "https://release-assets.githubusercontent.com/github-production-release-asset/1?sig=SECRET",
            ),
            ok(b"body"),
        ]);
        assert_eq!(run(&fake).await, Ok(b"body".to_vec()));
        let seen = fake.seen();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].host, "github.com");
        assert_eq!(seen[0].path, FIRST);
        assert_eq!(seen[1].host, "github.com");
        assert_eq!(seen[1].path, "/o/r/releases/download/v1.2.3/manifest.json");
        assert_eq!(seen[2].host, "release-assets.githubusercontent.com");
        assert_eq!(
            seen[2].path,
            "/github-production-release-asset/1?sig=SECRET"
        );
    }

    #[tokio::test]
    async fn release_github_self_loop_is_refused_as_a_loop() {
        let fake = Fake::new(vec![
            redirect(302, &format!("https://github.com{FIRST}")),
            ok(b"never"),
        ]);
        assert_eq!(run(&fake).await, Err(ReleaseRefusal::Loop));
        assert_eq!(fake.seen().len(), 1);
    }

    #[test]
    fn release_redirect_hosts_accepted_are_the_first_hop_host_plus_the_shared_redirect_hosts() {
        let candidates = [
            "github.com",
            "objects.githubusercontent.com",
            "release-assets.githubusercontent.com",
            "api.github.com",
            "githubusercontent.com",
            "evil.example",
            "github.com.evil.example",
            "raw.githubusercontent.com",
        ];
        let mut accepted: Vec<&str> = candidates
            .into_iter()
            .filter(|host| redirect_host_allowed(host))
            .collect();
        let mut expected: Vec<&str> = std::iter::once(fleet_proto::UPDATE_FIRST_HOP_HOST)
            .chain(fleet_proto::UPDATE_REDIRECT_HOSTS)
            .collect();
        accepted.sort_unstable();
        expected.sort_unstable();
        assert_eq!(accepted, expected);
    }

    #[test]
    fn release_server_hosts_are_the_shared_constants() {
        assert_eq!(FIRST_HOP_HOST, fleet_proto::UPDATE_FIRST_HOP_HOST);
        assert_eq!(REDIRECT_HOSTS, fleet_proto::UPDATE_REDIRECT_HOSTS);
    }

    #[tokio::test]
    async fn release_location_of_exactly_the_cap_passes_the_scan_and_one_over_is_refused() {
        let prefix = format!("{OBJ}/");
        let at = format!("{prefix}{}", "a".repeat(MAX_LOCATION_BYTES - prefix.len()));
        assert_eq!(at.len(), MAX_LOCATION_BYTES);
        assert_eq!(scan(&at), Ok(()));
        let fake = Fake::new(vec![redirect(302, &at), ok(b"x")]);
        assert_eq!(run(&fake).await, Ok(b"x".to_vec()));
        let over = format!("{at}a");
        assert_eq!(scan(&over), Err(ReleaseRefusal::LocationTooLong));
        let fake = Fake::new(vec![redirect(302, &over), ok(b"never")]);
        assert_eq!(run(&fake).await, Err(ReleaseRefusal::LocationTooLong));
        assert_eq!(fake.seen().len(), 1);
    }

    #[tokio::test]
    async fn release_explicit_default_port_is_accepted() {
        let fake = Fake::new(vec![
            redirect(302, "https://objects.githubusercontent.com:443/x"),
            ok(b"x"),
        ]);
        assert_eq!(run(&fake).await, Ok(b"x".to_vec()));
        assert_eq!(fake.seen()[1].path, "/x");
    }

    #[tokio::test]
    async fn release_literal_at_sign_in_a_query_is_refused_as_userinfo() {
        let fake = Fake::new(vec![
            redirect(302, &format!("{OBJ}/x?email=a@b")),
            ok(b"never"),
        ]);
        assert_eq!(run(&fake).await, Err(ReleaseRefusal::Userinfo));
        assert_eq!(fake.seen().len(), 1);
    }

    #[tokio::test]
    async fn release_first_hop_path_is_scanned_with_no_request() {
        let table = [
            ("/o/r\\x", ReleaseRefusal::Backslash),
            ("/o/r x", ReleaseRefusal::Whitespace),
            ("/o/r\tx", ReleaseRefusal::ControlCharacter),
            ("/o/r\nx", ReleaseRefusal::ControlCharacter),
            ("/o/r\u{85}x", ReleaseRefusal::ControlCharacter),
            ("/o/r\u{2028}x", ReleaseRefusal::Whitespace),
            ("/o/r\u{e9}x", ReleaseRefusal::NonAscii),
            ("/o/r#frag", ReleaseRefusal::Fragment),
            ("/o/r?x=1#", ReleaseRefusal::Fragment),
        ];
        for (path, reason) in table {
            let fake = Fake::new(vec![ok(b"never")]);
            let got = ReleaseFetcher::new(fake.clone()).fetch(path, 8).await;
            assert_eq!(got, Err(reason), "path {path:?}");
            assert!(fake.seen().is_empty(), "path {path:?} was requested");
        }
    }

    #[test]
    fn release_refusals_echo_no_input_or_query() {
        for reason in ReleaseRefusal::ALL {
            let text = format!("{reason} {reason:?}");
            assert!(!text.contains("SECRET") && !text.contains("sig="));
        }
    }
}
