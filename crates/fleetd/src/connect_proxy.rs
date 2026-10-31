//! The model-API `CONNECT` proxy on the per-job unix socket (ADR-0031, ADR-0038).
//!
//! The agent reaches the model API through this service, registered under
//! [`crate::jobsock::ServiceName::EgressProxy`] on the Job socket, never on a global socket, so
//! every tunnel carries the peer-verified Job id of the listener's [`JobContext`].
//!
//! The service reads one request: `CONNECT <host>:443 HTTP/1.1`, then header lines, then an
//! empty line, all CRLF, ASCII, at most [`ProxyLimits::max_header_bytes`] bytes and
//! [`MAX_HEADER_LINES`] lines, read within [`ProxyLimits::header_timeout`]. Any other method or
//! version, an absolute URI, userinfo, an IP literal, a port other than 443, a bare CR or LF,
//! folded headers, `Content-Length`, `Transfer-Encoding`, or bytes after the empty line before
//! the `200` is a refusal. The host is lowercased and loses one trailing dot, then must equal
//! [`MODEL_API_HOST`] or match a pattern of the Box config `egress_allow` list. A Job the runner
//! narrowed with [`ConnectProxy::set_job_hosts`] gets only the hosts its runner declares, so
//! [`MODEL_API_HOST`] is no longer implied for it. No Profile or bundle input reaches this
//! list.
//!
//! The service resolves the host itself. If any answer fails [`is_public_address`] (the one
//! predicate of fetch, shared from [`crate::netguard`]) it refuses. It dials only the checked
//! addresses, in order, with the connect timeout covering all of them. It then replies
//! `HTTP/1.1 200 Connection Established` and copies bytes both ways until a side closes, the
//! idle timeout or the total timeout passes, the byte cap is reached, or the Job socket is
//! cancelled (lease lost, Job cancel, shutdown).
//!
//! Every refusal and every failure before the `200` is the same fixed `403` line
//! ([`FORBIDDEN`]), with no detail. The service keeps per-Job counters only
//! ([`ProxyStats`]), with no per-connection event. One instance serves every Job of the Box, so
//! counters and caps live in a Job id map: call [`ConnectProxy::forget`] when a Job ends.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::time::{Instant, sleep_until, timeout};

use crate::fetch::{Dialer, Resolver};
use crate::fetch_policy::HostPattern;
use crate::jobsock::{JobContext, ServeFuture, Service};
use crate::netguard::is_public_address;

/// The model API host of the claude runner, allowed to a Job that was never narrowed.
pub const MODEL_API_HOST: &str = "api.anthropic.com";

/// The only port a tunnel may target.
pub const TUNNEL_PORT: u16 = 443;

/// The single response to every refusal and every failure before the tunnel opens.
pub const FORBIDDEN: &[u8] =
    b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

/// The response that opens a tunnel.
pub const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Most header lines after the request line.
pub const MAX_HEADER_LINES: usize = 16;

const COPY_CHUNK: usize = 16 * 1024;

/// Limits of the proxy. A test shrinks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyLimits {
    /// Most bytes of the request head, request line and headers included.
    pub max_header_bytes: usize,
    /// Time allowed to receive the whole request head.
    pub header_timeout: Duration,
    /// Time allowed to resolve the host and connect.
    pub connect_timeout: Duration,
    /// A tunnel with no byte in either direction for this long is closed.
    pub idle_timeout: Duration,
    /// A tunnel is closed this long after it opened.
    pub total_timeout: Duration,
    /// Most bytes copied, both directions together, per tunnel.
    pub max_tunnel_bytes: u64,
    /// Most tunnels of one Job open at once.
    pub max_tunnels_per_job: u32,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_header_bytes: 2048,
            header_timeout: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(120),
            total_timeout: Duration::from_secs(3600),
            max_tunnel_bytes: 1 << 30,
            max_tunnels_per_job: 4,
        }
    }
}

/// The counters of one Job. They feed the later summary; no event is recorded per connection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProxyStats {
    /// Tunnels opened.
    pub connections: u64,
    /// Bytes copied from the agent to the upstream.
    pub bytes_up: u64,
    /// Bytes copied from the upstream to the agent.
    pub bytes_down: u64,
    /// Requests refused or failed before a tunnel opened.
    pub refusals: u64,
}

#[derive(Default)]
struct JobCounts {
    stats: ProxyStats,
    open: u32,
    hosts: Option<Vec<HostPattern>>,
}

type Jobs = Mutex<HashMap<String, JobCounts>>;

struct Tunnel<'a> {
    jobs: &'a Jobs,
    job_id: &'a str,
    up: u64,
    down: u64,
}

impl Tunnel<'_> {
    fn established(&self) {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(counts) = jobs.get_mut(self.job_id) {
            counts.stats.connections = counts.stats.connections.saturating_add(1);
        }
    }
}

impl Drop for Tunnel<'_> {
    fn drop(&mut self) {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(counts) = jobs.get_mut(self.job_id) {
            counts.open = counts.open.saturating_sub(1);
            counts.stats.bytes_up = counts.stats.bytes_up.saturating_add(self.up);
            counts.stats.bytes_down = counts.stats.bytes_down.saturating_add(self.down);
        }
    }
}

fn valid_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn valid_header_line(line: &str) -> bool {
    let Some((name, value)) = line.split_once(':') else {
        return false;
    };
    let token = !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    let plain = value
        .bytes()
        .all(|b| b == b'\t' || (0x20..0x7f).contains(&b));
    let framing = name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("transfer-encoding");
    token && plain && !framing
}

/// Parses a request head, without the empty line that ends it, into the normalised host.
fn parse_head(head: &[u8]) -> Option<String> {
    if !head
        .iter()
        .all(|b| matches!(b, b'\r' | b'\n' | b'\t' | 0x20..=0x7e))
    {
        return None;
    }
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    let headers: Vec<&str> = lines.collect();
    if headers.len() > MAX_HEADER_LINES
        || headers
            .iter()
            .any(|line| line.contains(['\r', '\n']) || !valid_header_line(line))
        || request.contains(['\r', '\n'])
    {
        return None;
    }
    let mut parts = request.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || method != "CONNECT" || version != "HTTP/1.1" {
        return None;
    }
    let (host, port) = target.rsplit_once(':')?;
    if port != "443" || host.contains(['@', '[', ']', ':', '/']) {
        return None;
    }
    let host = host.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host);
    if !valid_host(host) || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(host.to_owned())
}

fn head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

/// The `CONNECT` proxy. Register it, behind an [`Arc`], under
/// [`crate::jobsock::ServiceName::EgressProxy`].
pub struct ConnectProxy<R, D> {
    allow: Vec<HostPattern>,
    limits: ProxyLimits,
    resolver: R,
    dialer: D,
    jobs: Jobs,
}

impl<R, D> fmt::Debug for ConnectProxy<R, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectProxy")
            .field("allow", &self.allow)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<R: Resolver, D: Dialer> ConnectProxy<R, D> {
    /// A proxy that allows [`MODEL_API_HOST`] and the hosts matching `allow`, the Box config
    /// `egress_allow` list, to a Job that was never narrowed.
    #[must_use]
    pub fn new(allow: Vec<HostPattern>, limits: ProxyLimits, resolver: R, dialer: D) -> Self {
        Self {
            allow,
            limits,
            resolver,
            dialer,
            jobs: Mutex::default(),
        }
    }

    /// The counters of a Job. A Job with none yet reads all zero.
    #[must_use]
    pub fn stats(&self, job_id: &str) -> ProxyStats {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(job_id)
            .map(|counts| counts.stats)
            .unwrap_or_default()
    }

    /// Drops the counters of a finished Job.
    pub fn forget(&self, job_id: &str) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }

    /// Narrows a Job to the hosts its runner declares, keeping only those inside the Box
    /// `egress_allow` ceiling. The narrowing is strict: [`MODEL_API_HOST`] is kept only when
    /// the runner declares it, so a codex or kimi Job never reaches the Anthropic host. A
    /// declared host outside the ceiling, or one that is not an exact host name, is dropped and
    /// never widens the narrowing. A second call for the same Job replaces the first. Returns
    /// how many declared hosts were admitted.
    ///
    /// A Job never narrowed keeps the whole ceiling. [`ConnectProxy::forget`] clears the
    /// narrowing.
    pub fn set_job_hosts(&self, job_id: &str, declared: &[&str]) -> usize {
        let admitted: Vec<HostPattern> = declared
            .iter()
            .filter_map(|raw| match HostPattern::parse(raw) {
                Ok(pattern @ HostPattern::Exact(_)) => Some(pattern),
                _ => None,
            })
            .filter(|pattern| matches!(pattern, HostPattern::Exact(name) if self.in_ceiling(name)))
            .collect();
        let count = admitted.len();
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(job_id.to_owned())
            .or_default()
            .hosts = Some(admitted);
        count
    }

    fn in_ceiling(&self, host: &str) -> bool {
        host == MODEL_API_HOST || self.allow.iter().any(|pattern| pattern.matches(host))
    }

    fn allowed(&self, job_id: &str, host: &str) -> bool {
        let jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        jobs.get(job_id)
            .and_then(|counts| counts.hosts.as_ref())
            .map_or_else(
                || self.in_ceiling(host),
                |hosts| hosts.iter().any(|pattern| pattern.matches(host)),
            )
    }

    fn refused(&self, job_id: &str) {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = jobs.entry(job_id.to_owned()).or_default();
        counts.stats.refusals = counts.stats.refusals.saturating_add(1);
        drop(jobs);
    }

    fn reserve<'a>(&'a self, job_id: &'a str) -> Option<Tunnel<'a>> {
        let mut jobs = self.jobs.lock().unwrap_or_else(PoisonError::into_inner);
        let counts = jobs.entry(job_id.to_owned()).or_default();
        if counts.open >= self.limits.max_tunnels_per_job {
            return None;
        }
        counts.open += 1;
        drop(jobs);
        Some(Tunnel {
            jobs: &self.jobs,
            job_id,
            up: 0,
            down: 0,
        })
    }

    async fn read_head(&self, stream: &mut UnixStream) -> Option<String> {
        let max = self.limits.max_header_bytes;
        let read = async {
            let mut buf = Vec::new();
            let mut chunk = [0_u8; 512];
            loop {
                let n = stream.read(&mut chunk).await.ok()?;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(chunk.get(..n)?);
                if let Some(end) = head_end(&buf) {
                    if end + 4 > max || buf.len() != end + 4 {
                        return None;
                    }
                    return parse_head(buf.get(..end)?);
                }
                if buf.len() >= max {
                    return None;
                }
            }
        };
        timeout(self.limits.header_timeout, read).await.ok()?
    }

    async fn connect(&self, host: &str) -> Option<TcpStream> {
        let attempt = async {
            let ips = self.resolver.resolve(host).await.ok()?;
            if ips.is_empty() || !ips.iter().all(|ip| is_public_address(*ip)) {
                return None;
            }
            for ip in ips {
                if let Ok(upstream) = self.dialer.dial(SocketAddr::new(ip, TUNNEL_PORT)).await {
                    return Some(upstream);
                }
            }
            None
        };
        timeout(self.limits.connect_timeout, attempt).await.ok()?
    }

    async fn ready_to_open(stream: &UnixStream) -> bool {
        match timeout(Duration::ZERO, stream.readable()).await {
            Err(_) => true,
            Ok(Err(_)) => false,
            Ok(Ok(())) => {
                matches!(stream.try_read(&mut [0_u8; 1]), Err(err) if err.kind() == std::io::ErrorKind::WouldBlock)
            }
        }
    }

    async fn serve_stream(&self, ctx: JobContext, mut stream: UnixStream) {
        let job_id = ctx.job_id.as_str();
        let admitted = async {
            if ctx.cancel.is_cancelled() {
                return None;
            }
            let host = self.read_head(&mut stream).await?;
            if !self.allowed(job_id, &host) {
                return None;
            }
            let tunnel = self.reserve(job_id)?;
            let upstream = self.connect(&host).await?;
            Some((tunnel, upstream))
        }
        .await;
        let Some((mut tunnel, upstream)) = admitted else {
            self.refuse(job_id, &mut stream).await;
            return;
        };
        if !Self::ready_to_open(&stream).await || stream.write_all(ESTABLISHED).await.is_err() {
            drop(tunnel);
            self.refuse(job_id, &mut stream).await;
            return;
        }
        tunnel.established();
        self.copy(&ctx, stream, upstream, &mut tunnel).await;
    }

    async fn refuse(&self, job_id: &str, stream: &mut UnixStream) {
        self.refused(job_id);
        let _ = stream.write_all(FORBIDDEN).await;
        let _ = stream.shutdown().await;
    }

    async fn copy(
        &self,
        ctx: &JobContext,
        stream: UnixStream,
        upstream: TcpStream,
        tunnel: &mut Tunnel<'_>,
    ) {
        let limits = self.limits;
        let deadline = Instant::now() + limits.total_timeout;
        let (mut client_rd, mut client_wr) = stream.into_split();
        let (mut up_rd, mut up_wr) = upstream.into_split();
        let mut from_client = vec![0_u8; COPY_CHUNK];
        let mut from_up = vec![0_u8; COPY_CHUNK];
        let mut idle = Instant::now() + limits.idle_timeout;
        loop {
            let room = limits
                .max_tunnel_bytes
                .saturating_sub(tunnel.up.saturating_add(tunnel.down));
            tokio::select! {
                biased;
                () = ctx.cancel.cancelled() => return,
                () = sleep_until(deadline) => return,
                () = sleep_until(idle) => return,
                read = client_rd.read(&mut from_client) => {
                    let Ok(n @ 1..) = read else { return };
                    if n as u64 > room {
                        return;
                    }
                    let Some(chunk) = from_client.get(..n) else { return };
                    if !matches!(timeout(limits.idle_timeout, up_wr.write_all(chunk)).await, Ok(Ok(()))) {
                        return;
                    }
                    tunnel.up += n as u64;
                    idle = Instant::now() + limits.idle_timeout;
                }
                read = up_rd.read(&mut from_up) => {
                    let Ok(n @ 1..) = read else { return };
                    if n as u64 > room {
                        return;
                    }
                    let Some(chunk) = from_up.get(..n) else { return };
                    if !matches!(timeout(limits.idle_timeout, client_wr.write_all(chunk)).await, Ok(Ok(()))) {
                        return;
                    }
                    tunnel.down += n as u64;
                    idle = Instant::now() + limits.idle_timeout;
                }
            }
        }
    }
}

impl<R: Resolver + 'static, D: Dialer + 'static> Service for Arc<ConnectProxy<R, D>> {
    fn serve(&self, ctx: JobContext, stream: UnixStream) -> ServeFuture<'_> {
        Box::pin(self.serve_stream(ctx, stream))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::io;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use tempfile::TempDir;
    use tokio::net::TcpListener;

    use super::*;
    use crate::jobsock::{
        AGENT_SLICE, JobSocket, Limits, Peer, PeerId, ServiceName, Services, write_frame,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const OUTER: Duration = Duration::from_secs(10);
    const GOOD: &[u8] =
        b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n";
    const PUBLIC: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

    struct Cgroup;

    impl Peer for Cgroup {
        fn identity(&self, _: &UnixStream) -> io::Result<PeerId> {
            Ok(PeerId {
                pid: 7,
                cgroup: format!("0::/{AGENT_SLICE}/fleet-agent@job1.service\n"),
            })
        }
    }

    #[derive(Default)]
    struct FakeInner {
        answers: Mutex<VecDeque<Vec<IpAddr>>>,
        queries: Mutex<Vec<String>>,
    }

    #[derive(Clone, Default)]
    struct Fake(Arc<FakeInner>);

    impl Fake {
        fn queries(&self) -> Vec<String> {
            self.0
                .queries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl Resolver for Fake {
        fn resolve(&self, host: &str) -> impl Future<Output = io::Result<Vec<IpAddr>>> + Send {
            self.0
                .queries
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(host.to_owned());
            let mut answers = self
                .0
                .answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let next = if answers.len() > 1 {
                answers.pop_front()
            } else {
                answers.front().cloned()
            };
            std::future::ready(next.ok_or_else(|| io::Error::other("none")))
        }
    }

    struct LocalInner {
        port: u16,
        delay: Duration,
        dialed: Mutex<Vec<SocketAddr>>,
    }

    #[derive(Clone)]
    struct Local(Arc<LocalInner>);

    impl Local {
        fn dialed(&self) -> Vec<SocketAddr> {
            self.0
                .dialed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    impl Dialer for Local {
        async fn dial(&self, addr: SocketAddr) -> io::Result<TcpStream> {
            self.0
                .dialed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(addr);
            tokio::time::sleep(self.0.delay).await;
            TcpStream::connect((Ipv4Addr::LOCALHOST, self.0.port)).await
        }
    }

    async fn echo_server() -> io::Result<u16> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0_u8; 4096];
                    while let Ok(n @ 1..) = conn.read(&mut buf).await {
                        let Some(chunk) = buf.get(..n) else { return };
                        if conn.write_all(chunk).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Ok(port)
    }

    struct Setup {
        allow: Vec<&'static str>,
        limits: ProxyLimits,
        answers: Vec<Vec<IpAddr>>,
        delay: Duration,
        dead_upstream: bool,
    }

    impl Default for Setup {
        fn default() -> Self {
            Self {
                allow: Vec::new(),
                limits: ProxyLimits::default(),
                answers: vec![vec![PUBLIC]],
                delay: Duration::ZERO,
                dead_upstream: false,
            }
        }
    }

    struct Rig {
        _dir: TempDir,
        socket: JobSocket,
        proxy: Arc<ConnectProxy<Fake, Local>>,
        resolver: Fake,
        dialer: Local,
    }

    impl Rig {
        async fn start(setup: Setup) -> Result<Self, Box<dyn std::error::Error>> {
            let port = if setup.dead_upstream {
                1
            } else {
                echo_server().await?
            };
            let resolver = Fake::default();
            *resolver
                .0
                .answers
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = setup.answers.into();
            let dialer = Local(Arc::new(LocalInner {
                port,
                delay: setup.delay,
                dialed: Mutex::default(),
            }));
            let allow = setup
                .allow
                .iter()
                .map(|raw| HostPattern::parse(raw))
                .collect::<Result<Vec<_>, _>>()?;
            let proxy = Arc::new(ConnectProxy::new(
                allow,
                setup.limits,
                resolver.clone(),
                dialer.clone(),
            ));
            let dir = TempDir::new()?;
            let mut services = Services::new();
            services.insert(ServiceName::EgressProxy, Arc::new(Arc::clone(&proxy)));
            let socket = JobSocket::bind(
                &dir.path().join("job.sock"),
                "job1",
                services,
                Arc::new(Cgroup),
                Limits::default(),
            )?;
            Ok(Self {
                _dir: dir,
                socket,
                proxy,
                resolver,
                dialer,
            })
        }

        async fn connect(&self) -> io::Result<UnixStream> {
            let mut stream = UnixStream::connect(self.socket.path()).await?;
            write_frame(&mut stream, ServiceName::EgressProxy.as_str().as_bytes()).await?;
            Ok(stream)
        }

        async fn tunnel(&self) -> TestResult2<UnixStream> {
            let mut stream = self.connect().await?;
            stream.write_all(GOOD).await?;
            expect_established(&mut stream).await?;
            Ok(stream)
        }

        async fn settled(&self, done: impl Fn(ProxyStats) -> bool) -> ProxyStats {
            let end = Instant::now() + OUTER;
            loop {
                let stats = self.proxy.stats("job1");
                if done(stats) || Instant::now() >= end {
                    return stats;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
    }

    type TestResult2<T> = Result<T, Box<dyn std::error::Error>>;

    async fn read_until_closed(stream: &mut UnixStream) -> TestResult2<Vec<u8>> {
        let mut got = Vec::new();
        let mut buf = [0_u8; 1024];
        let read = async {
            while let Ok(n @ 1..) = stream.read(&mut buf).await {
                got.extend_from_slice(buf.get(..n).unwrap_or_default());
            }
        };
        timeout(OUTER, read)
            .await
            .map_err(|_| "the proxy did not close the connection in time")?;
        Ok(got)
    }

    async fn expect_established(stream: &mut UnixStream) -> TestResult {
        let mut got = vec![0_u8; ESTABLISHED.len()];
        timeout(OUTER, stream.read_exact(&mut got)).await??;
        assert_eq!(got, ESTABLISHED);
        Ok(())
    }

    async fn echo_round_trip(stream: &mut UnixStream, payload: &[u8]) -> TestResult {
        stream.write_all(payload).await?;
        let mut back = vec![0_u8; payload.len()];
        timeout(OUTER, stream.read_exact(&mut back)).await??;
        assert_eq!(back, payload);
        Ok(())
    }

    #[tokio::test]
    async fn a_good_connect_opens_a_tunnel_that_echoes_and_counts_bytes() -> TestResult {
        let rig = Rig::start(Setup::default()).await?;
        let mut stream = rig.tunnel().await?;
        echo_round_trip(&mut stream, b"hello tunnel").await?;
        drop(stream);
        let stats = rig.settled(|s| s.bytes_up > 0 && s.bytes_down > 0).await;
        assert_eq!(
            stats,
            ProxyStats {
                connections: 1,
                bytes_up: 12,
                bytes_down: 12,
                refusals: 0,
            }
        );
        assert_eq!(rig.resolver.queries(), vec!["api.anthropic.com"]);
        assert_eq!(rig.dialer.dialed(), vec![SocketAddr::new(PUBLIC, 443)]);
        Ok(())
    }

    async fn connect_status(rig: &Rig, host: &str) -> TestResult2<bool> {
        let mut stream = rig.connect().await?;
        stream
            .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes())
            .await?;
        let got = read_prefix(&mut stream).await?;
        Ok(got.starts_with(b"HTTP/1.1 200"))
    }

    async fn read_prefix(stream: &mut UnixStream) -> TestResult2<Vec<u8>> {
        let mut buf = [0_u8; 12];
        timeout(OUTER, stream.read_exact(&mut buf)).await??;
        Ok(buf.to_vec())
    }

    #[tokio::test]
    async fn a_runner_host_inside_the_ceiling_is_allowed_and_siblings_are_not() -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["api.openai.com", "other.example"],
            ..Setup::default()
        })
        .await?;
        assert_eq!(rig.proxy.set_job_hosts("job1", &["api.openai.com"]), 1);
        assert!(connect_status(&rig, "api.openai.com").await?);
        assert!(!connect_status(&rig, "api.anthropic.com").await?);
        assert!(!connect_status(&rig, "other.example").await?);
        Ok(())
    }

    #[tokio::test]
    async fn a_runner_host_outside_the_ceiling_is_refused_and_never_widens_it() -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["api.openai.com"],
            ..Setup::default()
        })
        .await?;
        let admitted = rig
            .proxy
            .set_job_hosts("job1", &["evil.example", "*.openai.com", "api.openai.com"]);
        assert_eq!(admitted, 1);
        assert!(!connect_status(&rig, "evil.example").await?);
        assert!(!connect_status(&rig, "x.openai.com").await?);
        assert!(connect_status(&rig, "api.openai.com").await?);
        assert!(rig.resolver.queries().iter().all(|q| q == "api.openai.com"));
        Ok(())
    }

    #[tokio::test]
    async fn an_empty_ceiling_admits_no_runner_host_and_unknown_hosts_are_refused() -> TestResult {
        let rig = Rig::start(Setup::default()).await?;
        assert_eq!(rig.proxy.set_job_hosts("job1", &["api.openai.com"]), 0);
        assert!(!connect_status(&rig, "api.openai.com").await?);
        assert!(!connect_status(&rig, "unknown.example").await?);
        Ok(())
    }

    #[tokio::test]
    async fn host_case_and_one_trailing_dot_are_normalised_before_the_allowlist() -> TestResult {
        let rig = Rig::start(Setup::default()).await?;
        let mut stream = rig.connect().await?;
        stream
            .write_all(b"CONNECT API.Anthropic.COM.:443 HTTP/1.1\r\n\r\n")
            .await?;
        expect_established(&mut stream).await?;
        assert_eq!(rig.resolver.queries(), vec!["api.anthropic.com"]);
        Ok(())
    }

    #[tokio::test]
    async fn the_config_list_adds_hosts_and_wildcards_but_never_the_apex_or_the_model_subdomains()
    -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["pkg.example", "*.models.example"],
            ..Setup::default()
        })
        .await?;
        for host in ["pkg.example", "a.models.example"] {
            let mut stream = rig.connect().await?;
            stream
                .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes())
                .await?;
            expect_established(&mut stream).await?;
        }
        for host in ["models.example", "x.api.anthropic.com", "anthropic.com"] {
            let mut stream = rig.connect().await?;
            stream
                .write_all(format!("CONNECT {host}:443 HTTP/1.1\r\n\r\n").as_bytes())
                .await?;
            assert_eq!(read_until_closed(&mut stream).await?, FORBIDDEN, "{host}");
        }
        assert_eq!(
            rig.resolver.queries(),
            vec!["pkg.example", "a.models.example"]
        );
        Ok(())
    }

    fn hostile_line() -> Vec<(&'static str, Vec<u8>)> {
        let head = |line: &str| format!("{line}\r\n\r\n").into_bytes();
        let cases: Vec<(&'static str, Vec<u8>)> = vec![
            (
                "userinfo",
                head("CONNECT user:pw@api.anthropic.com:443 HTTP/1.1"),
            ),
            (
                "userinfo host trick",
                head("CONNECT evil.example@api.anthropic.com:443 HTTP/1.1"),
            ),
            (
                "ipv6 literal",
                head("CONNECT [2606:4700::1111]:443 HTTP/1.1"),
            ),
            ("ip literal", head("CONNECT 8.8.8.8:443 HTTP/1.1")),
            ("decimal ip", head("CONNECT 134744072:443 HTTP/1.1")),
            ("port 8443", head("CONNECT api.anthropic.com:8443 HTTP/1.1")),
            ("port 80", head("CONNECT api.anthropic.com:80 HTTP/1.1")),
            ("no port", head("CONNECT api.anthropic.com HTTP/1.1")),
            (
                "padded port",
                head("CONNECT api.anthropic.com:0443 HTTP/1.1"),
            ),
            (
                "signed port",
                head("CONNECT api.anthropic.com:+443 HTTP/1.1"),
            ),
            (
                "double space",
                head("CONNECT  api.anthropic.com:443 HTTP/1.1"),
            ),
            (
                "double space before version",
                head("CONNECT api.anthropic.com:443  HTTP/1.1"),
            ),
            (
                "tab separator",
                head("CONNECT\tapi.anthropic.com:443 HTTP/1.1"),
            ),
            (
                "leading space",
                head(" CONNECT api.anthropic.com:443 HTTP/1.1"),
            ),
            (
                "trailing space",
                head("CONNECT api.anthropic.com:443 HTTP/1.1 "),
            ),
            (
                "leading blank line",
                b"\r\nCONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\n".to_vec(),
            ),
            (
                "cr in request line",
                head("CONNECT api.anthropic.com:443\rX HTTP/1.1"),
            ),
            (
                "crlf injected header split",
                head("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: x\rY: z"),
            ),
            ("http 1.0", head("CONNECT api.anthropic.com:443 HTTP/1.0")),
            ("http 2", head("CONNECT api.anthropic.com:443 HTTP/2")),
            (
                "lowercase method",
                head("connect api.anthropic.com:443 HTTP/1.1"),
            ),
            ("get", head("GET / HTTP/1.1")),
            (
                "absolute uri get",
                head("GET http://api.anthropic.com/ HTTP/1.1"),
            ),
            (
                "absolute uri connect",
                head("CONNECT https://api.anthropic.com:443/ HTTP/1.1"),
            ),
            ("options star", head("OPTIONS * HTTP/1.1")),
        ];
        cases
    }

    fn hostile_framing() -> Vec<(&'static str, Vec<u8>)> {
        let head = |line: &str| format!("{line}\r\n\r\n").into_bytes();
        let mut cases: Vec<(&'static str, Vec<u8>)> = vec![
            (
                "obs fold",
                head("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: a\r\n b: c"),
            ),
            (
                "content length",
                head("CONNECT api.anthropic.com:443 HTTP/1.1\r\nContent-Length: 5"),
            ),
            (
                "transfer encoding",
                head("CONNECT api.anthropic.com:443 HTTP/1.1\r\ntransfer-encoding: chunked"),
            ),
            (
                "header without colon",
                head("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost"),
            ),
            (
                "nul in host",
                b"CONNECT api.anthropic.com\0.evil.example:443 HTTP/1.1\r\n\r\n".to_vec(),
            ),
            (
                "non ascii",
                "CONNECT api.anthropic.c\u{f6}m:443 HTTP/1.1\r\n\r\n"
                    .as_bytes()
                    .to_vec(),
            ),
            ("empty host", head("CONNECT :443 HTTP/1.1")),
            (
                "empty label",
                head("CONNECT api..anthropic.com:443 HTTP/1.1"),
            ),
            (
                "leading dot",
                head("CONNECT .api.anthropic.com:443 HTTP/1.1"),
            ),
            (
                "two trailing dots",
                head("CONNECT api.anthropic.com..:443 HTTP/1.1"),
            ),
            ("wildcard", head("CONNECT *.anthropic.com:443 HTTP/1.1")),
            (
                "path in target",
                head("CONNECT api.anthropic.com:443/x HTTP/1.1"),
            ),
            (
                "trailing bytes in one write",
                b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\n\r\n".to_vec(),
            ),
            ("empty head", b"\r\n\r\n".to_vec()),
            ("allowlist miss", head("CONNECT evil.example:443 HTTP/1.1")),
            (
                "suffix trick",
                head("CONNECT api.anthropic.com.evil.example:443 HTTP/1.1"),
            ),
            ("parent domain", head("CONNECT anthropic.com:443 HTTP/1.1")),
            (
                "subdomain of model host",
                head("CONNECT x.api.anthropic.com:443 HTTP/1.1"),
            ),
        ];
        let many = format!(
            "CONNECT api.anthropic.com:443 HTTP/1.1\r\n{}\r\n",
            "X: v\r\n".repeat(MAX_HEADER_LINES + 1)
        );
        cases.push(("too many header lines", many.into_bytes()));
        let mut big = String::from("CONNECT api.anthropic.com:443 HTTP/1.1\r\nX: ");
        big.push_str(&"a".repeat(4000));
        big.push_str("\r\n\r\n");
        cases.push(("huge header with terminator", big.into_bytes()));
        cases.push(("huge header without terminator", vec![b'a'; 3000]));
        cases
    }

    fn hostile() -> Vec<(&'static str, Vec<u8>)> {
        let mut cases = hostile_line();
        cases.extend(hostile_framing());
        cases
    }

    #[tokio::test]
    async fn every_hostile_request_gets_the_one_fixed_403_with_no_resolve_and_no_dial() -> TestResult
    {
        let cases = hostile();
        let rig = Rig::start(Setup::default()).await?;
        for (name, bytes) in &cases {
            let mut stream = rig.connect().await?;
            stream.write_all(bytes).await?;
            assert_eq!(read_until_closed(&mut stream).await?, FORBIDDEN, "{name}");
        }
        assert_eq!(rig.resolver.queries(), Vec::<String>::new());
        assert_eq!(rig.dialer.dialed(), Vec::<SocketAddr>::new());
        assert_eq!(
            rig.proxy.stats("job1"),
            ProxyStats {
                refusals: cases.len() as u64,
                ..ProxyStats::default()
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn heads_ended_by_bare_lf_never_complete_and_time_out_with_the_fixed_403() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                header_timeout: Duration::from_millis(300),
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        for bytes in [
            &b"CONNECT api.anthropic.com:443 HTTP/1.1\n\n"[..],
            &b"CONNECT api.anthropic.com:443 HTTP/1.1\r\n\n"[..],
        ] {
            let mut stream = rig.connect().await?;
            stream.write_all(bytes).await?;
            assert_eq!(read_until_closed(&mut stream).await?, FORBIDDEN);
        }
        assert_eq!(rig.dialer.dialed(), Vec::<SocketAddr>::new());
        Ok(())
    }

    #[tokio::test]
    async fn a_complete_head_over_the_cap_is_refused_with_no_dial() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                max_header_bytes: GOOD.len() - 1,
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        let mut stream = rig.connect().await?;
        stream.write_all(GOOD).await?;
        assert_eq!(read_until_closed(&mut stream).await?, FORBIDDEN);
        assert_eq!(rig.dialer.dialed(), Vec::<SocketAddr>::new());
        Ok(())
    }

    #[tokio::test]
    async fn a_head_exactly_at_the_cap_is_accepted() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                max_header_bytes: GOOD.len(),
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        let mut stream = rig.connect().await?;
        stream.write_all(GOOD).await?;
        expect_established(&mut stream).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_slowloris_header_is_cut_at_the_header_timeout() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                header_timeout: Duration::from_millis(400),
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        let mut stream = rig.connect().await?;
        stream
            .write_all(b"CONNECT api.anthropic.com:443 HTTP/1.1\r\nX-Slow: ")
            .await?;
        let (mut read, mut write) = stream.into_split();
        let writer = tokio::spawn(async move {
            for _ in 0..200 {
                if write.write_all(b"a").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let mut got = Vec::new();
        let mut buf = [0_u8; 256];
        let drain = async {
            while let Ok(n @ 1..) = read.read(&mut buf).await {
                got.extend_from_slice(buf.get(..n).unwrap_or_default());
            }
        };
        timeout(OUTER, drain).await?;
        writer.abort();
        assert_eq!(got, FORBIDDEN);
        assert_eq!(rig.dialer.dialed(), Vec::<SocketAddr>::new());
        Ok(())
    }

    #[tokio::test]
    async fn bytes_sent_after_the_head_but_before_the_200_are_refused() -> TestResult {
        let rig = Rig::start(Setup {
            delay: Duration::from_millis(500),
            ..Setup::default()
        })
        .await?;
        let mut stream = rig.connect().await?;
        stream.write_all(GOOD).await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        stream.write_all(b"\x16\x03\x01").await?;
        assert_eq!(read_until_closed(&mut stream).await?, FORBIDDEN);
        let stats = rig.settled(|s| s.refusals > 0).await;
        assert_eq!((stats.connections, stats.refusals), (0, 1));
        Ok(())
    }

    #[tokio::test]
    async fn the_second_answer_of_a_rebinding_name_is_never_dialed() -> TestResult {
        let rebound = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let rig = Rig::start(Setup {
            answers: vec![vec![PUBLIC], vec![rebound]],
            ..Setup::default()
        })
        .await?;
        let mut first = rig.tunnel().await?;
        echo_round_trip(&mut first, b"x").await?;
        assert_eq!(rig.resolver.queries().len(), 1);
        let mut second = rig.connect().await?;
        second.write_all(GOOD).await?;
        assert_eq!(read_until_closed(&mut second).await?, FORBIDDEN);
        assert_eq!(rig.dialer.dialed(), vec![SocketAddr::new(PUBLIC, 443)]);
        Ok(())
    }

    #[tokio::test]
    async fn any_non_public_answer_refuses_the_whole_request_with_no_dial() -> TestResult {
        let private: Vec<Vec<IpAddr>> = vec![
            vec!["10.0.0.1".parse()?],
            vec![PUBLIC, "192.168.1.1".parse()?],
            vec!["127.0.0.1".parse()?],
            vec!["169.254.169.254".parse()?],
            vec!["::1".parse()?],
            vec!["::ffff:10.0.0.1".parse()?],
            vec!["fd00::1".parse()?],
            vec![],
        ];
        for answers in private {
            let rig = Rig::start(Setup {
                answers: vec![answers.clone()],
                ..Setup::default()
            })
            .await?;
            let mut stream = rig.connect().await?;
            stream.write_all(GOOD).await?;
            assert_eq!(
                read_until_closed(&mut stream).await?,
                FORBIDDEN,
                "{answers:?}"
            );
            assert_eq!(rig.dialer.dialed(), Vec::<SocketAddr>::new());
            assert_eq!(rig.proxy.stats("job1").refusals, 1);
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_lookup_or_dial_is_the_same_fixed_403() -> TestResult {
        for setup in [
            Setup {
                answers: Vec::new(),
                ..Setup::default()
            },
            Setup {
                dead_upstream: true,
                ..Setup::default()
            },
        ] {
            let rig = Rig::start(setup).await?;
            let mut stream = rig.connect().await?;
            stream.write_all(GOOD).await?;
            assert_eq!(read_until_closed(&mut stream).await?, FORBIDDEN);
            assert_eq!(rig.proxy.stats("job1").connections, 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_idle_tunnel_is_closed_at_the_idle_timeout() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                idle_timeout: Duration::from_millis(300),
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        let mut stream = rig.tunnel().await?;
        echo_round_trip(&mut stream, b"ping").await?;
        assert_eq!(read_until_closed(&mut stream).await?, b"");
        Ok(())
    }

    #[tokio::test]
    async fn a_busy_tunnel_is_closed_at_the_total_timeout() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                total_timeout: Duration::from_millis(500),
                idle_timeout: Duration::from_secs(60),
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        let stream = rig.tunnel().await?;
        let (mut read, mut write) = stream.into_split();
        let pump = async {
            loop {
                if write.write_all(b"z").await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        let drain = async {
            let mut buf = [0_u8; 64];
            while let Ok(1..) = read.read(&mut buf).await {}
        };
        timeout(OUTER, async { tokio::join!(pump, drain) }).await?;
        Ok(())
    }

    #[tokio::test]
    async fn the_byte_cap_closes_the_tunnel_and_bounds_the_counters() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                max_tunnel_bytes: 1000,
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        let stream = rig.tunnel().await?;
        let (mut read, mut write) = stream.into_split();
        let pump = async {
            for _ in 0..60 {
                if write.write_all(&[7_u8; 100]).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        let mut received = 0_usize;
        let drain = async {
            let mut buf = [0_u8; 512];
            while let Ok(n @ 1..) = read.read(&mut buf).await {
                received += n;
            }
        };
        timeout(OUTER, async { tokio::join!(pump, drain) }).await?;
        assert!(received > 0 && received <= 1000, "{received}");
        let stats = rig.settled(|s| s.bytes_up > 0).await;
        assert!(stats.bytes_up + stats.bytes_down <= 1000, "{stats:?}");
        Ok(())
    }

    #[tokio::test]
    async fn cancelling_the_job_socket_closes_open_tunnels() -> TestResult {
        let rig = Rig::start(Setup::default()).await?;
        let mut stream = rig.tunnel().await?;
        echo_round_trip(&mut stream, b"a").await?;
        rig.socket.cancel();
        assert_eq!(read_until_closed(&mut stream).await?, b"");
        Ok(())
    }

    #[tokio::test]
    async fn the_per_job_tunnel_cap_refuses_the_extra_and_frees_on_close() -> TestResult {
        let rig = Rig::start(Setup {
            limits: ProxyLimits {
                max_tunnels_per_job: 1,
                ..ProxyLimits::default()
            },
            ..Setup::default()
        })
        .await?;
        let mut first = rig.tunnel().await?;
        echo_round_trip(&mut first, b"a").await?;
        let mut second = rig.connect().await?;
        second.write_all(GOOD).await?;
        assert_eq!(read_until_closed(&mut second).await?, FORBIDDEN);
        assert_eq!(rig.dialer.dialed().len(), 1);
        drop(first);
        let end = Instant::now() + OUTER;
        loop {
            let mut third = rig.connect().await?;
            third.write_all(GOOD).await?;
            let mut head = vec![0_u8; ESTABLISHED.len()];
            timeout(OUTER, third.read_exact(&mut head)).await??;
            if head == ESTABLISHED {
                return Ok(());
            }
            assert!(Instant::now() < end, "the slot was never freed");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn forget_drops_the_counters_of_a_job() -> TestResult {
        let rig = Rig::start(Setup::default()).await?;
        let mut stream = rig.tunnel().await?;
        echo_round_trip(&mut stream, b"abc").await?;
        drop(stream);
        let stats = rig.settled(|s| s.bytes_down > 0).await;
        assert_eq!(stats.connections, 1);
        rig.proxy.forget("job1");
        assert_eq!(rig.proxy.stats("job1"), ProxyStats::default());
        Ok(())
    }

    #[tokio::test]
    async fn counters_are_per_job() -> TestResult {
        let rig = Rig::start(Setup::default()).await?;
        let mut stream = rig.connect().await?;
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
        read_until_closed(&mut stream).await?;
        assert_eq!(rig.proxy.stats("job1").refusals, 1);
        assert_eq!(rig.proxy.stats("job2"), ProxyStats::default());
        Ok(())
    }

    #[tokio::test]
    async fn a_narrowed_job_never_reaches_the_anthropic_host_even_when_the_ceiling_lists_it()
    -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["api.openai.com", "api.anthropic.com"],
            ..Setup::default()
        })
        .await?;
        assert_eq!(rig.proxy.set_job_hosts("job1", &["api.openai.com"]), 1);
        assert!(rig.proxy.allowed("job1", "api.openai.com"));
        assert!(!rig.proxy.allowed("job1", "api.anthropic.com"));
        Ok(())
    }

    #[tokio::test]
    async fn a_job_never_narrowed_keeps_the_whole_ceiling_and_the_model_host() -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["pkg.example", "*.models.example"],
            ..Setup::default()
        })
        .await?;
        assert!(rig.proxy.allowed("job1", "pkg.example"));
        assert!(rig.proxy.allowed("job1", "x.models.example"));
        assert!(rig.proxy.allowed("job1", MODEL_API_HOST));
        assert!(!rig.proxy.allowed("job1", "other.example"));
        Ok(())
    }

    #[tokio::test]
    async fn forget_clears_the_narrowing_of_a_job() -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["api.openai.com", "pkg.example"],
            ..Setup::default()
        })
        .await?;
        rig.proxy.set_job_hosts("job1", &["api.openai.com"]);
        assert!(!rig.proxy.allowed("job1", "pkg.example"));
        rig.proxy.forget("job1");
        assert!(rig.proxy.allowed("job1", "pkg.example"));
        assert!(rig.proxy.allowed("job1", MODEL_API_HOST));
        Ok(())
    }

    #[tokio::test]
    async fn a_second_set_job_hosts_replaces_the_first() -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["api.openai.com", "api.moonshot.ai"],
            ..Setup::default()
        })
        .await?;
        rig.proxy.set_job_hosts("job1", &["api.openai.com"]);
        assert_eq!(rig.proxy.set_job_hosts("job1", &["api.moonshot.ai"]), 1);
        assert!(rig.proxy.allowed("job1", "api.moonshot.ai"));
        assert!(!rig.proxy.allowed("job1", "api.openai.com"));
        Ok(())
    }

    #[tokio::test]
    async fn a_narrowing_never_leaks_to_another_job() -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["api.openai.com", "pkg.example"],
            ..Setup::default()
        })
        .await?;
        rig.proxy.set_job_hosts("job1", &["api.openai.com"]);
        assert!(rig.proxy.allowed("job2", "pkg.example"));
        assert!(!rig.proxy.allowed("job1", "pkg.example"));
        Ok(())
    }

    #[tokio::test]
    async fn a_hostile_declared_host_is_rejected_and_never_widens_the_narrowing() -> TestResult {
        let long = format!("{}.openai.com", "a".repeat(300));
        let hostile = [
            "",
            ".",
            "api.openai.com.",
            "api..openai.com",
            "user@api.openai.com",
            "api.openai.com:443",
            "[::1]",
            "::1",
            "127.0.0.1",
            " api.openai.com",
            "api.openai.com ",
            "api.openai.com\r\n",
            "api.openai.com/x",
            "\u{ff41}pi.openai.com",
            "*.openai.com",
            long.as_str(),
        ];
        for raw in hostile {
            let rig = Rig::start(Setup {
                allow: vec!["api.openai.com", "*.openai.com", "pkg.example"],
                ..Setup::default()
            })
            .await?;
            assert_eq!(rig.proxy.set_job_hosts("job1", &[raw]), 0, "{raw:?}");
            for host in [
                "api.openai.com",
                "x.openai.com",
                "pkg.example",
                MODEL_API_HOST,
            ] {
                assert!(!rig.proxy.allowed("job1", host), "{raw:?} widened {host}");
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_uppercase_declared_host_is_normalised_to_the_exact_host() -> TestResult {
        let rig = Rig::start(Setup {
            allow: vec!["api.openai.com"],
            ..Setup::default()
        })
        .await?;
        assert_eq!(rig.proxy.set_job_hosts("job1", &["API.OpenAI.com"]), 1);
        assert!(rig.proxy.allowed("job1", "api.openai.com"));
        Ok(())
    }
}
