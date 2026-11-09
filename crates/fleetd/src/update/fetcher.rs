//! The production [`ArchiveFetcher`]: archive downloads through the egress policy.
//!
//! [`PolicyArchiveFetcher`] drives the async [`Fetcher`] from the blocking [`Stager`]. The
//! fetch policy is an allow-list of the update hosts, and the fetch core checks it on the first
//! URL and on every redirect hop before it resolves or connects, so a redirect to an off-list
//! host, or to an IP literal, ends the download without a connection. The fetch core takes
//! `https` on port 443 only and caps the redirect hops at [`MAX_ARCHIVE_REDIRECTS`].
//!
//! [`ArchiveFetcher::get`] blocks on the runtime handle, so call it from a blocking thread
//! (`spawn_blocking`), never from an async task. Extraction of the archive is a later step.
//!
//! [`Stager`]: super::Stager

use std::io::{self, Read};
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::{ArchiveFetcher, ArchiveResponse, MAX_ARCHIVE_BYTES};
use crate::fetch::{
    Dialer, FetchStream, Fetcher, Resolver, SystemResolver, TcpDialer, webpki_tls_config,
};
use crate::fetch_policy::{FetchCaps, FetchPolicy, HostPattern};

/// Most redirect hops one archive download follows.
pub const MAX_ARCHIVE_REDIRECTS: u8 = 5;

/// Longest time for one archive download, redirects and body included.
pub const ARCHIVE_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Longest time to open one connection.
pub const ARCHIVE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const CHUNK_QUEUE: usize = 4;

/// The caps of an archive download: [`MAX_ARCHIVE_BYTES`] on the wire, [`ARCHIVE_TOTAL_TIMEOUT`]
/// for the whole download and [`MAX_ARCHIVE_REDIRECTS`] hops.
#[must_use]
pub fn archive_caps() -> FetchCaps {
    FetchCaps {
        max_body_bytes: MAX_ARCHIVE_BYTES,
        max_decoded_bytes: MAX_ARCHIVE_BYTES,
        connect_timeout: ARCHIVE_CONNECT_TIMEOUT,
        total_timeout: ARCHIVE_TOTAL_TIMEOUT,
        max_redirects: MAX_ARCHIVE_REDIRECTS,
        ..FetchCaps::default()
    }
}

/// An [`ArchiveFetcher`] over the egress-policy [`Fetcher`].
#[derive(Debug)]
pub struct PolicyArchiveFetcher<R, D> {
    fetcher: Arc<Fetcher<R, D>>,
    handle: Handle,
}

impl PolicyArchiveFetcher<SystemResolver, TcpDialer> {
    /// The production fetcher: system DNS, plain TCP, webpki roots, and only hosts that match
    /// `allow`.
    #[must_use]
    pub fn system(handle: Handle, allow: Vec<HostPattern>) -> Self {
        Self::with_parts(
            handle,
            FetchPolicy::Allowlist(allow),
            archive_caps(),
            SystemResolver,
            TcpDialer,
            webpki_tls_config(),
        )
    }
}

impl<R: Resolver + 'static, D: Dialer + 'static> PolicyArchiveFetcher<R, D> {
    /// A fetcher over an explicit policy, caps, resolver, dialer and TLS config. Tests inject a
    /// loopback dialer and their own roots here; nothing reads the environment.
    #[must_use]
    pub fn with_parts(
        handle: Handle,
        policy: FetchPolicy,
        caps: FetchCaps,
        resolver: R,
        dialer: D,
        tls: Arc<ClientConfig>,
    ) -> Self {
        Self {
            fetcher: Arc::new(Fetcher::new(policy, caps, resolver, dialer, tls)),
            handle,
        }
    }
}

type Chunk = io::Result<Vec<u8>>;

struct ChunkReader {
    rx: mpsc::Receiver<Chunk>,
    pump: JoinHandle<()>,
    current: io::Cursor<Vec<u8>>,
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            let n = self.current.read(buf)?;
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(Ok(chunk)) => self.current = io::Cursor::new(chunk),
                Some(Err(err)) => return Err(err),
                None => return Ok(0),
            }
        }
    }
}

impl Drop for ChunkReader {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Moves chunks from `stream` into `tx`. A full queue blocks it with no timeout of its own, and
/// dropping the reader aborts it.
async fn pump(mut stream: FetchStream, tx: mpsc::Sender<Chunk>) {
    loop {
        match stream.next_chunk().await {
            Ok(Some(chunk)) => {
                if tx.send(Ok(chunk.to_vec())).await.is_err() {
                    return;
                }
            }
            Ok(None) => return,
            Err(err) => {
                let _ = tx.send(Err(io::Error::other(err))).await;
                return;
            }
        }
    }
}

impl<R: Resolver + 'static, D: Dialer + 'static> ArchiveFetcher for PolicyArchiveFetcher<R, D> {
    /// The returned `final_url` is `https://<host>/` of the connected host. The path and query
    /// of the request are not kept.
    fn get(&self, url: &str) -> io::Result<ArchiveResponse> {
        let stream = self
            .handle
            .block_on(self.fetcher.open(url))
            .map_err(io::Error::other)?;
        let final_url = format!("https://{}/", stream.host());
        let (tx, rx) = mpsc::channel(CHUNK_QUEUE);
        let pump = self.handle.spawn(pump(stream, tx));
        Ok(ArchiveResponse {
            final_url,
            body: Box::new(ChunkReader {
                rx,
                pump,
                current: io::Cursor::new(Vec::new()),
            }),
        })
    }
}
