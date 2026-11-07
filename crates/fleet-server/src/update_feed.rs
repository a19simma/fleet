//! The cache, the seq gate and the poller of the release feed (ADR-0060).
//!
//! [`FeedPoller`] fetches the manifest and signature through a [`FeedSource`] on a timer and
//! offers each pair to a [`FeedCache`]. The cache holds the [`FeedPair`] last accepted by the
//! seq gate, in memory, with no maximum age. A failed fetch and a rejected pair never evict it.
//!
//! The gate reads one field, `seq`, from the manifest JSON. It is a sanity check on what the
//! server stores, not a trust decision: it does not verify the signature. fleetd verifies the
//! signature against its trust root and checks `seq` itself (ADR-0047, ADR-0050).
//!
//! The poller logs a refusal kind or a gate outcome, both closed enums, and never a URL.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use crate::config::UpdateRepo;
use crate::cred::release::{RELEASE_CYCLE_TIMEOUT, ReleaseFetcher, ReleaseRefusal};

/// Longest wait after failures, unless the poll interval is longer: one hour.
pub const MAX_BACKOFF: Duration = Duration::from_secs(3600);

/// Largest jitter on a wait, in parts per thousand: plus or minus 10 percent.
pub const MAX_JITTER_PERMILLE: i32 = 100;

/// What the seq gate decided about an offered pair.
///
/// `First`, `Replaced`, `Resigned` and `Unchanged` are accepted and reset the backoff. The rest
/// are rejections: the cached pair stays and the backoff grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateOutcome {
    /// Nothing was cached: the pair is stored.
    First,
    /// The `seq` is higher: the pair replaces the cached one.
    Replaced,
    /// The `seq` and manifest bytes are equal but the signature differs: the pair replaces the
    /// cached one. This heals a torn pair (ADR-0060), where a release landed between the two
    /// fetches.
    Resigned,
    /// The `seq`, manifest bytes and signature bytes are all equal: nothing changes.
    Unchanged,
    /// The `seq` is equal but the manifest bytes differ: rejected.
    Conflict,
    /// The `seq` is lower than the cached one: rejected.
    Lower,
    /// The manifest is JSON but has no `seq` that is an unsigned integer: rejected.
    BadSeq,
    /// The manifest is not JSON: rejected.
    NotJson,
    /// The manifest or signature is over its cap: rejected.
    TooLarge,
}

impl GateOutcome {
    /// Every variant, so tests can enumerate the closed set.
    pub const ALL: [Self; 9] = [
        Self::First,
        Self::Replaced,
        Self::Resigned,
        Self::Unchanged,
        Self::Conflict,
        Self::Lower,
        Self::BadSeq,
        Self::NotJson,
        Self::TooLarge,
    ];

    /// Whether the pair counts as an accepted fetch.
    pub const fn accepted(self) -> bool {
        matches!(
            self,
            Self::First | Self::Replaced | Self::Resigned | Self::Unchanged
        )
    }
}

/// A manifest and its signature as last accepted, with the manifest `seq`. The fields are
/// private so a pair always passed the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedPair {
    manifest: Vec<u8>,
    signature: Vec<u8>,
    seq: u64,
}

impl FeedPair {
    /// The manifest bytes.
    pub fn manifest(&self) -> &[u8] {
        &self.manifest
    }

    /// The signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The manifest `seq`.
    pub const fn seq(&self) -> u64 {
        self.seq
    }
}

fn read_seq(manifest: &[u8]) -> Result<u64, GateOutcome> {
    let value: serde_json::Value =
        serde_json::from_slice(manifest).map_err(|_| GateOutcome::NotJson)?;
    value
        .get("seq")
        .and_then(serde_json::Value::as_u64)
        .ok_or(GateOutcome::BadSeq)
}

fn seq_gate(cached: Option<&FeedPair>, seq: u64, manifest: &[u8], signature: &[u8]) -> GateOutcome {
    let Some(held) = cached else {
        return GateOutcome::First;
    };
    match seq.cmp(&held.seq) {
        std::cmp::Ordering::Greater => GateOutcome::Replaced,
        std::cmp::Ordering::Less => GateOutcome::Lower,
        std::cmp::Ordering::Equal if held.manifest != manifest => GateOutcome::Conflict,
        std::cmp::Ordering::Equal if held.signature != signature => GateOutcome::Resigned,
        std::cmp::Ordering::Equal => GateOutcome::Unchanged,
    }
}

/// The last good pair. Shared by the poller, which writes it, and the relay, which reads it
/// ([`UpdateRelay::from_feed`](crate::service::UpdateRelay::from_feed)). Clones share one pair.
#[derive(Debug, Clone, Default)]
pub struct FeedCache {
    held: Arc<Mutex<Option<FeedPair>>>,
}

impl FeedCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// A copy of the last good pair, or `None` before the first accepted fetch.
    pub fn current(&self) -> Option<FeedPair> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Runs the seq gate on a fetched pair and stores it when the gate replaces. A rejection
    /// leaves the cached pair untouched. The size caps are [`fleet_proto::MAX_MANIFEST_BYTES`]
    /// and [`fleet_proto::MAX_SIGNATURE_BYTES`].
    pub fn offer(&self, manifest: &[u8], signature: &[u8]) -> GateOutcome {
        if manifest.len() > fleet_proto::MAX_MANIFEST_BYTES
            || signature.len() > fleet_proto::MAX_SIGNATURE_BYTES
        {
            return GateOutcome::TooLarge;
        }
        let seq = match read_seq(manifest) {
            Ok(seq) => seq,
            Err(outcome) => return outcome,
        };
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let outcome = seq_gate(held.as_ref(), seq, manifest, signature);
        if matches!(
            outcome,
            GateOutcome::First | GateOutcome::Replaced | GateOutcome::Resigned
        ) {
            *held = Some(FeedPair {
                manifest: manifest.to_vec(),
                signature: signature.to_vec(),
                seq,
            });
        }
        outcome
    }
}

/// Fetches one manifest and signature pair. The real source is [`ReleaseFeed`]; tests inject
/// every failure.
#[tonic::async_trait]
pub trait FeedSource: Send + Sync {
    /// Returns `(manifest, signature)`.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseRefusal`] when either download fails.
    async fn fetch_pair(&self) -> Result<(Vec<u8>, Vec<u8>), ReleaseRefusal>;
}

/// The feed of one repository's latest release, fetched through [`ReleaseFetcher`].
pub struct ReleaseFeed {
    fetcher: ReleaseFetcher,
    repo: UpdateRepo,
    cycle_timeout: Duration,
}

impl ReleaseFeed {
    /// A feed with the ADR cycle timeout of [`RELEASE_CYCLE_TIMEOUT`].
    pub fn new(fetcher: ReleaseFetcher, repo: UpdateRepo) -> Self {
        Self::with_cycle_timeout(fetcher, repo, RELEASE_CYCLE_TIMEOUT)
    }

    /// A feed with an explicit cycle timeout, so tests can shrink it.
    pub fn with_cycle_timeout(
        fetcher: ReleaseFetcher,
        repo: UpdateRepo,
        cycle_timeout: Duration,
    ) -> Self {
        Self {
            fetcher,
            repo,
            cycle_timeout,
        }
    }

    fn path(&self, suffix: &str) -> String {
        format!(
            "/{}/{}/releases/latest/download/manifest.json{suffix}",
            self.repo.owner(),
            self.repo.repo()
        )
    }
}

#[tonic::async_trait]
impl FeedSource for ReleaseFeed {
    async fn fetch_pair(&self) -> Result<(Vec<u8>, Vec<u8>), ReleaseRefusal> {
        timeout(self.cycle_timeout, async {
            let manifest = self.fetcher.fetch_manifest(&self.path("")).await?;
            let signature = self.fetcher.fetch_signature(&self.path(".minisig")).await?;
            Ok((manifest, signature))
        })
        .await
        .map_err(|_| ReleaseRefusal::Timeout)?
    }
}

/// Where the jitter on each wait comes from.
pub trait Jitter: Send + Sync {
    /// A value in parts per thousand. [`jittered`] clamps it to plus or minus
    /// [`MAX_JITTER_PERMILLE`].
    fn permille(&self) -> i32;
}

/// Jitter from the system random source. A failed read gives no jitter.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemJitter;

impl Jitter for SystemJitter {
    fn permille(&self) -> i32 {
        let mut bytes = [0_u8; 2];
        if SystemRandom::new().fill(&mut bytes).is_err() {
            return 0;
        }
        let span = u16::try_from(2 * MAX_JITTER_PERMILLE + 1).unwrap_or(u16::MAX);
        i32::from(u16::from_le_bytes(bytes) % span) - MAX_JITTER_PERMILLE
    }
}

/// `base` scaled by `1 + permille / 1000`, with `permille` clamped to plus or minus
/// [`MAX_JITTER_PERMILLE`].
pub fn jittered(base: Duration, permille: i32) -> Duration {
    let clamped = permille.clamp(-MAX_JITTER_PERMILLE, MAX_JITTER_PERMILLE);
    let factor = u128::try_from(1000 + clamped).unwrap_or(1000);
    let nanos = base.as_nanos().saturating_mul(factor) / 1000;
    Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
}

/// The wait between polls: the interval, doubled on each failure up to the larger of
/// [`MAX_BACKOFF`] and the interval, and back to the interval after an accepted fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    interval: Duration,
    cap: Duration,
    wait: Duration,
}

impl Backoff {
    /// A backoff at `interval`.
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            cap: interval.max(MAX_BACKOFF),
            wait: interval,
        }
    }

    /// The current wait, before jitter.
    pub const fn wait(&self) -> Duration {
        self.wait
    }

    /// Doubles the wait, up to the cap.
    pub fn on_failure(&mut self) {
        self.wait = self.wait.saturating_mul(2).min(self.cap);
    }

    /// Returns the wait to the interval.
    pub fn on_success(&mut self) {
        self.wait = self.interval;
    }
}

/// What one poll cycle ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CycleOutcome {
    /// The fetch failed.
    Fetch(ReleaseRefusal),
    /// The fetch returned a pair and the gate ruled on it.
    Gate(GateOutcome),
}

/// Polls a [`FeedSource`] and fills a [`FeedCache`].
pub struct FeedPoller {
    source: Arc<dyn FeedSource>,
    cache: FeedCache,
    jitter: Arc<dyn Jitter>,
    backoff: Backoff,
}

impl FeedPoller {
    /// A poller that waits `interval` between polls.
    pub fn new(
        source: Arc<dyn FeedSource>,
        cache: FeedCache,
        interval: Duration,
        jitter: Arc<dyn Jitter>,
    ) -> Self {
        Self {
            source,
            cache,
            jitter,
            backoff: Backoff::new(interval),
        }
    }

    /// Fetches once and offers the pair to the cache. The backoff resets only when the gate
    /// accepts the pair. Every failure keeps the cached pair.
    pub async fn poll_once(&mut self) -> CycleOutcome {
        let outcome = match self.source.fetch_pair().await {
            Err(refusal) => {
                tracing::warn!(reason = %refusal, "release feed fetch failed");
                CycleOutcome::Fetch(refusal)
            }
            Ok((manifest, signature)) => {
                let gate = self.cache.offer(&manifest, &signature);
                if !gate.accepted() {
                    tracing::warn!(outcome = ?gate, "release feed pair rejected");
                }
                CycleOutcome::Gate(gate)
            }
        };
        match outcome {
            CycleOutcome::Gate(gate) if gate.accepted() => self.backoff.on_success(),
            _ => self.backoff.on_failure(),
        }
        outcome
    }

    /// The jittered wait before the next poll.
    pub fn next_wait(&self) -> Duration {
        jittered(self.backoff.wait(), self.jitter.permille())
    }

    /// Spawns the poll loop. The first poll runs inside the task, so a hung fetch never delays
    /// the caller. The task ends when `stop_rx` holds `true` or its sender is dropped, even
    /// mid-fetch.
    pub fn spawn(mut self, mut stop_rx: watch::Receiver<bool>) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = stopped(&mut stop_rx) => return,
                    _ = self.poll_once() => {}
                }
                let wait = self.next_wait();
                tokio::select! {
                    () = stopped(&mut stop_rx) => return,
                    () = sleep(wait) => {}
                }
            }
        })
    }
}

async fn stopped(rx: &mut watch::Receiver<bool>) {
    let _ = rx.wait_for(|stop| *stop).await;
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use hyper::StatusCode;
    use tokio::time::Instant;

    use super::*;
    use crate::cred::https::{FetchError, ForgeGet, ForgeReply, ForgeTransport};

    fn manifest(seq: u64, tag: &str) -> Vec<u8> {
        format!(r#"{{"seq":{seq},"tag":"{tag}"}}"#).into_bytes()
    }

    enum Step {
        Pair(Vec<u8>, Vec<u8>),
        Refuse(ReleaseRefusal),
        Hang,
    }

    struct Script {
        steps: Mutex<VecDeque<Step>>,
        calls: Mutex<Vec<Instant>>,
    }

    impl Script {
        fn new(steps: Vec<Step>) -> Arc<Self> {
            Arc::new(Self {
                steps: Mutex::new(steps.into()),
                calls: Mutex::new(Vec::new()),
            })
        }

        fn gaps(&self) -> Vec<Duration> {
            let calls = self.calls.lock().unwrap();
            calls.windows(2).map(|w| w[1] - w[0]).collect()
        }

        fn count(&self) -> usize {
            self.calls.lock().unwrap().len()
        }
    }

    #[tonic::async_trait]
    impl FeedSource for Script {
        async fn fetch_pair(&self) -> Result<(Vec<u8>, Vec<u8>), ReleaseRefusal> {
            self.calls.lock().unwrap().push(Instant::now());
            let step = self.steps.lock().unwrap().pop_front();
            match step {
                Some(Step::Pair(m, s)) => Ok((m, s)),
                Some(Step::Refuse(r)) => Err(r),
                Some(Step::Hang) => std::future::pending().await,
                None => Err(ReleaseRefusal::Unavailable),
            }
        }
    }

    struct Fixed(i32);

    impl Jitter for Fixed {
        fn permille(&self) -> i32 {
            self.0
        }
    }

    fn poller(steps: Vec<Step>, interval: Duration, jitter: i32) -> (FeedPoller, FeedCache) {
        let cache = FeedCache::new();
        let poller = FeedPoller::new(
            Script::new(steps),
            cache.clone(),
            interval,
            Arc::new(Fixed(jitter)),
        );
        (poller, cache)
    }

    fn held(cache: &FeedCache) -> Option<(Vec<u8>, Vec<u8>, u64)> {
        cache
            .current()
            .map(|p| (p.manifest().to_vec(), p.signature().to_vec(), p.seq()))
    }

    fn seed() -> (Vec<u8>, Vec<u8>, u64) {
        (manifest(5, "a"), b"sig-a".to_vec(), 5)
    }

    fn pair(m: Vec<u8>, s: &[u8]) -> Step {
        Step::Pair(m, s.to_vec())
    }

    type Held = Option<(Vec<u8>, Vec<u8>, u64)>;

    struct Row {
        name: &'static str,
        seeded: bool,
        step: Step,
        outcome: CycleOutcome,
        after: Held,
    }

    fn fetch_rows() -> Vec<Row> {
        let kept = Some(seed());
        vec![
            Row {
                name: "transport error",
                seeded: true,
                step: Step::Refuse(ReleaseRefusal::Unavailable),
                outcome: CycleOutcome::Fetch(ReleaseRefusal::Unavailable),
                after: kept.clone(),
            },
            Row {
                name: "non-200",
                seeded: true,
                step: Step::Refuse(ReleaseRefusal::BadStatus),
                outcome: CycleOutcome::Fetch(ReleaseRefusal::BadStatus),
                after: kept.clone(),
            },
            Row {
                name: "refused redirect",
                seeded: true,
                step: Step::Refuse(ReleaseRefusal::HostNotAllowed),
                outcome: CycleOutcome::Fetch(ReleaseRefusal::HostNotAllowed),
                after: kept.clone(),
            },
            Row {
                name: "over cap at the fetcher",
                seeded: true,
                step: Step::Refuse(ReleaseRefusal::TooLarge),
                outcome: CycleOutcome::Fetch(ReleaseRefusal::TooLarge),
                after: kept.clone(),
            },
            Row {
                name: "over cap manifest at the gate",
                seeded: true,
                step: pair(vec![b' '; fleet_proto::MAX_MANIFEST_BYTES + 1], b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::TooLarge),
                after: kept.clone(),
            },
            Row {
                name: "over cap signature at the gate",
                seeded: true,
                step: pair(
                    manifest(9, "b"),
                    &vec![b's'; fleet_proto::MAX_SIGNATURE_BYTES + 1],
                ),
                outcome: CycleOutcome::Gate(GateOutcome::TooLarge),
                after: kept,
            },
        ]
    }

    fn reject_rows() -> Vec<Row> {
        let kept = Some(seed());
        vec![
            Row {
                name: "non-JSON",
                seeded: true,
                step: pair(b"not json".to_vec(), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::NotJson),
                after: kept.clone(),
            },
            Row {
                name: "bad seq missing",
                seeded: true,
                step: pair(br#"{"tag":"b"}"#.to_vec(), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::BadSeq),
                after: kept.clone(),
            },
            Row {
                name: "bad seq negative",
                seeded: true,
                step: pair(br#"{"seq":-1}"#.to_vec(), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::BadSeq),
                after: kept.clone(),
            },
            Row {
                name: "bad seq string",
                seeded: true,
                step: pair(br#"{"seq":"9"}"#.to_vec(), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::BadSeq),
                after: kept.clone(),
            },
            Row {
                name: "bad seq float",
                seeded: true,
                step: pair(br#"{"seq":9.0}"#.to_vec(), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::BadSeq),
                after: kept.clone(),
            },
            Row {
                name: "bad seq not an object",
                seeded: true,
                step: pair(b"[9]".to_vec(), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::BadSeq),
                after: kept,
            },
        ]
    }

    fn compare_rows() -> Vec<Row> {
        let kept = Some(seed());
        vec![
            Row {
                name: "lower",
                seeded: true,
                step: pair(manifest(4, "b"), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::Lower),
                after: kept.clone(),
            },
            Row {
                name: "equal same bytes",
                seeded: true,
                step: pair(manifest(5, "a"), b"sig-a"),
                outcome: CycleOutcome::Gate(GateOutcome::Unchanged),
                after: kept.clone(),
            },
            Row {
                name: "equal different bytes",
                seeded: true,
                step: pair(manifest(5, "b"), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::Conflict),
                after: kept,
            },
            Row {
                name: "equal same manifest new signature",
                seeded: true,
                step: pair(manifest(5, "a"), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::Resigned),
                after: Some((manifest(5, "a"), b"sig-b".to_vec(), 5)),
            },
            Row {
                name: "higher",
                seeded: true,
                step: pair(manifest(6, "b"), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::Replaced),
                after: Some((manifest(6, "b"), b"sig-b".to_vec(), 6)),
            },
            Row {
                name: "first",
                seeded: false,
                step: pair(manifest(6, "b"), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::First),
                after: Some((manifest(6, "b"), b"sig-b".to_vec(), 6)),
            },
            Row {
                name: "first non-JSON leaves the cache empty",
                seeded: false,
                step: pair(b"not json".to_vec(), b"sig-b"),
                outcome: CycleOutcome::Gate(GateOutcome::NotJson),
                after: None,
            },
        ]
    }

    #[tokio::test(start_paused = true)]
    async fn seq_gate_table_asserts_cached_bytes() {
        let kept = Some(seed());
        let cases = fetch_rows()
            .into_iter()
            .chain(reject_rows())
            .chain(compare_rows());
        for Row {
            name,
            seeded,
            step,
            outcome,
            after,
        } in cases
        {
            let mut steps = Vec::new();
            if seeded {
                steps.push(pair(seed().0, &seed().1));
            }
            steps.push(step);
            let (mut poller, cache) = poller(steps, Duration::from_secs(100), 0);
            if seeded {
                poller.poll_once().await;
                assert_eq!(held(&cache), kept, "{name}: positive control");
            }
            assert_eq!(poller.poll_once().await, outcome, "{name}: outcome");
            assert_eq!(held(&cache), after, "{name}: cached bytes");
        }
    }

    #[test]
    fn a_pair_exactly_at_each_cap_is_accepted() {
        let head = br#"{"seq":1,"pad":""#;
        let tail = br#""}"#;
        let mut manifest = head.to_vec();
        manifest.resize(fleet_proto::MAX_MANIFEST_BYTES - tail.len(), b'x');
        manifest.extend_from_slice(tail);
        assert_eq!(manifest.len(), fleet_proto::MAX_MANIFEST_BYTES);
        let signature = vec![b's'; fleet_proto::MAX_SIGNATURE_BYTES];
        let cache = FeedCache::new();
        assert_eq!(cache.offer(&manifest, &signature), GateOutcome::First);
        assert_eq!(held(&cache), Some((manifest, signature, 1)));
    }

    #[test]
    fn every_gate_outcome_is_classified() {
        let accepted: Vec<_> = GateOutcome::ALL
            .into_iter()
            .filter(|o| o.accepted())
            .collect();
        assert_eq!(
            accepted,
            vec![
                GateOutcome::First,
                GateOutcome::Replaced,
                GateOutcome::Resigned,
                GateOutcome::Unchanged
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn good_fetch_after_failures_replaces_and_a_failure_after_good_keeps() {
        let (mut p, cache) = poller(
            vec![
                Step::Refuse(ReleaseRefusal::Unavailable),
                Step::Refuse(ReleaseRefusal::BadStatus),
                pair(manifest(7, "x"), b"sig-x"),
                Step::Refuse(ReleaseRefusal::Timeout),
            ],
            Duration::from_secs(100),
            0,
        );
        p.poll_once().await;
        p.poll_once().await;
        assert_eq!(held(&cache), None);
        assert_eq!(p.backoff.wait(), Duration::from_secs(400));
        p.poll_once().await;
        assert_eq!(held(&cache), Some((manifest(7, "x"), b"sig-x".to_vec(), 7)));
        assert_eq!(p.backoff.wait(), Duration::from_secs(100));
        p.poll_once().await;
        assert_eq!(held(&cache), Some((manifest(7, "x"), b"sig-x".to_vec(), 7)));
        assert_eq!(p.backoff.wait(), Duration::from_secs(200));
    }

    #[test]
    fn backoff_doubles_to_the_cap_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(900));
        let mut waits = Vec::new();
        for _ in 0..4 {
            b.on_failure();
            waits.push(b.wait().as_secs());
        }
        assert_eq!(waits, vec![1800, 3600, 3600, 3600]);
        b.on_success();
        assert_eq!(b.wait(), Duration::from_secs(900));
    }

    #[test]
    fn backoff_never_waits_less_than_a_long_interval() {
        let mut b = Backoff::new(Duration::from_secs(86_400));
        b.on_failure();
        assert_eq!(b.wait(), Duration::from_secs(86_400));
    }

    #[test]
    fn jitter_is_bounded_and_clamped() {
        let base = Duration::from_secs(1000);
        assert_eq!(jittered(base, 0), base);
        assert_eq!(jittered(base, 100), Duration::from_secs(1100));
        assert_eq!(jittered(base, -100), Duration::from_secs(900));
        assert_eq!(jittered(base, 5000), Duration::from_secs(1100));
        assert_eq!(jittered(base, -5000), Duration::from_secs(900));
        assert_eq!(jittered(base, i32::MIN), Duration::from_secs(900));
        assert_eq!(jittered(base, i32::MAX), Duration::from_secs(1100));
    }

    #[test]
    fn system_jitter_stays_in_range() {
        for _ in 0..2000 {
            let v = SystemJitter.permille();
            assert!(
                (-MAX_JITTER_PERMILLE..=MAX_JITTER_PERMILLE).contains(&v),
                "{v}"
            );
        }
    }

    async fn run_gaps(
        steps: Vec<Step>,
        interval: Duration,
        jitter: i32,
        total: Duration,
    ) -> Vec<Duration> {
        let script = Script::new(steps);
        let cache = FeedCache::new();
        let poller = FeedPoller::new(script.clone(), cache, interval, Arc::new(Fixed(jitter)));
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = poller.spawn(stop_rx);
        sleep(total).await;
        stop_tx.send(true).unwrap();
        handle.await.unwrap();
        script.gaps()
    }

    fn secs(v: &[u64]) -> Vec<Duration> {
        v.iter().map(|s| Duration::from_secs(*s)).collect()
    }

    #[tokio::test(start_paused = true)]
    async fn poller_backs_off_to_the_cap_and_resets_after_an_accepted_fetch() {
        let steps = vec![
            Step::Refuse(ReleaseRefusal::Unavailable),
            Step::Refuse(ReleaseRefusal::Unavailable),
            Step::Refuse(ReleaseRefusal::Unavailable),
            pair(manifest(1, "a"), b"s"),
            pair(manifest(1, "a"), b"s"),
        ];
        let gaps = run_gaps(
            steps,
            Duration::from_secs(1000),
            0,
            Duration::from_secs(12_000),
        )
        .await;
        assert_eq!(gaps[..4], secs(&[2000, 3600, 3600, 1000]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_rejected_200_does_not_reset_the_backoff() {
        let steps = vec![
            pair(manifest(5, "a"), b"s"),
            Step::Refuse(ReleaseRefusal::Unavailable),
            pair(manifest(4, "a"), b"s"),
            pair(manifest(5, "a"), b"s"),
            pair(manifest(5, "a"), b"s"),
        ];
        let gaps = run_gaps(
            steps,
            Duration::from_secs(500),
            0,
            Duration::from_secs(6000),
        )
        .await;
        assert_eq!(gaps[..4], secs(&[500, 1000, 2000, 500]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_resigned_pair_resets_the_backoff() {
        let steps = vec![
            pair(manifest(5, "a"), b"s1"),
            Step::Refuse(ReleaseRefusal::Unavailable),
            pair(manifest(5, "a"), b"s2"),
            pair(manifest(5, "a"), b"s2"),
        ];
        let gaps = run_gaps(
            steps,
            Duration::from_secs(500),
            0,
            Duration::from_secs(6000),
        )
        .await;
        assert_eq!(gaps[..3], secs(&[500, 1000, 500]));
    }

    #[tokio::test(start_paused = true)]
    async fn poller_applies_jitter_both_ways() {
        let good = || pair(manifest(1, "a"), b"s");
        let hi = run_gaps(
            vec![good(), good(), good()],
            Duration::from_secs(1000),
            100,
            Duration::from_secs(3000),
        )
        .await;
        assert_eq!(hi[..2], secs(&[1100, 1100]));
        let lo = run_gaps(
            vec![good(), good(), good()],
            Duration::from_secs(1000),
            -100,
            Duration::from_secs(3000),
        )
        .await;
        assert_eq!(lo[..2], secs(&[900, 900]));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_first_fetch_never_blocks_the_caller_and_stop_ends_it() {
        let script = Script::new(vec![Step::Hang]);
        let cache = FeedCache::new();
        let poller = FeedPoller::new(
            script.clone(),
            cache.clone(),
            Duration::from_secs(900),
            Arc::new(Fixed(0)),
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = poller.spawn(stop_rx);
        sleep(Duration::from_secs(5000)).await;
        assert_eq!(script.count(), 1);
        assert!(!handle.is_finished());
        assert_eq!(held(&cache), None);
        stop_tx.send(true).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn stop_ends_the_task_while_it_sleeps() {
        let script = Script::new(vec![pair(manifest(1, "a"), b"s")]);
        let poller = FeedPoller::new(
            script.clone(),
            FeedCache::new(),
            Duration::from_secs(900),
            Arc::new(Fixed(0)),
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = poller.spawn(stop_rx);
        sleep(Duration::from_secs(100)).await;
        stop_tx.send(true).unwrap();
        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
        sleep(Duration::from_secs(5000)).await;
        assert_eq!(script.count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_stop_sender_ends_the_task() {
        let script = Script::new(vec![Step::Hang]);
        let poller = FeedPoller::new(
            script,
            FeedCache::new(),
            Duration::from_secs(900),
            Arc::new(Fixed(0)),
        );
        let (stop_tx, stop_rx) = watch::channel(false);
        let handle = poller.spawn(stop_rx);
        drop(stop_tx);
        timeout(Duration::from_secs(1), handle)
            .await
            .unwrap()
            .unwrap();
    }

    struct Fake {
        delay: Duration,
        seen: Mutex<Vec<String>>,
    }

    #[tonic::async_trait]
    impl ForgeTransport for Fake {
        async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("{}{}", request.host, request.path));
            sleep(self.delay).await;
            let body = if request.path.ends_with(".minisig") {
                b"sig".to_vec()
            } else {
                manifest(3, "r")
            };
            Ok(ForgeReply {
                status: StatusCode::OK,
                body,
                location: None,
            })
        }
    }

    fn release_feed(delay: Duration) -> (ReleaseFeed, Arc<Fake>) {
        let fake = Arc::new(Fake {
            delay,
            seen: Mutex::new(Vec::new()),
        });
        let feed = ReleaseFeed::new(
            ReleaseFetcher::new(fake.clone()),
            UpdateRepo::parse("Own-er/re.po_1").unwrap(),
        );
        (feed, fake)
    }

    #[tokio::test(start_paused = true)]
    async fn release_feed_fetches_manifest_then_signature_of_the_latest_release() {
        let (feed, fake) = release_feed(Duration::ZERO);
        let (m, s) = feed.fetch_pair().await.unwrap();
        assert_eq!(m, manifest(3, "r"));
        assert_eq!(s, b"sig");
        assert_eq!(
            *fake.seen.lock().unwrap(),
            vec![
                "github.com/Own-er/re.po_1/releases/latest/download/manifest.json".to_owned(),
                "github.com/Own-er/re.po_1/releases/latest/download/manifest.json.minisig"
                    .to_owned(),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn release_feed_times_out_across_both_downloads() {
        let (feed, _) = release_feed(Duration::from_secs(20));
        assert_eq!(feed.fetch_pair().await, Err(ReleaseRefusal::Timeout));
        let (fast, _) = release_feed(Duration::from_secs(10));
        assert!(fast.fetch_pair().await.is_ok());
    }
}
