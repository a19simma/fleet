//! The update loop of the daemon (ADR-0047): offer, verify, stage, apply.
//!
//! The heartbeat hands each reply's `(manifest, signature)` pair to an [`OfferSink`], a
//! one-slot channel where the latest offer replaces an unread one and an identical offer is
//! not a change. [`UpdateDriver`] reads it, verifies the pair against the trust root and the
//! [`Policy`] (running version, stored `seq`, protocol), stages the archive through the
//! [`Stager`] and calls [`Updater::apply`], which drains, swaps and raises the restart signal.
//!
//! A failure leaves `current` as it was and logs a closed reason, never a URL or a path. The
//! driver retries only when a new manifest arrives, at most [`MAX_ATTEMPTS_PER_VERSION`] times
//! per version. The `seq` is stored once `current` has swapped, so a failed attempt does not
//! burn it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use fleet_core::tools::Version;
use fleet_proto::v1::HeartbeatReply;
use fleet_proto::{PROTOCOL_VERSION, update_within_caps};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::{
    ApplyOutcome, ArchiveFetcher, Policy, PolicyArchiveFetcher, ROOT_UID, SeqStore, StageError,
    Stager, Swapper, TrustRoot, UpdateError, UpdateWiring, Updater, load_trust_root,
    verify_manifest,
};
use crate::fetch_policy::HostPattern;

/// Most attempts the driver makes for one version across manifests that name it.
pub const MAX_ATTEMPTS_PER_VERSION: u32 = 3;

/// A manifest and its signature as the heartbeat carried them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offer {
    manifest: Vec<u8>,
    signature: Vec<u8>,
}

impl Offer {
    /// An offer of `manifest` signed by `signature`.
    #[must_use]
    pub const fn new(manifest: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            manifest,
            signature,
        }
    }

    /// The manifest bytes and the signature bytes.
    #[must_use]
    pub fn parts(&self) -> (&[u8], &[u8]) {
        (&self.manifest, &self.signature)
    }

    fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update((self.manifest.len() as u64).to_be_bytes());
        hasher.update(&self.manifest);
        hasher.update(&self.signature);
        hasher.finalize().into()
    }
}

/// Where the heartbeat puts the update pair of a reply. Holds one offer.
#[derive(Debug, Clone)]
pub struct OfferSink(Arc<watch::Sender<Option<Offer>>>);

impl OfferSink {
    /// A sink and the receiver the driver reads.
    #[must_use]
    pub fn channel() -> (Self, watch::Receiver<Option<Offer>>) {
        let (tx, rx) = watch::channel(None);
        (Self(Arc::new(tx)), rx)
    }

    /// Takes the update pair of `reply`. A reply with no pair, one half, or a field over its
    /// cap changes nothing. A pair equal to the held one does not wake the driver.
    pub fn offer(&self, reply: &HeartbeatReply) {
        if !update_within_caps(reply) {
            return;
        }
        let (Some(manifest), Some(signature)) = (&reply.update_manifest, &reply.update_signature)
        else {
            return;
        };
        let offer = Offer::new(manifest.clone(), signature.clone());
        self.0.send_if_modified(|slot| {
            if slot.as_ref() == Some(&offer) {
                return false;
            }
            *slot = Some(offer);
            true
        });
    }
}

/// How one offer ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverOutcome {
    /// The offer equals the last one handled. Nothing ran.
    Unchanged,
    /// Verification or policy refused the offer. Nothing was fetched.
    Refused(&'static str),
    /// Stage or apply failed. `current` is as it was.
    Failed(&'static str),
    /// `current` swapped and the restart signal is raised.
    Restarting,
}

/// What the driver needs to know about this box.
#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// The trust-root key.
    pub trust: TrustRoot,
    /// The version this process runs.
    pub running: Version,
    /// The manifest target name of this box.
    pub target: String,
    /// The bin root: staged versions, links, guard files and the `seq` file.
    pub bin_root: PathBuf,
    /// Hosts an archive may come from.
    pub hosts: Vec<HostPattern>,
}

/// Verifies offers, stages them and applies them.
pub struct UpdateDriver<F> {
    cfg: DriverConfig,
    fetcher: Arc<F>,
    updater: Updater,
    seq: SeqStore,
    last: Option<[u8; 32]>,
    attempts: HashMap<String, u32>,
}

impl<F> std::fmt::Debug for UpdateDriver<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UpdateDriver").finish_non_exhaustive()
    }
}

const fn refusal(err: &UpdateError) -> &'static str {
    match err {
        UpdateError::TrustRootNotRegular
        | UpdateError::TrustRootWritable { .. }
        | UpdateError::TrustRootOwner { .. }
        | UpdateError::TrustRootTooLarge
        | UpdateError::TrustRootInvalid(_)
        | UpdateError::TrustRootIo(_) => "trust root unusable",
        UpdateError::ManifestTooLarge => "manifest too large",
        UpdateError::SignatureTooLarge => "signature too large",
        UpdateError::Signature(_) => "signature refused",
        UpdateError::ManifestEncoding(_) => "manifest malformed",
        UpdateError::Field(_) => "manifest field invalid",
        UpdateError::SeqNotNewer { .. } => "seq not newer",
        UpdateError::VersionNotNewer => "version not newer",
        UpdateError::ProtocolTooNew { .. } => "protocol too new",
        UpdateError::UnknownTarget => "no entry for this target",
        UpdateError::SeqState(_) => "seq state unreadable",
    }
}

const fn stage_failure(err: &StageError) -> &'static str {
    match err {
        StageError::Version => "version not a safe name",
        StageError::NoUrl => "target has no url",
        StageError::Url(_) => "url refused",
        StageError::HostNotAllowed => "host not allowed",
        StageError::TooLarge => "archive too large",
        StageError::SizeMismatch { .. } => "archive size mismatch",
        StageError::HashMismatch => "archive hash mismatch",
        StageError::UnsafeDir(_) => "staging directory unsafe",
        StageError::AlreadyStaged => "version already staged",
        StageError::Fetch(_) => "download failed",
        StageError::Io(_) => "staging write failed",
    }
}

const fn apply_failure(outcome: ApplyOutcome) -> &'static str {
    match outcome {
        ApplyOutcome::Restarting => "restarting",
        ApplyOutcome::BadVersion => "version marked bad",
        ApplyOutcome::Busy => "another drain is running",
        ApplyOutcome::DrainAborted => "box did not go idle in time",
        ApplyOutcome::SwapFailed => "swap failed",
    }
}

impl<F: ArchiveFetcher + Send + Sync + 'static> UpdateDriver<F> {
    /// A driver over `fetcher` and `updater`.
    #[must_use]
    pub fn new(cfg: DriverConfig, fetcher: F, updater: Updater) -> Self {
        let seq = SeqStore::new(&cfg.bin_root);
        Self {
            cfg,
            fetcher: Arc::new(fetcher),
            updater,
            seq,
            last: None,
            attempts: HashMap::new(),
        }
    }

    /// Handles each offer the receiver delivers, until the sender is gone.
    pub async fn run(mut self, mut offers: watch::Receiver<Option<Offer>>) {
        while offers.changed().await.is_ok() {
            let offer = offers.borrow_and_update().clone();
            if let Some(offer) = offer {
                self.handle(&offer).await;
            }
        }
    }

    /// Verifies, stages and applies `offer`, and logs how it ended.
    pub async fn handle(&mut self, offer: &Offer) -> DriverOutcome {
        let digest = offer.digest();
        if self.last == Some(digest) {
            return DriverOutcome::Unchanged;
        }
        self.last = Some(digest);
        let outcome = self.process(offer).await;
        match outcome {
            DriverOutcome::Refused(reason @ ("seq not newer" | "version not newer")) => {
                tracing::info!(reason, "update offer ignored");
            }
            DriverOutcome::Refused(reason) => tracing::warn!(reason, "update offer refused"),
            DriverOutcome::Failed(reason) => tracing::warn!(reason, "update failed"),
            DriverOutcome::Restarting => tracing::info!("update applied, restart requested"),
            DriverOutcome::Unchanged => {}
        }
        outcome
    }

    async fn process(&mut self, offer: &Offer) -> DriverOutcome {
        let last_seq = match self.seq.load() {
            Ok(seq) => seq,
            Err(err) => return DriverOutcome::Refused(refusal(&err)),
        };
        let policy = Policy {
            running: self.cfg.running.clone(),
            last_seq,
            protocol: PROTOCOL_VERSION,
        };
        let manifest =
            match verify_manifest(&offer.manifest, &offer.signature, &self.cfg.trust, &policy) {
                Ok(manifest) => manifest,
                Err(err) => return DriverOutcome::Refused(refusal(&err)),
            };
        let target = match manifest.target(&self.cfg.target) {
            Ok(target) => target.clone(),
            Err(err) => return DriverOutcome::Refused(refusal(&err)),
        };
        let version = manifest.version.clone();
        let tries = self
            .attempts
            .entry(version.as_str().to_owned())
            .or_insert(0);
        if *tries >= MAX_ATTEMPTS_PER_VERSION {
            return DriverOutcome::Failed("attempts for this version are used up");
        }
        *tries += 1;
        let staged = {
            let fetcher = Arc::clone(&self.fetcher);
            let root = self.cfg.bin_root.clone();
            let hosts = self.cfg.hosts.clone();
            let version = version.clone();
            tokio::task::spawn_blocking(move || {
                Stager::new(root, hosts, &*fetcher).stage(&version, &target)
            })
            .await
        };
        match staged {
            Ok(Ok(_)) => {}
            Ok(Err(err)) => return DriverOutcome::Failed(stage_failure(&err)),
            Err(_) => return DriverOutcome::Failed("staging task failed"),
        }
        let applied = self.updater.apply(&version).await;
        if applied == ApplyOutcome::Restarting {
            if let Err(err) = self.seq.store(manifest.seq) {
                tracing::warn!(reason = refusal(&err), "seq not stored after the swap");
            }
            return DriverOutcome::Restarting;
        }
        self.discard(&version);
        DriverOutcome::Failed(apply_failure(applied))
    }

    fn discard(&self, version: &Version) {
        let swapper = Swapper::new(&self.cfg.bin_root);
        let in_use = [swapper.current_version(), swapper.previous_version()]
            .into_iter()
            .any(|link| matches!(link, Ok(Some(ref held)) if held == version));
        if in_use {
            return;
        }
        let dir = self.cfg.bin_root.join(version.as_str());
        if let Err(err) = std::fs::remove_dir_all(&dir)
            && err.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!("staged version not removed after a failed update");
        }
    }

    /// Starts the driver on the current runtime and returns the sink for the heartbeat.
    #[must_use]
    pub fn spawn(self) -> (OfferSink, JoinHandle<()>) {
        let (sink, offers) = OfferSink::channel();
        (sink, tokio::spawn(self.run(offers)))
    }
}

/// The manifest target name of this box: its CPU architecture with `-unknown-linux-gnu`.
#[must_use]
pub fn host_target() -> String {
    format!("{}-unknown-linux-gnu", std::env::consts::ARCH)
}

/// Starts the production driver, or returns `None` with one warning.
///
/// The trust root at `trust_root` must load: a missing, unsafe or invalid file disables
/// updating and nothing else. The driver fetches through the egress policy for `hosts` and
/// applies through `wiring`. Call it once at startup, inside the runtime.
#[must_use]
pub fn start_production(
    trust_root: &Path,
    bin_root: &Path,
    hosts: Vec<HostPattern>,
    wiring: &UpdateWiring,
) -> Option<(OfferSink, JoinHandle<()>)> {
    let trust = match load_trust_root(trust_root, ROOT_UID) {
        Ok(trust) => trust,
        Err(err) => {
            tracing::warn!(reason = refusal(&err), "self-update disabled");
            return None;
        }
    };
    let Ok(running) = Version::new(env!("CARGO_PKG_VERSION")) else {
        tracing::warn!(reason = "own version unusable", "self-update disabled");
        return None;
    };
    let cfg = DriverConfig {
        trust,
        running,
        target: host_target(),
        bin_root: bin_root.to_owned(),
        hosts: hosts.clone(),
    };
    let fetcher = PolicyArchiveFetcher::system(Handle::current(), hosts);
    let updater = wiring.updater(Swapper::new(bin_root));
    Some(UpdateDriver::new(cfg, fetcher, updater).spawn())
}
