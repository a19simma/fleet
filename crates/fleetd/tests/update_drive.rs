//! The update loop of the daemon against an in-process `FleetIngest` stub and a fake archive
//! fetcher: a signed manifest in a heartbeat reply swaps `current` and raises the restart
//! signal, and every refused or failed offer leaves the bin root exactly as it was.

#![expect(
    clippy::unwrap_used,
    clippy::format_collect,
    clippy::unwrap_in_result,
    clippy::significant_drop_in_scrutinee,
    reason = "test code asserts by panicking"
)]

use std::fs;
use std::io::{self, Cursor, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use flate2::Compression;
use flate2::write::GzEncoder;
use fleet_core::tools::Version;
use fleet_proto::v1::fleet_ingest_server::{FleetIngest, FleetIngestServer};
use fleet_proto::v1::{HeartbeatReply, HeartbeatRequest, PushEventsReply, PushEventsRequest};
use fleet_proto::{MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES};
use fleetd::fetch_policy::HostPattern;
use fleetd::heartbeat::{Heartbeat, QueueSnapshot, QueueSource};
use fleetd::update::{
    ArchiveFetcher, ArchiveResponse, DrainController, DriverConfig, DriverOutcome,
    MAX_ATTEMPTS_PER_VERSION, Offer, OfferSink, RestartSignal, SeqStore, Swapper, TrustRoot,
    TrustSource, UpdateDriver, UpdateWiring, Updater, load_trust_root, start_production,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::oneshot;
use tonic::transport::Server;
use tonic::transport::server::TcpIncoming;
use tonic::{Request, Response, Status};
use tracing_subscriber::fmt::MakeWriter;

#[path = "common/minisign.rs"]
mod minisign;
use minisign::Signer;

const TARGET: &str = "test-target";
const URL: &str = "https://github.com/owner/repo/releases/download/v1/fleetd.tar.gz";
const BIN: &[u8] = b"\x7fELF fake fleetd 1.1.0";
const WIDE: Duration = Duration::from_secs(10);
const CAP: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_secs(1);
const TOKEN: &str = "update-token-0123456789abcdef0123456789";

fn tar_gz(bin: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..6].copy_from_slice(b"fleetd");
    h[100..107].copy_from_slice(b"0000755");
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..135].copy_from_slice(format!("{:011o}", bin.len()).as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut tar = h.to_vec();
    tar.extend_from_slice(bin);
    tar.resize(tar.len().div_ceil(512) * 512, 0);
    tar.extend_from_slice(&[0u8; 1024]);
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(&tar).unwrap();
    enc.finish().unwrap()
}

fn sha_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

struct Fake {
    body: Vec<u8>,
    fail: bool,
    calls: Arc<AtomicUsize>,
}

impl ArchiveFetcher for Fake {
    fn get(&self, url: &str) -> io::Result<ArchiveResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err(io::Error::other("fake download failure"));
        }
        Ok(ArchiveResponse {
            final_url: url.to_owned(),
            body: Box::new(Cursor::new(self.body.clone())),
        })
    }
}

fn manifest(version: &str, seq: u64, target: &str, archive: &[u8]) -> Vec<u8> {
    format!(
        r#"{{"version":"{version}","min_protocol":1,"seq":{seq},"targets":{{"{target}":{{"sha256":"{}","size":{},"url":"{URL}"}}}}}}"#,
        sha_hex(archive),
        archive.len()
    )
    .into_bytes()
}

fn signed(signer: &Signer, json: Vec<u8>) -> Offer {
    let signature = signer.sign(&json);
    Offer::new(json, signature)
}

struct Rig {
    _dir: TempDir,
    root: PathBuf,
    signer: Signer,
    archive: Vec<u8>,
    wiring: UpdateWiring,
    restart: RestartSignal,
    calls: Arc<AtomicUsize>,
    trust: TrustRoot,
}

fn rig() -> Rig {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("bin");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let old = root.join("1.0.0");
    fs::create_dir(&old).unwrap();
    fs::write(old.join("fleetd"), b"old").unwrap();
    fs::set_permissions(&old, fs::Permissions::from_mode(0o755)).unwrap();
    symlink("1.0.0", root.join("current")).unwrap();
    let signer = Signer::new(7);
    let key = dir.path().join("update.pub");
    fs::write(&key, signer.public_text()).unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
    let owner = fs::metadata(dir.path()).unwrap().uid();
    let trust = load_trust_root(&key, owner).unwrap();
    let wiring = UpdateWiring::default();
    let restart = wiring.restart.clone();
    Rig {
        _dir: dir,
        root,
        signer,
        archive: tar_gz(BIN),
        wiring,
        restart,
        calls: Arc::default(),
        trust,
    }
}

impl Rig {
    fn driver(&self, fail: bool) -> UpdateDriver<Fake> {
        let updater = Updater::new(
            DrainController::new(self.wiring.gate.clone(), CAP, POLL),
            self.wiring.tracker.clone(),
            Swapper::new(&self.root),
            self.restart.clone(),
        );
        let cfg = DriverConfig {
            trust: self.trust.clone(),
            running: Version::new("1.0.0").unwrap(),
            target: TARGET.to_owned(),
            bin_root: self.root.clone(),
            hosts: vec![HostPattern::parse("github.com").unwrap()],
        };
        let fake = Fake {
            body: self.archive.clone(),
            fail,
            calls: Arc::clone(&self.calls),
        };
        UpdateDriver::new(cfg, fake, updater)
    }

    fn offer(&self, version: &str, seq: u64) -> Offer {
        signed(&self.signer, manifest(version, seq, TARGET, &self.archive))
    }

    fn current(&self) -> String {
        fs::read_link(self.root.join("current"))
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }

    fn snapshot(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let path = entry.path();
                let meta = fs::symlink_metadata(&path).unwrap();
                let detail = if meta.file_type().is_symlink() {
                    fs::read_link(&path).unwrap().to_string_lossy().into_owned()
                } else {
                    format!("{:o}", meta.permissions().mode())
                };
                (entry.file_name().into_string().unwrap(), detail)
            })
            .collect();
        rows.sort();
        rows
    }

    async fn raised(&self) -> bool {
        tokio::time::timeout(Duration::from_millis(20), self.restart.requested())
            .await
            .is_ok()
    }
}

struct Stub {
    reply: Arc<Mutex<Option<Offer>>>,
}

#[tonic::async_trait]
impl FleetIngest for Stub {
    async fn push_events(
        &self,
        _request: Request<PushEventsRequest>,
    ) -> Result<Response<PushEventsReply>, Status> {
        Err(Status::unimplemented("unused"))
    }

    async fn heartbeat(
        &self,
        _request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatReply>, Status> {
        let mut reply = HeartbeatReply {
            next_in_s: 30,
            ..HeartbeatReply::default()
        };
        if let Some(offer) = self.reply.lock().unwrap().clone() {
            let (manifest, signature) = offer.parts();
            reply.update_manifest = Some(manifest.to_vec());
            reply.update_signature = Some(signature.to_vec());
        }
        Ok(Response::new(reply))
    }
}

fn serve(reply: Arc<Mutex<Option<Offer>>>) -> SocketAddr {
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(
        Server::builder()
            .add_service(FleetIngestServer::new(Stub { reply }))
            .serve_with_incoming(incoming),
    );
    addr
}

struct NoQueue;

impl QueueSource for NoQueue {
    fn snapshot(&self) -> impl Future<Output = QueueSnapshot> + Send {
        std::future::ready(QueueSnapshot::default())
    }
}

fn identity() -> fleet_core::Identity {
    fleet_core::Identity {
        box_name: "alpha".into(),
        hostname: "host".into(),
        machine_id: "machine".into(),
        boot_id: "boot".into(),
    }
}

#[tokio::test]
async fn a_signed_manifest_in_a_heartbeat_reply_swaps_current_and_raises_the_restart() {
    let rig = rig();
    let reply = Arc::new(Mutex::new(Some(rig.offer("1.1.0", 7))));
    let addr = serve(reply);
    let (sink, task) = rig.driver(false).spawn();
    let (stop, stopped) = oneshot::channel::<()>();
    let beat = tokio::spawn(
        Heartbeat::new(&format!("http://{addr}"), TOKEN)
            .unwrap()
            .with_period(Duration::from_millis(50))
            .with_on_reply(move |reply| sink.offer(reply))
            .run(identity(), NoQueue, async move {
                let _ = stopped.await;
            }),
    );
    tokio::time::timeout(WIDE, rig.restart.requested())
        .await
        .unwrap();
    assert_eq!(rig.current(), "1.1.0");
    assert_eq!(fs::read(rig.root.join("1.1.0/fleetd")).unwrap(), BIN);
    assert_eq!(
        fs::read_link(rig.root.join("previous")).unwrap(),
        Path::new("1.0.0")
    );
    assert_eq!(SeqStore::new(&rig.root).load().unwrap(), 7);
    assert!(rig.wiring.gate.is_paused());
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
    let _ = stop.send(());
    beat.await.unwrap();
    task.abort();
}

#[tokio::test]
async fn an_offer_a_box_cannot_use_changes_nothing() {
    let rig = rig();
    let other = Signer::new(9);
    let good = manifest("1.1.0", 7, TARGET, &rig.archive);
    let legacy = Offer::new(good.clone(), rig.signer.sign_with(&good, b"Ed"));
    let mut tampered = good.clone();
    tampered.extend_from_slice(b" ");
    let tampered = Offer::new(tampered, rig.signer.sign(&good));
    let oversize = Offer::new(vec![b' '; MAX_MANIFEST_BYTES + 1], rig.signer.sign(b""));
    let oversize_sig = Offer::new(good.clone(), vec![b'x'; MAX_SIGNATURE_BYTES + 1]);
    let cases: Vec<(&str, Offer, &str)> = vec![
        (
            "signed by another key",
            signed(&other, good.clone()),
            "signature refused",
        ),
        ("legacy signature", legacy, "signature refused"),
        (
            "manifest altered after signing",
            tampered,
            "signature refused",
        ),
        (
            "garbage signature",
            Offer::new(good, b"nope".to_vec()),
            "signature refused",
        ),
        ("oversize manifest", oversize, "manifest too large"),
        ("oversize signature", oversize_sig, "signature too large"),
        ("same version", rig.offer("1.0.0", 7), "version not newer"),
        ("older version", rig.offer("0.9.0", 7), "version not newer"),
        (
            "wrong target",
            signed(
                &rig.signer,
                manifest("1.1.0", 7, "other-target", &rig.archive),
            ),
            "no entry for this target",
        ),
        (
            "protocol too new",
            signed(
                &rig.signer,
                String::from_utf8(manifest("1.1.0", 7, TARGET, &rig.archive))
                    .unwrap()
                    .replace("\"min_protocol\":1", "\"min_protocol\":99")
                    .into_bytes(),
            ),
            "protocol too new",
        ),
    ];
    let before = rig.snapshot();
    let mut driver = rig.driver(false);
    for (name, offer, reason) in cases {
        let outcome = driver.handle(&offer).await;
        assert_eq!(outcome, DriverOutcome::Refused(reason), "{name}");
        assert_eq!(rig.snapshot(), before, "{name}");
        assert_eq!(rig.current(), "1.0.0", "{name}");
        assert!(!rig.raised().await, "{name}");
        assert!(!rig.wiring.gate.is_paused(), "{name}");
    }
    assert_eq!(rig.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_replayed_seq_is_refused_after_a_good_update() {
    let rig = rig();
    let mut driver = rig.driver(false);
    assert_eq!(
        driver.handle(&rig.offer("1.1.0", 7)).await,
        DriverOutcome::Restarting
    );
    let after = rig.snapshot();
    let mut restarted = rig.driver(false);
    assert_eq!(
        restarted.handle(&rig.offer("1.2.0", 7)).await,
        DriverOutcome::Refused("seq not newer")
    );
    assert_eq!(rig.snapshot(), after);
}

#[tokio::test(start_paused = true)]
async fn a_running_job_blocks_the_swap_until_the_box_is_idle() {
    let rig = rig();
    rig.wiring.tracker.begin("job-a");
    let mut driver = rig.driver(false);
    let offer = rig.offer("1.1.0", 7);
    let task = tokio::spawn(async move { driver.handle(&offer).await });
    while !rig.wiring.gate.is_paused() {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(CAP / 2).await;
    assert!(!task.is_finished());
    assert_eq!(rig.current(), "1.0.0");
    assert!(!rig.raised().await);
    rig.wiring.tracker.end("job-a");
    tokio::time::sleep(POLL * 2).await;
    assert_eq!(task.await.unwrap(), DriverOutcome::Restarting);
    assert_eq!(rig.current(), "1.1.0");
    assert!(rig.raised().await);
}

#[tokio::test(start_paused = true)]
async fn a_box_that_never_goes_idle_keeps_current_and_drops_the_staged_copy() {
    let rig = rig();
    rig.wiring.tracker.begin("job-a");
    let mut driver = rig.driver(false);
    let outcome = driver.handle(&rig.offer("1.1.0", 7)).await;
    assert_eq!(
        outcome,
        DriverOutcome::Failed("box did not go idle in time")
    );
    assert_eq!(rig.current(), "1.0.0");
    assert!(!rig.root.join("1.1.0").exists());
    assert!(!rig.wiring.gate.is_paused());
    assert!(!rig.raised().await);
    assert_eq!(SeqStore::new(&rig.root).load().unwrap(), 0);
}

#[tokio::test]
async fn an_identical_offer_is_handled_once_and_a_version_has_a_capped_number_of_attempts() {
    let rig = rig();
    let mut driver = rig.driver(true);
    let before = rig.snapshot();
    let first = rig.offer("1.1.0", 7);
    assert_eq!(
        driver.handle(&first).await,
        DriverOutcome::Failed("download failed")
    );
    assert_eq!(driver.handle(&first).await, DriverOutcome::Unchanged);
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
    for seq in 8..=u64::from(MAX_ATTEMPTS_PER_VERSION) + 8 {
        let tries = rig.calls.load(Ordering::SeqCst);
        let outcome = driver.handle(&rig.offer("1.1.0", seq)).await;
        if tries < MAX_ATTEMPTS_PER_VERSION as usize {
            assert_eq!(outcome, DriverOutcome::Failed("download failed"));
        } else {
            assert_eq!(
                outcome,
                DriverOutcome::Failed("attempts for this version are used up")
            );
        }
    }
    assert_eq!(
        rig.calls.load(Ordering::SeqCst),
        MAX_ATTEMPTS_PER_VERSION as usize
    );
    assert_eq!(rig.current(), "1.0.0");
    assert_eq!(rig.snapshot(), before);
}

#[tokio::test]
async fn a_stage_error_discards_the_version_directory() {
    let rig = rig();
    let mut driver = rig.driver(false);
    let before = rig.snapshot();
    let json = String::from_utf8(manifest("1.1.0", 7, TARGET, &rig.archive))
        .unwrap()
        .replace(&sha_hex(&rig.archive), &sha_hex(b"other bytes"));
    let offer = signed(&rig.signer, json.into_bytes());
    assert_eq!(
        driver.handle(&offer).await,
        DriverOutcome::Failed("archive hash mismatch")
    );
    assert_eq!(rig.snapshot(), before);
}

#[tokio::test]
async fn a_second_signed_offer_after_the_restart_signal_applies_nothing() {
    let rig = rig();
    let mut driver = rig.driver(false);
    assert_eq!(
        driver.handle(&rig.offer("1.1.0", 7)).await,
        DriverOutcome::Restarting
    );
    let after_first = rig.snapshot();
    let second = driver.handle(&rig.offer("1.2.0", 8)).await;
    assert_eq!(second, DriverOutcome::Refused("restart pending"));
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
    assert_eq!(rig.current(), "1.1.0");
    assert_eq!(
        fs::read_link(rig.root.join("previous")).unwrap(),
        Path::new("1.0.0")
    );
    assert_eq!(rig.snapshot(), after_first);
    assert_eq!(SeqStore::new(&rig.root).load().unwrap(), 7);
}

fn reply_for(offer: &Offer) -> HeartbeatReply {
    let (manifest, signature) = offer.parts();
    HeartbeatReply {
        next_in_s: 30,
        update_manifest: Some(manifest.to_vec()),
        update_signature: Some(signature.to_vec()),
    }
}

#[tokio::test]
async fn the_driver_loop_ignores_offers_after_the_restart_signal() {
    let rig = rig();
    let (sink, task) = rig.driver(false).spawn();
    sink.offer(&reply_for(&rig.offer("1.1.0", 7)));
    tokio::time::timeout(WIDE, rig.restart.requested())
        .await
        .unwrap();
    sink.offer(&reply_for(&rig.offer("1.2.0", 8)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!task.is_finished());
    assert!(rig.wiring.gate.is_paused());
    assert_eq!(rig.calls.load(Ordering::SeqCst), 1);
    assert_eq!(rig.current(), "1.1.0");
}

#[tokio::test]
async fn a_swap_failure_logs_a_closed_reason_with_no_path() {
    let rig = rig();
    let capture = Capture(Arc::default());
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish(),
    );
    let staged = rig.root.join("1.1.0");
    fs::create_dir(&staged).unwrap();
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o777)).unwrap();
    let updater = Updater::new(
        DrainController::new(rig.wiring.gate.clone(), CAP, POLL),
        rig.wiring.tracker.clone(),
        Swapper::new(&rig.root),
        rig.restart.clone(),
    );
    let outcome = updater.apply(&Version::new("1.1.0").unwrap()).await;
    assert_eq!(outcome, fleetd::update::ApplyOutcome::SwapFailed);
    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("update swap failed"), "{text}");
    assert!(text.contains("directory unsafe"), "{text}");
    assert!(!text.contains(rig.root.to_str().unwrap()), "{text}");
    assert!(!text.contains("1.1.0"), "{text}");
}

#[tokio::test]
async fn a_hash_mismatch_installs_nothing() {
    let rig = rig();
    let mut driver = rig.driver(false);
    let json = String::from_utf8(manifest("1.1.0", 7, TARGET, &rig.archive))
        .unwrap()
        .replace(&sha_hex(&rig.archive), &sha_hex(b"other bytes"));
    let offer = signed(&rig.signer, json.into_bytes());
    assert_eq!(
        driver.handle(&offer).await,
        DriverOutcome::Failed("archive hash mismatch")
    );
    assert_eq!(rig.current(), "1.0.0");
    assert!(!rig.root.join("1.1.0/fleetd").exists());
    assert!(!rig.raised().await);
}

#[test]
fn the_sink_keeps_the_latest_offer_and_ignores_unusable_replies() {
    let (sink, rx) = OfferSink::channel();
    let reply = |manifest: Option<&[u8]>, signature: Option<&[u8]>| HeartbeatReply {
        update_manifest: manifest.map(<[u8]>::to_vec),
        update_signature: signature.map(<[u8]>::to_vec),
        ..HeartbeatReply::default()
    };
    sink.offer(&reply(None, None));
    sink.offer(&reply(Some(b"m"), None));
    sink.offer(&reply(None, Some(b"s")));
    sink.offer(&reply(
        Some(&vec![b'm'; MAX_MANIFEST_BYTES + 1]),
        Some(b"s"),
    ));
    assert!(!rx.has_changed().unwrap());
    sink.offer(&reply(Some(b"a"), Some(b"s")));
    sink.offer(&reply(Some(b"b"), Some(b"s")));
    assert!(rx.has_changed().unwrap());
    assert_eq!(
        rx.borrow().clone(),
        Some(Offer::new(b"b".to_vec(), b"s".to_vec()))
    );
    let mut rx = rx;
    rx.borrow_and_update();
    sink.offer(&reply(Some(b"b"), Some(b"s")));
    assert!(!rx.has_changed().unwrap());
}

#[derive(Clone)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for Capture {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

fn hosts() -> Vec<HostPattern> {
    vec![HostPattern::parse("github.com").unwrap()]
}

#[tokio::test]
async fn a_missing_explicit_or_unsafe_trust_root_disables_updating_with_one_warning() {
    let rig = rig();
    let capture = Capture(Arc::default());
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish(),
    );
    let before = rig.snapshot();
    let missing = rig.root.join("absent.pub");
    assert!(
        start_production(
            &missing,
            TrustSource::Explicit,
            &rig.root,
            hosts(),
            &rig.wiring
        )
        .is_none()
    );
    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.matches("self-update disabled").count(), 1, "{text}");
    assert_eq!(text.matches("WARN").count(), 1, "{text}");
    assert!(!text.contains(missing.to_str().unwrap()), "{text}");
    assert_eq!(rig.snapshot(), before);
    let loose = rig.root.join("loose.pub");
    fs::write(&loose, rig.signer.public_text()).unwrap();
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(
        start_production(
            &loose,
            TrustSource::Default,
            &rig.root,
            hosts(),
            &rig.wiring
        )
        .is_none()
    );
    let mut with_loose = before;
    with_loose.push(("loose.pub".to_owned(), "100666".to_owned()));
    with_loose.sort();
    assert_eq!(rig.snapshot(), with_loose);
}

#[tokio::test]
async fn a_bad_default_trust_file_disables_updating_and_never_uses_the_baked_key() {
    let rig = rig();
    let capture = Capture(Arc::default());
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish(),
    );
    let before = rig.snapshot();
    let garbage = rig.root.join("garbage.pub");
    fs::write(&garbage, "not a key\n").unwrap();
    fs::set_permissions(&garbage, fs::Permissions::from_mode(0o644)).unwrap();
    let mut with_garbage = before;
    with_garbage.push(("garbage.pub".to_owned(), "100644".to_owned()));
    with_garbage.sort();
    assert!(
        start_production(
            &garbage,
            TrustSource::Default,
            &rig.root,
            hosts(),
            &rig.wiring
        )
        .is_none()
    );
    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert_eq!(text.matches("self-update disabled").count(), 1, "{text}");
    assert_eq!(text.matches("baked key not used").count(), 1, "{text}");
    assert!(!text.contains("update trust root selected"), "{text}");
    assert_eq!(rig.snapshot(), with_garbage);
}

#[tokio::test]
async fn an_absent_default_trust_file_starts_the_driver_on_the_baked_key() {
    let rig = rig();
    let capture = Capture(Arc::default());
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::fmt()
            .with_writer(capture.clone())
            .with_ansi(false)
            .finish(),
    );
    let absent = rig.root.join("absent.pub");
    let (_sink, task) = start_production(
        &absent,
        TrustSource::Default,
        &rig.root,
        hosts(),
        &rig.wiring,
    )
    .unwrap();
    task.abort();
    let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("update trust root selected"), "{text}");
    assert!(text.contains("baked"), "{text}");
    assert!(!text.contains("self-update disabled"), "{text}");
}
