//! Unpack and atomic activation of a staged release: hostile archive entries, the size caps,
//! the `current` and `previous` symlinks, and the crash-safe ordering between them.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code asserts by panicking and indexes fixed-size headers"
)]

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use fleet_core::tools::Version;
use fleetd::update::{STAGED_FILE, SwapError, Swapper};
use tempfile::TempDir;

const BIN: &[u8] = b"\x7fELF fake fleetd";

fn header(name: &str, kind: u8, size: usize, link: &str) -> [u8; 512] {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..107].copy_from_slice(b"0000755");
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = kind;
    h[157..157 + link.len()].copy_from_slice(link.as_bytes());
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    h
}

struct Tar(Vec<u8>);

impl Tar {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn file(mut self, name: &str, data: &[u8]) -> Self {
        self.0
            .extend_from_slice(&header(name, b'0', data.len(), ""));
        self.0.extend_from_slice(data);
        self.0.resize(self.0.len().div_ceil(512) * 512, 0);
        self
    }

    fn entry(mut self, name: &str, kind: u8, link: &str) -> Self {
        self.0.extend_from_slice(&header(name, kind, 0, link));
        self
    }

    fn gz(mut self) -> Vec<u8> {
        self.0.extend_from_slice(&[0u8; 1024]);
        let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(&self.0).unwrap();
        enc.finish().unwrap()
    }
}

struct Rig {
    _tmp: TempDir,
    root: PathBuf,
}

impl Rig {
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("bin");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        Self { _tmp: tmp, root }
    }

    fn stage(&self, ver: &str, archive: &[u8]) {
        let dir = self.root.join(ver);
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let file = dir.join(STAGED_FILE);
        fs::write(&file, archive).unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn stage_ok(&self, ver: &str) {
        self.stage(ver, &Tar::new().file("fleetd-x/fleetd", BIN).gz());
    }

    fn target(&self, name: &str) -> Option<PathBuf> {
        fs::read_link(self.root.join(name)).ok()
    }
}

fn ver(s: &str) -> Version {
    Version::new(s).unwrap()
}

#[test]
fn unpack_writes_runnable_binary_and_opens_the_dir() {
    let rig = Rig::new();
    rig.stage_ok("1.2.3");
    let path = Swapper::new(&rig.root).unpack(&ver("1.2.3")).unwrap();
    assert_eq!(path, rig.root.join("1.2.3").join("fleetd"));
    assert_eq!(fs::read(&path).unwrap(), BIN);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o755);
    let dir = fs::metadata(rig.root.join("1.2.3")).unwrap();
    assert_eq!(dir.permissions().mode() & 0o7777, 0o755);
    let archive = fs::metadata(rig.root.join("1.2.3").join(STAGED_FILE)).unwrap();
    assert_eq!(archive.permissions().mode() & 0o7777, 0o700);
}

#[test]
fn unpack_is_idempotent() {
    let rig = Rig::new();
    rig.stage_ok("1.2.3");
    let swapper = Swapper::new(&rig.root);
    swapper.unpack(&ver("1.2.3")).unwrap();
    swapper.unpack(&ver("1.2.3")).unwrap();
}

#[test]
fn unpack_refuses_hostile_entries_and_leaves_no_binary() {
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("absolute", Tar::new().file("/etc/fleetd", BIN).gz()),
        ("dotdot", Tar::new().file("../fleetd", BIN).gz()),
        ("nested dotdot", Tar::new().file("a/../../fleetd", BIN).gz()),
        (
            "symlink",
            Tar::new().entry("fleetd", b'2', "/etc/passwd").gz(),
        ),
        (
            "symlink after binary",
            Tar::new().file("d/fleetd", BIN).entry("x", b'2', "y").gz(),
        ),
        (
            "hardlink",
            Tar::new().entry("fleetd", b'1', "/etc/passwd").gz(),
        ),
        ("device", Tar::new().entry("fleetd", b'3', "").gz()),
        ("fifo", Tar::new().entry("fleetd", b'6', "").gz()),
        ("pax header", Tar::new().entry("fleetd", b'x', "").gz()),
        ("no binary", Tar::new().file("README", b"hi").gz()),
        (
            "two binaries",
            Tar::new().file("a/fleetd", BIN).file("b/fleetd", BIN).gz(),
        ),
        ("not gzip", b"plain bytes".to_vec()),
        ("empty", Vec::new()),
    ];
    for (label, archive) in cases {
        let rig = Rig::new();
        rig.stage("1.0.0", &archive);
        let err = Swapper::new(&rig.root).unpack(&ver("1.0.0")).unwrap_err();
        assert!(
            matches!(err, SwapError::Archive(_) | SwapError::UnsafeEntry(_)),
            "{label}: {err}"
        );
        let names: Vec<_> = fs::read_dir(rig.root.join("1.0.0"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            names,
            vec![std::ffi::OsString::from(STAGED_FILE)],
            "{label}"
        );
    }
}

#[test]
fn unpack_refuses_corrupt_checksum() {
    let rig = Rig::new();
    let mut tar = Tar::new().file("fleetd", BIN);
    tar.0[0] = b'g';
    rig.stage("1.0.0", &tar.gz());
    let err = Swapper::new(&rig.root).unpack(&ver("1.0.0")).unwrap_err();
    assert!(matches!(err, SwapError::Archive(_)), "{err}");
}

#[test]
fn binary_cap_accepts_exact_and_refuses_one_over() {
    let data = vec![7u8; 4096];
    let rig = Rig::new();
    rig.stage("1.0.0", &Tar::new().file("fleetd", &data).gz());
    Swapper::new(&rig.root)
        .with_limits(4096, 1 << 20)
        .unpack(&ver("1.0.0"))
        .unwrap();

    let rig = Rig::new();
    rig.stage("1.0.0", &Tar::new().file("fleetd", &data).gz());
    let err = Swapper::new(&rig.root)
        .with_limits(4095, 1 << 20)
        .unpack(&ver("1.0.0"))
        .unwrap_err();
    assert!(matches!(err, SwapError::TooLarge), "{err}");
    assert!(!rig.root.join("1.0.0").join("fleetd").exists());
}

#[test]
fn unpacked_cap_counts_skipped_entries() {
    let rig = Rig::new();
    let filler = vec![0u8; 64 * 1024];
    rig.stage(
        "1.0.0",
        &Tar::new().file("junk", &filler).file("fleetd", BIN).gz(),
    );
    let err = Swapper::new(&rig.root)
        .with_limits(1 << 20, 32 * 1024)
        .unpack(&ver("1.0.0"))
        .unwrap_err();
    assert!(matches!(err, SwapError::TooLarge), "{err}");
    assert!(!rig.root.join("1.0.0").join("fleetd").exists());
}

#[test]
fn unpack_refuses_unsafe_dirs_and_archive() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    fs::set_permissions(rig.root.join("1.0.0"), fs::Permissions::from_mode(0o770)).unwrap();
    let err = Swapper::new(&rig.root).unpack(&ver("1.0.0")).unwrap_err();
    assert!(matches!(err, SwapError::UnsafeDir(_)), "{err}");

    let rig = Rig::new();
    fs::create_dir(rig.root.join("real")).unwrap();
    symlink(rig.root.join("real"), rig.root.join("1.0.0")).unwrap();
    let err = Swapper::new(&rig.root).unpack(&ver("1.0.0")).unwrap_err();
    assert!(matches!(err, SwapError::UnsafeDir(_)), "{err}");

    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    let archive = rig.root.join("1.0.0").join(STAGED_FILE);
    fs::remove_file(&archive).unwrap();
    symlink("/etc/hostname", &archive).unwrap();
    let err = Swapper::new(&rig.root).unpack(&ver("1.0.0")).unwrap_err();
    assert!(
        matches!(err, SwapError::Io(_) | SwapError::NotStaged),
        "{err}"
    );
}

#[test]
fn unpack_of_unstaged_version_fails() {
    let rig = Rig::new();
    let err = Swapper::new(&rig.root).unpack(&ver("1.0.0")).unwrap_err();
    assert!(matches!(err, SwapError::NotStaged), "{err}");
}

#[test]
fn first_install_has_no_previous() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    Swapper::new(&rig.root).swap(&ver("1.0.0")).unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.0.0")));
    assert_eq!(rig.target("previous"), None);
    assert_eq!(
        fs::read(rig.root.join("current").join("fleetd")).unwrap(),
        BIN
    );
}

#[test]
fn second_swap_keeps_old_as_previous() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    rig.stage_ok("1.1.0");
    rig.stage_ok("1.2.0");
    let swapper = Swapper::new(&rig.root);
    swapper.swap(&ver("1.0.0")).unwrap();
    swapper.swap(&ver("1.1.0")).unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.1.0")));
    assert_eq!(rig.target("previous"), Some(PathBuf::from("1.0.0")));
    swapper.swap(&ver("1.2.0")).unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.2.0")));
    assert_eq!(rig.target("previous"), Some(PathBuf::from("1.1.0")));
    let temps: Vec<_> = fs::read_dir(&rig.root)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with('.'))
        .collect();
    assert!(temps.is_empty(), "{temps:?}");
}

#[test]
fn swap_to_the_running_version_is_refused() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    let swapper = Swapper::new(&rig.root);
    swapper.swap(&ver("1.0.0")).unwrap();
    let err = swapper.swap(&ver("1.0.0")).unwrap_err();
    assert!(matches!(err, SwapError::AlreadyCurrent), "{err}");
    assert_eq!(rig.target("previous"), None);
}

#[test]
fn failure_between_previous_and_current_keeps_current() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    rig.stage_ok("1.1.0");
    let swapper = Swapper::new(&rig.root);
    swapper.swap(&ver("1.0.0")).unwrap();
    swapper.unpack(&ver("1.1.0")).unwrap();
    let err = swapper
        .activate_with(&ver("1.1.0"), || Err(io::Error::other("injected crash")))
        .unwrap_err();
    assert!(matches!(err, SwapError::Io(_)), "{err}");
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.0.0")));
    assert_eq!(rig.target("previous"), Some(PathBuf::from("1.0.0")));
    assert!(rig.root.join("current").join("fleetd").exists());
}

#[test]
fn previous_is_set_before_current_flips() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    rig.stage_ok("1.1.0");
    let swapper = Swapper::new(&rig.root);
    swapper.swap(&ver("1.0.0")).unwrap();
    swapper.unpack(&ver("1.1.0")).unwrap();
    let root = rig.root.clone();
    swapper
        .activate_with(&ver("1.1.0"), || {
            assert_eq!(
                fs::read_link(root.join("current")).unwrap(),
                Path::new("1.0.0")
            );
            assert_eq!(
                fs::read_link(root.join("previous")).unwrap(),
                Path::new("1.0.0")
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.1.0")));
}

#[test]
fn dangling_current_is_replaced_and_not_kept_as_previous() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    rig.stage_ok("1.1.0");
    let swapper = Swapper::new(&rig.root);
    swapper.swap(&ver("1.0.0")).unwrap();
    fs::remove_file(rig.root.join("1.0.0").join("fleetd")).unwrap();
    swapper.swap(&ver("1.1.0")).unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.1.0")));
    assert_eq!(rig.target("previous"), None);
}

#[test]
fn dangling_current_keeps_an_older_good_previous() {
    let rig = Rig::new();
    for v in ["1.0.0", "1.1.0", "1.2.0"] {
        rig.stage_ok(v);
    }
    let swapper = Swapper::new(&rig.root);
    swapper.swap(&ver("1.0.0")).unwrap();
    swapper.swap(&ver("1.1.0")).unwrap();
    fs::remove_file(rig.root.join("1.1.0").join("fleetd")).unwrap();
    swapper.swap(&ver("1.2.0")).unwrap();
    assert_eq!(rig.target("previous"), Some(PathBuf::from("1.0.0")));
}

#[test]
fn current_that_is_not_a_symlink_is_refused() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    fs::create_dir(rig.root.join("current")).unwrap();
    let err = Swapper::new(&rig.root).swap(&ver("1.0.0")).unwrap_err();
    assert!(matches!(err, SwapError::UnsafeLink(_)), "{err}");
    assert!(rig.root.join("current").is_dir());
}

#[test]
fn seeded_current_is_replaced_without_a_previous() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    symlink("/usr/local/bin", rig.root.join("current")).unwrap();
    Swapper::new(&rig.root).swap(&ver("1.0.0")).unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.0.0")));
    assert_eq!(rig.target("previous"), None);
}

#[test]
fn stale_temp_links_are_replaced() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    symlink("junk", rig.root.join(".current.tmp")).unwrap();
    symlink("junk", rig.root.join(".previous.tmp")).unwrap();
    Swapper::new(&rig.root).swap(&ver("1.0.0")).unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.0.0")));
}

#[test]
fn hostile_versions_are_refused() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    let swapper = Swapper::new(&rig.root);
    for bad in ["..", ".", "1.0.0/../x", "a/b", "1.0.0\n", "", "1\\0"] {
        if let Ok(version) = Version::new(bad) {
            let err = swapper.swap(&version).unwrap_err();
            assert!(matches!(err, SwapError::Version), "{bad:?}: {err}");
        }
    }
    assert_eq!(rig.target("current"), None);
}

#[test]
fn activate_requires_an_unpacked_binary() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    let err = Swapper::new(&rig.root)
        .activate_with(&ver("1.0.0"), || Ok(()))
        .unwrap_err();
    assert!(matches!(err, SwapError::NotStaged), "{err}");
    assert_eq!(rig.target("current"), None);
}

#[test]
fn works_under_a_relative_state_dir() {
    let rig = Rig::new();
    rig.stage_ok("1.0.0");
    rig.stage_ok("1.1.0");
    let cwd = std::env::current_dir().unwrap();
    let rel = pathdiff(&rig.root, &cwd);
    let swapper = Swapper::new(&rel);
    swapper.swap(&ver("1.0.0")).unwrap();
    swapper.swap(&ver("1.1.0")).unwrap();
    assert_eq!(rig.target("current"), Some(PathBuf::from("1.1.0")));
    assert_eq!(rig.target("previous"), Some(PathBuf::from("1.0.0")));
    assert_eq!(
        fs::read(rig.root.join("current").join("fleetd")).unwrap(),
        BIN
    );
}

fn pathdiff(target: &Path, base: &Path) -> PathBuf {
    let t: Vec<_> = target.components().collect();
    let b: Vec<_> = base.components().collect();
    let common = t.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut out = PathBuf::new();
    for _ in common..b.len() {
        out.push("..");
    }
    for c in &t[common..] {
        out.push(c);
    }
    out
}
