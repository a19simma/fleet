//! A release archive made by the repack script unpacks with fleetd's own unpacker, and
//! `host_target` names the target the manifest carries.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "test code asserts by panicking and indexes fixed-size headers"
)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use flate2::Compression;
use flate2::write::GzEncoder;
use fleet_core::tools::Version;
use fleetd::update::{STAGED_FILE, SwapError, Swapper, host_target, target_name};
use tempfile::TempDir;

const BIN: &[u8] = b"\x7fELF fixture fleetd release binary";

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/scripts/repack_archive.py")
}

fn run_script(args: &[&str]) -> std::process::Output {
    Command::new("python3")
        .arg(script())
        .args(args)
        .output()
        .unwrap()
}

fn stage_and_unpack(archive: &[u8]) -> (TempDir, Result<PathBuf, SwapError>) {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path().join("bin");
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
    let dir = root.join("1.2.3");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    let file = dir.join(STAGED_FILE);
    fs::write(&file, archive).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o700)).unwrap();
    let got = Swapper::new(&root).unpack(&Version::new("1.2.3").unwrap());
    (tmp, got)
}

fn tar_entry(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..107].copy_from_slice(b"0000755");
    h[108..115].copy_from_slice(b"0000000");
    h[116..123].copy_from_slice(b"0000000");
    h[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    h[136..147].copy_from_slice(b"00000000000");
    h[156] = kind;
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
    h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    let mut out = h.to_vec();
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

fn tar_file(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = tar_entry(name, b'0', data);
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn gz(raw: &[u8]) -> Vec<u8> {
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(raw).unwrap();
    enc.finish().unwrap()
}

#[test]
fn repacked_binary_unpacks_with_the_real_unpacker() {
    let tmp = TempDir::new().unwrap();
    let bin = tmp.path().join("fleetd-built");
    fs::write(&bin, BIN).unwrap();
    let out = tmp.path().join("fleetd-x86_64-unknown-linux-musl.tar.gz");
    let run = run_script(&[
        "--binary",
        bin.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let (_keep, got) = stage_and_unpack(&fs::read(&out).unwrap());
    let path = got.unwrap();
    assert_eq!(fs::read(&path).unwrap(), BIN);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o755
    );
}

#[test]
fn repacked_dist_archive_with_a_pax_header_unpacks_though_the_source_does_not() {
    let tmp = TempDir::new().unwrap();
    let mut raw = tar_entry("PaxHeaders/fleetd", b'x', b"13 mtime=1.5\n");
    raw.extend_from_slice(&tar_file("fleetd-x86_64-unknown-linux-musl/fleetd", BIN));
    let dist = gz(&raw);
    let (_k, refused) = stage_and_unpack(&dist);
    assert!(matches!(refused, Err(SwapError::Archive(_))), "{refused:?}");
    let src = tmp.path().join("dist.tar.gz");
    fs::write(&src, &dist).unwrap();
    let out = tmp.path().join("out.tar.gz");
    let run = run_script(&[
        "--from",
        src.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(
        run.status.success(),
        "{}",
        String::from_utf8_lossy(&run.stderr)
    );
    let repacked = fs::read(&out).unwrap();
    let (_keep, got) = stage_and_unpack(&repacked);
    assert_eq!(fs::read(got.unwrap()).unwrap(), BIN);
}

#[test]
fn the_script_refuses_what_the_unpacker_would_refuse() {
    let tmp = TempDir::new().unwrap();
    let src = tmp.path().join("dist.tar.gz");
    let mut two = tar_file("a/fleetd", BIN);
    two.truncate(two.len() - 1024);
    two.extend_from_slice(&tar_file("b/fleetd", BIN));
    fs::write(&src, gz(&two)).unwrap();
    let out = tmp.path().join("out.tar.gz");
    let run = run_script(&[
        "--from",
        src.to_str().unwrap(),
        "--out",
        out.to_str().unwrap(),
    ]);
    assert!(!run.status.success());
    assert!(!out.exists());
}

#[test]
fn target_names_match_the_manifest_names() {
    assert_eq!(target_name("x86_64", "musl"), "x86_64-unknown-linux-musl");
    assert_eq!(target_name("aarch64", "musl"), "aarch64-unknown-linux-musl");
    assert_eq!(target_name("x86_64", "gnu"), "x86_64-unknown-linux-gnu");
    assert_eq!(target_name("aarch64", ""), "aarch64-unknown-linux-gnu");
}

#[test]
fn host_target_follows_the_build_environment() {
    let env = if cfg!(target_env = "musl") {
        "musl"
    } else {
        "gnu"
    };
    assert_eq!(host_target(), target_name(std::env::consts::ARCH, env));
}
