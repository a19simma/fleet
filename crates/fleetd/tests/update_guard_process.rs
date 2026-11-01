//! Runs `fleetd update-guard` as the unit's `ExecStartPre` does. Own test binary because it
//! spawns children.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

use tempfile::TempDir;

fn stage(root: &Path, name: &str) {
    let dir = root.join(name);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("fleetd"), b"bin").unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
}

fn guard(root: &Path) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_fleetd"))
        .arg("update-guard")
        .arg("--bin-root")
        .arg(root)
        .env_remove("FLEET_SERVER_URL")
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn the_guard_exits_zero_through_start_counting_and_a_rollback() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("bin");
    fs::create_dir(&root).unwrap();
    stage(&root, "1.0.0");
    stage(&root, "1.1.0");
    symlink("1.1.0", root.join("current")).unwrap();
    symlink("1.0.0", root.join("previous")).unwrap();
    for start in 1..=3 {
        let (ok, line) = guard(&root);
        assert!(ok, "{line}");
        assert!(line.contains(&format!("start {start} ")), "{line}");
    }
    let (ok, line) = guard(&root);
    assert!(ok, "{line}");
    assert!(line.contains("rolled back from 1.1.0 to 1.0.0"), "{line}");
    assert_eq!(
        fs::read_link(root.join("current")).unwrap(),
        Path::new("1.0.0")
    );
    assert_eq!(
        fs::read_to_string(root.join("bad_versions")).unwrap(),
        "1.1.0\n"
    );
}

#[test]
fn a_missing_bin_root_still_exits_zero() {
    let dir = TempDir::new().unwrap();
    let (ok, line) = guard(&dir.path().join("absent"));
    assert!(ok, "{line}");
}
