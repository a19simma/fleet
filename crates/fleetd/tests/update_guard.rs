//! Rollback guard: start counting, the health marker, the swap back to `previous`, and the
//! bad-version record, over a real temp dir and the real `Swapper` rename path.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use fleet_core::tools::Version;
use fleetd::update::{
    BAD_VERSIONS_FILE, Guard, GuardOutcome, HEALTH_FILE, MAX_UNHEALTHY_STARTS, STARTS_FILE,
    is_bad_version, write_health_marker,
};
use tempfile::TempDir;

const SHRUNK: u32 = 2;

struct Rig {
    _dir: TempDir,
    root: PathBuf,
}

fn rig() -> Rig {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("bin");
    fs::create_dir(&root).unwrap();
    Rig { _dir: dir, root }
}

fn stage(root: &Path, version: &str) {
    let dir = root.join(version);
    fs::create_dir(&dir).unwrap();
    fs::write(dir.join("fleetd"), b"bin").unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
}

fn link(root: &Path, name: &str, target: &str) {
    let _ = fs::remove_file(root.join(name));
    symlink(target, root.join(name)).unwrap();
}

fn target(root: &Path, name: &str) -> Option<String> {
    fs::read_link(root.join(name))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

fn two_versions() -> Rig {
    let rig = rig();
    stage(&rig.root, "1.0.0");
    stage(&rig.root, "1.1.0");
    link(&rig.root, "current", "1.1.0");
    link(&rig.root, "previous", "1.0.0");
    rig
}

fn version(raw: &str) -> Version {
    Version::new(raw).unwrap()
}

fn guard(rig: &Rig) -> Guard {
    Guard::new(&rig.root).with_limit(SHRUNK)
}

fn starts(rig: &Rig) -> Option<String> {
    fs::read_to_string(rig.root.join(STARTS_FILE)).ok()
}

#[test]
fn the_default_limit_is_a_small_named_constant() {
    assert_eq!(MAX_UNHEALTHY_STARTS, 3);
    assert_eq!(Guard::new("x").limit(), MAX_UNHEALTHY_STARTS);
}

#[test]
fn no_current_link_is_a_first_boot_and_writes_nothing() {
    let rig = rig();
    assert_eq!(guard(&rig).run(), GuardOutcome::NoCurrent);
    assert_eq!(fs::read_dir(&rig.root).unwrap().count(), 0);
}

#[test]
fn a_current_link_to_the_baked_binary_is_ignored() {
    let rig = rig();
    link(&rig.root, "current", "/usr/local/bin");
    assert_eq!(guard(&rig).run(), GuardOutcome::NoCurrent);
    assert_eq!(starts(&rig), None);
}

#[test]
fn a_marker_for_current_resets_the_counter_and_keeps_the_links() {
    let rig = two_versions();
    assert_eq!(guard(&rig).run(), GuardOutcome::Counted(1));
    write_health_marker(&rig.root, &version("1.1.0")).unwrap();
    assert_eq!(guard(&rig).run(), GuardOutcome::Healthy);
    assert_eq!(starts(&rig), None);
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.1.0"));
}

#[test]
fn a_marker_for_another_version_counts_as_missing() {
    let rig = two_versions();
    write_health_marker(&rig.root, &version("1.0.0")).unwrap();
    assert_eq!(guard(&rig).run(), GuardOutcome::Counted(1));
}

#[test]
fn starts_under_the_limit_count_and_leave_current_alone() {
    let rig = two_versions();
    assert_eq!(guard(&rig).run(), GuardOutcome::Counted(1));
    assert_eq!(guard(&rig).run(), GuardOutcome::Counted(2));
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.1.0"));
    assert!(!is_bad_version(&rig.root, &version("1.1.0")));
}

#[test]
fn the_start_after_the_limit_rolls_back_and_records_the_bad_version() {
    let rig = two_versions();
    let _ = guard(&rig).run();
    let _ = guard(&rig).run();
    let outcome = guard(&rig).run();
    assert_eq!(
        outcome,
        GuardOutcome::RolledBack {
            from: "1.1.0".to_owned(),
            to: "1.0.0".to_owned()
        }
    );
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.0.0"));
    assert_eq!(target(&rig.root, "previous"), None);
    assert!(is_bad_version(&rig.root, &version("1.1.0")));
    assert!(!is_bad_version(&rig.root, &version("1.0.0")));
    assert_eq!(starts(&rig), None);
}

#[test]
fn after_a_rollback_the_restored_version_is_healthy_and_never_rolls_forward() {
    let rig = two_versions();
    for _ in 0..3 {
        let _ = guard(&rig).run();
    }
    assert_eq!(guard(&rig).run(), GuardOutcome::Healthy);
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.0.0"));
    assert!(rig.root.join(HEALTH_FILE).exists());
}

#[test]
fn a_counter_over_the_limit_rolls_back_too() {
    let rig = two_versions();
    fs::write(rig.root.join(STARTS_FILE), "1.1.0\n9\n").unwrap();
    assert!(matches!(guard(&rig).run(), GuardOutcome::RolledBack { .. }));
}

#[test]
fn a_counter_just_under_the_limit_still_starts_the_new_version() {
    let rig = two_versions();
    fs::write(
        rig.root.join(STARTS_FILE),
        format!("1.1.0\n{}\n", SHRUNK - 1),
    )
    .unwrap();
    assert_eq!(guard(&rig).run(), GuardOutcome::Counted(SHRUNK));
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.1.0"));
}

#[test]
fn a_counter_for_an_older_version_restarts_at_one() {
    let rig = two_versions();
    fs::write(rig.root.join(STARTS_FILE), "0.9.0\n9\n").unwrap();
    assert_eq!(guard(&rig).run(), GuardOutcome::Counted(1));
}

#[test]
fn a_corrupt_counter_rolls_back_the_stricter_way() {
    for body in [
        &b"garbage"[..],
        b"",
        b"1.1.0\nx\n",
        b"1.1.0\n-1\n",
        b"\xff\xfe\n3\n",
        b"1.1.0\n99999999999999999999\n",
    ] {
        let rig = two_versions();
        fs::write(rig.root.join(STARTS_FILE), body).unwrap();
        assert!(
            matches!(guard(&rig).run(), GuardOutcome::RolledBack { .. }),
            "{body:?}"
        );
    }
}

#[test]
fn an_oversized_counter_rolls_back() {
    let rig = two_versions();
    fs::write(rig.root.join(STARTS_FILE), vec![b'1'; 4096]).unwrap();
    assert!(matches!(guard(&rig).run(), GuardOutcome::RolledBack { .. }));
}

#[test]
fn a_counter_that_is_a_symlink_counts_as_corrupt() {
    let rig = two_versions();
    fs::write(rig.root.join("elsewhere"), "1.1.0\n0\n").unwrap();
    symlink("elsewhere", rig.root.join(STARTS_FILE)).unwrap();
    assert!(matches!(guard(&rig).run(), GuardOutcome::RolledBack { .. }));
}

#[test]
fn a_missing_previous_starts_the_daemon_and_keeps_current() {
    let rig = two_versions();
    fs::remove_file(rig.root.join("previous")).unwrap();
    for _ in 0..SHRUNK {
        let _ = guard(&rig).run();
    }
    assert_eq!(guard(&rig).run(), GuardOutcome::NoPrevious);
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.1.0"));
    assert!(!is_bad_version(&rig.root, &version("1.1.0")));
}

#[test]
fn a_dangling_previous_starts_the_daemon_and_keeps_current() {
    let rig = two_versions();
    fs::remove_dir_all(rig.root.join("1.0.0")).unwrap();
    for _ in 0..SHRUNK {
        let _ = guard(&rig).run();
    }
    assert!(matches!(guard(&rig).run(), GuardOutcome::Failed(_)));
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.1.0"));
}

#[test]
fn a_previous_that_is_a_known_bad_version_is_never_restored() {
    let rig = two_versions();
    fs::write(rig.root.join(BAD_VERSIONS_FILE), "1.0.0\n").unwrap();
    for _ in 0..SHRUNK {
        let _ = guard(&rig).run();
    }
    assert_eq!(guard(&rig).run(), GuardOutcome::PreviousRefused);
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.1.0"));
}

#[test]
fn a_version_already_in_the_bad_file_is_not_written_twice() {
    let rig = two_versions();
    fs::write(rig.root.join(BAD_VERSIONS_FILE), "1.1.0\n").unwrap();
    for _ in 0..=SHRUNK {
        let _ = guard(&rig).run();
    }
    let body = fs::read_to_string(rig.root.join(BAD_VERSIONS_FILE)).unwrap();
    assert_eq!(body, "1.1.0\n");
    assert_eq!(target(&rig.root, "current").as_deref(), Some("1.0.0"));
}

#[test]
fn bad_versions_accumulate_across_rollbacks() {
    let rig = two_versions();
    for _ in 0..=SHRUNK {
        let _ = guard(&rig).run();
    }
    stage(&rig.root, "1.2.0");
    link(&rig.root, "previous", "1.0.0");
    link(&rig.root, "current", "1.2.0");
    for _ in 0..=SHRUNK {
        let _ = guard(&rig).run();
    }
    assert!(is_bad_version(&rig.root, &version("1.1.0")));
    assert!(is_bad_version(&rig.root, &version("1.2.0")));
}

#[test]
fn a_hostile_bad_file_line_never_matches_a_version() {
    let rig = two_versions();
    fs::write(
        rig.root.join(BAD_VERSIONS_FILE),
        "../1.1.0\n 1.1.0\n1.1.0 \n\n",
    )
    .unwrap();
    assert!(!is_bad_version(&rig.root, &version("1.1.0")));
}

#[test]
fn counter_and_marker_writes_leave_no_temp_file_and_no_loose_mode() {
    let rig = two_versions();
    let _ = guard(&rig).run();
    write_health_marker(&rig.root, &version("1.1.0")).unwrap();
    let mut names: Vec<String> = fs::read_dir(&rig.root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "1.0.0",
            "1.1.0",
            "current",
            HEALTH_FILE,
            "previous",
            STARTS_FILE
        ]
    );
    let mode = fs::metadata(rig.root.join(HEALTH_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o022, 0);
}

#[test]
fn a_stale_counter_temp_file_does_not_block_a_write() {
    let rig = two_versions();
    fs::write(rig.root.join(".starts.tmp"), "junk").unwrap();
    assert_eq!(guard(&rig).run(), GuardOutcome::Counted(1));
}

#[test]
fn a_relative_state_dir_works() {
    let dir = TempDir::new().unwrap();
    let work = dir.path().join("work");
    fs::create_dir(&work).unwrap();
    let rel = Path::new("rel-bin");
    let root = work.join(rel);
    fs::create_dir(&root).unwrap();
    stage(&root, "1.0.0");
    stage(&root, "1.1.0");
    link(&root, "current", "1.1.0");
    link(&root, "previous", "1.0.0");
    let _cwd = CwdGuard::enter(&work);
    let guard = Guard::new(rel).with_limit(1);
    assert_eq!(guard.run(), GuardOutcome::Counted(1));
    assert!(matches!(guard.run(), GuardOutcome::RolledBack { .. }));
    assert_eq!(target(&root, "current").as_deref(), Some("1.0.0"));
}

struct CwdGuard(PathBuf);

impl CwdGuard {
    fn enter(dir: &Path) -> Self {
        let old = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        Self(old)
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

#[test]
fn a_bad_file_over_its_cap_lists_nothing_and_one_just_under_still_does() {
    let rig = two_versions();
    let mut body = String::from("1.1.0\n");
    body.push_str(&"\n".repeat(8192 - body.len()));
    fs::write(rig.root.join(BAD_VERSIONS_FILE), &body).unwrap();
    assert!(is_bad_version(&rig.root, &version("1.1.0")));
    body.push('\n');
    fs::write(rig.root.join(BAD_VERSIONS_FILE), &body).unwrap();
    assert!(!is_bad_version(&rig.root, &version("1.1.0")));
}
