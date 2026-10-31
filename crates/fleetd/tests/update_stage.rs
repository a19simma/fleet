//! Download and stage of a verified release: the host allow-list, the size caps, the hash
//! check and the file modes, against a fake fetcher.

#![expect(
    clippy::unwrap_used,
    clippy::unwrap_in_result,
    clippy::format_collect,
    reason = "test code asserts by panicking, and the hostile table is long"
)]

use std::fs;
use std::io::{self, Cursor, Read};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::sync::Mutex;

use fleet_core::tools::Version;
use fleetd::fetch_policy::HostPattern;
use fleetd::update::{
    ArchiveFetcher, ArchiveResponse, MAX_ARCHIVE_BYTES, StageError, Stager, Target,
    validate_stage_version,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const URL: &str = "https://github.com/owner/repo/releases/download/v1/fleetd.tar.gz";

struct Fake {
    final_url: Mutex<Option<String>>,
    body: Vec<u8>,
    seen: Mutex<Vec<String>>,
}

impl Fake {
    fn new(body: &[u8]) -> Self {
        Self {
            final_url: Mutex::new(None),
            body: body.to_vec(),
            seen: Mutex::new(Vec::new()),
        }
    }

    fn redirecting(body: &[u8], to: &str) -> Self {
        let fake = Self::new(body);
        *fake.final_url.lock().unwrap() = Some(to.to_owned());
        fake
    }
}

impl ArchiveFetcher for Fake {
    fn get(&self, url: &str) -> io::Result<ArchiveResponse> {
        self.seen.lock().unwrap().push(url.to_owned());
        let final_url = self
            .final_url
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| url.to_owned());
        Ok(ArchiveResponse {
            final_url,
            body: Box::new(Cursor::new(self.body.clone())),
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn target(body: &[u8], url: Option<&str>) -> Target {
    Target {
        sha256: hex(body),
        size: body.len() as u64,
        url: url.map(str::to_owned),
    }
}

fn allow() -> Vec<HostPattern> {
    vec![
        HostPattern::parse("github.com").unwrap(),
        HostPattern::parse("*.githubusercontent.com").unwrap(),
    ]
}

fn version() -> Version {
    Version::new("1.2.3").unwrap()
}

fn root() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    (dir, bin)
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[test]
fn a_good_download_is_staged_at_0700_in_a_0700_dir() {
    let (_guard, bin) = root();
    let body = b"release bytes";
    let fake = Fake::new(body);
    let stager = Stager::new(&bin, allow(), &fake);
    let path = stager.stage(&version(), &target(body, Some(URL))).unwrap();
    assert_eq!(path.parent().unwrap(), bin.join("1.2.3"));
    assert_eq!(fs::read(&path).unwrap(), body);
    assert_eq!(mode(&path), 0o700);
    assert_eq!(mode(&bin.join("1.2.3")), 0o700);
    assert_eq!(entries(&bin.join("1.2.3")).len(), 1);
    assert_eq!(fake.seen.lock().unwrap().as_slice(), [URL]);
}

#[test]
fn a_sha_mismatch_leaves_nothing_behind() {
    let (_guard, bin) = root();
    let body = b"release bytes";
    let mut t = target(body, Some(URL));
    t.sha256 = hex(b"other");
    let fake = Fake::new(body);
    let err = Stager::new(&bin, allow(), &fake)
        .stage(&version(), &t)
        .unwrap_err();
    assert!(matches!(err, StageError::HashMismatch), "{err}");
    assert_eq!(entries(&bin.join("1.2.3")), Vec::<String>::new());
}

#[test]
fn a_body_one_byte_over_the_manifest_size_is_refused() {
    let (_guard, bin) = root();
    let body = b"release bytes";
    let fake = Fake::new(&[body.as_slice(), b"x"].concat());
    let err = Stager::new(&bin, allow(), &fake)
        .stage(&version(), &target(body, Some(URL)))
        .unwrap_err();
    assert!(matches!(err, StageError::TooLarge), "{err}");
    assert_eq!(entries(&bin.join("1.2.3")), Vec::<String>::new());
}

#[test]
fn a_body_one_byte_short_is_refused() {
    let (_guard, bin) = root();
    let body = b"release bytes";
    let fake = Fake::new(&body[..body.len() - 1]);
    let err = Stager::new(&bin, allow(), &fake)
        .stage(&version(), &target(body, Some(URL)))
        .unwrap_err();
    assert!(matches!(err, StageError::SizeMismatch { .. }), "{err}");
    assert_eq!(entries(&bin.join("1.2.3")), Vec::<String>::new());
}

#[test]
fn the_read_stops_one_byte_past_the_cap() {
    struct Endless(u64);
    impl Read for Endless {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0 += buf.len() as u64;
            assert!(self.0 < 1 << 20, "read past the cap");
            buf.fill(7);
            Ok(buf.len())
        }
    }
    struct EndlessFetch;
    impl ArchiveFetcher for EndlessFetch {
        fn get(&self, url: &str) -> io::Result<ArchiveResponse> {
            Ok(ArchiveResponse {
                final_url: url.to_owned(),
                body: Box::new(Endless(0)),
            })
        }
    }
    let (_guard, bin) = root();
    let t = Target {
        sha256: hex(b"x"),
        size: 100,
        url: Some(URL.to_owned()),
    };
    let err = Stager::new(&bin, allow(), &EndlessFetch)
        .stage(&version(), &t)
        .unwrap_err();
    assert!(matches!(err, StageError::TooLarge), "{err}");
}

#[test]
fn a_size_above_the_named_maximum_is_refused_before_any_fetch() {
    let (_guard, bin) = root();
    let fake = Fake::new(b"x");
    let t = Target {
        sha256: hex(b"x"),
        size: MAX_ARCHIVE_BYTES + 1,
        url: Some(URL.to_owned()),
    };
    let err = Stager::new(&bin, allow(), &fake)
        .stage(&version(), &t)
        .unwrap_err();
    assert!(matches!(err, StageError::TooLarge), "{err}");
    assert!(fake.seen.lock().unwrap().is_empty());
}

#[test]
fn a_redirect_to_another_host_is_refused() {
    let (_guard, bin) = root();
    let body = b"release bytes";
    for to in [
        "https://evil.example/fleetd.tar.gz",
        "http://github.com/fleetd.tar.gz",
        "https://github.com.evil.example/x",
        "https://githubusercontent.com/x",
    ] {
        let fake = Fake::redirecting(body, to);
        let err = Stager::new(&bin, allow(), &fake)
            .stage(&version(), &target(body, Some(URL)))
            .unwrap_err();
        assert!(
            matches!(err, StageError::Url(_) | StageError::HostNotAllowed),
            "{to}: {err}"
        );
    }
    assert!(!bin.join("1.2.3").exists() || entries(&bin.join("1.2.3")) == Vec::<String>::new());
}

#[test]
fn a_redirect_to_an_allowed_subdomain_is_followed() {
    let (_guard, bin) = root();
    let body = b"release bytes";
    let fake = Fake::redirecting(body, "https://objects.githubusercontent.com/a?b=c");
    Stager::new(&bin, allow(), &fake)
        .stage(&version(), &target(body, Some(URL)))
        .unwrap();
}

#[test]
fn hostile_urls_are_refused_before_any_fetch() {
    let (_guard, bin) = root();
    let body = b"x";
    for url in [
        "http://github.com/x",
        "ftp://github.com/x",
        "github.com/x",
        "",
        "https://",
        "https://evil.example/x",
        "https://github.com@evil.example/x",
        "https://evil.example\\@github.com/x",
        "https://github.com:8443/x",
        "https://github.com\r\n/x",
        "https://github.com /x",
        "https://127.0.0.1/x",
        "https://[::1]/x",
        "https://github.com.evil.example/x",
        "https://gıthub.com/x",
        "https://github..com/x",
    ] {
        let fake = Fake::new(body);
        let err = Stager::new(&bin, allow(), &fake)
            .stage(&version(), &target(body, Some(url)))
            .unwrap_err();
        assert!(
            matches!(err, StageError::Url(_) | StageError::HostNotAllowed),
            "{url:?}: {err}"
        );
        assert!(fake.seen.lock().unwrap().is_empty(), "{url:?}");
    }
}

#[test]
fn a_target_without_a_url_is_refused() {
    let (_guard, bin) = root();
    let fake = Fake::new(b"x");
    let err = Stager::new(&bin, allow(), &fake)
        .stage(&version(), &target(b"x", None))
        .unwrap_err();
    assert!(matches!(err, StageError::NoUrl), "{err}");
}

#[test]
fn the_default_port_and_mixed_case_host_are_accepted() {
    let (_guard, bin) = root();
    let body = b"x";
    let fake = Fake::new(body);
    Stager::new(&bin, allow(), &fake)
        .stage(
            &version(),
            &target(body, Some("https://GitHub.com:443/a/b")),
        )
        .unwrap();
}

#[test]
fn hostile_version_strings_are_refused() {
    for ver in [
        "", "..", ".", "../x", "1/2", "1\\2", "1\0", "1\r\n", "1.2.3\n", " 1", "1 ", "v1/../..",
        "é1", "-1", "1..2", "1.2.3/",
    ] {
        assert!(validate_stage_version(ver).is_err(), "{ver:?}");
    }
    for ver in ["1", "1.2.3", "1.2.3-rc1", "10.20.30-beta.2"] {
        assert!(validate_stage_version(ver).is_ok(), "{ver:?}");
    }
}

#[test]
fn a_symlinked_version_dir_is_refused() {
    let (guard, bin) = root();
    let elsewhere = guard.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    symlink(&elsewhere, bin.join("1.2.3")).unwrap();
    let body = b"x";
    let fake = Fake::new(body);
    let err = Stager::new(&bin, allow(), &fake)
        .stage(&version(), &target(body, Some(URL)))
        .unwrap_err();
    assert!(matches!(err, StageError::UnsafeDir(_)), "{err}");
    assert_eq!(entries(&elsewhere), Vec::<String>::new());
}

#[test]
fn a_loose_existing_version_dir_is_refused() {
    let (_guard, bin) = root();
    let dir = bin.join("1.2.3");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    let body = b"x";
    let fake = Fake::new(body);
    let err = Stager::new(&bin, allow(), &fake)
        .stage(&version(), &target(body, Some(URL)))
        .unwrap_err();
    assert!(matches!(err, StageError::UnsafeDir(_)), "{err}");
}

#[test]
fn a_symlinked_bin_root_is_refused() {
    let guard = TempDir::new().unwrap();
    let real = guard.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = guard.path().join("bin");
    symlink(&real, &link).unwrap();
    let body = b"x";
    let fake = Fake::new(body);
    let err = Stager::new(&link, allow(), &fake)
        .stage(&version(), &target(body, Some(URL)))
        .unwrap_err();
    assert!(matches!(err, StageError::UnsafeDir(_)), "{err}");
    assert_eq!(entries(&real), Vec::<String>::new());
}

#[test]
fn an_existing_staged_binary_is_never_replaced() {
    let (_guard, bin) = root();
    let body = b"x";
    let fake = Fake::new(body);
    let stager = Stager::new(&bin, allow(), &fake);
    stager.stage(&version(), &target(body, Some(URL))).unwrap();
    let err = stager
        .stage(&version(), &target(body, Some(URL)))
        .unwrap_err();
    assert!(matches!(err, StageError::AlreadyStaged), "{err}");
}

#[test]
fn a_stale_temp_symlink_is_not_followed() {
    let (guard, bin) = root();
    let victim = guard.path().join("victim");
    fs::write(&victim, b"keep").unwrap();
    let dir = bin.join("1.2.3");
    fs::create_dir(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    for name in entries_for_temp() {
        let _ = symlink(&victim, dir.join(name));
    }
    let body = b"x";
    let fake = Fake::new(body);
    let _ = Stager::new(&bin, allow(), &fake).stage(&version(), &target(body, Some(URL)));
    assert_eq!(fs::read(&victim).unwrap(), b"keep");
}

fn entries_for_temp() -> [&'static str; 2] {
    [".fleetd.tar.gz.tmp", "fleetd.tar.gz.tmp"]
}
