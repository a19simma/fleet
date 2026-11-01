//! Signed update manifest verification: the signature, the trust-root file checks, the
//! monotonic `seq`, the version rule and the field table, against minisign signatures made
//! in the test with a ring Ed25519 key.

#![expect(
    clippy::unwrap_used,
    clippy::too_many_lines,
    clippy::format_collect,
    reason = "test code asserts by panicking, and the table and the reference blake2b are long"
)]

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use fleet_core::tools::Version;
use fleet_proto::{MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, PROTOCOL_VERSION};
use fleetd::update::{
    Policy, SeqStore, TrustRoot, UpdateError, load_trust_root, verify_manifest, version_is_newer,
};
use tempfile::TempDir;

#[path = "common/minisign.rs"]
mod minisign;
use minisign::{Signer, blake2b};

#[test]
fn blake2b_matches_the_reference_vector() {
    let hex: String = blake2b(b"abc").iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    );
}

fn trust_dir(signer: &Signer) -> (TempDir, TrustRoot) {
    let dir = tempfile::tempdir().unwrap();
    let root = write_root(dir.path(), signer);
    (dir, root)
}

fn write_root(dir: &Path, signer: &Signer) -> TrustRoot {
    let path = dir.join("update.pub");
    fs::write(&path, signer.public_text()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    load_trust_root(&path, owner_of(dir)).unwrap()
}

fn owner_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().uid()
}

fn sha(c: char) -> String {
    c.to_string().repeat(64)
}

fn manifest_json(version: &str, seq: u64) -> String {
    format!(
        r#"{{"version":"{version}","min_protocol":1,"seq":{seq},"targets":{{"x86_64-unknown-linux-gnu":{{"sha256":"{}","size":1234,"url":"https://example.org/fleetd-x86_64.tar.gz"}},"aarch64-unknown-linux-gnu":{{"sha256":"{}","size":99}}}}}}"#,
        sha('a'),
        sha('b')
    )
}

fn policy() -> Policy {
    Policy {
        running: Version::new("1.2.3").unwrap(),
        last_seq: 5,
        protocol: PROTOCOL_VERSION,
    }
}

fn verify(
    signer: &Signer,
    root: &TrustRoot,
    json: &str,
) -> Result<fleetd::update::Manifest, UpdateError> {
    verify_manifest(
        json.as_bytes(),
        &signer.sign(json.as_bytes()),
        root,
        &policy(),
    )
}

#[test]
fn a_signed_newer_manifest_is_accepted() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    let manifest = verify(&signer, &root, &manifest_json("1.3.0", 6)).unwrap();
    assert_eq!(manifest.version.as_str(), "1.3.0");
    assert_eq!(manifest.seq, 6);
    assert_eq!(manifest.min_protocol, 1);
    let linux = manifest.target("x86_64-unknown-linux-gnu").unwrap();
    assert_eq!(linux.size, 1234);
    assert_eq!(linux.sha256, sha('a'));
    assert_eq!(
        linux.url.as_deref(),
        Some("https://example.org/fleetd-x86_64.tar.gz")
    );
    assert_eq!(
        manifest.target("aarch64-unknown-linux-gnu").unwrap().url,
        None
    );
}

#[test]
fn an_unknown_target_is_refused() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    let manifest = verify(&signer, &root, &manifest_json("1.3.0", 6)).unwrap();
    assert!(matches!(
        manifest.target("riscv64-unknown-linux-gnu"),
        Err(UpdateError::UnknownTarget)
    ));
}

#[test]
fn signature_hostile_table() {
    let signer = Signer::new(1);
    let other = Signer::new(2);
    let (_dir, root) = trust_dir(&signer);
    let json = manifest_json("1.3.0", 6);
    let good = String::from_utf8(signer.sign(json.as_bytes())).unwrap();
    let lines: Vec<&str> = good.lines().collect();
    let bad_b64 = format!(
        "{}\n!!!notbase64!!!\n{}\n{}\n",
        lines[0], lines[2], lines[3]
    );
    let truncated = format!("{}\n{}\n", lines[0], &lines[1][..20]);
    let short_global = format!(
        "{}\n{}\n{}\n{}\n",
        lines[0],
        lines[1],
        lines[2],
        &lines[3][..40]
    );
    let rows: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("truncated", truncated.into_bytes()),
        ("short global signature", short_global.into_bytes()),
        ("bad base64", bad_b64.into_bytes()),
        ("wrong key", other.sign(json.as_bytes())),
        ("legacy algorithm", signer.sign_with(json.as_bytes(), b"Ed")),
        ("other message", signer.sign(b"{}")),
        ("not utf8", vec![0xff, 0xfe, 0xfd]),
        ("nul bytes", vec![0; 64]),
    ];
    for (name, sig) in rows {
        let got = verify_manifest(json.as_bytes(), &sig, &root, &policy());
        assert!(
            matches!(got, Err(UpdateError::Signature(_))),
            "{name}: {got:?}"
        );
    }
}

#[test]
fn a_tampered_manifest_is_refused() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    let json = manifest_json("1.3.0", 6);
    let sig = signer.sign(json.as_bytes());
    let tampered = json.replace("1234", "9999");
    assert!(matches!(
        verify_manifest(tampered.as_bytes(), &sig, &root, &policy()),
        Err(UpdateError::Signature(_))
    ));
}

#[test]
fn the_signature_cap_is_exact() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    let json = manifest_json("1.3.0", 6);
    let mut sig = signer.sign(json.as_bytes());
    sig.resize(MAX_SIGNATURE_BYTES, b'\n');
    assert!(verify_manifest(json.as_bytes(), &sig, &root, &policy()).is_ok());
    sig.push(b'\n');
    assert!(matches!(
        verify_manifest(json.as_bytes(), &sig, &root, &policy()),
        Err(UpdateError::SignatureTooLarge)
    ));
}

#[test]
fn the_manifest_cap_is_exact() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    let mut json = manifest_json("1.3.0", 6);
    json.push_str(&" ".repeat(MAX_MANIFEST_BYTES - json.len()));
    assert_eq!(json.len(), MAX_MANIFEST_BYTES);
    assert!(verify(&signer, &root, &json).is_ok());
    json.push(' ');
    assert!(matches!(
        verify(&signer, &root, &json),
        Err(UpdateError::ManifestTooLarge)
    ));
}

#[test]
fn field_hostile_table() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    let good = manifest_json("1.3.0", 6);
    let target = "x86_64-unknown-linux-gnu";
    let sha_a = sha('a');
    let url = "https://example.org/fleetd-x86_64.tar.gz";
    let long_url = format!("https://example.org/{}", "a".repeat(3000));
    let rows: Vec<(String, String)> = vec![
        ("CR in version".into(), good.replace("1.3.0", "1.3.0\\r")),
        ("LF in version".into(), good.replace("1.3.0", "1.3.0\\n")),
        (
            "NEL in version".into(),
            good.replace("1.3.0", "1.3.0\\u0085"),
        ),
        (
            "U+2028 in version".into(),
            good.replace("1.3.0", "1.3.0\\u2028"),
        ),
        ("space in version".into(), good.replace("1.3.0", "1.3.0 ")),
        (
            "non-ascii version".into(),
            good.replace("1.3.0", "1.3.\\u0660"),
        ),
        ("empty version".into(), good.replace("1.3.0", "")),
        ("range version".into(), good.replace("1.3.0", "^1.3.0")),
        ("CR in target".into(), good.replace(target, "x86\\r64")),
        ("LF in target".into(), good.replace(target, "x86\\n64")),
        ("NEL in target".into(), good.replace(target, "x86\\u008564")),
        (
            "U+2028 in target".into(),
            good.replace(target, "x86\\u202864"),
        ),
        ("slash in target".into(), good.replace(target, "../x")),
        ("uppercase target".into(), good.replace(target, "X86")),
        ("empty target".into(), good.replace(target, "")),
        (
            "CR in url".into(),
            good.replace(url, "https://example.org/a\\rb"),
        ),
        (
            "LF in url".into(),
            good.replace(url, "https://example.org/a\\nb"),
        ),
        (
            "NEL in url".into(),
            good.replace(url, "https://example.org/a\\u0085b"),
        ),
        (
            "U+2028 in url".into(),
            good.replace(url, "https://example.org/a\\u2028b"),
        ),
        (
            "space in url".into(),
            good.replace(url, "https://example.org/a b"),
        ),
        (
            "userinfo in url".into(),
            good.replace(url, "https://user@example.org/a"),
        ),
        (
            "backslash in url".into(),
            good.replace(url, "https://example.org\\\\a"),
        ),
        ("http url".into(), good.replace(url, "http://example.org/a")),
        ("ftp url".into(), good.replace(url, "ftp://example.org/a")),
        (
            "non-ascii url".into(),
            good.replace(url, "https://exämple.org/a"),
        ),
        ("empty url".into(), good.replace(url, "")),
        ("over-long url".into(), good.replace(url, &long_url)),
        (
            "CR in sha256".into(),
            good.replacen(&sha_a, &format!("{}\\r", &sha_a[..63]), 1),
        ),
        (
            "sha256 63 long".into(),
            good.replacen(&sha_a, &sha_a[..63], 1),
        ),
        (
            "sha256 65 long".into(),
            good.replacen(&sha_a, &format!("{sha_a}a"), 1),
        ),
        (
            "sha256 uppercase".into(),
            good.replacen(&sha_a, &"A".repeat(64), 1),
        ),
        (
            "sha256 not hex".into(),
            good.replacen(&sha_a, &"g".repeat(64), 1),
        ),
        ("sha256 empty".into(), good.replacen(&sha_a, "", 1)),
        ("size 0".into(), good.replace("1234", "0")),
        ("size negative".into(), good.replace("1234", "-1")),
        ("size float".into(), good.replace("1234", "1.5")),
        ("size over cap".into(), good.replace("1234", "99999999999")),
        ("size as string".into(), good.replace("1234", "\"1234\"")),
        (
            "seq as string".into(),
            good.replace("\"seq\":6", "\"seq\":\"6\""),
        ),
        (
            "seq negative".into(),
            good.replace("\"seq\":6", "\"seq\":-6"),
        ),
        ("missing seq".into(), good.replace("\"seq\":6,", "")),
        (
            "missing version".into(),
            good.replace("\"version\":\"1.3.0\",", ""),
        ),
        (
            "missing min_protocol".into(),
            good.replace("\"min_protocol\":1,", ""),
        ),
        (
            "missing targets".into(),
            r#"{"version":"1.3.0","min_protocol":1,"seq":6}"#.to_owned(),
        ),
        (
            "empty targets".into(),
            r#"{"version":"1.3.0","min_protocol":1,"seq":6,"targets":{}}"#.to_owned(),
        ),
        (
            "missing sha256".into(),
            good.replacen(&format!("\"sha256\":\"{sha_a}\","), "", 1),
        ),
        (
            "unknown top field".into(),
            good.replacen('{', "{\"extra\":1,", 1),
        ),
        (
            "unknown target field".into(),
            good.replacen("\"size\":1234", "\"size\":1234,\"extra\":1", 1),
        ),
        (
            "dup version".into(),
            good.replacen('{', "{\"version\":\"9.9.9\",", 1),
        ),
        ("dup seq".into(), good.replacen('{', "{\"seq\":99,", 1)),
        (
            "dup min_protocol".into(),
            good.replacen('{', "{\"min_protocol\":0,", 1),
        ),
        (
            "dup targets".into(),
            good.replacen("\"targets\":{", "\"targets\":{},\"targets\":{", 1),
        ),
        (
            "dup target name".into(),
            good.replacen("\"aarch64-unknown-linux-gnu\"", &format!("\"{target}\""), 1),
        ),
        (
            "dup target field".into(),
            good.replacen("\"size\":1234", "\"size\":1234,\"size\":1", 1),
        ),
        (
            "dup sha256".into(),
            good.replacen(
                "\"sha256\":",
                &format!("\"sha256\":\"{}\",\"sha256\":", sha('c')),
                1,
            ),
        ),
        (
            "dup url".into(),
            good.replacen("\"url\":", "\"url\":\"https://a.example/x\",\"url\":", 1),
        ),
        ("trailing data".into(), format!("{good}{{}}")),
        ("not an object".into(), "[]".into()),
        ("null".into(), "null".into()),
        ("empty".into(), String::new()),
        ("bom".into(), format!("\u{feff}{good}")),
        (
            "protocol too new".into(),
            good.replace(
                "\"min_protocol\":1",
                &format!("\"min_protocol\":{}", PROTOCOL_VERSION + 1),
            ),
        ),
        ("too many targets".into(), many_targets(17)),
    ];
    for (name, json) in rows {
        let got = verify(&signer, &root, &json);
        assert!(got.is_err(), "{name} accepted");
        assert!(
            !matches!(got, Err(UpdateError::Signature(_))),
            "{name}: refused by the signature, not the field check: {got:?}"
        );
    }
    assert!(verify(&signer, &root, &many_targets(16)).is_ok());
}

fn many_targets(n: usize) -> String {
    let targets: Vec<String> = (0..n)
        .map(|i| format!(r#""t{i}":{{"sha256":"{}","size":1}}"#, sha('a')))
        .collect();
    format!(
        r#"{{"version":"1.3.0","min_protocol":1,"seq":6,"targets":{{{}}}}}"#,
        targets.join(",")
    )
}

#[test]
fn seq_must_be_strictly_greater() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    for seq in [0, 4, 5] {
        let got = verify(&signer, &root, &manifest_json("1.3.0", seq));
        assert!(
            matches!(got, Err(UpdateError::SeqNotNewer { seen, last }) if seen == seq && last == 5),
            "seq {seq}: {got:?}"
        );
    }
    assert!(verify(&signer, &root, &manifest_json("1.3.0", 6)).is_ok());
    assert!(verify(&signer, &root, &manifest_json("1.3.0", u64::MAX)).is_ok());
}

#[test]
fn version_must_be_newer_than_the_running_one() {
    let signer = Signer::new(1);
    let (_dir, root) = trust_dir(&signer);
    for old in [
        "1.2.3",
        "1.2.2",
        "1.1.9",
        "0.9.9",
        "1.2.3-rc.1",
        "1.2",
        "1.2.3.0",
        "1.02.3",
    ] {
        let got = verify(&signer, &root, &manifest_json(old, 6));
        assert!(
            matches!(got, Err(UpdateError::VersionNotNewer)),
            "{old}: {got:?}"
        );
    }
    for new in ["1.2.4", "1.3.0", "2.0.0", "1.10.0", "1.2.3.1", "10.0.0"] {
        assert!(
            verify(&signer, &root, &manifest_json(new, 6)).is_ok(),
            "{new}"
        );
    }
}

#[test]
fn version_order_follows_semver() {
    let v = |s: &str| Version::new(s).unwrap();
    let newer = [
        ("1.10.0", "1.9.0"),
        ("1.0.0", "1.0.0-rc.1"),
        ("1.0.0-rc.2", "1.0.0-rc.1"),
        ("1.0.0-rc.10", "1.0.0-rc.9"),
        ("1.0.0-rc", "1.0.0-beta"),
        ("1.0.0-rc.1", "1.0.0-rc"),
        ("1.0.0-beta", "1.0.0-1"),
        ("1.0.1", "1.0"),
        ("2", "1.99.99"),
        (
            "100000000000000000000000000000000000000.0",
            "99999999999999999999999999999999999999.0",
        ),
    ];
    for (a, b) in newer {
        assert!(version_is_newer(&v(a), &v(b)), "{a} > {b}");
        assert!(!version_is_newer(&v(b), &v(a)), "{b} !> {a}");
    }
    for same in [
        ("1.0", "1.0.0"),
        ("1.02", "1.2"),
        ("1.0.0-rc.1", "1.0.0-rc.1"),
    ] {
        assert!(!version_is_newer(&v(same.0), &v(same.1)), "{same:?}");
        assert!(!version_is_newer(&v(same.1), &v(same.0)), "{same:?}");
    }
}

#[test]
fn a_signature_is_checked_before_the_fields() {
    let signer = Signer::new(1);
    let other = Signer::new(2);
    let (_dir, root) = trust_dir(&signer);
    let json = manifest_json("0.0.1", 1);
    let got = verify_manifest(
        json.as_bytes(),
        &other.sign(json.as_bytes()),
        &root,
        &policy(),
    );
    assert!(matches!(got, Err(UpdateError::Signature(_))), "{got:?}");
}

#[test]
fn trust_root_refusals() {
    let signer = Signer::new(1);
    let text = signer.public_text();
    let make = |mode: u32| {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update.pub");
        fs::write(&path, &text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        (dir, path)
    };
    let (dir, path) = make(0o644);
    let me = owner_of(dir.path());
    assert!(load_trust_root(&path, me).is_ok());
    assert!(
        load_trust_root(&path, me + 1)
            .is_err_and(|e| matches!(e, UpdateError::TrustRootOwner { .. }))
    );
    for mode in [0o664, 0o646, 0o666, 0o620, 0o602, 0o622] {
        let (dir, path) = make(mode);
        let got = load_trust_root(&path, owner_of(dir.path()));
        assert!(
            matches!(got, Err(UpdateError::TrustRootWritable { .. })),
            "{mode:o}: {got:?}"
        );
    }
    for mode in [0o600, 0o640, 0o444] {
        let (dir, path) = make(mode);
        assert!(
            load_trust_root(&path, owner_of(dir.path())).is_ok(),
            "{mode:o}"
        );
    }
}

#[test]
fn trust_root_must_be_a_regular_file() {
    let signer = Signer::new(1);
    let dir = tempfile::tempdir().unwrap();
    let me = owner_of(dir.path());
    let real = dir.path().join("real.pub");
    fs::write(&real, signer.public_text()).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o644)).unwrap();
    let link = dir.path().join("link.pub");
    symlink(&real, &link).unwrap();
    let sub = dir.path().join("sub.pub");
    fs::create_dir(&sub).unwrap();
    for (name, path) in [
        ("symlink", link),
        ("directory", sub),
        ("missing", dir.path().join("none.pub")),
    ] {
        assert!(load_trust_root(&path, me).is_err(), "{name}");
    }
    assert!(matches!(
        load_trust_root(&dir.path().join("link.pub"), me),
        Err(UpdateError::TrustRootNotRegular | UpdateError::TrustRootIo(_))
    ));
}

#[test]
fn trust_root_in_a_writable_directory_is_refused() {
    let signer = Signer::new(1);
    let dir = tempfile::tempdir().unwrap();
    let me = owner_of(dir.path());
    let path = dir.path().join("update.pub");
    fs::write(&path, signer.public_text()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_trust_root(&path, me).is_ok());
    for mode in [0o775, 0o757, 0o777] {
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode)).unwrap();
        let got = load_trust_root(&path, me);
        assert!(
            matches!(got, Err(UpdateError::TrustRootWritable { .. })),
            "{mode:o}: {got:?}"
        );
    }
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn trust_root_with_a_relative_path() {
    let signer = Signer::new(1);
    let dir = tempfile::tempdir_in(".").unwrap();
    let me = owner_of(dir.path());
    fs::write(dir.path().join("update.pub"), signer.public_text()).unwrap();
    fs::set_permissions(
        dir.path().join("update.pub"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let relative = dir
        .path()
        .strip_prefix(std::env::current_dir().unwrap())
        .unwrap()
        .join("update.pub");
    assert!(relative.is_relative());
    assert!(load_trust_root(&relative, me).is_ok());
    fs::set_permissions(
        dir.path().join("update.pub"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(matches!(
        load_trust_root(&relative, me),
        Err(UpdateError::TrustRootWritable { .. })
    ));
}

#[test]
fn trust_root_content_table() {
    let signer = Signer::new(1);
    let good = signer.public_text();
    let lines: Vec<&str> = good.lines().collect();
    let rows: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("one line", lines[0].as_bytes().to_vec()),
        ("bad base64", format!("{}\n!!!\n", lines[0]).into_bytes()),
        (
            "truncated key",
            format!("{}\n{}\n", lines[0], &lines[1][..30]).into_bytes(),
        ),
        ("not utf8", vec![0xff; 80]),
        ("over cap", vec![b'a'; 4096]),
    ];
    for (name, bytes) in rows {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update.pub");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            load_trust_root(&path, owner_of(dir.path())).is_err(),
            "{name}"
        );
    }
}

#[test]
fn seq_store_round_trips_and_defaults_to_zero() {
    let dir = tempfile::tempdir().unwrap();
    let store = SeqStore::new(dir.path());
    assert_eq!(store.load().unwrap(), 0);
    store.store(7).unwrap();
    assert_eq!(store.load().unwrap(), 7);
    store.store(9).unwrap();
    assert_eq!(SeqStore::new(dir.path()).load().unwrap(), 9);
}

#[test]
fn seq_store_never_goes_back() {
    let dir = tempfile::tempdir().unwrap();
    let store = SeqStore::new(dir.path());
    store.store(7).unwrap();
    for seq in [0, 6, 7] {
        assert!(
            matches!(store.store(seq), Err(UpdateError::SeqNotNewer { .. })),
            "{seq}"
        );
    }
    assert_eq!(store.load().unwrap(), 7);
}

#[test]
fn a_crash_before_the_rename_keeps_the_old_seq() {
    let dir = tempfile::tempdir().unwrap();
    let store = SeqStore::new(dir.path());
    store.store(7).unwrap();
    let crash = store.store_with(8, || Err(io::Error::other("crash")));
    assert!(matches!(crash, Err(UpdateError::SeqState(_))));
    assert_eq!(store.load().unwrap(), 7);
    assert!(fs::read_dir(dir.path()).unwrap().count() >= 1);
    store.store(8).unwrap();
    assert_eq!(store.load().unwrap(), 8);
    let leftovers: Vec<_> = fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(leftovers.len(), 1, "{leftovers:?}");
}

#[test]
fn a_crash_on_a_first_store_leaves_zero() {
    let dir = tempfile::tempdir().unwrap();
    let store = SeqStore::new(dir.path());
    assert!(
        store
            .store_with(3, || Err(io::Error::other("crash")))
            .is_err()
    );
    assert_eq!(store.load().unwrap(), 0);
}

#[test]
fn a_corrupt_seq_file_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let store = SeqStore::new(dir.path());
    store.store(7).unwrap();
    let file = fs::read_dir(dir.path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    for bad in [
        "",
        "abc",
        "-1",
        "+7",
        "7\n7",
        " 7",
        "7 ",
        "99999999999999999999999",
        "٧",
    ] {
        fs::write(&file, bad).unwrap();
        assert!(
            matches!(store.load(), Err(UpdateError::SeqState(_))),
            "{bad:?}"
        );
    }
    fs::write(&file, vec![b'1'; 4096]).unwrap();
    assert!(matches!(store.load(), Err(UpdateError::SeqState(_))));
}

#[test]
fn seq_store_in_a_missing_directory_errors_on_store_not_on_load() {
    let dir = tempfile::tempdir().unwrap();
    let store = SeqStore::new(dir.path().join("absent"));
    assert_eq!(store.load().unwrap(), 0);
    assert!(store.store(1).is_err());
}
