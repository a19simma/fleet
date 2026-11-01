//! The embedded default update key and its resolution against `/etc/fleetd/update.pub`:
//! the baked key serves when the file is absent, a present file replaces it, and a present
//! file that fails any check never falls back to the baked key.

#![expect(
    clippy::unwrap_used,
    clippy::format_collect,
    reason = "test code asserts by panicking and builds a hex string from bytes"
)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::Path;

use fleet_core::tools::Version;
use fleet_proto::PROTOCOL_VERSION;
use fleetd::update::{
    BAKED_TRUST_KEY, Policy, TrustRoot, TrustSource, UpdateError, load_trust_root,
    resolve_trust_root, verify_manifest,
};

#[path = "common/minisign.rs"]
mod minisign;
use minisign::Signer;

const FIXTURE_PUB: &str = include_str!("fixtures/trust/test.pub");
const FIXTURE_MANIFEST: &[u8] = include_bytes!("fixtures/trust/manifest.json");
const FIXTURE_SIG: &[u8] = include_bytes!("fixtures/trust/manifest.json.minisig");

fn owner_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().uid()
}

fn policy() -> Policy {
    Policy {
        running: Version::new("1.2.3").unwrap(),
        last_seq: 5,
        protocol: PROTOCOL_VERSION,
    }
}

fn write_key(dir: &Path, text: &str, mode: u32) -> std::path::PathBuf {
    let path = dir.join("update.pub");
    fs::write(&path, text).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn fixture_verdict(root: &TrustRoot) -> Result<(), UpdateError> {
    verify_manifest(FIXTURE_MANIFEST, FIXTURE_SIG, root, &policy()).map(|_| ())
}

fn signer_verdict(root: &TrustRoot, signer: &Signer) -> Result<(), UpdateError> {
    verify_manifest(
        FIXTURE_MANIFEST,
        &signer.sign(FIXTURE_MANIFEST),
        root,
        &policy(),
    )
    .map(|_| ())
}

fn is_baked(root: &TrustRoot) -> bool {
    matches!(fixture_verdict(root), Err(UpdateError::Signature(_)))
        && signer_verdict(root, &Signer::new(2)).is_err()
}

type Case = (
    &'static str,
    Box<dyn Fn(&Path) -> u32>,
    fn(&UpdateError) -> bool,
);

fn dir_in_tmp() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

#[test]
fn baked_only() {
    let dir = dir_in_tmp();
    let absent = dir.path().join("update.pub");
    let root = resolve_trust_root(&absent, TrustSource::Default, owner_of(dir.path())).unwrap();
    assert!(is_baked(&root));
}

#[test]
fn file_overrides() {
    let dir = dir_in_tmp();
    let key_b = Signer::new(2);
    let path = write_key(dir.path(), &key_b.public_text(), 0o644);
    let owner = owner_of(dir.path());
    for source in [TrustSource::Default, TrustSource::Explicit] {
        let root = resolve_trust_root(&path, source, owner).unwrap();
        signer_verdict(&root, &key_b).unwrap();
        assert!(fixture_verdict(&root).is_err());
    }
}

#[test]
fn file_invalid_fails_closed() {
    let valid = Signer::new(2).public_text();
    let mut cases: Vec<Case> = Vec::new();
    let garbage = |dir: &Path| {
        write_key(dir, "not a key at all\n", 0o644);
        owner_of(dir)
    };
    cases.push(("garbage", Box::new(garbage), |e| {
        matches!(e, UpdateError::TrustRootInvalid(_))
    }));
    cases.push((
        "non-utf8",
        Box::new(|dir: &Path| {
            let path = dir.join("update.pub");
            fs::write(&path, [0xff, 0xfe, 0xfd, 0x0a]).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            owner_of(dir)
        }),
        |e| matches!(e, UpdateError::TrustRootInvalid(why) if why == "not UTF-8"),
    ));
    cases.push((
        "too large",
        Box::new(|dir: &Path| {
            write_key(dir, &"a".repeat(1025), 0o644);
            owner_of(dir)
        }),
        |e| matches!(e, UpdateError::TrustRootTooLarge),
    ));
    let text = valid.clone();
    cases.push((
        "group writable",
        Box::new(move |dir: &Path| {
            write_key(dir, &text, 0o664);
            owner_of(dir)
        }),
        |e| matches!(e, UpdateError::TrustRootWritable { .. }),
    ));
    let text = valid.clone();
    cases.push((
        "wrong owner",
        Box::new(move |dir: &Path| {
            write_key(dir, &text, 0o644);
            owner_of(dir) + 1
        }),
        |e| matches!(e, UpdateError::TrustRootOwner { .. }),
    ));
    let text = valid.clone();
    cases.push((
        "symlink",
        Box::new(move |dir: &Path| {
            let real = dir.join("real.pub");
            fs::write(&real, &text).unwrap();
            fs::set_permissions(&real, fs::Permissions::from_mode(0o644)).unwrap();
            symlink(&real, dir.join("update.pub")).unwrap();
            owner_of(dir)
        }),
        |e| matches!(e, UpdateError::TrustRootNotRegular),
    ));
    cases.push((
        "directory",
        Box::new(|dir: &Path| {
            fs::create_dir(dir.join("update.pub")).unwrap();
            owner_of(dir)
        }),
        |e| matches!(e, UpdateError::TrustRootNotRegular),
    ));
    let text = valid.clone();
    cases.push((
        "mode 000",
        Box::new(move |dir: &Path| {
            write_key(dir, &text, 0o000);
            owner_of(dir)
        }),
        |e| {
            matches!(e, UpdateError::TrustRootIo(err)
                if err.kind() == std::io::ErrorKind::PermissionDenied)
        },
    ));
    let text = valid;
    cases.push((
        "group writable parent",
        Box::new(move |dir: &Path| {
            write_key(dir, &text, 0o644);
            fs::set_permissions(dir, fs::Permissions::from_mode(0o775)).unwrap();
            owner_of(dir)
        }),
        |e| matches!(e, UpdateError::TrustRootWritable { .. }),
    ));
    for (name, prepare, expect) in &cases {
        for source in [TrustSource::Default, TrustSource::Explicit] {
            let dir = dir_in_tmp();
            let owner = prepare(dir.path());
            let got = resolve_trust_root(&dir.path().join("update.pub"), source, owner);
            let err = got.expect_err(name);
            assert!(expect(&err), "{name}: {err:?}");
            assert!(
                !matches!(err, UpdateError::TrustRootMissing),
                "{name}: fell back or reported missing"
            );
        }
    }
}

#[test]
fn explicit_missing_fails() {
    let dir = dir_in_tmp();
    let owner = owner_of(dir.path());
    let absent = dir.path().join("update.pub");
    let err = resolve_trust_root(&absent, TrustSource::Explicit, owner).unwrap_err();
    assert!(matches!(err, UpdateError::TrustRootMissing), "{err:?}");
    assert_eq!(err.to_string(), "trust root file is required and missing");
    let no_parent = dir.path().join("gone").join("update.pub");
    let root = resolve_trust_root(&no_parent, TrustSource::Default, owner).unwrap();
    assert!(is_baked(&root));
    let err = resolve_trust_root(&no_parent, TrustSource::Explicit, owner).unwrap_err();
    assert!(matches!(err, UpdateError::TrustRootMissing), "{err:?}");
}

#[test]
fn load_trust_root_still_fails_on_a_missing_file() {
    let dir = dir_in_tmp();
    let err = load_trust_root(&dir.path().join("update.pub"), owner_of(dir.path())).unwrap_err();
    assert!(
        matches!(&err, UpdateError::TrustRootIo(e) if e.kind() == std::io::ErrorKind::NotFound),
        "{err:?}"
    );
}

fn b64_decode(text: &str) -> Vec<u8> {
    let table = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes().filter(|b| *b != b'=') {
        let value = u32::try_from(table.iter().position(|c| *c == byte).unwrap()).unwrap();
        acc = (acc << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap());
        }
    }
    out
}

#[test]
fn baked_key_comment_id_matches() {
    let lines: Vec<&str> = BAKED_TRUST_KEY.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(BAKED_TRUST_KEY.ends_with('\n'));
    let comment_id = lines[0]
        .strip_prefix("untrusted comment: minisign public key ")
        .unwrap();
    let raw = b64_decode(lines[1]);
    assert_eq!(raw.len(), 42);
    assert_eq!(&raw[..2], b"Ed");
    let mut id = raw[2..10].to_vec();
    id.reverse();
    let hex: String = id.iter().map(|b| format!("{b:02X}")).collect();
    assert_eq!(hex, comment_id);
}

#[test]
fn baked_key_verifies_test_signature() {
    let dir = dir_in_tmp();
    let owner = owner_of(dir.path());
    let own = write_key(dir.path(), FIXTURE_PUB, 0o644);
    let fixture_root = resolve_trust_root(&own, TrustSource::Explicit, owner).unwrap();
    fixture_verdict(&fixture_root).unwrap();
    let absent = dir.path().join("none.pub");
    let baked = resolve_trust_root(&absent, TrustSource::Default, owner).unwrap();
    assert!(matches!(
        fixture_verdict(&baked),
        Err(UpdateError::Signature(_))
    ));
}
