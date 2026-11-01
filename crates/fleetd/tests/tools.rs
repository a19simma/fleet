//! Bundled mise verification: pins, sha256, minisign, owner and mode checks, symlinks and the
//! size cap, against minisign signatures made in the test with a ring Ed25519 key.

#![expect(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    clippy::many_single_char_names,
    clippy::trivially_copy_pass_by_ref,
    clippy::format_collect,
    reason = "test code asserts by panicking, and the reference blake2b is long"
)]

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use fleet_core::tools::ToolName;
use fleet_proto::MAX_SIGNATURE_BYTES;
use fleetd::tools::{
    CacheLimits, MAX_CACHE_BYTES, MAX_CACHE_ENTRIES, MisePins, MisePinsConfig, TOOL_ENV_FILE,
    ToolCache, ToolsError, check_tool_hosts, tool_hosts, verify_mise, verify_mise_capped,
    write_tool_env,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

const IV: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn compress(h: &mut [u64; 8], block: &[u8], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *w = u64::from_le_bytes(b);
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }
    let g = |v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64| {
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
        v[d] = (v[d] ^ v[a]).rotate_right(32);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(24);
        v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
        v[d] = (v[d] ^ v[a]).rotate_right(16);
        v[c] = v[c].wrapping_add(v[d]);
        v[b] = (v[b] ^ v[c]).rotate_right(63);
    };
    for r in 0..12 {
        let s = &SIGMA[r % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

fn blake2b(data: &[u8]) -> Vec<u8> {
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ 64;
    let mut offset = 0usize;
    while data.len() - offset > 128 {
        compress(
            &mut h,
            &data[offset..offset + 128],
            (offset + 128) as u128,
            false,
        );
        offset += 128;
    }
    let mut block = [0u8; 128];
    let rest = &data[offset..];
    block[..rest.len()].copy_from_slice(rest);
    compress(&mut h, &block, data.len() as u128, true);
    h.iter().flat_map(|w| w.to_le_bytes()).collect()
}

struct Signer {
    pair: Ed25519KeyPair,
    key_id: [u8; 8],
}

impl Signer {
    fn new(seed: u8) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        Self {
            pair,
            key_id: [seed; 8],
        }
    }

    fn public_text(&self) -> String {
        let mut raw = b"Ed".to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(self.pair.public_key().as_ref());
        format!("untrusted comment: minisign public key\n{}\n", b64(&raw))
    }

    fn sign_with(&self, message: &[u8], algorithm: &[u8; 2]) -> Vec<u8> {
        let payload = if algorithm == b"ED" {
            blake2b(message)
        } else {
            message.to_vec()
        };
        let sig = self.pair.sign(&payload);
        let mut raw = algorithm.to_vec();
        raw.extend_from_slice(&self.key_id);
        raw.extend_from_slice(sig.as_ref());
        let comment = "t";
        let mut global = sig.as_ref().to_vec();
        global.extend_from_slice(comment.as_bytes());
        let gsig = self.pair.sign(&global);
        format!(
            "untrusted comment: signature\n{}\ntrusted comment: {comment}\n{}\n",
            b64(&raw),
            b64(gsig.as_ref())
        )
        .into_bytes()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.sign_with(message, b"ED")
    }
}

fn owner_of(path: &Path) -> u32 {
    fs::metadata(path).unwrap().uid()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const BODY: &[u8] = b"\x7fELF pretend mise build";

struct Fixture {
    dir: TempDir,
    signer: Signer,
    binary: PathBuf,
    sig: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let signer = Signer::new(7);
        let binary = dir.path().join("mise");
        let sig = dir.path().join("mise.minisig");
        let key = dir.path().join("mise.pub");
        fs::write(&binary, BODY).unwrap();
        fs::write(&sig, signer.sign(BODY)).unwrap();
        fs::write(&key, signer.public_text()).unwrap();
        for path in [&binary, &sig, &key] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            dir,
            signer,
            binary,
            sig,
            key,
        }
    }

    fn owner(&self) -> u32 {
        owner_of(self.dir.path())
    }

    fn config(&self) -> MisePinsConfig {
        MisePinsConfig {
            version: Some("2025.1.2".to_owned()),
            sha256: Some(hex(&Sha256::digest(BODY))),
            signature_path: Some(self.sig.clone()),
            public_key_path: Some(self.key.clone()),
        }
    }

    fn pins(&self) -> MisePins {
        MisePins::new(self.config()).unwrap()
    }

    fn verify(&self) -> Result<fleetd::tools::VerifiedMise, ToolsError> {
        verify_mise(&self.binary, &self.pins(), self.owner())
    }
}

#[test]
fn a_pinned_signed_binary_is_accepted_and_the_handle_carries_the_path() {
    let fx = Fixture::new();
    let verified = fx.verify().unwrap();
    assert_eq!(verified.path(), fx.binary);
    assert_eq!(verified.version().as_str(), "2025.1.2");
}

type Strip = fn(&mut MisePinsConfig);

#[test]
fn each_missing_pin_is_refused_by_name() {
    let fx = Fixture::new();
    let cases: [(&str, Strip); 4] = [
        ("version", |c| c.version = None),
        ("sha256", |c| c.sha256 = None),
        ("signature_path", |c| c.signature_path = None),
        ("public_key_path", |c| c.public_key_path = None),
    ];
    for (name, strip) in cases {
        let mut config = fx.config();
        strip(&mut config);
        match MisePins::new(config) {
            Err(ToolsError::MissingPin(got)) => assert_eq!(got, name),
            other => panic!("{name}: {other:?}"),
        }
    }
    assert!(matches!(
        MisePins::new(MisePinsConfig::default()),
        Err(ToolsError::MissingPin(_))
    ));
}

#[test]
fn hostile_pin_values_are_refused() {
    let fx = Fixture::new();
    let good = hex(&Sha256::digest(BODY));
    let shas = [
        good.to_uppercase(),
        good[..63].to_owned(),
        format!("{good}0"),
        format!("{}g", &good[..63]),
        format!("{good}\n"),
        format!("{good}\r\n"),
        format!(" {good}"),
        String::new(),
        "\u{ff10}".repeat(64),
    ];
    for sha in shas {
        let mut config = fx.config();
        config.sha256 = Some(sha.clone());
        assert!(
            matches!(MisePins::new(config), Err(ToolsError::InvalidPin("sha256"))),
            "{sha:?}"
        );
    }
    for version in [
        "latest",
        "^1.0",
        "1.*",
        "",
        "1.0 ",
        "1.0\n",
        "v1.0",
        "\u{661}.0",
    ] {
        let mut config = fx.config();
        config.version = Some(version.to_owned());
        assert!(
            matches!(
                MisePins::new(config),
                Err(ToolsError::InvalidPin("version"))
            ),
            "{version:?}"
        );
    }
}

#[test]
fn a_config_with_an_unknown_key_does_not_parse() {
    let raw = r#"version = "1.0"
sha256 = "x"
extra = 1"#;
    assert!(toml::from_str::<MisePinsConfig>(raw).is_err());
}

#[test]
fn a_wrong_sha_is_refused() {
    let fx = Fixture::new();
    let mut config = fx.config();
    config.sha256 = Some("0".repeat(64));
    let pins = MisePins::new(config).unwrap();
    assert!(matches!(
        verify_mise(&fx.binary, &pins, fx.owner()),
        Err(ToolsError::ShaMismatch)
    ));
}

#[test]
fn a_tampered_binary_with_a_matching_sha_fails_the_signature() {
    let fx = Fixture::new();
    let evil = b"\x7fELF evil";
    fs::write(&fx.binary, evil).unwrap();
    let mut config = fx.config();
    config.sha256 = Some(hex(&Sha256::digest(evil)));
    let pins = MisePins::new(config).unwrap();
    assert!(matches!(
        verify_mise(&fx.binary, &pins, fx.owner()),
        Err(ToolsError::Signature(_))
    ));
}

#[test]
fn a_signature_from_another_key_is_refused() {
    let fx = Fixture::new();
    fs::write(&fx.sig, Signer::new(9).sign(BODY)).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::Signature(_))));
}

#[test]
fn a_legacy_non_prehashed_signature_is_refused() {
    let fx = Fixture::new();
    fs::write(&fx.sig, fx.signer.sign_with(BODY, b"Ed")).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::Signature(_))));
}

#[test]
fn hostile_signature_files_are_refused() {
    let fx = Fixture::new();
    let good = fx.signer.sign(BODY);
    let mut bad_utf8 = good.clone();
    bad_utf8[0] = 0xff;
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"garbage".to_vec(),
        bad_utf8,
        vec![b'a'; MAX_SIGNATURE_BYTES + 1],
        [good, vec![b'\n'; MAX_SIGNATURE_BYTES]].concat(),
    ];
    for case in cases {
        fs::write(&fx.sig, &case).unwrap();
        assert!(
            matches!(fx.verify(), Err(ToolsError::Signature(_))),
            "{} bytes",
            case.len()
        );
    }
}

#[test]
fn a_missing_signature_file_is_an_io_error() {
    let fx = Fixture::new();
    fs::remove_file(&fx.sig).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::Io(_))));
}

#[test]
fn a_missing_binary_is_an_io_error() {
    let fx = Fixture::new();
    fs::remove_file(&fx.binary).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::Io(_))));
}

#[test]
fn a_symlinked_binary_is_refused() {
    let fx = Fixture::new();
    let real = fx.dir.path().join("real");
    fs::rename(&fx.binary, &real).unwrap();
    symlink(&real, &fx.binary).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::NotRegular)));
}

#[test]
fn a_directory_and_a_fifo_are_refused() {
    let fx = Fixture::new();
    fs::remove_file(&fx.binary).unwrap();
    fs::create_dir(&fx.binary).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::NotRegular)));
    fs::remove_dir(&fx.binary).unwrap();
    let status = std::process::Command::new("mkfifo")
        .arg(&fx.binary)
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(fx.verify(), Err(ToolsError::NotRegular)));
}

#[test]
fn a_binary_writable_by_group_or_other_is_refused() {
    let fx = Fixture::new();
    for mode in [0o775, 0o757, 0o777, 0o772, 0o755 | 0o020] {
        fs::set_permissions(&fx.binary, fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(fx.verify(), Err(ToolsError::Writable { .. })),
            "{mode:o}"
        );
    }
}

#[test]
fn a_binary_directory_writable_by_group_or_other_is_refused() {
    let fx = Fixture::new();
    for mode in [0o775, 0o757, 0o777] {
        fs::set_permissions(fx.dir.path(), fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            matches!(fx.verify(), Err(ToolsError::Writable { .. })),
            "{mode:o}"
        );
    }
    fs::set_permissions(fx.dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fx.verify().unwrap();
}

#[test]
fn a_wrong_owner_is_refused() {
    let fx = Fixture::new();
    let found = fx.owner();
    let pins = fx.pins();
    match verify_mise(&fx.binary, &pins, found + 1) {
        Err(ToolsError::Owner {
            found: f,
            expected: e,
        }) => {
            assert_eq!(f, found);
            assert_eq!(e, found + 1);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_key_file_the_loader_refuses_is_refused() {
    let fx = Fixture::new();
    fs::set_permissions(&fx.key, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::Key(_))));
    fs::set_permissions(&fx.key, fs::Permissions::from_mode(0o644)).unwrap();
    let real = fx.dir.path().join("real.pub");
    fs::rename(&fx.key, &real).unwrap();
    symlink(&real, &fx.key).unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::Key(_))));
}

#[test]
fn a_key_that_is_not_minisign_is_refused() {
    let fx = Fixture::new();
    fs::write(&fx.key, "not a key").unwrap();
    assert!(matches!(fx.verify(), Err(ToolsError::Key(_))));
}

#[test]
fn the_size_cap_admits_exactly_the_cap_and_refuses_one_over() {
    let fx = Fixture::new();
    let pins = fx.pins();
    let len = BODY.len() as u64;
    verify_mise_capped(&fx.binary, &pins, fx.owner(), len).unwrap();
    assert!(matches!(
        verify_mise_capped(&fx.binary, &pins, fx.owner(), len - 1),
        Err(ToolsError::TooLarge)
    ));
}

#[test]
fn a_relative_binary_path_verifies() {
    let dir = tempfile::tempdir_in(".").unwrap();
    let fx = Fixture::new();
    let rel = dir.path().join("mise");
    fs::copy(&fx.binary, &rel).unwrap();
    fs::set_permissions(&rel, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let verified = verify_mise(&rel, &fx.pins(), owner_of(dir.path())).unwrap();
    assert_eq!(verified.path(), rel);
}

const PROXY_PORT: u16 = 43_127;

fn tool_env_dir() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("job_1")).unwrap();
    dir
}

#[test]
fn tool_env_content_and_mode_are_exact() {
    let dir = tool_env_dir();
    let path = write_tool_env(dir.path(), "job_1", PROXY_PORT, &[ToolName::Node])
        .unwrap()
        .unwrap();
    assert_eq!(path, dir.path().join("job_1").join(TOOL_ENV_FILE));
    let p = PROXY_PORT;
    let want = format!(
        "HTTPS_PROXY=http://127.0.0.1:{p}\nhttps_proxy=http://127.0.0.1:{p}\nHTTP_PROXY=http://127.0.0.1:{p}\nhttp_proxy=http://127.0.0.1:{p}\n"
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), want);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
}

#[test]
fn tool_env_is_absent_without_tools() {
    let dir = tool_env_dir();
    assert!(
        write_tool_env(dir.path(), "job_1", PROXY_PORT, &[])
            .unwrap()
            .is_none()
    );
    assert!(!dir.path().join("job_1").join(TOOL_ENV_FILE).exists());
}

#[test]
fn tool_env_refuses_bad_instance_ids() {
    let dir = tool_env_dir();
    let long = "a".repeat(65);
    for id in ["", "..", "a/b", "a-b", "a b", "job\n1", "job\0", "é", &long] {
        let err = write_tool_env(dir.path(), id, PROXY_PORT, &[ToolName::Jq]).unwrap_err();
        assert!(matches!(err, ToolsError::InvalidId), "{id:?}");
    }
}

#[test]
fn tool_env_refuses_port_zero_and_existing_file() {
    let dir = tool_env_dir();
    let err = write_tool_env(dir.path(), "job_1", 0, &[ToolName::Jq]).unwrap_err();
    assert!(matches!(err, ToolsError::InvalidProxy));
    write_tool_env(dir.path(), "job_1", PROXY_PORT, &[ToolName::Jq]).unwrap();
    let err = write_tool_env(dir.path(), "job_1", PROXY_PORT, &[ToolName::Jq]).unwrap_err();
    assert!(matches!(err, ToolsError::Io(_)));
}

#[test]
fn tool_env_refuses_an_id_directory_that_is_a_symlink() {
    let dir = tool_env_dir();
    let elsewhere = TempDir::new().unwrap();
    symlink(elsewhere.path(), dir.path().join("job_2")).unwrap();
    let err = write_tool_env(dir.path(), "job_2", PROXY_PORT, &[ToolName::Jq]).unwrap_err();
    assert!(matches!(err, ToolsError::Io(_)));
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn tool_env_refuses_an_id_that_is_a_file_or_missing() {
    let dir = tool_env_dir();
    fs::write(dir.path().join("job_3"), b"x").unwrap();
    for id in ["job_3", "job_missing"] {
        let err = write_tool_env(dir.path(), id, PROXY_PORT, &[ToolName::Jq]).unwrap_err();
        assert!(matches!(err, ToolsError::Io(_)), "{id}");
    }
}

#[test]
fn tool_env_refuses_a_file_symlink_at_the_target_name() {
    let dir = tool_env_dir();
    let outside = TempDir::new().unwrap();
    let target = outside.path().join("victim");
    fs::write(&target, b"keep").unwrap();
    symlink(&target, dir.path().join("job_1").join(TOOL_ENV_FILE)).unwrap();
    let err = write_tool_env(dir.path(), "job_1", PROXY_PORT, &[ToolName::Jq]).unwrap_err();
    assert!(matches!(err, ToolsError::Io(_)));
    assert_eq!(fs::read(&target).unwrap(), b"keep");
}

#[test]
fn tool_hosts_are_exact_sorted_and_cover_every_tool() {
    for tool in ToolName::ALL {
        let hosts = tool_hosts(&[tool]);
        assert!(!hosts.is_empty(), "{tool}");
        for host in &hosts {
            assert!(
                host.bytes().all(|b| b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'.'
                    || b == b'-'),
                "{host}"
            );
            assert!(!host.contains('*') && !host.starts_with('.') && host.contains('.'));
        }
        assert!(hosts.windows(2).all(|w| w[0] < w[1]));
    }
    assert_eq!(tool_hosts(&[]).len(), 0);
    assert!(tool_hosts(&[ToolName::Node]).contains(&"nodejs.org"));
    assert!(!tool_hosts(&[ToolName::Jq]).contains(&"nodejs.org"));
}

#[test]
fn check_tool_hosts_accepts_a_ceiling_that_covers_the_need() {
    let mut ceiling: Vec<String> = tool_hosts(&[ToolName::Go])
        .iter()
        .map(|h| (*h).to_owned())
        .collect();
    ceiling.push("example.org".to_owned());
    check_tool_hosts(&ceiling, &[ToolName::Go]).unwrap();
}

#[test]
fn check_tool_hosts_refuses_a_missing_host() {
    let ceiling = vec!["github.com".to_owned()];
    let err = check_tool_hosts(&ceiling, &[ToolName::Node]).unwrap_err();
    assert!(matches!(err, ToolsError::HostNotAllowed));
}

#[test]
fn check_tool_hosts_refuses_hostile_entries() {
    let mut good: Vec<String> = tool_hosts(&[ToolName::Jq])
        .iter()
        .map(|h| (*h).to_owned())
        .collect();
    let rows = [
        "*.github.com",
        "*",
        ".github.com",
        "github.com\r\n",
        "github.com\n",
        "github.com\u{85}",
        "github.com\u{2028}",
        "user@github.com",
        "github.com:443",
        "github.com\\evil.com",
        "[::1]",
        "GITHUB.COM",
        " github.com",
        "github..com",
        "gíthub.com",
        "",
    ];
    for row in rows {
        good.push(row.to_owned());
        let err = check_tool_hosts(&good, &[ToolName::Jq]).unwrap_err();
        assert!(matches!(err, ToolsError::InvalidHost), "{row:?}");
        good.pop();
    }
    let long = format!("{}.com", "a".repeat(260));
    good.push(long);
    assert!(matches!(
        check_tool_hosts(&good, &[ToolName::Jq]),
        Err(ToolsError::InvalidHost)
    ));
}

fn cache_owner(dir: &Path) -> u32 {
    fs::metadata(dir).unwrap().uid()
}

fn put_entry(root: &Path, name: &str, version: &str, bytes: usize) -> PathBuf {
    let dir = root.join(name).join(version);
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(dir.join("payload"), vec![7u8; bytes]).unwrap();
    dir
}

fn entry_exists(root: &Path, name: &str, version: &str) -> bool {
    root.join(name).join(version).exists()
}

fn leftovers(root: &Path) -> Vec<String> {
    fs::read_dir(root)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with('.'))
        .collect()
}

#[test]
fn cache_miss_then_hit_after_entry_appears() {
    let tmp = TempDir::new().unwrap();
    let cache = ToolCache::new(tmp.path(), cache_owner(tmp.path()));
    assert!(cache.lookup("jq", "1.7.1").unwrap().is_none());
    let dir = put_entry(tmp.path(), "jq", "1.7.1", 4);
    let hit = cache.lookup("jq", "1.7.1").unwrap().unwrap();
    assert_eq!(hit.path(), dir.as_path());
    assert!(cache.lookup("jq", "1.7.2").unwrap().is_none());
    assert!(cache.lookup("just", "1.7.1").unwrap().is_none());
}

#[test]
fn cache_hit_works_with_a_relative_root() {
    let tmp = TempDir::new().unwrap();
    let rel = PathBuf::from(format!("target/tool-cache-rel-{}", std::process::id()));
    let _ = fs::remove_dir_all(&rel);
    fs::create_dir_all(&rel).unwrap();
    let owner = cache_owner(&rel);
    put_entry(&rel, "jq", "1.7.1", 4);
    let cache = ToolCache::new(&rel, owner);
    assert!(cache.lookup("jq", "1.7.1").unwrap().is_some());
    let report = cache
        .evict(CacheLimits {
            max_bytes: 0,
            max_entries: 8,
        })
        .unwrap();
    assert_eq!(report.evicted.len(), 1);
    assert!(!entry_exists(&rel, "jq", "1.7.1"));
    fs::remove_dir_all(&rel).unwrap();
    drop(tmp);
}

#[test]
fn cache_refuses_symlink_entry_and_symlink_name_dir() {
    let tmp = TempDir::new().unwrap();
    let owner = cache_owner(tmp.path());
    let cache = ToolCache::new(tmp.path(), owner);
    let real = put_entry(tmp.path(), "go", "1.22.0", 4);
    fs::create_dir_all(tmp.path().join("jq")).unwrap();
    symlink(&real, tmp.path().join("jq").join("1.7.1")).unwrap();
    assert!(cache.lookup("jq", "1.7.1").unwrap().is_none());
    symlink(tmp.path().join("go"), tmp.path().join("uv")).unwrap();
    assert!(cache.lookup("uv", "1.22.0").unwrap().is_none());
    assert!(cache.lookup("go", "1.22.0").unwrap().is_some());
}

#[test]
fn cache_refuses_wrong_owner_file_and_writable_entry() {
    let tmp = TempDir::new().unwrap();
    let owner = cache_owner(tmp.path());
    let dir = put_entry(tmp.path(), "jq", "1.7.1", 4);
    assert!(
        ToolCache::new(tmp.path(), owner + 1)
            .lookup("jq", "1.7.1")
            .unwrap()
            .is_none()
    );
    let cache = ToolCache::new(tmp.path(), owner);
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();
    assert!(cache.lookup("jq", "1.7.1").unwrap().is_none());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(cache.lookup("jq", "1.7.1").unwrap().is_some());
    fs::remove_dir_all(&dir).unwrap();
    fs::write(&dir, b"file").unwrap();
    assert!(cache.lookup("jq", "1.7.1").unwrap().is_none());
}

#[test]
fn cache_lookup_rejects_hostile_names_and_versions() {
    let tmp = TempDir::new().unwrap();
    let cache = ToolCache::new(tmp.path(), cache_owner(tmp.path()));
    put_entry(tmp.path(), "jq", "1.7.1", 4);
    let long_version = "1".repeat(65);
    let long_name = "j".repeat(300);
    let names = [
        "../jq",
        "jq/../jq",
        "jq/",
        "/jq",
        "jq\x00",
        "",
        "JQ",
        "Jq",
        "jq ",
        "j\u{fb}q",
        "ｊｑ",
        "..",
        ".",
        long_name.as_str(),
        "bash",
    ];
    for name in names {
        assert!(
            matches!(cache.lookup(name, "1.7.1"), Err(ToolsError::InvalidTool)),
            "{name:?}"
        );
    }
    let versions = [
        "../1.7.1",
        "1.7.1/",
        "1/../1",
        "..",
        ".",
        "1..7",
        "1.7.1\0",
        "",
        "latest",
        "1.7.x",
        "^1.7",
        "1.7.1 ",
        "1.7.\u{661}",
        "1.7.1\n",
        "1.7.1\r\n",
        long_version.as_str(),
    ];
    for version in versions {
        assert!(
            matches!(cache.lookup("jq", version), Err(ToolsError::InvalidTool)),
            "{version:?}"
        );
        assert!(matches!(
            cache.touch("jq", version, 1),
            Err(ToolsError::InvalidTool)
        ));
        assert!(matches!(
            cache.lease("jq", version),
            Err(ToolsError::InvalidTool)
        ));
    }
    let exact = "1".repeat(64);
    assert!(cache.lookup("jq", &exact).unwrap().is_none());
}

#[test]
fn cache_evicts_least_recently_used_first_until_under_the_byte_cap() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 100);
    put_entry(root, "jq", "2.0.0", 100);
    put_entry(root, "just", "1.0.0", 100);
    cache.touch("jq", "1.0.0", 30).unwrap();
    cache.touch("jq", "2.0.0", 10).unwrap();
    cache.touch("just", "1.0.0", 20).unwrap();
    let report = cache
        .evict(CacheLimits {
            max_bytes: 200 + 64,
            max_entries: 8,
        })
        .unwrap();
    assert_eq!(report.evicted.len(), 1);
    assert!(!entry_exists(root, "jq", "2.0.0"));
    assert!(entry_exists(root, "jq", "1.0.0"));
    assert!(entry_exists(root, "just", "1.0.0"));
    assert!(leftovers(root).is_empty(), "{:?}", leftovers(root));
}

#[test]
fn cache_touch_reorders_the_lru() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 10);
    put_entry(root, "jq", "2.0.0", 10);
    cache.touch("jq", "1.0.0", 5).unwrap();
    cache.touch("jq", "2.0.0", 6).unwrap();
    cache.touch("jq", "1.0.0", 7).unwrap();
    cache
        .evict(CacheLimits {
            max_bytes: u64::MAX,
            max_entries: 1,
        })
        .unwrap();
    assert!(entry_exists(root, "jq", "1.0.0"));
    assert!(!entry_exists(root, "jq", "2.0.0"));
}

#[test]
fn cache_entry_without_marker_is_oldest() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 10);
    put_entry(root, "jq", "2.0.0", 10);
    cache.touch("jq", "1.0.0", 1).unwrap();
    cache
        .evict(CacheLimits {
            max_bytes: u64::MAX,
            max_entries: 1,
        })
        .unwrap();
    assert!(entry_exists(root, "jq", "1.0.0"));
    assert!(!entry_exists(root, "jq", "2.0.0"));
}

#[test]
fn cache_touch_leaves_no_temp_file_and_ignores_atime() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    let dir = put_entry(root, "jq", "1.0.0", 10);
    cache.touch("jq", "1.0.0", 9).unwrap();
    cache.touch("jq", "1.0.0", 11).unwrap();
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&"payload".to_owned()));
    assert!(matches!(
        cache.touch("jq", "9.9.9", 1),
        Err(ToolsError::NotCached)
    ));
}

#[test]
fn cache_evicts_by_entry_count_with_exactly_the_limit_kept() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    for n in 1..=4u64 {
        let v = format!("{n}.0.0");
        put_entry(root, "uv", &v, 1);
        cache.touch("uv", &v, n).unwrap();
    }
    let at = cache
        .evict(CacheLimits {
            max_bytes: u64::MAX,
            max_entries: 4,
        })
        .unwrap();
    assert_eq!(at.evicted.len(), 0);
    let over = cache
        .evict(CacheLimits {
            max_bytes: u64::MAX,
            max_entries: 3,
        })
        .unwrap();
    assert_eq!(over.evicted.len(), 1);
    assert!(!entry_exists(root, "uv", "1.0.0"));
    assert!(entry_exists(root, "uv", "4.0.0"));
}

#[test]
fn cache_byte_cap_exact_keeps_and_one_over_evicts() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 100);
    cache.touch("jq", "1.0.0", 1).unwrap();
    let size = cache
        .evict(CacheLimits {
            max_bytes: u64::MAX,
            max_entries: 8,
        })
        .unwrap()
        .remaining_bytes;
    assert!(size >= 100);
    let at = cache
        .evict(CacheLimits {
            max_bytes: size,
            max_entries: 8,
        })
        .unwrap();
    assert_eq!(at.evicted.len(), 0);
    let over = cache
        .evict(CacheLimits {
            max_bytes: size - 1,
            max_entries: 8,
        })
        .unwrap();
    assert_eq!(over.evicted.len(), 1);
    assert_eq!(over.remaining_bytes, 0);
}

#[test]
fn cache_never_evicts_an_entry_with_a_live_lease() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 50);
    put_entry(root, "jq", "2.0.0", 50);
    cache.touch("jq", "1.0.0", 1).unwrap();
    cache.touch("jq", "2.0.0", 2).unwrap();
    let lease = cache.lease("jq", "1.0.0").unwrap();
    let busy = cache
        .evict(CacheLimits {
            max_bytes: 0,
            max_entries: 0,
        })
        .unwrap();
    assert!(entry_exists(root, "jq", "1.0.0"));
    assert!(!entry_exists(root, "jq", "2.0.0"));
    assert_eq!(busy.skipped_in_use, 1);
    assert_eq!(busy.evicted.len(), 1);
    drop(lease);
    let idle = cache
        .evict(CacheLimits {
            max_bytes: 0,
            max_entries: 0,
        })
        .unwrap();
    assert!(!entry_exists(root, "jq", "1.0.0"));
    assert_eq!(idle.skipped_in_use, 0);
    assert_eq!(idle.evicted.len(), 1);
}

#[test]
fn cache_two_leases_share_and_lease_on_a_miss_fails() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 5);
    let a = cache.lease("jq", "1.0.0").unwrap();
    let b = cache.lease("jq", "1.0.0").unwrap();
    drop(a);
    let report = cache
        .evict(CacheLimits {
            max_bytes: 0,
            max_entries: 0,
        })
        .unwrap();
    assert_eq!(report.skipped_in_use, 1);
    drop(b);
    assert!(matches!(
        cache.lease("jq", "9.9.9"),
        Err(ToolsError::NotCached)
    ));
}

#[test]
fn cache_eviction_ignores_foreign_dirs_and_sweeps_stale_aside_dirs() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    fs::create_dir_all(root.join("cache/state")).unwrap();
    fs::create_dir_all(root.join("notatool/1.0.0")).unwrap();
    fs::create_dir_all(root.join("jq/not-a-version")).unwrap();
    let stale = root.join(".evicting-jq-1.0.0-0");
    fs::create_dir_all(stale.join("x")).unwrap();
    put_entry(root, "jq", "1.0.0", 5);
    cache
        .evict(CacheLimits {
            max_bytes: 0,
            max_entries: 0,
        })
        .unwrap();
    assert!(root.join("cache/state").exists());
    assert!(root.join("notatool/1.0.0").exists());
    assert!(root.join("jq/not-a-version").exists());
    assert!(!stale.exists());
    assert!(!entry_exists(root, "jq", "1.0.0"));
}

#[test]
fn cache_default_limits_are_the_named_constants() {
    let limits = CacheLimits::default();
    assert_eq!(limits.max_bytes, MAX_CACHE_BYTES);
    assert_eq!(limits.max_entries, MAX_CACHE_ENTRIES);
}

#[test]
fn deploy_units_keep_the_cache_read_only_to_the_agent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy");
    let agent = fs::read_to_string(root.join("fleet-agent@.service")).unwrap();
    let install = fs::read_to_string(root.join("fleet-tool-install@.service")).unwrap();
    let tmpfiles = fs::read_to_string(root.join("tmpfiles.d/fleet.conf")).unwrap();
    assert!(
        agent
            .lines()
            .any(|l| l == "ReadOnlyPaths=/var/lib/fleet/tools")
    );
    assert!(
        !agent
            .lines()
            .any(|l| l.starts_with("ReadWritePaths=") && l.contains("/var/lib/fleet/tools"))
    );
    let writers: Vec<&str> = install
        .lines()
        .filter(|l| l.starts_with("ReadWritePaths="))
        .collect();
    assert_eq!(writers, ["ReadWritePaths=/var/lib/fleet/tools"]);
    assert!(
        tmpfiles
            .lines()
            .any(|l| l == "d /var/lib/fleet/tools 0750 fleet-job fleet-work -")
    );
}

#[test]
fn lease_refuses_an_entry_renamed_aside_between_open_and_lock() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 5);
    let entry = root.join("jq").join("1.0.0");
    let aside = root.join("jq").join("aside");
    let result = cache.lease_with_hook("jq", "1.0.0", || {
        fs::rename(&entry, &aside).unwrap();
    });
    assert!(matches!(result, Err(ToolsError::NotCached)));
    assert!(aside.is_dir());
    assert_eq!(fs::read_dir(&aside).unwrap().count(), 1);
}

#[test]
fn lease_refuses_an_entry_replaced_by_a_new_dir_between_open_and_lock() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 5);
    let entry = root.join("jq").join("1.0.0");
    let aside = root.join("jq").join("aside");
    let result = cache.lease_with_hook("jq", "1.0.0", || {
        fs::rename(&entry, &aside).unwrap();
        fs::create_dir(&entry).unwrap();
    });
    assert!(matches!(result, Err(ToolsError::NotCached)));
    assert!(aside.is_dir());
    assert!(entry.is_dir());
}

#[test]
fn lease_refuses_an_entry_removed_between_open_and_lock() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 5);
    let entry = root.join("jq").join("1.0.0");
    let result = cache.lease_with_hook("jq", "1.0.0", || {
        fs::remove_dir_all(&entry).unwrap();
    });
    assert!(matches!(result, Err(ToolsError::NotCached)));
    assert!(!entry.exists());
}

#[test]
fn lease_with_hook_still_leases_an_untouched_entry() {
    let tmp = TempDir::new().unwrap();
    let root = tmp.path();
    let cache = ToolCache::new(root, cache_owner(root));
    put_entry(root, "jq", "1.0.0", 5);
    assert!(cache.lease_with_hook("jq", "1.0.0", || {}).is_ok());
}
