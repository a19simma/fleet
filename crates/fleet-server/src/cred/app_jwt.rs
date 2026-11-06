//! GitHub App key loading and RS256 JWT signing (ADR-0058, SEC-007, SEC-013, SEC-020).
//!
//! JWT `Debug` redaction (SEC-020) is deferred until the JWT is wired.
//!
//! Built, not wired: no runtime path calls this module yet.
//!
//! Key bytes are read into a preallocated `Zeroizing` buffer so growth never leaves unwiped
//! copies, and the DER moves out of the parsed PEM into a `Zeroizing` buffer. Not zeroized: the
//! `pem` crate's internal base64 decode scratch and line handling while `pem::parse` runs, and
//! the key material `ring` holds inside `RsaKeyPair`.

use std::fmt;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use ring::rand::SystemRandom;
use ring::signature::RsaKeyPair;
use zeroize::Zeroizing;

const IAT_BACKDATE_SECS: u64 = 60;
const EXP_AHEAD_SECS: u64 = 540;
const MAX_KEY_FILE_BYTES: u64 = 16 * 1024;
const HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Why an App key could not be loaded. Messages are fixed and never carry key or path text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKeyError {
    /// The key file could not be read.
    Read,
    /// The key file is readable by group or other.
    Mode,
    /// The key path is not a regular file.
    NotFile,
    /// The file is over 16 KiB, or is not a PEM RSA private key `ring` accepts.
    Key,
}

impl fmt::Display for AppKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "github app key file unreadable",
            Self::Mode => "github app key file must not be group or other accessible",
            Self::NotFile => "github app key path is not a regular file",
            Self::Key => "github app key is not a PEM RSA private key of at least 2048 bits",
        })
    }
}

impl std::error::Error for AppKeyError {}

/// Why a JWT could not be signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The clock is earlier than the 60 second backdate.
    Clock,
    /// The signature operation failed.
    Sign,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Clock => "github app jwt clock out of range",
            Self::Sign => "github app jwt signing failed",
        })
    }
}

impl std::error::Error for SignError {}

/// The parsed GitHub App private key, held for the life of the process.
pub struct AppKey {
    pair: RsaKeyPair,
}

impl fmt::Debug for AppKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppKey(..)")
    }
}

impl AppKey {
    /// Loads a PKCS#1 or PKCS#8 RSA PEM key from `path`.
    ///
    /// Refuses a path that is not a regular file, a file that group or other can access
    /// (`mode & 0o077`), anything that is not RSA, and RSA under 2048 bits. Symlinks are
    /// followed because Kubernetes Secret mounts are symlinks. The file should be owned by the
    /// server's uid and writable by no one else. The file bytes live in a preallocated
    /// `Zeroizing` buffer while parsing.
    ///
    /// # Errors
    ///
    /// Returns [`AppKeyError`]:
    /// - `Read` when the file cannot be opened or read.
    /// - `NotFile` when the path is not a regular file.
    /// - `Mode` when group or other can access the file.
    /// - `Key` when the file is over 16 KiB or holds no usable RSA key (`ring` accepts RSA 2048 to 8192 bits).
    pub fn load(path: &Path) -> Result<Self, AppKeyError> {
        let mut file = std::fs::File::open(path).map_err(|_| AppKeyError::Read)?;
        let meta = file.metadata().map_err(|_| AppKeyError::Read)?;
        if !meta.is_file() {
            return Err(AppKeyError::NotFile);
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(AppKeyError::Mode);
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(
            usize::try_from(MAX_KEY_FILE_BYTES).map_err(|_| AppKeyError::Read)? + 1,
        ));
        file.by_ref()
            .take(MAX_KEY_FILE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AppKeyError::Read)?;
        if bytes.len() as u64 > MAX_KEY_FILE_BYTES {
            return Err(AppKeyError::Key);
        }
        let parsed = pem::parse(bytes.as_slice()).map_err(|_| AppKeyError::Key)?;
        let tag = parsed.tag().to_owned();
        let der = Zeroizing::new(parsed.into_contents());
        let pair = match tag.as_str() {
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
            _ => return Err(AppKeyError::Key),
        }
        .map_err(|_| AppKeyError::Key)?;
        Ok(Self { pair })
    }

    /// Signs an RS256 JWT with `iat = now - 60`, `exp = now + 540` and `iss = app_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SignError`]:
    /// - `Clock` when `now` is under 60 or `now + 540` overflows `u64`.
    /// - `Sign` when the signature or the claim serialisation fails.
    pub fn sign(&self, app_id: &str, now: u64) -> Result<Zeroizing<String>, SignError> {
        let iat = now.checked_sub(IAT_BACKDATE_SECS).ok_or(SignError::Clock)?;
        let exp = now.checked_add(EXP_AHEAD_SECS).ok_or(SignError::Clock)?;
        let iss = serde_json::to_string(app_id).map_err(|_| SignError::Sign)?;
        let claims = format!("{{\"iat\":{iat},\"exp\":{exp},\"iss\":{iss}}}");
        let mut jwt = Zeroizing::new(String::with_capacity(1024));
        b64url(HEADER.as_bytes(), &mut jwt);
        jwt.push('.');
        b64url(claims.as_bytes(), &mut jwt);
        let mut sig = vec![0_u8; self.pair.public().modulus_len()];
        self.pair
            .sign(
                &ring::signature::RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                jwt.as_bytes(),
                &mut sig,
            )
            .map_err(|_| SignError::Sign)?;
        jwt.push('.');
        b64url(&sig, &mut jwt);
        Ok(jwt)
    }
}

fn b64url(input: &[u8], out: &mut String) {
    for chunk in input.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0_u32, |acc, (i, b)| acc | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=chunk.len() {
            let idx = ((n >> (18 - 6 * i)) & 63) as usize;
            out.push(char::from(B64URL.get(idx).copied().unwrap_or(b'=')));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        dir: std::path::PathBuf,
    }

    impl Fixture {
        fn new(tag: &str) -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir =
                std::env::temp_dir().join(format!("fleet-appjwt-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            Self { dir }
        }
        fn file(&self, bytes: &[u8], mode: u32) -> std::path::PathBuf {
            let p = self.dir.join("key.pem");
            let _ = std::fs::remove_file(&p);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn rsa(bits: u32) -> Rsa<openssl::pkey::Private> {
        Rsa::generate(bits).unwrap()
    }

    fn b64url_decode(s: &str) -> Vec<u8> {
        let mut t = s.replace('-', "+").replace('_', "/");
        while !t.len().is_multiple_of(4) {
            t.push('=');
        }
        openssl::base64::decode_block(&t).unwrap()
    }

    const NOW: u64 = 1_700_000_000;

    fn loaded(pem: &[u8]) -> (Fixture, Result<AppKey, AppKeyError>) {
        let fx = Fixture::new("load");
        let p = fx.file(pem, 0o400);
        let r = AppKey::load(&p);
        (fx, r)
    }

    #[test]
    fn signs_verifiable_rs256_jwt_with_exact_header_and_claims() {
        let key = rsa(2048);
        let (_fx, r) = loaded(&key.private_key_to_pem().unwrap());
        let jwt = r.unwrap().sign("12345", NOW).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(b64url_decode(parts[0]), br#"{"alg":"RS256","typ":"JWT"}"#);
        assert_eq!(
            String::from_utf8(b64url_decode(parts[1])).unwrap(),
            format!(
                r#"{{"iat":{},"exp":{},"iss":"12345"}}"#,
                NOW - 60,
                NOW + 540
            )
        );
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let public = key.public_key_to_der_pkcs1().unwrap();
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            public,
        )
        .verify(signing_input.as_bytes(), &b64url_decode(parts[2]))
        .unwrap();
        assert!(!jwt.contains('=') && !jwt.contains('+') && !jwt.contains('/'));
    }

    #[test]
    fn exp_is_at_most_540_seconds_after_now_and_span_is_600() {
        let (_fx, r) = loaded(&rsa(2048).private_key_to_pem().unwrap());
        let jwt = r.unwrap().sign("1", NOW).unwrap();
        let claims = b64url_decode(jwt.split('.').nth(1).unwrap());
        let v: serde_json::Value = serde_json::from_slice(&claims).unwrap();
        let (iat, exp) = (v["iat"].as_u64().unwrap(), v["exp"].as_u64().unwrap());
        assert_eq!(exp - iat, 600);
        assert!(exp - NOW <= 540 && iat < NOW);
    }

    #[test]
    fn iss_is_json_escaped() {
        let (_fx, r) = loaded(&rsa(2048).private_key_to_pem().unwrap());
        let jwt = r.unwrap().sign("a\"b", NOW).unwrap();
        let claims = String::from_utf8(b64url_decode(jwt.split('.').nth(1).unwrap())).unwrap();
        assert!(claims.ends_with(r#""iss":"a\"b"}"#));
    }

    #[test]
    fn clock_before_backdate_is_refused() {
        let (_fx, r) = loaded(&rsa(2048).private_key_to_pem().unwrap());
        let k = r.unwrap();
        assert_eq!(k.sign("1", 59).unwrap_err(), SignError::Clock);
        assert!(k.sign("1", 60).is_ok());
    }

    #[test]
    fn loads_pkcs8_pem() {
        let key = PKey::from_rsa(rsa(2048)).unwrap();
        let (_fx, r) = loaded(&key.private_key_to_pem_pkcs8().unwrap());
        assert!(r.unwrap().sign("1", NOW).is_ok());
    }

    #[test]
    fn garbage_ec_small_and_encrypted_keys_are_refused() {
        let ec =
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap();
        let ec_pem = ec.private_key_to_pem().unwrap();
        let ec8 = PKey::from_ec_key(ec)
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        let small = rsa(1024);
        let small1 = small.private_key_to_pem().unwrap();
        let small8 = PKey::from_rsa(small)
            .unwrap()
            .private_key_to_pem_pkcs8()
            .unwrap();
        let enc = PKey::from_rsa(rsa(2048))
            .unwrap()
            .private_key_to_pem_pkcs8_passphrase(openssl::symm::Cipher::aes_256_cbc(), b"pw")
            .unwrap();
        let bad_body =
            b"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n".to_vec();
        for (name, pem) in [
            ("garbage", b"hunter2 not a pem".to_vec()),
            ("empty", Vec::new()),
            ("ec", ec_pem),
            ("ec8", ec8),
            ("small", small1),
            ("small8", small8),
            ("enc", enc),
            ("badbody", bad_body),
        ] {
            let (_fx, r) = loaded(&pem);
            assert_eq!(r.unwrap_err(), AppKeyError::Key, "{name}");
        }
    }

    #[test]
    fn loose_modes_are_refused_before_parsing() {
        let pem = rsa(2048).private_key_to_pem().unwrap();
        let fx = Fixture::new("modes");
        for mode in [0o644, 0o640, 0o604, 0o660, 0o666, 0o440, 0o404] {
            let p = fx.file(&pem, mode);
            assert_eq!(AppKey::load(&p).unwrap_err(), AppKeyError::Mode, "{mode:o}");
        }
        for mode in [0o400, 0o600, 0o700] {
            let p = fx.file(&pem, mode);
            assert!(AppKey::load(&p).is_ok(), "{mode:o}");
        }
    }

    #[test]
    fn key_file_size_cap_is_exact() {
        let mut pem = rsa(2048).private_key_to_pem().unwrap();
        pem.resize(usize::try_from(MAX_KEY_FILE_BYTES).unwrap(), b'\n');
        let fx = Fixture::new("cap");
        let p = fx.file(&pem, 0o400);
        assert!(AppKey::load(&p).is_ok());
        pem.push(b'\n');
        let p = fx.file(&pem, 0o400);
        assert_eq!(AppKey::load(&p).unwrap_err(), AppKeyError::Key);
    }

    #[test]
    fn directory_path_is_refused_as_not_a_file() {
        let fx = Fixture::new("dir");
        assert_eq!(AppKey::load(&fx.dir).unwrap_err(), AppKeyError::NotFile);
    }

    #[test]
    fn loose_mode_with_garbage_content_reports_mode() {
        let fx = Fixture::new("modegarbage");
        let p = fx.file(b"garbage", 0o644);
        assert_eq!(AppKey::load(&p).unwrap_err(), AppKeyError::Mode);
    }

    #[test]
    fn missing_file_is_read_error_without_path_text() {
        let fx = Fixture::new("missing-secretpath");
        let p = fx.dir.join("absent-secretname.pem");
        let e = AppKey::load(&p).unwrap_err();
        assert_eq!(e, AppKeyError::Read);
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains("secretpath") && !shown.contains("secretname"));
    }

    #[test]
    fn errors_never_echo_key_content_or_path() {
        let fx = Fixture::new("echo-secretdir");
        let p = fx.file(
            b"-----BEGIN RSA PRIVATE KEY-----\nSECRETBODY\n-----END RSA PRIVATE KEY-----\n",
            0o400,
        );
        let e = AppKey::load(&p).unwrap_err();
        let shown = format!("{e} {e:?}");
        assert!(
            !shown.contains("SECRETBODY")
                && !shown.contains("secretdir")
                && !shown.contains("key.pem")
        );
    }

    #[test]
    fn debug_is_redacted() {
        let (_fx, r) = loaded(&rsa(2048).private_key_to_pem().unwrap());
        assert_eq!(format!("{:?}", r.unwrap()), "AppKey(..)");
    }

    #[test]
    fn jwt_never_appears_in_errors() {
        let (_fx, r) = loaded(&rsa(2048).private_key_to_pem().unwrap());
        let k = r.unwrap();
        let jwt = k.sign("1", NOW).unwrap();
        let e = k.sign("1", 1).unwrap_err();
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains(jwt.as_str()));
        assert!(!format!("{:?}", SignError::Sign).contains('.'));
    }
}
