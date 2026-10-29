//! Authenticated sealing of credentials with a key ring.
//!
//! The ciphertext is `nonce(24) || XChaCha20-Poly1305(ciphertext || tag)`. The associated
//! data binds a ciphertext to one user, credential row and kind.
//!
//! # Key file format
//!
//! One key per line as `key_id:hex`, where `hex` is exactly 64 hex digits (32 bytes) and
//! `key_id` uses only ASCII letters, digits, `-` and `_`. Blank lines are skipped. The
//! first key is the active sealing key. Every key can open.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use fleet_core::credential::CredentialKind;
use zeroize::{Zeroize, Zeroizing};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;

/// Associated data for one sealed credential: `user_id|credential_id|kind`.
#[derive(Clone, PartialEq, Eq)]
pub struct Aad(Vec<u8>);

impl Aad {
    /// Builds the associated data. The only constructor, so every caller agrees on the bytes.
    pub fn new(user_id: &str, credential_id: &str, kind: CredentialKind) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(user_id.as_bytes());
        bytes.push(b'|');
        bytes.extend_from_slice(credential_id.as_bytes());
        bytes.push(b'|');
        bytes.extend_from_slice(kind.wire_name().as_bytes());
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Aad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Aad(..)")
    }
}

/// A sealed value and the id of the key that sealed it.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// Id of the sealing key.
    pub key_id: String,
    /// Nonce followed by ciphertext and tag.
    pub ciphertext: Vec<u8>,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed")
            .field("key_id", &self.key_id)
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

/// Why sealing or opening failed. No variant says which check failed beyond its kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealError {
    /// No key with the given id is in the ring.
    UnknownKey,
    /// The ciphertext failed authentication: tampered, truncated or bound to other data.
    Open,
    /// Encryption failed.
    Seal,
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnknownKey => "unknown sealing key",
            Self::Open => "credential could not be opened",
            Self::Seal => "credential could not be sealed",
        })
    }
}

impl std::error::Error for SealError {}

/// Seals and opens credential values.
pub trait Sealer: Send + Sync {
    /// Seals `plaintext` under the active key, bound to `aad`.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::Seal`] when encryption fails.
    fn seal(&self, aad: &Aad, plaintext: &[u8]) -> Result<Sealed, SealError>;

    /// Opens `ciphertext` with the key named `key_id`.
    ///
    /// # Errors
    ///
    /// Returns [`SealError::UnknownKey`] for a missing key and [`SealError::Open`] when
    /// authentication fails.
    fn open(
        &self,
        aad: &Aad,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError>;

    /// Opens under `old_key_id` and seals again under the active key.
    ///
    /// # Errors
    ///
    /// Returns the error of [`Sealer::open`] or [`Sealer::seal`].
    fn rewrap(
        &self,
        old_ciphertext: &[u8],
        old_key_id: &str,
        aad: &Aad,
    ) -> Result<Sealed, SealError> {
        let plaintext = self.open(aad, old_key_id, old_ciphertext)?;
        self.seal(aad, &plaintext)
    }
}

/// Why a key ring file could not be loaded. Messages carry no key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyRingError {
    /// The key file does not exist.
    Missing,
    /// The key file exists but could not be read as UTF-8 text.
    Unreadable,
    /// A line is not `key_id:hex` or has an invalid key id. Carries the 1-based line.
    Malformed(usize),
    /// A key is not exactly 32 bytes. Carries the 1-based line.
    BadKeyLength(usize),
    /// Two lines share a key id. Carries the 1-based line of the second.
    DuplicateKeyId(usize),
    /// The file holds no keys.
    Empty,
}

impl fmt::Display for KeyRingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => f.write_str("key file is missing"),
            Self::Unreadable => f.write_str("key file is unreadable"),
            Self::Malformed(n) => write!(f, "key file line {n} is malformed"),
            Self::BadKeyLength(n) => write!(f, "key file line {n} is not a 32 byte key"),
            Self::DuplicateKeyId(n) => write!(f, "key file line {n} repeats a key id"),
            Self::Empty => f.write_str("key file holds no keys"),
        }
    }
}

impl std::error::Error for KeyRingError {}

struct KeyBytes([u8; KEY_LEN]);

impl Drop for KeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// A sealer backed by a key ring read from a file.
pub struct FileSealer {
    active: String,
    keys: HashMap<String, KeyBytes>,
}

impl fmt::Debug for FileSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileSealer")
            .field("active", &self.active)
            .field("keys", &self.keys.len())
            .finish()
    }
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl FileSealer {
    /// Loads the key ring at `path`.
    ///
    /// # Errors
    ///
    /// Returns a [`KeyRingError`] for a missing or unreadable file, a malformed line, a key
    /// that is not 32 bytes, a repeated key id or an empty ring.
    pub fn load(path: &Path) -> Result<Self, KeyRingError> {
        let raw = std::fs::read(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KeyRingError::Missing
            } else {
                KeyRingError::Unreadable
            }
        })?;
        let raw = Zeroizing::new(raw);
        let text = std::str::from_utf8(&raw).map_err(|_| KeyRingError::Unreadable)?;
        Self::parse(text)
    }

    fn parse(text: &str) -> Result<Self, KeyRingError> {
        let mut active: Option<String> = None;
        let mut keys: HashMap<String, KeyBytes> = HashMap::new();
        for (idx, line) in text.lines().enumerate() {
            let n = idx + 1;
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let (id, hex) = line.split_once(':').ok_or(KeyRingError::Malformed(n))?;
            if !valid_key_id(id) {
                return Err(KeyRingError::Malformed(n));
            }
            let hex = hex.as_bytes();
            if !hex.iter().all(u8::is_ascii_hexdigit) {
                return Err(KeyRingError::Malformed(n));
            }
            if hex.len() != KEY_LEN * 2 {
                return Err(KeyRingError::BadKeyLength(n));
            }
            if keys.contains_key(id) {
                return Err(KeyRingError::DuplicateKeyId(n));
            }
            let mut key = KeyBytes([0; KEY_LEN]);
            for (slot, &[h, l]) in key.0.iter_mut().zip(hex.as_chunks::<2>().0) {
                let hi = hex_val(h).ok_or(KeyRingError::Malformed(n))?;
                let lo = hex_val(l).ok_or(KeyRingError::Malformed(n))?;
                *slot = hi << 4 | lo;
            }
            if active.is_none() {
                active = Some(id.to_owned());
            }
            keys.insert(id.to_owned(), key);
        }
        let active = active.ok_or(KeyRingError::Empty)?;
        Ok(Self { active, keys })
    }

    /// Id of the key new seals use.
    pub fn active_key_id(&self) -> &str {
        &self.active
    }

    fn cipher(&self, key_id: &str) -> Result<XChaCha20Poly1305, SealError> {
        let key = self.keys.get(key_id).ok_or(SealError::UnknownKey)?;
        Ok(XChaCha20Poly1305::new(Key::from_slice(&key.0)))
    }
}

impl Sealer for FileSealer {
    fn seal(&self, aad: &Aad, plaintext: &[u8]) -> Result<Sealed, SealError> {
        let cipher = self.cipher(&self.active)?;
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let body = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| SealError::Seal)?;
        let mut ciphertext = Vec::with_capacity(NONCE_LEN + body.len());
        ciphertext.extend_from_slice(&nonce);
        ciphertext.extend_from_slice(&body);
        Ok(Sealed {
            key_id: self.active.clone(),
            ciphertext,
        })
    }

    fn open(
        &self,
        aad: &Aad,
        key_id: &str,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, SealError> {
        let cipher = self.cipher(key_id)?;
        if ciphertext.len() < NONCE_LEN {
            return Err(SealError::Open);
        }
        let (nonce, body) = ciphertext.split_at(NONCE_LEN);
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: aad.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| SealError::Open)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::fmt::Write as _;

    use super::*;

    fn hex_key(byte: u8) -> String {
        let mut s = String::new();
        for _ in 0..KEY_LEN {
            write!(s, "{byte:02x}").unwrap_or_default();
        }
        s
    }

    fn ring(lines: &[(&str, u8)]) -> FileSealer {
        let mut text = String::new();
        for (id, b) in lines {
            writeln!(text, "{id}:{}", hex_key(*b)).unwrap_or_default();
        }
        FileSealer::parse(&text).unwrap()
    }

    fn aad() -> Aad {
        Aad::new("u1", "c1", CredentialKind::GithubPat)
    }

    #[test]
    fn round_trip() {
        let s = ring(&[("k1", 1)]);
        let sealed = s.seal(&aad(), b"hunter2-secret").unwrap();
        assert_eq!(sealed.key_id, "k1");
        let open = s.open(&aad(), "k1", &sealed.ciphertext).unwrap();
        assert_eq!(open.as_slice(), b"hunter2-secret");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let s = ring(&[("k1", 1)]);
        let mut sealed = s.seal(&aad(), b"value").unwrap();
        for i in [0, NONCE_LEN, sealed.ciphertext.len() - 1] {
            let mut c = sealed.ciphertext.clone();
            c[i] ^= 1;
            assert_eq!(s.open(&aad(), "k1", &c).unwrap_err(), SealError::Open);
        }
        sealed.ciphertext.truncate(10);
        assert_eq!(
            s.open(&aad(), "k1", &sealed.ciphertext).unwrap_err(),
            SealError::Open
        );
    }

    #[test]
    fn wrong_aad_fails() {
        let s = ring(&[("k1", 1)]);
        let sealed = s.seal(&aad(), b"value").unwrap();
        for other in [
            Aad::new("u2", "c1", CredentialKind::GithubPat),
            Aad::new("u1", "c2", CredentialKind::GithubPat),
            Aad::new("u1", "c1", CredentialKind::CodexApiKey),
        ] {
            assert_eq!(
                s.open(&other, "k1", &sealed.ciphertext).unwrap_err(),
                SealError::Open
            );
        }
    }

    #[test]
    fn unknown_key_id_fails() {
        let s = ring(&[("k1", 1)]);
        let sealed = s.seal(&aad(), b"value").unwrap();
        assert_eq!(
            s.open(&aad(), "nope", &sealed.ciphertext).unwrap_err(),
            SealError::UnknownKey
        );
    }

    #[test]
    fn rotation_opens_old_and_rewrap_moves_to_active() {
        let old = ring(&[("k1", 1)]);
        let sealed = old.seal(&aad(), b"value").unwrap();
        let new = ring(&[("k2", 2), ("k1", 1)]);
        assert_eq!(new.active_key_id(), "k2");
        let open = new.open(&aad(), "k1", &sealed.ciphertext).unwrap();
        assert_eq!(open.as_slice(), b"value");
        assert_eq!(new.seal(&aad(), b"x").unwrap().key_id, "k2");
        let moved = new.rewrap(&sealed.ciphertext, "k1", &aad()).unwrap();
        assert_eq!(moved.key_id, "k2");
        let only_new = ring(&[("k2", 2)]);
        let open = only_new.open(&aad(), "k2", &moved.ciphertext).unwrap();
        assert_eq!(open.as_slice(), b"value");
    }

    #[test]
    fn rewrap_with_wrong_aad_fails() {
        let s = ring(&[("k2", 2), ("k1", 1)]);
        let old = ring(&[("k1", 1)]).seal(&aad(), b"v").unwrap();
        let other = Aad::new("u9", "c1", CredentialKind::GithubPat);
        assert_eq!(
            s.rewrap(&old.ciphertext, "k1", &other).unwrap_err(),
            SealError::Open
        );
    }

    #[test]
    fn short_key_is_rejected() {
        assert_eq!(
            FileSealer::parse("k1:abcd\n").unwrap_err(),
            KeyRingError::BadKeyLength(1)
        );
        let long = format!("k1:{}00\n", hex_key(1));
        assert_eq!(
            FileSealer::parse(&long).unwrap_err(),
            KeyRingError::BadKeyLength(1)
        );
    }

    #[test]
    fn malformed_lines_are_rejected() {
        assert_eq!(
            FileSealer::parse("nocolon\n").unwrap_err(),
            KeyRingError::Malformed(1)
        );
        assert_eq!(
            FileSealer::parse(&format!("k1:{}zz\n", &hex_key(1)[2..])).unwrap_err(),
            KeyRingError::Malformed(1)
        );
        assert_eq!(
            FileSealer::parse(&format!(":{}\n", hex_key(1))).unwrap_err(),
            KeyRingError::Malformed(1)
        );
    }

    #[test]
    fn empty_ring_is_rejected() {
        assert_eq!(FileSealer::parse("").unwrap_err(), KeyRingError::Empty);
        assert_eq!(FileSealer::parse("\n \n").unwrap_err(), KeyRingError::Empty);
    }

    #[test]
    fn duplicate_key_id_is_rejected() {
        let text = format!("k1:{}\nk1:{}\n", hex_key(1), hex_key(2));
        assert_eq!(
            FileSealer::parse(&text).unwrap_err(),
            KeyRingError::DuplicateKeyId(2)
        );
    }

    #[test]
    fn missing_file_is_rejected() {
        let dir = std::env::temp_dir().join("fleet-seal-no-such-file");
        assert_eq!(FileSealer::load(&dir).unwrap_err(), KeyRingError::Missing);
    }

    #[test]
    fn load_reads_a_file() {
        let path = std::env::temp_dir().join(format!("fleet-seal-load-{}", std::process::id()));
        std::fs::write(&path, format!("k1:{}\n", hex_key(7))).unwrap();
        let loaded = FileSealer::load(&path);
        std::fs::remove_file(&path).unwrap();
        assert_eq!(loaded.unwrap().active_key_id(), "k1");
    }

    #[test]
    fn nonces_are_unique_over_10k_seals() {
        let s = ring(&[("k1", 1)]);
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            let sealed = s.seal(&aad(), b"value").unwrap();
            let prefix: [u8; NONCE_LEN] = sealed.ciphertext[..NONCE_LEN].try_into().unwrap();
            assert!(seen.insert(prefix));
        }
        assert_eq!(seen.len(), 10_000);
    }

    #[test]
    fn debug_prints_no_secret() {
        let s = ring(&[("k1", 0xab)]);
        let sealed = s.seal(&aad(), b"plaintext-marker").unwrap();
        let shown = format!("{s:?} {sealed:?} {:?}", aad());
        assert!(!shown.contains("abab"));
        assert!(!shown.contains("plaintext-marker"));
        assert!(!shown.contains("u1"));
        let ct = format!("{:?}", sealed.ciphertext);
        assert!(!shown.contains(&ct));
    }
}
