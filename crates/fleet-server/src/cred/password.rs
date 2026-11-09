//! The bootstrap password: an argon2id verifier for the first admin's setup (ADR-0042).
//!
//! The server hashes the plaintext once at startup and drops it. Verification runs in
//! `spawn_blocking` behind a semaphore so a flood of guesses cannot starve the runtime. A
//! disarmed verifier, one with no hash or one whose caller says setup is closed, still
//! verifies against a fixed decoy hash, so those states cost the same hashing work. A candidate
//! with a bad shape, or one that finds every permit busy, is refused without hashing.

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::OsRng;
use tokio::sync::Semaphore;

/// The longest accepted password in bytes. Longer input is refused before any hashing.
pub const MAX_PASSWORD_LEN: usize = 128;

/// Argon2id memory cost in KiB (19 MiB, the OWASP minimum for `t = 2`).
pub const ARGON_MEMORY_KIB: u32 = 19_456;

/// Argon2id iteration count.
pub const ARGON_ITERATIONS: u32 = 2;

/// Argon2id parallelism.
pub const ARGON_LANES: u32 = 1;

/// How many verifications may run at once.
pub const VERIFY_PERMITS: usize = 2;

const DECOY_SALT: &str = "ZGVjb3lzYWx0ZGVjb3k";
const DECOY_PASSWORD: &[u8] = b"decoy-password-never-matches";

static DECOY: LazyLock<String> = LazyLock::new(|| {
    let hashed = SaltString::from_b64(DECOY_SALT)
        .map_err(|_| PasswordError::Hash)
        .and_then(|salt| {
            hasher()?
                .hash_password(DECOY_PASSWORD, &salt)
                .map(|hash| hash.to_string())
                .map_err(|_| PasswordError::Hash)
        });
    hashed.unwrap_or_default()
});

/// Why a password could not be set up. Messages are fixed text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordError {
    /// The text is empty, longer than [`MAX_PASSWORD_LEN`] or has a character outside
    /// printable ASCII without spaces.
    Shape,
    /// Hashing failed.
    Hash,
}

impl fmt::Display for PasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Shape => {
                "the bootstrap password must be 1 to 128 printable ASCII characters with no spaces"
            }
            Self::Hash => "the bootstrap password could not be hashed",
        })
    }
}

impl std::error::Error for PasswordError {}

fn hasher() -> Result<Argon2<'static>, PasswordError> {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_ITERATIONS, ARGON_LANES, None)
        .map_err(|_| PasswordError::Hash)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Whether `candidate` has an acceptable shape: 1 to [`MAX_PASSWORD_LEN`] bytes, each
/// printable ASCII and not a space. This refuses NUL, CR, LF, tabs, other whitespace and
/// all non-ASCII text.
#[must_use]
pub fn shape_ok(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= MAX_PASSWORD_LEN
        && candidate.bytes().all(|b| b.is_ascii_graphic())
}

fn hash_blocking(plain: &str) -> Result<String, PasswordError> {
    if !shape_ok(plain) {
        return Err(PasswordError::Shape);
    }
    let salt = SaltString::generate(&mut OsRng);
    hasher()?
        .hash_password(plain.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| PasswordError::Hash)
}

fn verify_blocking(phc: &str, candidate: &[u8]) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    hasher().is_ok_and(|argon| argon.verify_password(candidate, &parsed).is_ok())
}

/// An argon2id verifier for the bootstrap password. The plaintext is not kept.
#[derive(Clone)]
pub struct BootstrapPassword {
    phc: Option<Arc<str>>,
    permits: Arc<Semaphore>,
    hash_runs: Arc<AtomicUsize>,
}

impl fmt::Debug for BootstrapPassword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BootstrapPassword(..)")
    }
}

impl BootstrapPassword {
    /// A verifier with no password. Every verification fails after the decoy hash.
    #[must_use]
    pub fn disarmed() -> Self {
        Self {
            phc: None,
            permits: Arc::new(Semaphore::new(VERIFY_PERMITS)),
            hash_runs: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Hashes `plain` with argon2id and a random salt, then drops it.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordError::Shape`] for an unacceptable password and
    /// [`PasswordError::Hash`] when hashing fails.
    pub async fn from_plaintext(plain: String) -> Result<Self, PasswordError> {
        let phc = tokio::task::spawn_blocking(move || hash_blocking(&plain))
            .await
            .map_err(|_| PasswordError::Hash)??;
        Ok(Self {
            phc: Some(Arc::from(phc)),
            permits: Arc::new(Semaphore::new(VERIFY_PERMITS)),
            hash_runs: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// How many verifications have started a hash, counted across clones.
    #[must_use]
    pub fn hash_runs(&self) -> usize {
        self.hash_runs.load(Ordering::SeqCst)
    }

    /// The PHC string of the stored hash, `None` when disarmed.
    #[must_use]
    pub fn phc(&self) -> Option<&str> {
        self.phc.as_deref()
    }

    /// Verifies `candidate`. True only when `armed` is true, a hash exists and it matches.
    ///
    /// A candidate with a bad shape is refused without hashing, and so is one that finds
    /// all [`VERIFY_PERMITS`] busy: the wait never queues. Otherwise the work is the
    /// same whether `armed` is set or a hash exists: a decoy hash stands in when either is
    /// missing.
    pub async fn verify(&self, candidate: &str, armed: bool) -> bool {
        if !shape_ok(candidate) {
            return false;
        }
        let Ok(_permit) = self.permits.try_acquire() else {
            return false;
        };
        self.hash_runs.fetch_add(1, Ordering::SeqCst);
        let real = armed.then(|| self.phc.clone()).flatten();
        let used = real.clone();
        let candidate = candidate.as_bytes().to_vec();
        let matched = tokio::task::spawn_blocking(move || {
            let phc = used.as_deref().unwrap_or_else(|| DECOY.as_str());
            verify_blocking(phc, &candidate)
        })
        .await
        .unwrap_or(false);
        matched && real.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "Zx9-correct-horse-battery";

    async fn armed() -> BootstrapPassword {
        BootstrapPassword::from_plaintext(PASSWORD.to_owned())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_hash_is_argon2id_with_the_pinned_params_and_hides_the_plaintext() {
        let password = armed().await;
        let phc = password.phc().unwrap();
        let prefix =
            format!("$argon2id$v=19$m={ARGON_MEMORY_KIB},t={ARGON_ITERATIONS},p={ARGON_LANES}$");
        assert!(phc.starts_with(&prefix), "{phc}");
        assert!(!phc.contains(PASSWORD));
        assert!(!format!("{password:?}").contains(PASSWORD));
        let other = armed().await;
        assert_ne!(phc, other.phc().unwrap(), "each hash has its own salt");
    }

    #[tokio::test]
    async fn the_right_password_verifies_only_while_armed() {
        let password = armed().await;
        assert!(password.verify(PASSWORD, true).await);
        assert!(!password.verify(PASSWORD, false).await);
        assert!(!password.verify("Zx9-correct-horse-batterz", true).await);
    }

    #[tokio::test]
    async fn attempts_beyond_the_permits_are_refused_without_hashing() {
        let password = armed().await;
        let held: Vec<_> = (0..VERIFY_PERMITS)
            .map(|_| Arc::clone(&password.permits).try_acquire_owned().unwrap())
            .collect();
        let busy = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            password.verify(PASSWORD, true),
        )
        .await;
        assert_eq!(busy, Ok(false));
        assert_eq!(password.hash_runs(), 0);
        drop(held);
        assert!(password.verify(PASSWORD, true).await);
        assert_eq!(password.hash_runs(), 1);
    }

    #[tokio::test]
    async fn a_burst_over_the_permits_never_queues() {
        let password = armed().await;
        let waiting = (0..VERIFY_PERMITS)
            .map(|_| Arc::clone(&password.permits).try_acquire_owned().unwrap())
            .collect::<Vec<_>>();
        let burst: Vec<_> = (0..12)
            .map(|_| {
                let password = password.clone();
                tokio::spawn(async move { password.verify(PASSWORD, true).await })
            })
            .collect();
        for task in burst {
            assert!(
                !tokio::time::timeout(std::time::Duration::from_secs(5), task)
                    .await
                    .unwrap()
                    .unwrap()
            );
        }
        assert_eq!(password.hash_runs(), 0);
        drop(waiting);
    }

    #[tokio::test]
    async fn a_disarmed_verifier_refuses_everything_after_the_decoy() {
        let password = BootstrapPassword::disarmed();
        assert!(password.phc().is_none());
        assert!(!password.verify(PASSWORD, true).await);
        assert!(!password.verify(DECOY_PASSWORD_TEXT, true).await);
    }

    const DECOY_PASSWORD_TEXT: &str = "decoy-password-never-matches";

    #[test]
    fn the_decoy_is_a_valid_hash_with_the_pinned_params() {
        assert!(
            DECOY.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{}",
            *DECOY
        );
    }

    #[test]
    fn the_shape_table() {
        let long = "a".repeat(MAX_PASSWORD_LEN + 1);
        let max = "a".repeat(MAX_PASSWORD_LEN);
        let hostile = [
            "",
            " ",
            "pass word",
            " leading",
            "trailing ",
            "tab\there",
            "nul\0byte",
            "cr\rhere",
            "lf\nhere",
            "crlf\r\nhere",
            "caf\u{e9}",
            "line\u{2028}sep",
            "nel\u{85}here",
            "pw\u{a0}nbsp",
            "emoji\u{1f511}",
            long.as_str(),
        ];
        for bad in hostile {
            assert!(!shape_ok(bad), "{bad:?}");
        }
        for good in ["a", "Zx9-correct", "!~", max.as_str()] {
            assert!(shape_ok(good), "{good:?}");
        }
    }

    #[tokio::test]
    async fn a_hostile_plaintext_cannot_arm_the_verifier() {
        for bad in [
            "",
            "has space",
            "nul\0",
            "caf\u{e9}",
            &"a".repeat(MAX_PASSWORD_LEN + 1),
        ] {
            assert_eq!(
                BootstrapPassword::from_plaintext(bad.to_owned())
                    .await
                    .unwrap_err(),
                PasswordError::Shape,
                "{bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn hostile_candidates_never_verify() {
        let password = armed().await;
        for bad in [
            "",
            "Zx9-correct-horse-battery\n",
            "Zx9-correct-horse-battery\r\n",
            "Zx9-correct-horse-battery\0",
            " Zx9-correct-horse-battery",
            "ZX9-CORRECT-HORSE-BATTERY",
        ] {
            assert!(!password.verify(bad, true).await, "{bad:?}");
        }
    }
}
