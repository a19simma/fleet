use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Error;

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const ID_LEN: usize = 26;
const ENTROPY_BITS: u32 = 80;
const FNV_OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
const FNV_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013B;

/// A 128-bit event id rendered as a 26 character ULID-shaped string.
///
/// Random ids carry a millisecond timestamp prefix and 80 bits of caller supplied
/// entropy. Derived ids are an FNV-1a 128 hash of the event kind and its natural key,
/// so a restarted watcher produces the same id for the same fact (ADR-0012). Derived ids
/// have no time ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventId(u128);

impl EventId {
    /// Builds a random-style id from a millisecond timestamp and caller supplied entropy.
    ///
    /// Only the low 48 bits of the timestamp and the low 80 bits of the entropy are kept.
    pub fn new(timestamp_ms: u64, entropy: u128) -> Self {
        let ts = u128::from(timestamp_ms) & ((1 << 48) - 1);
        let rand = entropy & ((1 << ENTROPY_BITS) - 1);
        Self((ts << ENTROPY_BITS) | rand)
    }

    /// Derives a stable id from an event kind and the parts of its natural key.
    ///
    /// Each part is length prefixed, so `["ab", "c"]` and `["a", "bc"]` differ.
    pub fn derive(kind: &str, parts: &[&str]) -> Self {
        let mut hash = FNV_OFFSET;
        for part in std::iter::once(&kind).chain(parts) {
            for byte in (part.len() as u64)
                .to_le_bytes()
                .iter()
                .chain(part.as_bytes())
            {
                hash ^= u128::from(*byte);
                hash = hash.wrapping_mul(FNV_PRIME);
            }
        }
        Self(hash)
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut out = [0u8; ID_LEN];
        for (i, slot) in out.iter_mut().enumerate() {
            let shift = 5 * (ID_LEN - 1 - i);
            let index = usize::try_from((self.0 >> shift) & 31).unwrap_or(0);
            *slot = ALPHABET.get(index).copied().unwrap_or(b'0');
        }
        f.write_str(&String::from_utf8_lossy(&out))
    }
}

/// Parses the 26 character form. Lowercase input is accepted and canonicalized: the
/// parsed id displays in uppercase.
impl FromStr for EventId {
    type Err = Error;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let bad = || Error::InvalidId(raw.to_owned());
        if raw.len() != ID_LEN {
            return Err(bad());
        }
        let mut value: u128 = 0;
        for (i, byte) in raw.bytes().enumerate() {
            let digit = ALPHABET
                .iter()
                .position(|c| *c == byte.to_ascii_uppercase())
                .ok_or_else(bad)?;
            if i == 0 && digit > 7 {
                return Err(bad());
            }
            value = (value << 5) | digit as u128;
        }
        Ok(Self(value))
    }
}

impl Serialize for EventId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EventId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_roundtrips() {
        let id = EventId::new(1_790_000_000_000, 0xdead_beef_cafe_f00d_1234);
        let text = id.to_string();
        assert_eq!(text.len(), 26);
        assert_eq!(text.parse::<EventId>().unwrap(), id);
    }

    #[test]
    fn random_ids_sort_by_time() {
        let early = EventId::new(1_000, u128::MAX).to_string();
        let late = EventId::new(2_000, 0).to_string();
        assert!(early < late);
    }

    #[test]
    fn derive_is_stable_across_calls() {
        let a = EventId::derive("workmux.agent_crashed", &["%10", "1790000000"]);
        let b = EventId::derive("workmux.agent_crashed", &["%10", "1790000000"]);
        assert_eq!(a, b);
        assert_eq!(a.to_string(), b.to_string());
    }

    #[test]
    fn derive_pins_a_known_value() {
        assert_eq!(
            EventId::derive("k", &["a"]).to_string(),
            "3BFJTGXPQ45EPDPF4GPEJ6CRVF"
        );
    }

    #[test]
    fn derive_separates_parts_and_kinds() {
        assert_ne!(
            EventId::derive("k", &["ab", "c"]),
            EventId::derive("k", &["a", "bc"])
        );
        assert_ne!(EventId::derive("a", &["x"]), EventId::derive("b", &["x"]));
        assert_ne!(
            EventId::derive("k", &["x"]),
            EventId::derive("k", &["x", ""])
        );
    }

    #[test]
    fn rejects_bad_ids() {
        assert!("short".parse::<EventId>().is_err());
        assert!("U0000000000000000000000000".parse::<EventId>().is_err());
        assert!("ZZZZZZZZZZZZZZZZZZZZZZZZZZ".parse::<EventId>().is_err());
        assert!("0000000000000000000000000!".parse::<EventId>().is_err());
    }

    #[test]
    fn serde_uses_the_string_form() {
        let id = EventId::derive("k", &["a"]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        assert_eq!(serde_json::from_str::<EventId>(&json).unwrap(), id);
    }
}
