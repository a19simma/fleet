//! The rules of a per-Box token that the server, the CLI and the web page share.

use crate::redact::{BOX_TOKEN_HEX_LEN, BOX_TOKEN_PREFIX};

/// The longest per-Box token label in characters.
pub const MAX_LABEL_CHARS: usize = 64;

/// The default lifetime of a per-Box token in days.
pub const DEFAULT_DAYS: u32 = 90;

/// The longest lifetime of a per-Box token in days.
pub const MAX_DAYS: u32 = 365;

/// Whether `raw` is a usable label: at most [`MAX_LABEL_CHARS`] characters and no control or
/// hostile character. An empty label is usable.
#[must_use]
pub fn label_is_valid(raw: &str) -> bool {
    raw.chars().count() <= MAX_LABEL_CHARS
        && !raw
            .chars()
            .any(|c| c.is_control() || crate::text::is_hostile(c))
}

/// Whether `days` is a usable lifetime: 1 to [`MAX_DAYS`].
#[must_use]
pub const fn days_are_valid(days: u32) -> bool {
    matches!(days, 1..=MAX_DAYS)
}

/// Whether `text` is exactly one per-Box token: the prefix and [`BOX_TOKEN_HEX_LEN`] lowercase
/// hex digits, nothing before or after.
#[must_use]
pub fn is_token(text: &str) -> bool {
    text.strip_prefix(BOX_TOKEN_PREFIX).is_some_and(|hex| {
        hex.len() == BOX_TOKEN_HEX_LEN
            && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(hex: &str) -> String {
        format!("{BOX_TOKEN_PREFIX}{hex}")
    }

    #[test]
    fn a_label_is_counted_in_characters_and_refuses_hostile_ones() {
        assert!(label_is_valid(""));
        assert!(label_is_valid(&"\u{e9}".repeat(MAX_LABEL_CHARS)));
        assert!(!label_is_valid(&"\u{e9}".repeat(MAX_LABEL_CHARS + 1)));
        for bad in [
            "a\n",
            "a\r",
            "a\t",
            "a\u{85}",
            "a\u{2028}",
            "a\u{202e}",
            "a\0",
        ] {
            assert!(!label_is_valid(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_lifetime_runs_from_one_to_the_maximum() {
        assert!(!days_are_valid(0));
        assert!(days_are_valid(1));
        assert!(days_are_valid(MAX_DAYS));
        assert!(!days_are_valid(MAX_DAYS + 1));
    }

    #[test]
    fn a_token_is_the_prefix_and_exactly_the_hex_length() {
        let good = "0f".repeat(BOX_TOKEN_HEX_LEN / 2);
        assert!(is_token(&token(&good)));
        assert!(!is_token(&token(&good[1..])));
        assert!(!is_token(&token(&format!("{good}0"))));
        assert!(!is_token(&token(&good.to_uppercase())));
        assert!(!is_token(&token(&format!("{}g", &good[1..]))));
        assert!(!is_token(&format!(" {}", token(&good))));
        assert!(!is_token(&format!("{}\n", token(&good))));
        assert!(!is_token(&good));
        assert!(!is_token(""));
    }
}
