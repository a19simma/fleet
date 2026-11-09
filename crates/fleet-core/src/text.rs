//! Hostile-text sanitiser shared by the CLI and other crates. Performs no IO.

use std::borrow::Cow;

use crate::Redactor;

/// Inclusive code point ranges of hostile characters.
///
/// The ranges are the `Cf`, `Zl` and `Zp` values of the `General_Category` field in
/// `UnicodeData.txt` for Unicode 16.0.0, plus the tag block `U+E0000..=U+E007F`. Together with
/// `Cc`, which [`is_hostile`] adds, the set is exactly `Cc`, `Cf`, `Zl`, `Zp` and the tag block.
///
/// Blank or confusable characters that are not `Cf` are out of scope: `U+034F`, `U+115F`,
/// `U+1160`, `U+3164`, `U+FFA0`, the variation selectors `U+FE00..=U+FE0F` and
/// `U+E0100..=U+E01EF`, `U+17B4`, `U+17B5` and `U+2800`. Callers that need them keep their
/// own extra list, as `fleetd` does for fetched bodies.
///
/// Sorted by start and non-overlapping. Control characters (`Cc`) are not listed: [`is_hostile`]
/// tests them with [`char::is_control`].
pub const HOSTILE_RANGES: [(u32, u32); 20] = [
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x2028, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE007F),
];

fn in_table(cp: u32) -> bool {
    HOSTILE_RANGES
        .binary_search_by(|&(lo, hi)| {
            if hi < cp {
                std::cmp::Ordering::Less
            } else if lo > cp {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// Whether `c` must not reach the terminal: a control character or a member of
/// [`HOSTILE_RANGES`].
pub fn is_hostile(c: char) -> bool {
    c.is_control() || in_table(c as u32)
}

/// [`is_hostile`] minus `U+200C..=U+200F` (ZWNJ, ZWJ, LRM, RLM), for paths that reject a
/// value instead of cleaning it.
pub fn is_hostile_allowing_joiners(c: char) -> bool {
    is_hostile(c) && !matches!(c, '\u{200C}'..='\u{200F}')
}

/// Strips hostile characters except newline and tab.
pub fn strip_keeping_lines(text: &str) -> String {
    strip(text, true)
}

fn strip(text: &str, keep_lines: bool) -> String {
    text.chars()
        .filter(|&c| (keep_lines && matches!(c, '\n' | '\t')) || !is_hostile(c))
        .collect()
}

/// An upper bound on the length of sanitised text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cap {
    /// At most this many UTF-8 bytes, cut on a char boundary.
    Bytes(usize),
    /// At most this many chars.
    Chars(usize),
}

/// Sanitised text and whether the cap dropped any of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clean {
    /// The sanitised text.
    pub text: String,
    /// Whether the cap dropped anything. Stripped characters do not count.
    pub cut: bool,
}

/// Sanitises `text` onto one line: hostile characters, newline and tab are removed.
///
/// Runs redact, strip, redact, strip, cut in that order. The first redaction matches a secret
/// that itself contains a stripped character, such as a multi-line key. The first strip lets a
/// secret split by a hidden character match in the second redaction, the second strip removes
/// anything the redactions joined, and the cut comes last so a secret straddling the cap
/// leaves no prefix.
pub fn sanitise_text(redactor: &Redactor, text: &str, cap: Cap) -> Clean {
    pipeline(redactor, text, cap, false)
}

/// [`sanitise_text`] that keeps newline and tab.
pub fn sanitise_lines(redactor: &Redactor, text: &str, cap: Cap) -> Clean {
    pipeline(redactor, text, cap, true)
}

fn pipeline(redactor: &Redactor, text: &str, cap: Cap, keep_lines: bool) -> Clean {
    let raw = redactor.redact_str(text);
    let first = strip(&raw, keep_lines);
    let redacted = match redactor.redact_str(&first) {
        Cow::Borrowed(_) => first,
        Cow::Owned(owned) => owned,
    };
    let mut text = strip(&redacted, keep_lines);
    let end = match cap {
        Cap::Bytes(max) => (0..=max.min(text.len()))
            .rev()
            .find(|&i| text.is_char_boundary(i))
            .unwrap_or(0),
        Cap::Chars(max) => text.char_indices().nth(max).map_or(text.len(), |(i, _)| i),
    };
    let cut = end < text.len();
    text.truncate(end);
    Clean { text, cut }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PLACEHOLDER, Redactor};
    use unicode_general_category::{GeneralCategory, get_general_category};

    const SECRET: &str = "qzqzjxvk-9981";

    fn redactor() -> Redactor {
        Redactor::new([SECRET])
    }

    fn flat(text: &str) -> String {
        sanitise_text(&Redactor::default(), text, Cap::Bytes(usize::MAX)).text
    }

    fn lines(text: &str) -> String {
        sanitise_lines(&Redactor::default(), text, Cap::Bytes(usize::MAX)).text
    }

    #[test]
    fn table_is_sorted_and_non_overlapping() {
        for &(lo, hi) in &HOSTILE_RANGES {
            assert!(lo <= hi, "U+{lo:04X}..U+{hi:04X}");
        }
        for pair in HOSTILE_RANGES.windows(2) {
            assert!(pair[0].1 < pair[1].0, "{pair:?}");
        }
    }

    #[test]
    fn hostile_set_equals_the_unicode_categories_for_every_scalar() {
        let (mut cc, mut cf, mut sep, mut tag_extra, mut total) =
            (0_u32, 0_u32, 0_u32, 0_u32, 0_u32);
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            let category = get_general_category(c);
            let is_tag = matches!(u32::from(c), 0xE0000..=0xE007F);
            let want = matches!(
                category,
                GeneralCategory::Control
                    | GeneralCategory::Format
                    | GeneralCategory::LineSeparator
                    | GeneralCategory::ParagraphSeparator
            ) || is_tag;
            assert_eq!(is_hostile(c), want, "U+{:04X}", u32::from(c));
            cc += u32::from(category == GeneralCategory::Control);
            cf += u32::from(category == GeneralCategory::Format);
            sep += u32::from(matches!(
                category,
                GeneralCategory::LineSeparator | GeneralCategory::ParagraphSeparator
            ));
            tag_extra += u32::from(is_tag && category != GeneralCategory::Format);
            total += u32::from(is_hostile(c));
        }
        assert_eq!(cc, 65);
        assert_eq!(cf, 170);
        assert_eq!(sep, 2);
        assert_eq!(cf + sep, 172);
        assert_eq!(tag_extra, 31);
        assert_eq!(total, 65 + 172 + 31);
    }

    #[test]
    fn joiner_variant_differs_on_exactly_the_four_marks() {
        let mut differing = Vec::new();
        for c in (0..=u32::from(char::MAX)).filter_map(char::from_u32) {
            if is_hostile(c) != is_hostile_allowing_joiners(c) {
                differing.push(u32::from(c));
            }
        }
        assert_eq!(differing, [0x200C, 0x200D, 0x200E, 0x200F]);
        for cp in 0x200C..=0x200F {
            let c = char::from_u32(cp).unwrap_or('\0');
            assert!(is_hostile(c) && !is_hostile_allowing_joiners(c));
        }
    }

    #[test]
    fn hostile_input_table_has_exact_output_for_both_fns() {
        let rows: [(&str, &str, &str); 30] = [
            ("a\rb", "ab", "ab"),
            ("a\r\nb", "ab", "a\nb"),
            ("a\u{85}b", "ab", "ab"),
            ("a\u{2028}b", "ab", "ab"),
            ("a\u{2029}b", "ab", "ab"),
            ("a\u{E0000}\u{E0001}\u{E0041}\u{E007F}b", "ab", "ab"),
            ("a\u{61C}b", "ab", "ab"),
            ("a\u{200E}\u{200F}b", "ab", "ab"),
            ("a\u{202A}\u{202B}\u{202C}\u{202D}\u{202E}b", "ab", "ab"),
            ("a\u{2066}\u{2067}\u{2068}\u{2069}b", "ab", "ab"),
            ("a\u{200B}b", "ab", "ab"),
            ("a\u{200C}\u{200D}b", "ab", "ab"),
            ("a\u{FEFF}b", "ab", "ab"),
            ("a\u{AD}b", "ab", "ab"),
            ("a\0b", "ab", "ab"),
            ("a\u{80}\u{9F}b", "ab", "ab"),
            ("a\x1b[31mb", "a[31mb", "a[31mb"),
            ("a\x7Fb", "ab", "ab"),
            ("l1\nl2\tx", "l1l2x", "l1\nl2\tx"),
            ("\n\t", "", "\n\t"),
            ("caf\u{E9}", "caf\u{E9}", "caf\u{E9}"),
            ("e\u{301}", "e\u{301}", "e\u{301}"),
            ("\u{4E2D}\u{6587}", "\u{4E2D}\u{6587}", "\u{4E2D}\u{6587}"),
            (
                "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}",
                "\u{1F468}\u{1F469}\u{1F467}",
                "\u{1F468}\u{1F469}\u{1F467}",
            ),
            ("\u{1F600}", "\u{1F600}", "\u{1F600}"),
            ("\u{3000}x", "\u{3000}x", "\u{3000}x"),
            ("\u{FE0F}", "\u{FE0F}", "\u{FE0F}"),
            ("", "", ""),
            ("\u{200B}", "", ""),
            ("\r", "", ""),
        ];
        for (input, want_flat, want_lines) in rows {
            assert_eq!(flat(input), want_flat, "flat {input:?}");
            assert_eq!(lines(input), want_lines, "lines {input:?}");
        }
    }

    #[test]
    fn secret_split_by_a_zero_width_space_is_redacted() {
        let split = format!("a{}\u{200B}{}b", &SECRET[..4], &SECRET[4..]);
        let clean = sanitise_text(&redactor(), &split, Cap::Bytes(1024));
        assert_eq!(clean.text, format!("a{PLACEHOLDER}b"));
        assert!(!clean.cut);
    }

    #[test]
    fn secret_containing_a_stripped_character_is_redacted_by_both_fns() {
        for (name, hostile) in [
            ("newline", "\n"),
            ("crlf", "\r\n"),
            ("zwsp", "\u{200B}"),
            ("tab", "\t"),
        ] {
            let secret = format!("-----BEGIN KEY-----{hostile}abcdefgh");
            let r = Redactor::new([secret.as_str()]);
            let text = format!("x {secret} y");
            let want = format!("x {PLACEHOLDER} y");
            for out in [
                sanitise_text(&r, &text, Cap::Bytes(1024)),
                sanitise_lines(&r, &text, Cap::Bytes(1024)),
            ] {
                assert_eq!(out.text, want, "{name}");
                assert!(!out.cut, "{name}");
            }
        }
    }

    #[test]
    fn secret_with_a_hostile_character_straddling_the_cap_leaves_no_prefix() {
        let secret = "qzqz\u{200B}jxvk\n9981";
        let r = Redactor::new([secret]);
        let text = format!("xxxx{secret}yy");
        for cap in 0..=text.len() + 2 {
            for out in [
                sanitise_text(&r, &text, Cap::Bytes(cap)),
                sanitise_lines(&r, &text, Cap::Bytes(cap)),
                sanitise_text(&r, &text, Cap::Chars(cap)),
                sanitise_lines(&r, &text, Cap::Chars(cap)),
            ] {
                assert!(!out.text.contains("qz"), "cap {cap}: {:?}", out.text);
            }
        }
    }

    #[test]
    fn secret_straddling_the_cap_leaves_no_prefix() {
        let text = format!("xxxx{SECRET}yy");
        for cap in 0..=text.len() + 2 {
            for out in [
                sanitise_text(&redactor(), &text, Cap::Bytes(cap)),
                sanitise_lines(&redactor(), &text, Cap::Bytes(cap)),
                sanitise_text(&redactor(), &text, Cap::Chars(cap)),
            ] {
                assert!(!out.text.contains("qz"), "cap {cap}: {:?}", out.text);
            }
        }
        let cut = sanitise_text(&redactor(), &text, Cap::Bytes(6));
        assert_eq!(cut.text, format!("xxxx{}", &PLACEHOLDER[..2]));
        assert!(cut.cut);
    }

    #[test]
    fn redaction_replacement_cannot_join_into_a_hidden_char() {
        assert!(!PLACEHOLDER.chars().any(is_hostile));
        let wrapped = format!("\u{200B}{SECRET}\u{E0041}");
        let clean = sanitise_text(&redactor(), &wrapped, Cap::Bytes(1024));
        assert_eq!(clean.text, PLACEHOLDER);
        assert!(!clean.cut);
        let doubled = format!("{SECRET}\u{202E}{SECRET}");
        let clean = sanitise_text(&redactor(), &doubled, Cap::Bytes(1024));
        assert_eq!(clean.text, format!("{PLACEHOLDER}{PLACEHOLDER}"));
    }

    #[test]
    fn caps_of_zero_and_inside_multibyte_characters() {
        let none = Redactor::default();
        let zero = sanitise_text(&none, "abc", Cap::Bytes(0));
        assert_eq!((zero.text.as_str(), zero.cut), ("", true));
        let zero = sanitise_text(&none, "abc", Cap::Chars(0));
        assert_eq!((zero.text.as_str(), zero.cut), ("", true));
        let zero = sanitise_text(&none, "", Cap::Bytes(0));
        assert_eq!((zero.text.as_str(), zero.cut), ("", false));
        let zero = sanitise_text(&none, "\u{200B}", Cap::Chars(0));
        assert_eq!((zero.text.as_str(), zero.cut), ("", false));
        let rows: [(&str, Cap, &str, bool); 8] = [
            ("\u{E9}a", Cap::Bytes(1), "", true),
            ("\u{E9}a", Cap::Bytes(2), "\u{E9}", true),
            ("\u{E9}a", Cap::Bytes(3), "\u{E9}a", false),
            ("\u{1F600}a", Cap::Bytes(3), "", true),
            ("\u{1F600}a", Cap::Bytes(4), "\u{1F600}", true),
            ("\u{E9}a", Cap::Chars(1), "\u{E9}", true),
            ("\u{E9}a", Cap::Chars(2), "\u{E9}a", false),
            ("a\u{200B}", Cap::Bytes(1), "a", false),
        ];
        for (input, cap, want, want_cut) in rows {
            let out = sanitise_text(&none, input, cap);
            assert_eq!(
                (out.text.as_str(), out.cut),
                (want, want_cut),
                "{input:?} {cap:?}"
            );
            let out = sanitise_lines(&none, input, cap);
            assert_eq!(
                (out.text.as_str(), out.cut),
                (want, want_cut),
                "{input:?} {cap:?}"
            );
        }
    }

    #[test]
    fn lines_keeps_newline_and_tab_within_the_cap() {
        let out = sanitise_lines(&Redactor::default(), "a\n\tb\r\nc", Cap::Chars(4));
        assert_eq!((out.text.as_str(), out.cut), ("a\n\tb", true));
    }
}
