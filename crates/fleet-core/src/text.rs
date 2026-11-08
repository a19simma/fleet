//! Hostile-text sanitiser shared by the CLI and other crates. Performs no IO.

/// Inclusive code point ranges of the Unicode `Cf` (format) category, Unicode 16.0.0.
pub const FORMAT_RANGES: [(u32, u32); 21] = [
    (0xAD, 0xAD),
    (0x600, 0x605),
    (0x61C, 0x61C),
    (0x6DD, 0x6DD),
    (0x70F, 0x70F),
    (0x890, 0x891),
    (0x8E2, 0x8E2),
    (0x180E, 0x180E),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x2066, 0x206F),
    (0xFEFF, 0xFEFF),
    (0xFFF9, 0xFFFB),
    (0x110BD, 0x110BD),
    (0x110CD, 0x110CD),
    (0x13430, 0x1343F),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0001, 0xE0001),
    (0xE0020, 0xE007F),
];

/// Whether `c` must not reach the terminal: a control character, a code point of the
/// Unicode `Cf` category, or a line or paragraph separator.
pub fn is_hostile(c: char) -> bool {
    if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
        return true;
    }
    let cp = c as u32;
    FORMAT_RANGES
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

/// Strips hostile characters except newline and tab.
pub fn strip_keeping_lines(text: &str) -> String {
    text.chars()
        .filter(|c| matches!(c, '\n' | '\t') || !is_hostile(*c))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_FORMAT: [(u32, u32); 21] = [
        (0xAD, 0xAD),
        (0x600, 0x605),
        (0x61C, 0x61C),
        (0x6DD, 0x6DD),
        (0x70F, 0x70F),
        (0x890, 0x891),
        (0x8E2, 0x8E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];

    #[test]
    fn every_format_code_point_is_hostile() {
        let mut count = 0;
        for (lo, hi) in ALL_FORMAT {
            for cp in lo..=hi {
                let c = char::from_u32(cp).expect("scalar value");
                assert!(is_hostile(c), "U+{cp:04X} not hostile");
                count += 1;
            }
        }
        assert_eq!(count, 170);
    }

    #[test]
    fn ordinary_characters_are_not_hostile() {
        for c in [
            'a',
            'Z',
            '0',
            ' ',
            '~',
            '\u{4E2D}',
            '\u{1F600}',
            '\u{E9}',
            '\u{8F0}',
        ] {
            assert!(!is_hostile(c), "{c:?} hostile");
        }
    }

    #[test]
    fn format_ranges_match_the_independent_list() {
        assert_eq!(FORMAT_RANGES, ALL_FORMAT);
    }

    #[test]
    fn hostile_input_table_has_exact_output() {
        let rows: [(&str, &str); 11] = [
            ("a\rb", "ab"),
            ("a\r\nb", "a\nb"),
            ("a\u{85}b", "ab"),
            ("a\u{2028}b", "ab"),
            ("a\u{2029}b", "ab"),
            ("a\u{202E}b", "ab"),
            ("a\u{2066}b", "ab"),
            ("a\x1b[31mb", "a[31mb"),
            ("a\x1b]8;;b", "a]8;;b"),
            ("a\0b", "ab"),
            ("l1\nl2\tx", "l1\nl2\tx"),
        ];
        for (input, want) in rows {
            assert_eq!(strip_keeping_lines(input), want, "{input:?}");
        }
    }
}
