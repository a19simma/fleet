//! The name and state rules of [`CiCheck`], shared by both adapters.

use fleet_forge::{CheckState, CiCheck, ForgeError, MAX_CHECK_NAME_BYTES, MAX_CHECKS};
use unicode_general_category::{GeneralCategory, get_general_category};

#[test]
fn a_check_name_with_a_hostile_character_is_malformed() {
    let long = "x".repeat(MAX_CHECK_NAME_BYTES + 1);
    let multibyte = "é".repeat(MAX_CHECK_NAME_BYTES / 2 + 1);
    let hostile = [
        "",
        " ",
        "\u{a0}\u{2003}",
        "a\rb",
        "a\nb",
        "a\tb",
        "a\r\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\0b",
        "a\u{1b}[31mb",
        "a\u{7f}b",
        "a\u{200b}b",
        "a\u{200d}b",
        "a\u{200e}b",
        "a\u{200f}b",
        "a\u{202a}b",
        "a\u{202b}b",
        "a\u{202c}b",
        "a\u{202d}b",
        "a\u{202e}b",
        "a\u{2066}b",
        "a\u{2067}b",
        "a\u{2068}b",
        "a\u{2069}b",
        "a\u{61c}b",
        "a\u{feff}b",
        "a\u{2060}b",
        long.as_str(),
        multibyte.as_str(),
    ];
    for name in hostile {
        assert_eq!(
            CiCheck::new(name, CheckState::Success).err(),
            Some(ForgeError::Malformed),
            "{name:?}"
        );
    }
}

#[test]
fn a_check_name_is_kept_as_sent_within_the_bounds() {
    let edge = "x".repeat(MAX_CHECK_NAME_BYTES);
    let multibyte = "é".repeat(MAX_CHECK_NAME_BYTES / 2);
    let names = [
        "build",
        "ci / build (ubuntu-latest, 1.80)",
        "  padded  ",
        "テスト",
        "Ünï-çödé",
        edge.as_str(),
        multibyte.as_str(),
    ];
    for name in names {
        let check = CiCheck::new(name, CheckState::Queued);
        assert_eq!(check.as_ref().map(CiCheck::name).ok(), Some(name));
        assert_eq!(check.map(|c| c.state()).ok(), Some(CheckState::Queued));
    }
}

#[test]
fn the_check_cap_is_fifty() {
    assert_eq!(MAX_CHECKS, 50);
}

fn ascii_allowed(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | ' ' | '!'..='/' | ':'..='@' | '['..='`' | '{'..='~')
}

fn allowed(c: char) -> bool {
    if c.is_ascii() {
        ascii_allowed(c)
    } else {
        letter_or_number(c)
    }
}

fn letter_or_number(c: char) -> bool {
    matches!(
        get_general_category(c),
        GeneralCategory::UppercaseLetter
            | GeneralCategory::LowercaseLetter
            | GeneralCategory::TitlecaseLetter
            | GeneralCategory::ModifierLetter
            | GeneralCategory::OtherLetter
            | GeneralCategory::DecimalNumber
            | GeneralCategory::LetterNumber
            | GeneralCategory::OtherNumber
    ) && !FILLERS.contains(&c)
}

const EXPECTED: u32 = 142_968;

const FILLERS: [char; 4] = ['\u{115f}', '\u{1160}', '\u{3164}', '\u{ffa0}'];

fn has_letter_or_digit(c: char) -> bool {
    if c.is_ascii() {
        c.is_ascii_alphanumeric()
    } else {
        letter_or_number(c)
    }
}

#[test]
fn every_code_point_is_judged_by_the_allowlist() {
    let mut refused = 0_u32;
    let mut accepted = 0_u32;
    for code in 0..=0x0010_FFFF_u32 {
        let Some(c) = char::from_u32(code) else {
            continue;
        };
        let inside = format!("a{c}b");
        let got = CiCheck::new(&inside, CheckState::Success);
        if allowed(c) {
            accepted += 1;
            assert_eq!(
                got.as_ref().map(CiCheck::name).ok(),
                Some(inside.as_str()),
                "U+{code:04X}"
            );
        } else {
            refused += 1;
            assert_eq!(got.err(), Some(ForgeError::Malformed), "U+{code:04X}");
        }
        let alone = c.to_string();
        let got = CiCheck::new(&alone, CheckState::Success);
        assert_eq!(got.is_ok(), has_letter_or_digit(c), "alone U+{code:04X}");
    }
    assert!(accepted > 100_000);
    assert!(refused > 800_000);
    assert_eq!(accepted + refused, 0x0010_F800);
    assert_eq!(accepted, EXPECTED);
}

#[test]
fn a_combining_mark_is_refused_inside_a_name() {
    for mark in ['\u{300}', '\u{93e}', '\u{20dd}'] {
        let name = format!("a{mark}b");
        assert_eq!(
            CiCheck::new(&name, CheckState::Success).err(),
            Some(ForgeError::Malformed),
            "{mark:?}"
        );
    }
    let alone = '\u{300}'.to_string();
    assert!(CiCheck::new(&alone, CheckState::Success).is_err());
}

#[test]
fn invisible_and_format_characters_are_refused_by_name() {
    let rows = [
        "a\u{ad}b",
        "a\u{fff9}b",
        "a\u{fffa}b",
        "a\u{fffb}b",
        "a\u{e0001}b",
        "a\u{e0020}b",
        "a\u{e007f}b",
        "a\u{180e}b",
        "a\u{200d}b",
        "a\u{202e}b",
        "a\u{2066}b",
        "a\tb",
        "a\u{85}b",
        "\u{2800}",
        "\u{115f}",
        "\u{1160}",
        "\u{ffa0}",
        "a\u{3164}b",
        "\u{3164}",
        "\u{2800}\u{3164} ",
        "---",
        " - ",
    ];
    for name in rows {
        assert_eq!(
            CiCheck::new(name, CheckState::Failed).err(),
            Some(ForgeError::Malformed),
            "{name:?}"
        );
    }
}
