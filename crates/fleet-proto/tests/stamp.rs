//! The version stamp fields of a job summary on the wire, and the shared text check.

use fleet_proto::is_plain_text;
use fleet_proto::v1::JobSummary;
use prost::Message;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn stamp_fields_round_trip_and_unset_ones_stay_unset() -> TestResult {
    let set = JobSummary {
        bundle_sha: Some("ab".repeat(32)),
        claude_version: Some("2.1.289".to_owned()),
        model: Some("claude-opus-4".to_owned()),
        ..JobSummary::default()
    };
    assert_eq!(JobSummary::decode(set.encode_to_vec().as_slice())?, set);
    let unset = JobSummary::decode(JobSummary::default().encode_to_vec().as_slice())?;
    assert_eq!(unset.bundle_sha, None);
    assert_eq!(unset.claude_version, None);
    assert_eq!(unset.model, None);
    Ok(())
}

#[test]
fn plain_text_is_non_empty_and_free_of_control_characters() {
    assert!(is_plain_text("claude-opus-4 (beta)"));
    assert!(is_plain_text("\u{e9}"));
    assert!(!is_plain_text(""));
    for bad in ["a\nb", "a\0b", "\u{7}", "a\u{1b}[0m", "a\tb", "a\u{85}b"] {
        assert!(!is_plain_text(bad), "{bad:?}");
    }
}

#[test]
fn plain_text_rejects_format_characters() {
    for bad in [
        "a\u{ad}b",
        "a\u{61c}b",
        "a\u{200b}b",
        "a\u{202a}b",
        "a\u{202e}b",
        "a\u{2060}b",
        "a\u{2066}b",
        "a\u{2069}b",
        "a\u{206f}b",
        "\u{feff}a",
        "a\u{fff9}b",
        "a\u{e0001}b",
        "a\u{e0041}b",
        "a\u{e007f}b",
        "a\u{180e}b",
        "a\u{2064}b",
        "a\u{fffb}b",
        "a\u{e0020}b",
        "a\u{202c}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\u{600}b",
        "a\u{605}b",
        "a\u{6dd}b",
        "a\u{70f}b",
        "a\u{8e2}b",
        "a\u{110bd}b",
        "a\u{1d173}b",
        "a\u{1d17a}b",
    ] {
        assert!(!is_plain_text(bad), "{bad:?}");
    }
    for good in [
        "a\u{2010}b",
        "a\u{2065}b",
        "a\u{e0000}b",
        "a\u{e0080}b",
        "\u{4e2d}\u{6587}",
        "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}",
        "\u{645}\u{200c}\u{6cc}\u{62e}\u{648}\u{627}\u{647}\u{645}",
        "\u{915}\u{94d}\u{200d}\u{937}",
        "\u{606}a",
        "a\u{1d172}b",
        "a\u{200e}b",
        "a\u{200f}b",
        "a\u{200c}b",
        "a\u{1d17b}b",
    ] {
        assert!(is_plain_text(good), "{good:?}");
    }
}
