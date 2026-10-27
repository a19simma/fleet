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
