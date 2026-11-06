//! The profile read messages: old wire bytes stay valid and the new fields sit at pinned
//! field numbers.

use fleet_proto::v1::{ProfileSummary, ProfileVersion, ProfileVisibility, SelectionEntry};
use prost::Message;

const OLD_SUMMARY: &[u8] = &[0x0a, 0x01, b'p', 0x10, 0x02, 0x1a, 0x01, b'h'];
const OLD_VERSION: &[u8] = &[
    0x0a, 0x01, b'n', 0x10, 0x01, 0x1a, 0x01, b'h', 0x22, 0x02, b'{', b'}', 0x28, 0x01,
];

fn old_summary() -> ProfileSummary {
    ProfileSummary {
        name: "p".to_owned(),
        latest_version: 2,
        hash: "h".to_owned(),
        ..ProfileSummary::default()
    }
}

fn old_version() -> ProfileVersion {
    ProfileVersion {
        name: "n".to_owned(),
        version: 1,
        hash: "h".to_owned(),
        content_json: "{}".to_owned(),
        created: true,
        ..ProfileVersion::default()
    }
}

#[test]
fn old_summary_bytes_decode_with_the_new_fields_omitted() {
    let decoded = ProfileSummary::decode(OLD_SUMMARY).unwrap();
    assert_eq!(decoded, old_summary());
    assert_eq!(decoded.owner, "");
    assert_eq!(decoded.visibility, ProfileVisibility::Unspecified as i32);
}

#[test]
fn old_version_bytes_decode_with_the_new_fields_omitted() {
    let decoded = ProfileVersion::decode(OLD_VERSION).unwrap();
    assert_eq!(decoded, old_version());
    assert_eq!(decoded.owner, "");
    assert_eq!(decoded.visibility, ProfileVisibility::Unspecified as i32);
    assert_eq!(decoded.selection, Vec::<SelectionEntry>::new());
    assert_eq!(decoded.authored_prompt, "");
}

#[test]
fn unset_new_fields_leave_the_old_bytes_unchanged() {
    assert_eq!(old_summary().encode_to_vec(), OLD_SUMMARY);
    assert_eq!(old_version().encode_to_vec(), OLD_VERSION);
}

#[test]
fn summary_owner_and_visibility_sit_at_fields_four_and_five() {
    let summary = ProfileSummary {
        owner: "al".to_owned(),
        visibility: ProfileVisibility::Shared as i32,
        ..old_summary()
    };
    let mut expected = OLD_SUMMARY.to_vec();
    expected.extend([0x22, 0x02, b'a', b'l', 0x28, 0x02]);
    assert_eq!(summary.encode_to_vec(), expected);
    assert_eq!(
        ProfileSummary::decode(expected.as_slice()).unwrap(),
        summary
    );
}

#[test]
fn version_new_fields_sit_at_fields_six_to_nine() {
    let version = ProfileVersion {
        owner: "al".to_owned(),
        visibility: ProfileVisibility::Private as i32,
        selection: vec![SelectionEntry {
            item_id: "x".to_owned(),
            enabled: false,
        }],
        authored_prompt: "hi".to_owned(),
        ..old_version()
    };
    let mut expected = OLD_VERSION.to_vec();
    expected.extend([0x32, 0x02, b'a', b'l']);
    expected.extend([0x38, 0x01]);
    expected.extend([0x42, 0x03, 0x0a, 0x01, b'x']);
    expected.extend([0x4a, 0x02, b'h', b'i']);
    assert_eq!(version.encode_to_vec(), expected);
    assert_eq!(
        ProfileVersion::decode(expected.as_slice()).unwrap(),
        version
    );
}

#[test]
fn a_hostile_owner_name_survives_the_encoding() {
    let owner = "a\"\r\n\u{85}\u{2028}\u{202e}<b>\\\u{1f600}".to_owned();
    let summary = ProfileSummary {
        owner: owner.clone(),
        ..old_summary()
    };
    let version = ProfileVersion {
        owner: owner.clone(),
        ..old_version()
    };
    let summary = ProfileSummary::decode(summary.encode_to_vec().as_slice()).unwrap();
    let version = ProfileVersion::decode(version.encode_to_vec().as_slice()).unwrap();
    assert_eq!(summary.owner, owner);
    assert_eq!(version.owner, owner);
}
