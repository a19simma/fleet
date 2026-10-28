//! The CI url rule fleetd and the server share.

use fleet_proto::{MAX_CI_URL_BYTES, is_ci_url};

#[test]
fn a_plain_https_url_is_accepted() {
    assert!(is_ci_url(
        "https://example.invalid/actions/runs/9/job/41?pr=1#x"
    ));
}

#[test]
fn a_url_that_is_not_plain_ascii_https_is_refused() {
    for url in [
        "",
        "http://example.invalid/x",
        "https://",
        "https:///x",
        "https://user@example.invalid/x",
        "https://example.invalid/a b",
        "https://example.invalid/a\tb",
        "https://example.invalid/a\\b",
        "https://example.invalid/\u{e9}",
        "https://example.invalid/a\u{200b}b",
        "https://example.invalid/a\u{7f}b",
    ] {
        assert!(!is_ci_url(url), "{url:?}");
    }
}

#[test]
fn the_cap_is_inclusive() {
    let prefix = "https://example.invalid/";
    let exact = format!("{prefix}{}", "a".repeat(MAX_CI_URL_BYTES - prefix.len()));
    assert_eq!(exact.len(), MAX_CI_URL_BYTES);
    assert!(is_ci_url(&exact));
    assert!(!is_ci_url(&format!("{exact}a")));
}
