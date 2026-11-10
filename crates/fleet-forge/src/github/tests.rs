use std::error::Error;

use fleet_core::host::HostName;

use super::*;

type TestResult = Result<(), Box<dyn Error>>;

fn repo(owner: &str, name: &str) -> Result<RepoRef, Box<dyn Error>> {
    Ok(RepoRef::new(
        HostName::normalise("github.com")?,
        owner,
        name,
    )?)
}

#[test]
fn segment_refuses_every_hostile_value() {
    let long = "x".repeat(MAX_SEGMENT_BYTES + 1);
    let hostile = [
        "",
        ".",
        "..",
        "a/b",
        "/",
        "a\\b",
        "a%2fb",
        "%2e%2e",
        "a\rb",
        "a\nb",
        "a\r\nb",
        "a b",
        " ",
        "a\tb",
        "é",
        "a\u{85}b",
        "a\u{2028}b",
        "a?b",
        "a#b",
        "a:b",
        "a@b",
        "a\0b",
        long.as_str(),
    ];
    for text in hostile {
        assert_eq!(segment(text), Err(ForgeError::Malformed), "{text:?}");
    }
}

#[test]
fn segment_accepts_the_edges() {
    let longest = "x".repeat(MAX_SEGMENT_BYTES);
    for text in ["a", "A-b_c.d", "..a", "a..", "1", longest.as_str()] {
        assert_eq!(segment(text), Ok(text), "{text:?}");
    }
}

#[test]
fn encode_escapes_every_reserved_and_non_ascii_byte() {
    assert_eq!(encode("octo:fleet/job-1"), "octo%3Afleet%2Fjob-1");
    assert_eq!(encode("a b&c=d?e#f%g"), "a%20b%26c%3Dd%3Fe%23f%25g");
    assert_eq!(encode("\r\n"), "%0D%0A");
    assert_eq!(encode("é"), "%C3%A9");
    assert_eq!(encode("A-z_0.9~"), "A-z_0.9~");
    assert_eq!(encode(""), "");
}

#[test]
fn pr_number_reads_only_the_pull_url_of_the_repo() -> TestResult {
    let r = repo("octo", "widgets")?;
    assert_eq!(
        pr_number("https://github.com/octo/widgets/pull/7", &r),
        Ok(7)
    );
    assert_eq!(
        pr_number("https://GitHub.com/Octo/Widgets/pull/7", &r),
        Ok(7)
    );
    assert_eq!(
        pr_number("https://github.com/octo/widgets/pull/9999999999", &r),
        Ok(9_999_999_999)
    );
    let long = format!("https://github.com/octo/widgets/pull/{}", "1".repeat(11));
    let hostile = [
        "",
        "https://github.com/octo/widgets/pull/",
        "https://github.com/octo/widgets/pull/0",
        "https://github.com/octo/widgets/pull/-1",
        "https://github.com/octo/widgets/pull/+1",
        "https://github.com/octo/widgets/pull/7/",
        "https://github.com/octo/widgets/pull/7?x=1",
        "https://github.com/octo/widgets/pull/7#f",
        "https://github.com/octo/widgets/pull/7\r\n",
        "https://github.com/octo/widgets/pull/7 ",
        "https://github.com/octo/widgets/pull/ 7",
        "https://github.com/octo/widgets/pull/%37",
        "https://github.com/octo/widgets/pull/٣",
        "http://github.com/octo/widgets/pull/7",
        "https://github.com@evil.example/octo/widgets/pull/7",
        "https://evil.example/octo/widgets/pull/7",
        "https://github.com:443/octo/widgets/pull/7",
        "https://github.com\\octo/widgets/pull/7",
        "https://github.com/octo/other/pull/7",
        "https://github.com/other/widgets/pull/7",
        "https://github.com/octo/widgets/issues/7",
        "https://github.com/octo/widgets/pulls/7",
        "https://github.com/octo/widgets/../widgets/pull/7",
        "é",
        long.as_str(),
    ];
    for url in hostile {
        assert_eq!(pr_number(url, &r), Err(ForgeError::Malformed), "{url:?}");
    }
    Ok(())
}

#[test]
fn sha_must_be_hex_and_bounded() {
    let longest = "a".repeat(MAX_SHA_BYTES);
    let over = "a".repeat(MAX_SHA_BYTES + 1);
    assert!(valid_sha("abc123"));
    assert!(valid_sha("ABCDEF0"));
    assert!(valid_sha(&longest));
    for text in [
        "",
        "xyz",
        "abc/123",
        "abc 123",
        "abc\n",
        "../x",
        "é",
        over.as_str(),
    ] {
        assert!(!valid_sha(text), "{text:?}");
    }
}

#[test]
fn status_error_table() {
    let table = [
        (301, ForgeError::Redirected),
        (302, ForgeError::Redirected),
        (399, ForgeError::Redirected),
        (400, ForgeError::Rejected),
        (401, ForgeError::Unauthorized),
        (403, ForgeError::Unauthorized),
        (404, ForgeError::NotFound),
        (422, ForgeError::Rejected),
        (429, ForgeError::Unavailable),
        (500, ForgeError::Unavailable),
        (599, ForgeError::Unavailable),
        (100, ForgeError::Malformed),
        (200, ForgeError::Malformed),
        (204, ForgeError::Malformed),
        (299, ForgeError::Malformed),
        (600, ForgeError::Malformed),
    ];
    for (status, error) in table {
        assert_eq!(status_error(status), error, "{status}");
    }
}

#[test]
fn http_errors_map_to_fixed_forge_errors() {
    assert_eq!(map_http(HttpError::Timeout), ForgeError::Timeout);
    assert_eq!(map_http(HttpError::Reset), ForgeError::Unavailable);
    assert_eq!(map_http(HttpError::BodyTooLarge), ForgeError::TooLarge);
    assert_eq!(map_http(HttpError::HostRefused), ForgeError::Rejected);
}

#[test]
fn a_tally_ranks_failure_over_running_over_queued_over_success_over_neutral() {
    let order = [
        Rank::Neutral,
        Rank::Success,
        Rank::Queued,
        Rank::Running,
        Rank::Failed,
    ];
    let expected = [
        CiResult::Neutral,
        CiResult::Success,
        CiResult::Queued,
        CiResult::InProgress,
        CiResult::Failure,
    ];
    assert_eq!(Tally::default().result(), CiResult::NoChecks);
    for (index, (rank, want)) in order.iter().zip(expected).enumerate() {
        let mut up = Tally::default();
        let mut down = Tally::default();
        for other in order.iter().take(index + 1) {
            up.note(*other);
        }
        for other in order.iter().take(index + 1).rev() {
            down.note(*other);
        }
        assert_eq!(up.result(), want, "{rank:?} up");
        assert_eq!(down.result(), want, "{rank:?} down");
    }
}
