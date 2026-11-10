//! Tests for `fleet_core::host`: one test per row of the ADR-0068 hostile-input table.

use fleet_core::host::{Host, HostError as E, HostKind, HostName, MAX_RAW_HOST_BYTES};

fn refused(rows: &[&str], want: E) {
    for row in rows {
        assert_eq!(HostName::normalise(row), Err(want), "input {row:?}");
    }
}

fn ok(input: &str) -> String {
    let name = HostName::normalise(input);
    assert!(name.is_ok(), "{input:?} refused: {name:?}");
    name.map_or_else(|_| String::new(), |n| n.as_str().to_owned())
}

#[test]
fn accepted_shapes() {
    assert_eq!(ok("git.simonmalm.com"), "git.simonmalm.com");
    assert_eq!(ok("a-b.c1.example.org"), "a-b.c1.example.org");
}

#[test]
fn empty() {
    refused(&[""], E::Empty);
    refused(&["."], E::EmptyLabel);
}

#[test]
fn raw_input_over_cap() {
    refused(&[&"a".repeat(MAX_RAW_HOST_BYTES + 1)], E::InputTooLong);
}

#[test]
fn userinfo() {
    refused(
        &[
            "user@git.example.com",
            "user:pw@git.example.com",
            "@git.example.com",
        ],
        E::Userinfo,
    );
}

#[test]
fn port() {
    refused(
        &[
            "git.example.com:8443",
            "git.example.com:443",
            "git.example.com:",
        ],
        E::Port,
    );
}

#[test]
fn ip_literals() {
    refused(
        &[
            "10.0.0.1",
            "127.1",
            "0x7f000001",
            "2130706433",
            "0x",
            "[::1]",
            "[2001:db8::1]",
            "[::1",
            "::1]",
        ],
        E::IpLiteral,
    );
    refused(&["::1"], E::Port);
}

#[test]
fn wildcard() {
    refused(&["*.example.com", "exa*mple.com", "*"], E::Wildcard);
}

#[test]
fn trailing_dot_normalises_to_one_row() {
    assert_eq!(ok("git.example.com."), "git.example.com");
    refused(&["git.example.com.."], E::EmptyLabel);
}

#[test]
fn case_normalises_to_lowercase() {
    assert_eq!(ok("GIT.Example.COM"), "git.example.com");
}

#[test]
fn idn_and_punycode_are_one_row() {
    assert_eq!(ok("bücher.example"), "xn--bcher-kva.example");
    assert_eq!(ok("xn--bcher-kva.example"), "xn--bcher-kva.example");
    assert_eq!(ok("BÜCHER.example."), "xn--bcher-kva.example");
}

#[test]
fn invalid_punycode() {
    refused(
        &["xn--zz--.example", "xn--a.example", "xn--.example"],
        E::Idna,
    );
}

#[test]
fn mixed_script() {
    refused(
        &[
            "g\u{0456}t.example",
            "xn--gt-hoc.example",
            "\u{03b1}b\u{0430}.example",
            "git\u{65e5}\u{672c}.example",
            "\u{0430}\u{65e5}.example",
            "\u{03b1}\u{65e5}.example",
        ],
        E::MixedScript,
    );
    assert_eq!(
        ok("\u{043f}\u{0440}\u{0438}\u{043c}\u{0435}\u{0440}.example"),
        "xn--e1afmkfd.example"
    );
}

#[test]
fn single_script_labels_are_accepted() {
    assert_eq!(ok("b\u{1ea1}n.example"), "xn--bn-f5s.example");
    assert_eq!(ok("\u{1f00}\u{03b1}.example"), "xn--mxa590l.example");
    assert_eq!(ok("\u{0430}\u{0431}.example"), "xn--80ac.example");
}

#[test]
fn scheme() {
    refused(
        &[
            "https://git.example.com",
            "ssh://git.example.com",
            "http://x.example",
        ],
        E::Scheme,
    );
}

#[test]
fn path() {
    refused(
        &[
            "//git.example.com",
            "git.example.com/path",
            "git.example.com/",
            "git.example.com?x",
            "git.example.com#x",
        ],
        E::Path,
    );
}

#[test]
fn whitespace() {
    refused(
        &[
            "git .example.com",
            "git\t.example.com",
            "git\r.example.com",
            "git\n.example.com",
            "git\u{85}.example.com",
            "git\u{2028}.example.com",
            "git\u{2029}.example.com",
            " git.example.com",
        ],
        E::Whitespace,
    );
}

#[test]
fn control() {
    refused(
        &[
            "git\0.example.com",
            "git\u{1b}.example.com",
            "git\u{7f}.example.com",
        ],
        E::Control,
    );
}

#[test]
fn hostile_format_characters() {
    refused(
        &[
            "git\u{200b}.example.com",
            "git\u{ad}.example.com",
            "git\u{202e}.example.com",
        ],
        E::Hostile,
    );
}

#[test]
fn backslash() {
    refused(
        &[
            "git.example.com\\path",
            "git\\.example.com",
            "\\\\git.example.com",
        ],
        E::Backslash,
    );
}

#[test]
fn empty_label() {
    refused(
        &["git..example.com", ".git.example.com", "..example.com"],
        E::EmptyLabel,
    );
}

#[test]
fn hyphen_edges() {
    refused(
        &[
            "-git.example.com",
            "git-.example.com",
            "git.-example.com",
            "git.example-.com",
        ],
        E::LabelHyphen,
    );
    assert_eq!(ok("g-t.example.com"), "g-t.example.com");
}

#[test]
fn label_over_63() {
    let l63 = "a".repeat(63);
    let l64 = "a".repeat(64);
    assert_eq!(
        ok(&format!("{l63}.example.com")),
        format!("{l63}.example.com")
    );
    refused(&[&format!("{l64}.example.com")], E::LabelTooLong);
}

#[test]
fn name_over_253() {
    let l = "a".repeat(63);
    let at_cap = format!("{l}.{l}.{l}.{}.com", "b".repeat(57));
    assert_eq!(at_cap.len(), 253);
    assert_eq!(ok(&at_cap), at_cap);
    let over = format!("{l}.{l}.{l}.{}.com", "b".repeat(58));
    assert_eq!(over.len(), 254);
    refused(&[&over], E::NameTooLong);
}

#[test]
fn single_label() {
    refused(&["localhost", "git", "intranet-box"], E::SingleLabel);
}

#[test]
fn reserved_suffix() {
    refused(
        &[
            "git.local",
            "git.localhost",
            "git.localdomain",
            "git.internal",
            "git.intranet",
            "git.private",
            "git.corp",
            "git.home",
            "git.lan",
            "git.invalid",
            "git.onion",
            "git.home.arpa",
        ],
        E::ReservedSuffix,
    );
    assert_eq!(ok("git.localnet.example"), "git.localnet.example");
}

#[test]
fn errors_never_echo_the_input() {
    for e in ["secret.host\\x", "user@secret.host", "secret.host:1"] {
        let err = HostName::normalise(e).unwrap_err();
        assert!(!err.to_string().contains("secret"));
    }
}

#[test]
fn user_added_is_always_forgejo() {
    let host = Host::user_added("Git.Example.com.").unwrap();
    assert_eq!(host.kind(), HostKind::Forgejo);
    assert_eq!(host.name().as_str(), "git.example.com");
}

#[test]
fn user_cannot_add_github() {
    for input in ["github.com", "GitHub.com.", "GITHUB.COM"] {
        assert_eq!(
            Host::user_added(input),
            Err(E::GithubReserved),
            "input {input:?}"
        );
    }
    assert_eq!(
        Host::user_added("gist.github.com").map(|h| h.kind()),
        Ok(HostKind::Forgejo)
    );
}

#[test]
fn seed_and_stored_kinds() {
    let seed = Host::seed_github();
    assert_eq!(seed.kind(), HostKind::Github);
    assert_eq!(seed.name().as_str(), "github.com");
    assert_eq!(HostKind::from_stored("github"), Some(HostKind::Github));
    assert_eq!(HostKind::from_stored("forgejo"), Some(HostKind::Forgejo));
    assert_eq!(HostKind::from_stored("gitea"), None);
    assert_eq!(HostKind::from_stored("GitHub"), None);
    assert_eq!(HostKind::Github.as_str(), "github");
    assert_eq!(HostKind::Forgejo.as_str(), "forgejo");
}
