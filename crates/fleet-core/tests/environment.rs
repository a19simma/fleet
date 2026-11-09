//! Tests for `fleet_core::environment`: the name grammar under a hostile table, every limit at
//! the limit and one over, the reserved list, the cross-entry rules and the version hash.

use std::error::Error;

use fleet_core::MIN_SECRET_LEN;
use fleet_core::Redactor;
use fleet_core::environment::{
    DEFAULT_AGENT_VISIBLE, DEFAULT_TIMEOUT_S, Delivery, EgressHost, Entry, EntryName,
    EnvironmentError as E, EnvironmentName, EnvironmentSpec, MAX_EGRESS_HOSTS, MAX_ENTRIES,
    MAX_NAME_BYTES, MAX_SCRIPT_BYTES, MAX_SCRIPT_TIMEOUT_S, MAX_SECRET_BYTES, MAX_SETUP_TOTAL_S,
    MAX_SHEBANG_BYTES, MAX_TOTAL_BYTES, MIN_SECRET_BYTES, OnFail, RESERVED, ScriptBody, ScriptSpec,
    SecretSpec, SecretValue, VersionHash, environment_version_hash, is_reserved,
};
use serde_json::Value;

type Res = Result<(), Box<dyn Error>>;

const BODY: &str = "#!/bin/sh\nset -eu\n";

fn name(raw: &str) -> Result<EntryName, E> {
    EntryName::new(raw)
}

fn secret(raw: &str, visible: bool, delivery: Delivery) -> Result<Entry, E> {
    Ok(Entry::Secret(SecretSpec::new(
        name(raw)?,
        visible,
        delivery,
    )?))
}

fn script(raw: &str, body: &str, on_fail: OnFail, timeout_s: u32) -> Result<Entry, E> {
    Ok(Entry::Script(ScriptSpec::new(
        name(raw)?,
        ScriptBody::new(body)?,
        on_fail,
        timeout_s,
    )?))
}

fn host(raw: &str) -> Result<EgressHost, E> {
    EgressHost::new(raw)
}

fn spec(entries: Vec<Entry>, hosts: &[&str]) -> Result<EnvironmentSpec, E> {
    let hosts = hosts
        .iter()
        .map(|h| host(h))
        .collect::<Result<Vec<_>, E>>()?;
    EnvironmentSpec::new(entries, hosts)
}

fn body_of(len: usize) -> String {
    format!("#!/x\n{}", "a".repeat(len - 5))
}

#[test]
fn constants_are_pinned() {
    assert_eq!(MIN_SECRET_BYTES, MIN_SECRET_LEN);
    assert_eq!(MIN_SECRET_BYTES, 8);
    assert_eq!(MAX_SECRET_BYTES, 64 * 1024);
    assert_eq!(MAX_SCRIPT_BYTES, 64 * 1024);
    assert_eq!(MAX_ENTRIES, 64);
    assert_eq!(MAX_TOTAL_BYTES, 768 * 1024);
    assert_eq!(MAX_NAME_BYTES, 64);
    assert_eq!(MAX_EGRESS_HOSTS, 16);
    assert_eq!(MAX_SHEBANG_BYTES, 128);
    assert_eq!(MAX_SCRIPT_TIMEOUT_S, 600);
    assert_eq!(MAX_SETUP_TOTAL_S, 1200);
    assert_eq!(DEFAULT_TIMEOUT_S, 120);
    const { assert!(!DEFAULT_AGENT_VISIBLE) };
}

#[test]
fn entry_name_hostile_table() {
    let long = "A".repeat(65);
    let multibyte = "\u{e9}".repeat(64);
    let rows: Vec<(&str, E)> = vec![
        ("", E::EntryNameEmpty),
        (long.as_str(), E::EntryNameTooLong),
        (multibyte.as_str(), E::EntryNameTooLong),
        ("1A", E::EntryNameChars),
        ("A-B", E::EntryNameChars),
        ("A.B", E::EntryNameChars),
        ("A B", E::EntryNameChars),
        ("A=B", E::EntryNameChars),
        (" A", E::EntryNameChars),
        ("a/b", E::EntryNameChars),
        ("a\\b", E::EntryNameChars),
        ("..", E::EntryNameChars),
        (".", E::EntryNameChars),
        ("A\0", E::EntryNameChars),
        ("\0", E::EntryNameChars),
        ("A\t", E::EntryNameChars),
        ("A\n", E::EntryNameChars),
        ("A\r", E::EntryNameChars),
        ("A\r\n", E::EntryNameChars),
        ("A\u{1b}", E::EntryNameChars),
        ("PATH\n", E::EntryNameChars),
        ("PATH\r\n", E::EntryNameChars),
        ("PATH ", E::EntryNameChars),
        ("A\u{85}", E::EntryNameChars),
        ("A\u{2028}", E::EntryNameChars),
        ("A\u{2029}", E::EntryNameChars),
        ("A\u{a0}", E::EntryNameChars),
        ("A\u{200b}", E::EntryNameChars),
        ("A\u{200c}", E::EntryNameChars),
        ("A\u{200d}", E::EntryNameChars),
        ("A\u{feff}", E::EntryNameChars),
        ("A\u{202e}", E::EntryNameChars),
        ("A\u{2066}", E::EntryNameChars),
        ("A\u{e0041}", E::EntryNameChars),
        ("\u{420}ATH", E::EntryNameChars),
        ("\u{ff30}ATH", E::EntryNameChars),
        ("%50ATH", E::EntryNameChars),
        ("\u{212a}EY", E::EntryNameChars),
        ("telemetry", E::EntryNameReserved),
        ("TELEMETRY", E::EntryNameReserved),
        ("Telemetry", E::EntryNameReserved),
        ("PATH", E::EntryNameReserved),
        ("path", E::EntryNameReserved),
        ("Path", E::EntryNameReserved),
        ("HOME", E::EntryNameReserved),
        ("HTTPS_PROXY", E::EntryNameReserved),
        ("https_proxy", E::EntryNameReserved),
        ("GH_TOKEN", E::EntryNameReserved),
        ("gh_token", E::EntryNameReserved),
        ("GITHUB_TOKEN", E::EntryNameReserved),
        ("FLEET_X", E::EntryNameReserved),
        ("fleet_x", E::EntryNameReserved),
        ("FLEET_", E::EntryNameReserved),
        ("fleet_", E::EntryNameReserved),
        ("LD_PRELOAD", E::EntryNameReserved),
        ("ld_library_path", E::EntryNameReserved),
        ("ANTHROPIC_API_KEY", E::EntryNameReserved),
        ("CLAUDE_CODE_X", E::EntryNameReserved),
        ("CLAUDE_", E::EntryNameReserved),
        ("OTEL_X", E::EntryNameReserved),
        ("DYLD_X", E::EntryNameReserved),
        ("HTTP_PROXY", E::EntryNameReserved),
        ("NO_PROXY", E::EntryNameReserved),
        ("GIT_DIR", E::EntryNameReserved),
        ("SSH_AUTH_SOCK", E::EntryNameReserved),
        ("XDG_X", E::EntryNameReserved),
        ("BASH_ENV", E::EntryNameReserved),
        ("MISE_X", E::EntryNameReserved),
        ("GH_TOKEN2", E::EntryNameReserved),
    ];
    for (raw, want) in rows {
        assert_eq!(EntryName::new(raw).err(), Some(want), "{raw:?}");
    }
}

#[test]
fn entry_name_accepts_the_grammar_edges() -> Res {
    let at_limit = "A".repeat(64);
    for ok in [
        "A",
        "_",
        "a1",
        "_1",
        "Z9_z",
        at_limit.as_str(),
        "FLEET",
        "LD",
        "PATHS",
        "MYPATH",
        "HOMEDIR",
        "ANTHROPIC",
        "CLAUDE",
        "GITHUB",
        "GH",
        "FLEETX",
        "kube_login",
        "SECRET_1",
    ] {
        assert_eq!(EntryName::new(ok)?.as_str(), ok);
    }
    Ok(())
}

#[test]
fn reserved_list_is_the_acceptance_list_plus_additions() {
    let acceptance = [
        "telemetry",
        "PATH",
        "HOME",
        "HTTPS_PROXY",
        "FLEET_*",
        "LD_*",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ANTHROPIC_*",
        "CLAUDE_*",
    ];
    for rule in acceptance {
        assert!(RESERVED.contains(&rule), "{rule}");
    }
    for rule in RESERVED {
        let stars = rule.matches('*').count();
        assert!(stars == 0 || (stars == 1 && rule.ends_with('*')), "{rule}");
        assert!(!rule.is_empty() && *rule != "*", "{rule}");
    }
}

#[test]
fn reserved_list_is_pinned_row_by_row() {
    let expected = [
        "telemetry",
        "PATH",
        "HOME",
        "HTTPS_PROXY",
        "FLEET_*",
        "LD_*",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "ANTHROPIC_*",
        "CLAUDE_*",
        "OTEL_*",
        "DYLD_*",
        "HTTP_PROXY",
        "NO_PROXY",
        "ALL_PROXY",
        "GIT_*",
        "GH_*",
        "SSH_*",
        "XDG_*",
        "TMPDIR",
        "SHELL",
        "USER",
        "LOGNAME",
        "PWD",
        "OLDPWD",
        "IFS",
        "BASH_ENV",
        "ENV",
        "MISE_*",
    ];
    assert_eq!(RESERVED, expected);
}

#[test]
fn every_reserved_row_is_enforced() {
    let prefixes: Vec<&str> = RESERVED
        .iter()
        .filter_map(|r| r.strip_suffix('*'))
        .collect();
    for rule in RESERVED {
        if let Some(prefix) = rule.strip_suffix('*') {
            let stem = prefix.trim_end_matches('_');
            for raw in [
                prefix.to_owned(),
                format!("{prefix}X"),
                format!("{prefix}x_9"),
                prefix.to_ascii_lowercase(),
                format!("{}Zz", prefix.to_ascii_lowercase()),
            ] {
                assert_eq!(
                    EntryName::new(&raw).err(),
                    Some(E::EntryNameReserved),
                    "{raw}"
                );
                assert!(is_reserved(&raw), "{raw}");
            }
            assert!(!is_reserved(stem), "{stem}");
            assert!(!is_reserved(&format!("{stem}X")), "{stem}X");
            assert!(EntryName::new(stem).is_ok(), "{stem}");
        } else {
            for raw in [
                (*rule).to_owned(),
                rule.to_ascii_lowercase(),
                rule.to_ascii_uppercase(),
            ] {
                assert_eq!(
                    EntryName::new(&raw).err(),
                    Some(E::EntryNameReserved),
                    "{raw}"
                );
            }
            let longer = format!("{rule}X");
            let covered = prefixes.iter().any(|p| {
                longer
                    .to_ascii_uppercase()
                    .starts_with(&p.to_ascii_uppercase())
            });
            assert_eq!(is_reserved(&longer), covered, "{longer}");
            let shorter = &rule[..rule.len() - 1];
            let covered = prefixes.iter().any(|p| {
                shorter
                    .to_ascii_uppercase()
                    .starts_with(&p.to_ascii_uppercase())
            });
            assert_eq!(is_reserved(shorter), covered, "{shorter}");
        }
    }
}

#[test]
fn duplicate_names_fold_and_cross_kinds() -> Res {
    let cases = [
        vec![
            secret("KUBE", false, Delivery::File)?,
            secret("kube", false, Delivery::File)?,
        ],
        vec![
            secret("KUBE", false, Delivery::File)?,
            script("Kube", BODY, OnFail::Abort, 10)?,
        ],
        vec![
            script("a_1", BODY, OnFail::Abort, 10)?,
            script("A_1", BODY, OnFail::Continue, 10)?,
        ],
    ];
    for entries in cases {
        assert_eq!(spec(entries, &[]).err(), Some(E::EntryNameDuplicate));
    }
    let ok = spec(
        vec![
            secret("KUBE", false, Delivery::File)?,
            script("KUBE2", BODY, OnFail::Abort, 10)?,
        ],
        &[],
    )?;
    assert_eq!(ok.entries().len(), 2);
    Ok(())
}

#[test]
fn environment_name_table() {
    let long = "a".repeat(65);
    let rows: Vec<(&str, E)> = vec![
        ("", E::EnvNameEmpty),
        (long.as_str(), E::EnvNameTooLong),
        (".hidden", E::EnvNameChars),
        ("-a", E::EnvNameChars),
        ("_a", E::EnvNameChars),
        ("/a", E::EnvNameChars),
        ("a/b", E::EnvNameChars),
        ("a\\b", E::EnvNameChars),
        ("..", E::EnvNameChars),
        (".", E::EnvNameChars),
        ("a\0", E::EnvNameChars),
        ("a\r\n", E::EnvNameChars),
        ("a\n", E::EnvNameChars),
        ("a\u{85}", E::EnvNameChars),
        ("a\u{2028}", E::EnvNameChars),
        ("a\u{200b}", E::EnvNameChars),
        ("a\u{202e}", E::EnvNameChars),
        ("\u{430}bc", E::EnvNameChars),
        ("a b", E::EnvNameChars),
        (" a", E::EnvNameChars),
        ("%2e%2e", E::EnvNameChars),
        ("a=b", E::EnvNameChars),
        ("a:b", E::EnvNameChars),
    ];
    for (raw, want) in rows {
        assert_eq!(EnvironmentName::new(raw).err(), Some(want), "{raw:?}");
    }
}

#[test]
fn environment_name_accepts_the_grammar() -> Res {
    let at_limit = "a".repeat(64);
    for ok in [
        "a",
        "0",
        "A.b-c_d",
        "1.2",
        "PATH",
        "telemetry",
        "a..b",
        "a.",
        at_limit.as_str(),
    ] {
        assert_eq!(EnvironmentName::new(ok)?.as_str(), ok);
    }
    Ok(())
}

#[test]
fn secret_value_table() {
    let rows: Vec<(String, Option<E>)> = vec![
        ("abcdefg".to_owned(), Some(E::SecretTooShort)),
        (String::new(), Some(E::SecretTooShort)),
        ("abcdefgh".to_owned(), None),
        ("ab".repeat(MAX_SECRET_BYTES / 2), None),
        (
            format!("{}b", "a".repeat(MAX_SECRET_BYTES)),
            Some(E::SecretTooLong),
        ),
        (" ".repeat(8), Some(E::SecretBlank)),
        ("\u{a0}".repeat(4), Some(E::SecretBlank)),
        ("aaaaaaaa".to_owned(), Some(E::SecretBlank)),
        ("\n\n\n\n\n\n\n\n".to_owned(), Some(E::SecretBlank)),
        ("abc\0defgh".to_owned(), Some(E::SecretText)),
        ("abcdefg\0".to_owned(), Some(E::SecretText)),
        ("abc\rdefgh".to_owned(), Some(E::SecretText)),
        ("abc\r\ndefgh".to_owned(), Some(E::SecretText)),
        ("abc\u{200b}defgh".to_owned(), Some(E::SecretText)),
        ("abc\u{2028}defgh".to_owned(), Some(E::SecretText)),
        ("abc\u{2029}defgh".to_owned(), Some(E::SecretText)),
        ("abc\u{85}defgh".to_owned(), Some(E::SecretText)),
        ("abc\u{feff}defgh".to_owned(), Some(E::SecretText)),
        ("abc\u{202e}defgh".to_owned(), Some(E::SecretText)),
        ("abc\u{e0041}defgh".to_owned(), Some(E::SecretText)),
        ("abc\u{1b}[0mdef".to_owned(), Some(E::SecretText)),
        (
            "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}".to_owned(),
            None,
        ),
        ("line1\nline2".to_owned(), None),
        ("tab\tvalue".to_owned(), None),
        ("p\u{e4}ssw\u{f6}rd".to_owned(), None),
    ];
    for (value, want) in rows {
        assert_eq!(
            SecretValue::new(value.clone()).err(),
            want,
            "{:?}",
            value.len()
        );
    }
}

#[test]
fn secret_value_limits_use_the_constants() {
    assert!(SecretValue::new("ab".repeat(MIN_SECRET_BYTES / 2)).is_ok());
    assert_eq!(
        SecretValue::new(format!("{}b", "a".repeat(MIN_SECRET_BYTES - 1))).err(),
        None
    );
    assert_eq!(
        SecretValue::new("ab".repeat(MIN_SECRET_BYTES / 2)[..MIN_SECRET_BYTES - 1].to_owned())
            .err(),
        Some(E::SecretTooShort)
    );
    assert!(SecretValue::new("ab".repeat(MAX_SECRET_BYTES / 2)).is_ok());
    assert_eq!(
        SecretValue::new("ab".repeat(MAX_SECRET_BYTES / 2) + "c").err(),
        Some(E::SecretTooLong)
    );
}

#[test]
fn secret_value_debug_and_display_hide_the_value() -> Res {
    let value = SecretValue::new("hunter2-hunter2".to_owned())?;
    assert_eq!(value.expose(), b"hunter2-hunter2");
    assert_eq!(value.len(), 15);
    assert!(!value.is_empty());
    let shown = format!("{value:?}");
    assert!(!shown.contains("hunter2"));
    assert_eq!(shown, "SecretValue([REDACTED])");
    let wrapped = format!("{:?}", Entry::Secret(SecretSpec::with_defaults(name("K")?)));
    assert!(!wrapped.contains("hunter2"));
    Ok(())
}

#[test]
fn accepted_secret_values_are_redactable() {
    let samples: Vec<String> = [
        "abcdefgh",
        "a b c d e f g h",
        "line1\nline2",
        "tab\tvalue",
        "\u{e4}\u{e4}\u{e4}\u{e4}b",
        "aaaaaaab",
        "baaaaaaa",
        "ab",
        "",
        "        ",
        "aaaaaaaa",
        "\u{a0}\u{a0}\u{a0}\u{a0}\u{a0}",
        "\n\n\n\n\n\n\n\n",
        "abc\0defgh",
        "short",
        "1234567",
        "12345678",
        "\u{1f600}\u{1f600}",
        "\u{1f600}\u{1f601}",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for value in samples {
        let accepted = SecretValue::new(value.clone()).is_ok();
        let masked = Redactor::new([value.as_str()]).len() == 1;
        if accepted {
            assert!(masked, "{value:?}");
        }
        if !masked {
            assert!(!accepted, "{value:?}");
        }
    }
}

#[test]
fn script_body_table() {
    let long_shebang = format!("#!/{}\n", "a".repeat(MAX_SHEBANG_BYTES - 3));
    let long_shebang_over = format!("#!/{}\n", "a".repeat(MAX_SHEBANG_BYTES - 2));
    let rows: Vec<(String, Option<E>)> = vec![
        (String::new(), Some(E::ScriptEmpty)),
        ("echo hi\n".to_owned(), Some(E::ScriptNoShebang)),
        ("#!sh\n".to_owned(), Some(E::ScriptNoShebang)),
        ("#!\n".to_owned(), Some(E::ScriptNoShebang)),
        (" #!/bin/sh\n".to_owned(), Some(E::ScriptNoShebang)),
        ("\n#!/bin/sh\n".to_owned(), Some(E::ScriptNoShebang)),
        ("#/bin/sh\n".to_owned(), Some(E::ScriptNoShebang)),
        (long_shebang_over, Some(E::ScriptNoShebang)),
        (long_shebang, None),
        ("#!/bin/sh".to_owned(), None),
        ("#!/".to_owned(), None),
        ("#!/bin/sh\r\necho\r\n".to_owned(), Some(E::ScriptText)),
        ("#!/bin/sh\0".to_owned(), Some(E::ScriptText)),
        ("#!/bin/sh\n# \u{202e}x\n".to_owned(), Some(E::ScriptText)),
        ("#!/bin/sh\n# \u{200b}\n".to_owned(), Some(E::ScriptText)),
        ("#!/bin/sh\n# \u{2028}\n".to_owned(), Some(E::ScriptText)),
        ("#!/bin/sh\n# \u{85}\n".to_owned(), Some(E::ScriptText)),
        ("#!/bin/sh\n\tx\n".to_owned(), None),
        ("#!/bin/sh\n# \u{200d}\n".to_owned(), None),
        (body_of(MAX_SCRIPT_BYTES), None),
        (body_of(MAX_SCRIPT_BYTES + 1), Some(E::ScriptTooLong)),
    ];
    for (body, want) in rows {
        assert_eq!(
            ScriptBody::new(&body).err(),
            want,
            "{:?}",
            &body[..body.len().min(40)]
        );
    }
}

#[test]
fn egress_host_table() {
    let label64 = format!("{}.example.com", "a".repeat(64));
    let label63 = format!("{}.example.com", "a".repeat(63));
    let long = format!("{}.com", vec!["a".repeat(63); 4].join("."));
    let at_253 = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    let rows: Vec<(String, bool)> = vec![
        ("pve.example.com".to_owned(), true),
        ("a.b".to_owned(), true),
        ("a-b.example.com".to_owned(), true),
        ("1a.example.com".to_owned(), true),
        ("example.c0m".to_owned(), true),
        (label63, true),
        (at_253.clone(), true),
        (format!("{at_253}e"), false),
        (long, false),
        (label64, false),
        (String::new(), false),
        ("PVE.example.com".to_owned(), false),
        ("Example.com".to_owned(), false),
        ("10.0.0.1".to_owned(), false),
        ("1.2.3.4".to_owned(), false),
        ("::1".to_owned(), false),
        ("[::1]".to_owned(), false),
        ("2001:db8::1".to_owned(), false),
        ("host:443".to_owned(), false),
        ("user@host.example.com".to_owned(), false),
        ("example.com.".to_owned(), false),
        ("-a.example.com".to_owned(), false),
        ("a-.example.com".to_owned(), false),
        ("a..b".to_owned(), false),
        (".example.com".to_owned(), false),
        ("localhost".to_owned(), false),
        ("caf\u{e9}.example.com".to_owned(), false),
        ("*.example.com".to_owned(), false),
        ("a_b.example.com".to_owned(), false),
        ("a.example.com\r".to_owned(), false),
        ("a.example.com\n".to_owned(), false),
        ("a.example.com\r\n".to_owned(), false),
        ("a b.example.com".to_owned(), false),
        (" a.example.com".to_owned(), false),
        ("a.example.com/".to_owned(), false),
        ("a.example.com\\x".to_owned(), false),
        ("a.example.com\u{85}".to_owned(), false),
        ("a.example.com\u{2028}".to_owned(), false),
        ("a.example.com\0".to_owned(), false),
        ("a.exampl\u{435}.com".to_owned(), false),
        ("%61.example.com".to_owned(), false),
    ];
    for (raw, ok) in rows {
        let got = EgressHost::new(&raw);
        if ok {
            assert!(got.is_ok(), "{raw:?}");
        } else {
            assert_eq!(got.err(), Some(E::HostInvalid), "{raw:?}");
        }
    }
}

#[test]
fn entry_count_counts_secrets_and_scripts_together() -> Res {
    let secrets = |n: usize| -> Result<Vec<Entry>, E> {
        (0..n)
            .map(|i| secret(&format!("S{i}"), false, Delivery::File))
            .collect()
    };
    let scripts = |n: usize| -> Result<Vec<Entry>, E> {
        (0..n)
            .map(|i| script(&format!("T{i}"), BODY, OnFail::Abort, 1))
            .collect()
    };
    assert_eq!(
        spec(secrets(MAX_ENTRIES)?, &[])?.entries().len(),
        MAX_ENTRIES
    );
    assert_eq!(
        spec(scripts(MAX_ENTRIES)?, &[])?.entries().len(),
        MAX_ENTRIES
    );
    let mut mixed = secrets(MAX_ENTRIES - 1)?;
    mixed.extend(scripts(1)?);
    assert_eq!(spec(mixed, &[])?.entries().len(), MAX_ENTRIES);
    let mut over = secrets(MAX_ENTRIES)?;
    over.extend(scripts(1)?);
    assert_eq!(spec(over, &[]).err(), Some(E::TooManyEntries));
    let mut over = secrets(MAX_ENTRIES / 2)?;
    over.extend(scripts(MAX_ENTRIES / 2 + 1)?);
    assert_eq!(spec(over, &[]).err(), Some(E::TooManyEntries));
    Ok(())
}

#[test]
fn script_total_cap_at_the_cap_and_one_over() -> Res {
    let full = MAX_SCRIPT_BYTES;
    let n_full = MAX_TOTAL_BYTES / full - 1;
    let build = |filler: usize, last: usize| -> Result<Result<EnvironmentSpec, E>, E> {
        let mut entries = Vec::new();
        for i in 0..n_full {
            entries.push(script(&format!("F{i}"), &body_of(full), OnFail::Abort, 1)?);
        }
        entries.push(script("G", &body_of(filler), OnFail::Abort, 1)?);
        entries.push(script("H", &body_of(last), OnFail::Abort, 1)?);
        Ok(spec(entries, &[]))
    };
    assert_eq!(build(full - 5, 5)??.script_bytes(), MAX_TOTAL_BYTES);
    assert_eq!(build(full - 6, 6)??.script_bytes(), MAX_TOTAL_BYTES);
    assert_eq!(build(full - 5, 6)?.err(), Some(E::TotalTooLarge));
    assert_eq!(build(full, 5)?.err(), Some(E::TotalTooLarge));
    Ok(())
}

#[test]
fn total_cap_with_secret_values_at_the_cap_and_one_over() -> Res {
    let s = spec(vec![script("T", &body_of(100), OnFail::Abort, 1)?], &[])?;
    assert_eq!(s.script_bytes(), 100);
    assert_eq!(s.check_total_with_secrets(MAX_TOTAL_BYTES - 100), Ok(()));
    assert_eq!(
        s.check_total_with_secrets(MAX_TOTAL_BYTES - 100 + 1),
        Err(E::TotalTooLarge)
    );
    assert_eq!(
        s.check_total_with_secrets(usize::MAX),
        Err(E::TotalTooLarge)
    );
    Ok(())
}

#[test]
fn script_timeouts_and_setup_total() -> Res {
    for (t, ok) in [
        (0, false),
        (1, true),
        (MAX_SCRIPT_TIMEOUT_S, true),
        (MAX_SCRIPT_TIMEOUT_S + 1, false),
        (u32::MAX, false),
    ] {
        let got = script("T", BODY, OnFail::Abort, t);
        if ok {
            assert!(got.is_ok(), "{t}");
        } else {
            assert_eq!(got.err(), Some(E::TimeoutRange), "{t}");
        }
    }
    let two = |a: u32, b: u32| -> Result<EnvironmentSpec, E> {
        spec(
            vec![
                script("A", BODY, OnFail::Abort, a)?,
                script("B", BODY, OnFail::Abort, b)?,
            ],
            &[],
        )
    };
    assert!(two(MAX_SCRIPT_TIMEOUT_S, MAX_SCRIPT_TIMEOUT_S).is_ok());
    assert!(two(MAX_SCRIPT_TIMEOUT_S, MAX_SCRIPT_TIMEOUT_S - 1).is_ok());
    let three = spec(
        vec![
            script("A", BODY, OnFail::Abort, MAX_SCRIPT_TIMEOUT_S)?,
            script("B", BODY, OnFail::Abort, MAX_SCRIPT_TIMEOUT_S)?,
            script("C", BODY, OnFail::Abort, 1)?,
        ],
        &[],
    );
    assert_eq!(three.err(), Some(E::SetupTotalTooLong));
    Ok(())
}

#[test]
fn egress_host_count_and_duplicates() -> Res {
    let hosts: Vec<String> = (0..=MAX_EGRESS_HOSTS)
        .map(|i| format!("h{i}.example.com"))
        .collect();
    let refs = |n: usize| -> Vec<&str> { hosts.iter().take(n).map(String::as_str).collect() };
    assert_eq!(
        spec(vec![], &refs(MAX_EGRESS_HOSTS))?.egress_hosts().len(),
        MAX_EGRESS_HOSTS
    );
    assert_eq!(
        spec(vec![], &refs(MAX_EGRESS_HOSTS + 1)).err(),
        Some(E::TooManyHosts)
    );
    assert_eq!(
        spec(vec![], &["a.example.com", "b.example.com", "a.example.com"]).err(),
        Some(E::HostDuplicate)
    );
    Ok(())
}

#[test]
fn env_delivery_needs_agent_visible() -> Res {
    let ok = SecretSpec::new(name("K")?, true, Delivery::Env)?;
    assert_eq!(ok.delivery(), Delivery::Env);
    assert!(ok.agent_visible());
    assert_eq!(
        SecretSpec::new(name("K")?, false, Delivery::Env).err(),
        Some(E::EnvDeliveryNeedsVisible)
    );
    assert!(SecretSpec::new(name("K")?, true, Delivery::File).is_ok());
    assert!(SecretSpec::new(name("K")?, false, Delivery::File).is_ok());
    Ok(())
}

#[test]
fn defaults_are_private_file_and_abort() -> Res {
    let s = SecretSpec::with_defaults(name("K")?);
    assert!(!s.agent_visible());
    assert_eq!(s.delivery(), Delivery::File);
    assert_eq!(s.name().as_str(), "K");
    let t = ScriptSpec::with_defaults(name("T")?, ScriptBody::new(BODY)?);
    assert_eq!(t.on_fail(), OnFail::Abort);
    assert_eq!(t.timeout_s(), DEFAULT_TIMEOUT_S);
    assert_eq!(t.body().as_str(), BODY);
    assert_eq!(Delivery::default(), Delivery::File);
    assert_eq!(OnFail::default(), OnFail::Abort);
    Ok(())
}

#[test]
fn required_field_negatives() -> Res {
    assert_eq!(EntryName::new("").err(), Some(E::EntryNameEmpty));
    assert_eq!(ScriptBody::new("").err(), Some(E::ScriptEmpty));
    assert_eq!(ScriptBody::new("echo\n").err(), Some(E::ScriptNoShebang));
    assert_eq!(
        ScriptSpec::new(name("T")?, ScriptBody::new(BODY)?, OnFail::Abort, 0).err(),
        Some(E::TimeoutRange)
    );
    assert_eq!(
        SecretSpec::new(name("K")?, false, Delivery::Env).err(),
        Some(E::EnvDeliveryNeedsVisible)
    );
    assert_eq!(
        SecretValue::new(String::new()).err(),
        Some(E::SecretTooShort)
    );
    Ok(())
}

#[test]
fn error_text_is_fixed_and_carries_no_input() {
    for e in [
        E::EnvNameEmpty,
        E::EnvNameTooLong,
        E::EnvNameChars,
        E::EntryNameEmpty,
        E::EntryNameTooLong,
        E::EntryNameChars,
        E::EntryNameReserved,
        E::EntryNameDuplicate,
        E::SecretTooShort,
        E::SecretTooLong,
        E::SecretBlank,
        E::SecretText,
        E::ScriptEmpty,
        E::ScriptTooLong,
        E::ScriptNoShebang,
        E::ScriptText,
        E::TimeoutRange,
        E::SetupTotalTooLong,
        E::TooManyEntries,
        E::TotalTooLarge,
        E::HostInvalid,
        E::HostDuplicate,
        E::TooManyHosts,
        E::EnvDeliveryNeedsVisible,
    ] {
        let text = e.to_string();
        assert_ne!(text, "");
        assert!(
            text.chars().all(|c| c.is_ascii() && !c.is_control()),
            "{text}"
        );
    }
}

type Case = (String, EnvironmentSpec, String);

fn load_fixture() -> Result<Vec<Case>, Box<dyn Error>> {
    let root: Value = serde_json::from_str(include_str!("fixtures/environment_hash.json"))?;
    let text = |v: &Value, k: &str| -> Result<String, Box<dyn Error>> {
        Ok(v.get(k)
            .and_then(Value::as_str)
            .ok_or_else(|| k.to_owned())?
            .to_owned())
    };
    let mut out = Vec::new();
    for case in root.get("cases").and_then(Value::as_array).ok_or("cases")? {
        let mut entries = Vec::new();
        for s in case
            .get("secrets")
            .and_then(Value::as_array)
            .ok_or("secrets")?
        {
            let delivery = if text(s, "delivery")? == "env" {
                Delivery::Env
            } else {
                Delivery::File
            };
            let vis = s
                .get("agent_visible")
                .and_then(Value::as_bool)
                .ok_or("agent_visible")?;
            entries.push(secret(&text(s, "name")?, vis, delivery)?);
        }
        for s in case
            .get("scripts")
            .and_then(Value::as_array)
            .ok_or("scripts")?
        {
            let on_fail = if text(s, "on_fail")? == "continue" {
                OnFail::Continue
            } else {
                OnFail::Abort
            };
            let t = u32::try_from(
                s.get("timeout_s")
                    .and_then(Value::as_u64)
                    .ok_or("timeout_s")?,
            )?;
            entries.push(script(&text(s, "name")?, &text(s, "body")?, on_fail, t)?);
        }
        let mut hosts = Vec::new();
        for h in case
            .get("egress_hosts")
            .and_then(Value::as_array)
            .ok_or("hosts")?
        {
            hosts.push(host(h.as_str().ok_or("host")?)?);
        }
        out.push((
            text(case, "label")?,
            EnvironmentSpec::new(entries, hosts)?,
            text(case, "digest")?,
        ));
    }
    Ok(out)
}

#[test]
fn version_hash_is_pinned_by_the_fixtures() -> Res {
    let cases = load_fixture()?;
    assert_eq!(cases.len(), 4);
    for (label, spec, digest) in &cases {
        assert_eq!(digest.len(), 64, "{label}");
        assert_eq!(
            environment_version_hash(spec).to_string(),
            *digest,
            "{label}"
        );
        assert_eq!(spec.version_hash().to_string(), *digest, "{label}");
    }
    assert_eq!(
        cases.first().map(|c| c.2.as_str()),
        Some("244c3f41937d4eaf2c8072dd3d9789f75fd66f09e161bb4110742fbf6d8371da")
    );
    Ok(())
}

#[test]
fn version_hash_formats_as_lowercase_hex() -> Res {
    let hash: VersionHash = spec(vec![], &[])?.version_hash();
    let shown = hash.to_string();
    assert_eq!(shown.len(), 64);
    assert!(
        shown
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    assert_eq!(format!("{hash:?}"), format!("VersionHash({shown})"));
    assert_eq!(hash.as_bytes().len(), 32);
    Ok(())
}

struct Parts {
    a_visible: bool,
    b_delivery: Delivery,
    on_fail: OnFail,
    timeout: u32,
    body: String,
    host: String,
    secret_a: String,
    swap: bool,
}

impl Parts {
    fn base() -> Self {
        Self {
            a_visible: false,
            b_delivery: Delivery::File,
            on_fail: OnFail::Abort,
            timeout: 120,
            body: BODY.to_owned(),
            host: "pve.example.com".to_owned(),
            secret_a: "A".to_owned(),
            swap: false,
        }
    }

    fn hash(&self) -> Result<String, E> {
        let mut scripts = vec![
            script("s1", &self.body, self.on_fail, self.timeout)?,
            script("s2", "#!/bin/sh\necho two\n", OnFail::Abort, 5)?,
        ];
        if self.swap {
            scripts.reverse();
        }
        let mut entries = vec![
            secret(&self.secret_a, self.a_visible, Delivery::File)?,
            secret("B", true, self.b_delivery)?,
        ];
        entries.extend(scripts);
        Ok(spec(entries, &[&self.host, "other.example.com"])?
            .version_hash()
            .to_string())
    }
}

#[test]
fn every_hashed_field_flips_the_hash() -> Res {
    let base = Parts::base().hash()?;
    let flips: Vec<(&str, Parts)> = vec![
        (
            "agent_visible",
            Parts {
                a_visible: true,
                ..Parts::base()
            },
        ),
        (
            "delivery",
            Parts {
                b_delivery: Delivery::Env,
                ..Parts::base()
            },
        ),
        (
            "on_fail",
            Parts {
                on_fail: OnFail::Continue,
                ..Parts::base()
            },
        ),
        (
            "timeout",
            Parts {
                timeout: 121,
                ..Parts::base()
            },
        ),
        (
            "body byte",
            Parts {
                body: "#!/bin/sh\nset -eu \n".to_owned(),
                ..Parts::base()
            },
        ),
        (
            "host",
            Parts {
                host: "pve2.example.com".to_owned(),
                ..Parts::base()
            },
        ),
        (
            "secret name",
            Parts {
                secret_a: "A2".to_owned(),
                ..Parts::base()
            },
        ),
        (
            "secret name case",
            Parts {
                secret_a: "a".to_owned(),
                ..Parts::base()
            },
        ),
        (
            "script order",
            Parts {
                swap: true,
                ..Parts::base()
            },
        ),
    ];
    for (label, parts) in flips {
        assert_ne!(parts.hash()?, base, "{label}");
    }
    assert_eq!(Parts::base().hash()?, base);
    Ok(())
}

#[test]
fn adding_or_removing_an_entry_or_host_flips_the_hash() -> Res {
    let one = |extra: Vec<Entry>, hosts: &[&str]| -> Result<String, E> {
        let mut entries = vec![secret("A", false, Delivery::File)?];
        entries.extend(extra);
        Ok(spec(entries, hosts)?.version_hash().to_string())
    };
    let base = one(vec![], &[])?;
    assert_ne!(base, one(vec![secret("B", false, Delivery::File)?], &[])?);
    assert_ne!(base, one(vec![script("T", BODY, OnFail::Abort, 1)?], &[])?);
    assert_ne!(base, one(vec![], &["a.example.com"])?);
    assert_ne!(
        spec(vec![], &[])?.version_hash(),
        spec(vec![secret("A", false, Delivery::File)?], &[])?.version_hash()
    );
    Ok(())
}

#[test]
fn secret_and_host_order_do_not_matter_but_script_order_does() -> Res {
    let s = |n: &str| secret(n, false, Delivery::File);
    let t = |n: &str| script(n, BODY, OnFail::Abort, 10);
    let forward = spec(
        vec![s("A")?, s("b")?, s("C")?, t("x")?, t("y")?],
        &["a.example.com", "b.example.com"],
    )?;
    let permuted = spec(
        vec![s("C")?, t("x")?, s("A")?, t("y")?, s("b")?],
        &["b.example.com", "a.example.com"],
    )?;
    let reordered = spec(
        vec![s("A")?, s("b")?, s("C")?, t("y")?, t("x")?],
        &["a.example.com", "b.example.com"],
    )?;
    assert_eq!(forward.version_hash(), permuted.version_hash());
    assert_ne!(forward.version_hash(), reordered.version_hash());
    Ok(())
}

#[test]
fn secret_values_are_not_a_hash_input() -> Res {
    let s = spec(vec![secret("K", true, Delivery::File)?], &[])?;
    let before = s.version_hash();
    let _first = SecretValue::new("first-value-1234".to_owned())?;
    let _second = SecretValue::new("second-value-5678".to_owned())?;
    assert_eq!(s.version_hash(), before);
    let hash_fn: fn(&EnvironmentSpec) -> VersionHash = environment_version_hash;
    assert_eq!(hash_fn(&s), before);
    Ok(())
}
