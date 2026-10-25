//! Runs the `fleetd askpass` binary the way git does. Own test binary because it spawns
//! children.

use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "not-a-real-askpass-value";

fn askpass(prompt: &str, token: Option<&str>) -> Result<Output, std::io::Error> {
    askpass_for(prompt, token, Some("github.com"))
}

fn askpass_for(
    prompt: &str,
    token: Option<&str>,
    hosts: Option<&str>,
) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fleetd"));
    command.args(["askpass", prompt]).env_clear();
    if let Some(hosts) = hosts {
        command.env("FLEETD_ASKPASS_HOSTS", hosts);
    }
    if let Some(token) = token {
        command.env("GH_TOKEN", token);
    }
    command.output()
}

#[test]
fn a_password_prompt_prints_only_the_token() -> TestResult {
    let out = askpass(
        "Password for 'https://x-access-token@github.com': ",
        Some(TOKEN),
    )?;
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout)?, format!("{TOKEN}\n"));
    assert!(out.stderr.is_empty());
    Ok(())
}

#[test]
fn double_userinfo_prompts_are_answered_because_validate_repo_rejects_both_urls_first() -> TestResult
{
    for prompt in [
        "Password for 'https://x@evil.com@github.com': ",
        "Password for 'https://evil.com\\@github.com': ",
    ] {
        let out = askpass(prompt, Some(TOKEN))?;
        assert!(out.status.success(), "{prompt}");
        assert_eq!(String::from_utf8(out.stdout)?.trim_end(), TOKEN, "{prompt}");
    }
    Ok(())
}

#[test]
fn a_prompt_for_another_host_prints_nothing_and_fails() -> TestResult {
    for prompt in [
        "Password for 'https://attacker.example': ",
        "Username for 'https://attacker.example': ",
        "Password for 'https://github.com@attacker.example': ",
    ] {
        let out = askpass(prompt, Some(TOKEN))?;
        assert!(!out.status.success(), "{prompt}");
        assert!(out.stdout.is_empty(), "{prompt}");
        assert!(!String::from_utf8(out.stderr)?.contains(TOKEN));
    }
    Ok(())
}

#[test]
fn a_missing_or_empty_host_list_answers_nothing() -> TestResult {
    for hosts in [None, Some(""), Some(",")] {
        let out = askpass_for("Password for 'https://github.com': ", Some(TOKEN), hosts)?;
        assert!(!out.status.success(), "{hosts:?}");
        assert!(out.stdout.is_empty(), "{hosts:?}");
    }
    let out = askpass_for(
        "Password for 'https://git.example.com/a': ",
        Some(TOKEN),
        Some("github.com,git.example.com"),
    )?;
    assert_eq!(String::from_utf8(out.stdout)?, format!("{TOKEN}\n"));
    Ok(())
}

#[test]
fn a_username_prompt_prints_the_fixed_username() -> TestResult {
    let out = askpass("Username for 'https://github.com': ", Some(TOKEN))?;
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout)?, "x-access-token\n");
    assert!(!String::from_utf8(out.stderr)?.contains(TOKEN));
    Ok(())
}

#[test]
fn an_unknown_prompt_prints_nothing_and_fails() -> TestResult {
    let out = askpass("Passphrase for key: ", Some(TOKEN))?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert!(!String::from_utf8(out.stderr)?.contains(TOKEN));
    Ok(())
}

#[test]
fn a_password_prompt_without_a_token_prints_nothing_and_fails() -> TestResult {
    let out = askpass("Password for 'https://github.com': ", None)?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    Ok(())
}
