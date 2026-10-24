//! Runs the `fleetd askpass` binary the way git does. Own test binary because it spawns
//! children.

use std::process::{Command, Output};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "not-a-real-askpass-value";

fn askpass(prompt: &str, token: Option<&str>) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fleetd"));
    command.args(["askpass", prompt]).env_clear();
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
    let out = askpass("Password for 'x': ", None)?;
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    Ok(())
}
