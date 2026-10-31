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
    host: Option<&str>,
) -> Result<Output, std::io::Error> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fleetd"));
    command.args(["askpass", prompt]).env_clear();
    if let Some(host) = host {
        command.env("FLEETD_ASKPASS_HOST", host);
    }
    if let Some(token) = token {
        command.env("GH_TOKEN", token);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(command.output());
    });
    rx.recv_timeout(std::time::Duration::from_secs(60))
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "askpass hung",
            ))
        })
}

#[test]
fn a_password_prompt_prints_only_the_token() -> TestResult {
    let out = askpass(
        "Password for 'https://x-access-token@github.com': ",
        Some(TOKEN),
    )?;
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout)?, format!("{TOKEN}\n"));
    assert_eq!(out.stderr, Vec::<u8>::new());
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
fn a_missing_or_empty_token_host_answers_nothing() -> TestResult {
    for host in [None, Some(""), Some(",")] {
        let out = askpass_for("Password for 'https://github.com': ", Some(TOKEN), host)?;
        assert!(!out.status.success(), "{host:?}");
        assert!(out.stdout.is_empty(), "{host:?}");
    }
    let out = askpass_for(
        "Password for 'https://git.example.com/a': ",
        Some(TOKEN),
        Some("git.example.com"),
    )?;
    assert_eq!(String::from_utf8(out.stdout)?, format!("{TOKEN}\n"));
    Ok(())
}

#[test]
fn a_host_list_in_the_environment_does_not_widen_the_token_host() -> TestResult {
    let out = askpass_for(
        "Password for 'https://gitlab.com/a': ",
        Some(TOKEN),
        Some("github.com,gitlab.com"),
    )?;
    assert!(!out.status.success());
    assert_eq!(out.stdout, Vec::<u8>::new());
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
    assert_eq!(out.stdout, Vec::<u8>::new());
    assert!(!String::from_utf8(out.stderr)?.contains(TOKEN));
    Ok(())
}

#[test]
fn a_password_prompt_without_a_token_prints_nothing_and_fails() -> TestResult {
    let out = askpass("Password for 'https://github.com': ", None)?;
    assert!(!out.status.success());
    assert_eq!(out.stdout, Vec::<u8>::new());
    Ok(())
}

fn credential_fill(askpass: &str, marker: bool) -> Result<Output, std::io::Error> {
    use std::io::Write;
    use std::process::Stdio;
    let mut command = Command::new("git");
    command
        .args(["credential", "fill"])
        .current_dir(std::env::temp_dir())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_ASKPASS", askpass)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("FLEETD_ASKPASS_HOST", "github.com")
        .env("GH_TOKEN", TOKEN)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if marker {
        command.env("FLEETD_ASKPASS", "1");
    }
    let mut child = command.spawn()?;
    child
        .stdin
        .take()
        .ok_or(std::io::ErrorKind::BrokenPipe)?
        .write_all(b"protocol=https\nhost=github.com\n\n")?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    rx.recv_timeout(std::time::Duration::from_secs(60))
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "git hung",
            ))
        })
}

#[test]
fn git_gets_the_credentials_from_the_bare_binary_path_and_the_marker() -> TestResult {
    let out = credential_fill(env!("CARGO_BIN_EXE_fleetd"), true)?;
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout)?;
    assert!(text.contains("username=x-access-token\n"), "{text}");
    assert!(text.contains(&format!("password={TOKEN}\n")), "{text}");
    Ok(())
}

#[test]
fn the_binary_without_the_marker_still_needs_a_subcommand() -> TestResult {
    let out = credential_fill(env!("CARGO_BIN_EXE_fleetd"), false)?;
    assert!(!out.status.success());
    Ok(())
}

#[test]
fn the_quoted_command_string_is_not_an_executable_path() -> TestResult {
    let quoted = format!("'{}' askpass", env!("CARGO_BIN_EXE_fleetd"));
    let out = credential_fill(&quoted, true)?;
    assert!(!out.status.success());
    Ok(())
}

#[test]
fn the_marker_with_a_second_argument_falls_through_to_the_subcommand() -> TestResult {
    let out = Command::new(env!("CARGO_BIN_EXE_fleetd"))
        .args(["askpass", "Username for 'https://github.com': "])
        .env_clear()
        .env("FLEETD_ASKPASS", "1")
        .env("FLEETD_ASKPASS_HOST", "github.com")
        .output()?;
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout)?, "x-access-token\n");
    Ok(())
}
