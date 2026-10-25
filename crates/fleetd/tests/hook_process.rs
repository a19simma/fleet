//! Runs the `fleetd hook` binary with stdin held open.
//!
//! This is its own test binary on purpose. Spawning a child while sibling tests in the
//! same process create sockets lets the child inherit a listener fd that a test already
//! closed, so that listener keeps accepting until the child exits.

use std::time::Duration;

use tempfile::TempDir;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn exits_within_budget_with_open_stdin() -> TestResult {
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let dir = TempDir::new()?;
    let file = dir.path().join("config.toml");
    std::fs::write(
        &file,
        format!(
            "http_port = 1\nsocket_path = \"{}\"\n",
            dir.path().join("fleetd.sock").display()
        ),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fleetd"))
        .arg("--config")
        .arg(&file)
        .args(["hook", "SessionStart"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let held = child.stdin.take();
    let start = Instant::now();
    let mut status = None;
    while start.elapsed() < Duration::from_secs(3) {
        status = child.try_wait()?;
        if status.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if status.is_none() {
        child.kill()?;
        child.wait()?;
    }
    drop(held);
    assert!(status.is_some_and(|s| s.success()), "hook outlived 3 s");
    Ok(())
}

fn run_hook(event: &str, input: &[u8]) -> Result<(bool, Vec<u8>), Box<dyn std::error::Error>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let dir = TempDir::new()?;
    let file = dir.path().join("config.toml");
    std::fs::write(
        &file,
        format!(
            "http_port = 1\nsocket_path = \"{}\"\n",
            dir.path().join("fleetd.sock").display()
        ),
    )?;
    let mut child = Command::new(env!("CARGO_BIN_EXE_fleetd"))
        .arg("--config")
        .arg(&file)
        .args(["hook", event])
        .env("FLEET_JOB_ID", "job-1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("no stdin")?;
    let data = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if start.elapsed() > Duration::from_secs(5) {
            child.kill()?;
            child.wait()?;
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    let mut out = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        std::io::Read::read_to_end(&mut pipe, &mut out)?;
    }
    Ok((status.is_some_and(|s| s.success()), out))
}

#[test]
fn tool_hooks_exit_zero_and_print_nothing_whatever_the_input() -> TestResult {
    let success =
        br#"{"tool_name":"Bash","tool_use_id":"t","duration_ms":3,"tool_response":{"stdout":"x"}}"#;
    let oversize = vec![b'x'; 3 * 1024 * 1024];
    let inputs: [&[u8]; 6] = [b"", b"garbage", b"{}", b"[1]", success, &oversize];
    for event in ["PostToolUse", "PostToolUseFailure"] {
        for input in inputs {
            let (ok, out) = run_hook(event, input)?;
            assert!(ok, "{event} did not exit 0");
            assert!(out.is_empty(), "{event} printed to stdout");
        }
    }
    Ok(())
}
