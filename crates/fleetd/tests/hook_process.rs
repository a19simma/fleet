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
