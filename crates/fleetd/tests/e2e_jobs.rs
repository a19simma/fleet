//! A job submitted through the CLI library runs on a real in-process server and the real
//! daemon with fake `claude` and `gh`, ends `SUCCEEDED` with a pull request url, and leaves
//! its branch in a bare `file://` origin. One test in its own binary because it spawns
//! children and binds sockets. Needs `DATABASE_URL`, which `#[sqlx::test]` reads.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::service::router;
use fleet_server::store::Store;
use fleetd::{Config, run_with_env};
use sqlx::PgPool;
use tempfile::TempDir;
use tokio::sync::oneshot;
use tokio::time::{Instant, timeout};
use tonic::transport::server::TcpIncoming;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const BOX_TOKEN: &str = "e2e-box-token-0123456789abcdef0123456789";
const CLIENT_TOKEN: &str = "e2e-client-token-0123456789abcdef0123456789";
const PR_URL: &str = "https://example.invalid/pr/9";
const SUBMIT_REPO: &str = "https://example.invalid/e2e/repo.git";
const WAIT: Duration = Duration::from_secs(120);

const AGENT: &str = r#"#!/bin/sh
echo '{"type":"assistant","message":{"content":[{"type":"text","text":"adding the file"}]}}'
echo fake-agent-output > hello.txt
git add hello.txt
git -c user.name=t -c user.email=t@example.invalid commit -q -m "add hello.txt"
"#;

const GH: &str = "#!/bin/sh\necho created\necho https://example.invalid/pr/9\n";

fn script(dir: &Path, name: &str, body: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = dir.join(name);
    std::fs::write(&path, body)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

fn git(dir: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .output()?;
    assert!(out.status.success());
    Ok(String::from_utf8(out.stdout)?)
}

async fn fleet(url: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let env = HashMap::from([("FLEET_CLIENT_TOKEN", CLIENT_TOKEN)]);
    let mut out = Vec::new();
    let result = run(
        parsed,
        move |name| env.get(name).map(|v| (*v).to_owned()),
        &mut std::io::empty(),
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

#[sqlx::test(migrations = false)]
async fn a_submitted_job_runs_to_a_pushed_branch_and_a_pull_request(pool: PgPool) -> TestResult {
    let dir = TempDir::new()?;
    let origin = dir.path().join("origin.git");
    let seed = dir.path().join("seed");
    std::fs::create_dir(&origin)?;
    std::fs::create_dir(&seed)?;
    git(&origin, &["init", "--bare", "--quiet", "-b", "main"])?;
    git(&seed, &["init", "--quiet", "-b", "main"])?;
    std::fs::write(seed.join("a.txt"), "a")?;
    git(&seed, &["add", "."])?;
    git(&seed, &["commit", "--quiet", "-m", "seed"])?;
    git(
        &seed,
        &["push", "--quiet", &origin.to_string_lossy(), "main"],
    )?;
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin)?;
    let claude = script(&bin, "claude", AGENT)?;
    let gh = script(&bin, "gh", GH)?;

    let store = Store::new(pool.clone());
    store.migrate().await?;
    let auth = BearerAuth::new(
        &Token::new(BOX_TOKEN.to_owned())?,
        Some(&Token::new(CLIENT_TOKEN.to_owned())?),
    );
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse()?)?;
    let url = format!("http://{}", incoming.local_addr()?);
    let server = tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));

    let (submitted, out) = fleet(
        &url,
        &[
            "submit",
            "--repo",
            SUBMIT_REPO,
            "--base",
            "main",
            "--idempotency-key",
            "e2e-key",
            "add hello.txt",
        ],
    )
    .await;
    submitted?;
    let job_id = out.trim().to_owned();
    assert!(!job_id.is_empty());
    sqlx::query("UPDATE jobs SET repo = $1 WHERE job_id = $2")
        .bind(format!("file://{}", origin.display()))
        .bind(&job_id)
        .execute(&pool)
        .await?;

    let box_name = format!("box-{}", 7);
    let file = format!(
        "http_port = 0\nsocket_path = {:?}\ndb_path = {:?}\njobs_dir = {:?}\nbox_name = {box_name:?}\nclaude_bin = {:?}\ngh_bin = {:?}\nsecrets_file = {:?}\n",
        dir.path().join("fleetd.sock"),
        dir.path().join("queue.db"),
        dir.path().join("jobs"),
        claude,
        gh,
        dir.path().join("secrets.env"),
    );
    std::fs::write(dir.path().join("secrets.env"), "")?;
    let config = Config::resolve(Some(&file), &|_| None)?;
    let daemon_url = url.clone();
    let env = move |name: &str| match name {
        "FLEET_SERVER_URL" => Some(daemon_url.clone()),
        "FLEET_TOKEN" => Some(BOX_TOKEN.to_owned()),
        _ => None,
    };
    let (stop, stopped) = oneshot::channel::<()>();
    let daemon = tokio::spawn(async move {
        run_with_env(config, &env, async {
            let _ = stopped.await;
        })
        .await
    });

    let (watched, out) = timeout(WAIT, fleet(&url, &["watch", &job_id])).await?;
    watched?;
    assert!(out.contains(&format!("pr_url: {PR_URL}")), "{out}");

    let (status, out) = fleet(&url, &["status", &job_id]).await;
    status?;
    assert!(out.contains("state: SUCCEEDED"), "{out}");
    assert!(out.contains(&format!("pr_url: {PR_URL}")), "{out}");
    assert!(out.contains(&format!("branch: swarm/{job_id}")), "{out}");

    let branch = format!("swarm/{job_id}");
    assert_eq!(
        git(&origin, &["show", &format!("{branch}:hello.txt")])?.trim(),
        "fake-agent-output"
    );
    assert_eq!(
        git(&origin, &["log", "-1", "--format=%s", &branch])?.trim(),
        "add hello.txt"
    );

    let deadline = Instant::now() + WAIT;
    let transcript = loop {
        let (logs, out) = fleet(&url, &["logs", &job_id]).await;
        logs?;
        if !out.trim().is_empty() || Instant::now() >= deadline {
            break out;
        }
        tokio::task::yield_now().await;
    };
    assert!(transcript.contains("adding the file"), "{transcript}");

    let _ = stop.send(());
    timeout(Duration::from_secs(30), daemon).await???;
    server.abort();
    Ok(())
}
