//! Two users of one repo get two mirrors through the whole job path. Own test binary because it
//! spawns git and the runner.

use std::future::Future;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{Job, ReportJobReply, ReportJobRequest};
use fleetd::DaemonRunner;
use fleetd::poller::{JobRunner, Shutdown};
use fleetd::runner::{AgentRunner, Reporter, RunConfig};
use fleetd::workspace::{RepoPolicy, Workspace};
use tonic::Status;

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Silent;

impl Reporter for Silent {
    fn report(
        &self,
        _: ReportJobRequest,
    ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
        std::future::ready(Ok(ReportJobReply::default()))
    }
}

fn git(dir: &Path, args: &[&str]) -> TestResult {
    let out = Command::new("git").current_dir(dir).args(args).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).into_owned().into())
    }
}

fn origin(dir: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let origin = dir.join("origin.git");
    let seed = dir.join("seed");
    std::fs::create_dir_all(&seed)?;
    git(
        dir,
        &["init", "--bare", "--quiet", "-b", "main", "origin.git"],
    )?;
    git(&seed, &["init", "--quiet", "-b", "main"])?;
    std::fs::write(seed.join("a.txt"), "one")?;
    git(&seed, &["add", "."])?;
    git(
        &seed,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "--quiet",
            "-m",
            "one",
        ],
    )?;
    let url = origin.to_str().ok_or("path")?.to_owned();
    git(&seed, &["push", "--quiet", &url, "main"])?;
    Ok(url)
}

fn mirrors(jobs: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0;
    for entry in std::fs::read_dir(jobs.join(".cache"))? {
        if entry?.file_name().to_string_lossy().ends_with(".git") {
            count += 1;
        }
    }
    Ok(count)
}

async fn run_as(
    runner: &DaemonRunner<Silent>,
    url: &str,
    job_id: &str,
    user_id: u64,
) -> TestResult {
    let (_trigger, shutdown) = Shutdown::channel();
    let job = Job {
        job_id: job_id.into(),
        attempt: 1,
        repo: url.into(),
        base_ref: "main".into(),
        user_id,
        ..Job::default()
    };
    let _ = tokio::time::timeout(Duration::from_secs(30), runner.run(job, shutdown)).await?;
    Ok(())
}

#[tokio::test]
async fn two_users_of_one_repo_get_distinct_mirrors_and_one_user_reuses_theirs() -> TestResult {
    let dir = tempfile::tempdir()?;
    let url = origin(dir.path())?;
    let jobs = dir.path().join("jobs");
    let workspace =
        Workspace::new(&jobs).with_policy(RepoPolicy::new(Vec::<String>::new()).with_file_repos());
    let agent = AgentRunner::new(
        RunConfig::new("claude-fake-missing", false),
        Silent,
        Redactor::default(),
    );
    let runner = DaemonRunner::new(workspace, agent, "box");
    run_as(&runner, &url, "job1", 1).await?;
    assert_eq!(mirrors(&jobs)?, 1);
    run_as(&runner, &url, "job2", 2).await?;
    assert_eq!(mirrors(&jobs)?, 2);
    run_as(&runner, &url, "job3", 1).await?;
    assert_eq!(mirrors(&jobs)?, 2);
    Ok(())
}
