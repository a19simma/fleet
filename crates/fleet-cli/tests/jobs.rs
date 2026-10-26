//! Runs the CLI against an in-process `FleetJobs` stub.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::{
    CancelJobRequest, GetJobRequest, Job, JobState, ListJobsReply, ListJobsRequest,
    ReadTranscriptReply, ReadTranscriptRequest, SubmitJobRequest,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

#[derive(Default, Clone)]
struct Stub {
    jobs: Arc<Mutex<HashMap<String, Job>>>,
    submitted: Arc<Mutex<Vec<SubmitJobRequest>>>,
}

fn check(request: &Request<impl Sized>) -> Result<(), Status> {
    let expected = format!("Bearer {TOKEN}");
    match request.metadata().get("authorization") {
        Some(v) if v.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err(Status::unauthenticated("bad token")),
    }
}

fn with_jobs<R>(stub: &Stub, f: impl FnOnce(&mut HashMap<String, Job>) -> R) -> Result<R, Status> {
    let mut guard = stub.jobs.lock().map_err(|_| Status::internal("poisoned"))?;
    Ok(f(&mut guard))
}

#[tonic::async_trait]
impl FleetJobs for Stub {
    async fn submit_job(
        &self,
        request: Request<SubmitJobRequest>,
    ) -> Result<Response<Job>, Status> {
        check(&request)?;
        let r = request.into_inner();
        self.submitted
            .lock()
            .map_err(|_| Status::internal("poisoned"))?
            .push(r.clone());
        let job = with_jobs(self, |jobs| {
            let no_exit = r.prompt == "no-exit";
            let evil = r.prompt == "evil";
            let job = Job {
                job_id: format!("job-{}", jobs.len() + 1),
                idempotency_key: r.idempotency_key,
                prompt: r.prompt,
                repo: r.repo,
                base_ref: r.base_ref,
                open_pr: r.open_pr,
                state: JobState::Queued as i32,
                phase: "queued".into(),
                branch: Some("swarm/x".into()),
                exit_code: (!no_exit).then_some(0),
                error: evil.then(|| "\u{1b}[31mpwned\u{1b}[0m".to_owned()),
                ..Job::default()
            };
            jobs.insert(job.job_id.clone(), job.clone());
            job
        })?;
        Ok(Response::new(job))
    }

    async fn get_job(&self, request: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        check(&request)?;
        let id = request.into_inner().job_id;
        if id == "explode" {
            return Err(Status::internal(
                "\u{1b}[31mboom\u{1b}[0m secret-server-detail",
            ));
        }
        with_jobs(self, |jobs| jobs.get(&id).cloned())?
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such job"))
    }

    async fn list_jobs(
        &self,
        request: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        check(&request)?;
        let ListJobsRequest { state, limit } = request.into_inner();
        let mut jobs = with_jobs(self, |jobs| {
            jobs.values()
                .filter(|j| state.is_none_or(|s| s == j.state))
                .cloned()
                .collect::<Vec<Job>>()
        })?;
        jobs.sort_by(|a, b| a.job_id.cmp(&b.job_id));
        if limit > 0 {
            jobs.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        Ok(Response::new(ListJobsReply { jobs }))
    }

    async fn cancel_job(
        &self,
        request: Request<CancelJobRequest>,
    ) -> Result<Response<Job>, Status> {
        check(&request)?;
        let id = request.into_inner().job_id;
        with_jobs(self, |jobs| {
            jobs.get_mut(&id).map(|job| {
                job.state = JobState::Cancelled as i32;
                job.clone()
            })
        })?
        .map(Response::new)
        .ok_or_else(|| Status::not_found("no such job"))
    }

    async fn get_stats(
        &self,
        _: Request<fleet_proto::v1::GetStatsRequest>,
    ) -> Result<Response<fleet_proto::v1::GetStatsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn read_job_events(
        &self,
        _: Request<fleet_proto::v1::ReadJobEventsRequest>,
    ) -> Result<Response<fleet_proto::v1::ReadJobEventsReply>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn read_transcript(
        &self,
        _request: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

async fn serve() -> Result<(String, Stub), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    let stub = Stub::default();
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetJobsServer::new(stub.clone()))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok((url, stub))
}

async fn cli_with(
    url: &str,
    env: &[(&str, &str)],
    stdin: &str,
    args: &[&str],
) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let env: HashMap<String, String> = env
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let mut out = Vec::new();
    let result = run(
        parsed,
        move |name| env.get(name).cloned(),
        &mut stdin.as_bytes(),
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

async fn cli(url: &str, token: Option<&str>, args: &[&str]) -> (Result<(), CliError>, String) {
    let env: Vec<(&str, &str)> = token
        .map(|t| ("FLEET_CLIENT_TOKEN", t))
        .into_iter()
        .collect();
    cli_with(url, &env, "", args).await
}

fn submitted(stub: &Stub) -> Result<Vec<SubmitJobRequest>, Box<dyn std::error::Error>> {
    Ok(stub.submitted.lock().map_err(|_| "poisoned")?.clone())
}

#[tokio::test]
async fn submit_then_status() -> TestResult {
    let (url, _) = serve().await?;
    let (res, out) = cli(
        &url,
        Some(TOKEN),
        &["submit", "--repo", "o/r", "--base", "main", "do it"],
    )
    .await;
    res?;
    let id = out.trim().to_owned();
    assert_eq!(id, "job-1");

    let (res, out) = cli(&url, Some(TOKEN), &["status", &id]).await;
    res?;
    assert!(out.contains("state: QUEUED"), "{out}");
    assert!(out.contains("phase: queued"), "{out}");
    assert!(out.contains("branch: swarm/x"), "{out}");
    assert!(out.contains("pr_url: -"), "{out}");
    assert!(out.contains("exit_code: 0"), "{out}");
    assert!(out.contains("error: -"), "{out}");
    Ok(())
}

#[tokio::test]
async fn submit_opens_a_pr_by_default_and_not_with_no_pr() -> TestResult {
    let (url, stub) = serve().await?;
    let (res, _) = cli(
        &url,
        Some(TOKEN),
        &["submit", "--repo", "o/r", "--base", "main", "a"],
    )
    .await;
    res?;
    let (res, _) = cli(
        &url,
        Some(TOKEN),
        &["submit", "--repo", "o/r", "--base", "main", "--no-pr", "b"],
    )
    .await;
    res?;
    let sent = submitted(&stub)?;
    assert_eq!(sent.len(), 2);
    assert!(sent[0].open_pr);
    assert!(!sent[1].open_pr);
    assert_eq!(sent[0].base_ref, "main");
    assert_eq!(sent[0].repo, "o/r");
    Ok(())
}

#[tokio::test]
async fn submit_forwards_the_idempotency_key() -> TestResult {
    let (url, stub) = serve().await?;
    let (res, _) = cli(
        &url,
        Some(TOKEN),
        &[
            "submit",
            "--repo",
            "o/r",
            "--base",
            "main",
            "--idempotency-key",
            "key-42",
            "a",
        ],
    )
    .await;
    res?;
    let (res, _) = cli(
        &url,
        Some(TOKEN),
        &["submit", "--repo", "o/r", "--base", "main", "b"],
    )
    .await;
    res?;
    let sent = submitted(&stub)?;
    assert_eq!(sent[0].idempotency_key, "key-42");
    assert_eq!(sent[1].idempotency_key, "");
    Ok(())
}

#[tokio::test]
async fn dash_reads_the_prompt_from_stdin() -> TestResult {
    let (url, stub) = serve().await?;
    let (res, _) = cli_with(
        &url,
        &[("FLEET_CLIENT_TOKEN", TOKEN)],
        "from stdin\n",
        &["submit", "--repo", "o/r", "--base", "main", "-"],
    )
    .await;
    res?;
    assert_eq!(submitted(&stub)?[0].prompt, "from stdin\n");
    let (res, _) = cli_with(
        &url,
        &[("FLEET_CLIENT_TOKEN", TOKEN)],
        "  \n",
        &["submit", "--repo", "o/r", "--base", "main", "-"],
    )
    .await;
    assert_eq!(res.err().map(|e| e.exit_code()), Some(2));
    Ok(())
}

#[tokio::test]
async fn exit_code_shows_dash_when_absent_and_zero_when_present() -> TestResult {
    let (url, _) = serve().await?;
    let (res, _) = cli(
        &url,
        Some(TOKEN),
        &["submit", "--repo", "o/r", "--base", "main", "no-exit"],
    )
    .await;
    res?;
    let (res, _) = cli(
        &url,
        Some(TOKEN),
        &["submit", "--repo", "o/r", "--base", "main", "with-exit"],
    )
    .await;
    res?;
    let (res, absent) = cli(&url, Some(TOKEN), &["status", "job-1"]).await;
    res?;
    let (res, present) = cli(&url, Some(TOKEN), &["status", "job-2"]).await;
    res?;
    assert!(absent.contains("exit_code: -\n"), "{absent}");
    assert!(present.contains("exit_code: 0\n"), "{present}");
    Ok(())
}

#[tokio::test]
async fn jobs_filters_by_state_and_cancel_changes_it() -> TestResult {
    let (url, _) = serve().await?;
    for p in ["a", "b"] {
        let (res, _) = cli(
            &url,
            Some(TOKEN),
            &["submit", "--repo", "o/r", "--base", "main", p],
        )
        .await;
        res?;
    }
    let (res, out) = cli(&url, Some(TOKEN), &["cancel", "job-1"]).await;
    res?;
    assert!(out.contains("CANCELLED"), "{out}");
    let (res, out) = cli(&url, Some(TOKEN), &["jobs", "--state", "queued"]).await;
    res?;
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.contains("job-2"), "{out}");
    let (res, out) = cli(&url, Some(TOKEN), &["jobs"]).await;
    res?;
    assert_eq!(out.lines().count(), 2, "{out}");
    Ok(())
}

#[tokio::test]
async fn wrong_token_is_rejected_and_never_echoed() -> TestResult {
    let (url, _) = serve().await?;
    let (res, _) = cli(&url, Some("wrong-token-value"), &["jobs"]).await;
    let err = res.err().ok_or("expected failure")?;
    assert_eq!(err.exit_code(), 1);
    let text = err.to_string();
    assert!(text.contains("Unauthenticated"), "{text}");
    assert!(!text.contains("wrong-token-value"));
    Ok(())
}

#[tokio::test]
async fn missing_token_is_a_config_error_with_exit_code_two() -> TestResult {
    let (url, _) = serve().await?;
    let (res, _) = cli_with(&url, &[("HOME", "/nonexistent-home")], "", &["jobs"]).await;
    let err = res.err().ok_or("expected failure")?;
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("FLEET_CLIENT_TOKEN"), "{err}");
    Ok(())
}

#[tokio::test]
async fn token_file_is_used_when_the_env_token_is_unset() -> TestResult {
    let (url, _) = serve().await?;
    let dir = tempfile::tempdir()?;
    std::fs::create_dir_all(dir.path().join("fleet"))?;
    std::fs::write(dir.path().join("fleet").join("token"), format!("{TOKEN}\n"))?;
    let base = dir.path().to_str().ok_or("utf8")?;
    let (res, _) = cli_with(&url, &[("XDG_CONFIG_HOME", base)], "", &["jobs"]).await;
    res?;
    Ok(())
}

#[tokio::test]
async fn plain_http_to_a_remote_host_is_a_usage_error_before_any_connection() -> TestResult {
    let (res, _) = cli("http://example.invalid:7070", Some(TOKEN), &["jobs"]).await;
    let err = res.err().ok_or("expected failure")?;
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("--insecure"), "{err}");
    let (res, _) = cli("HTTP://example.invalid:7070", Some(TOKEN), &["jobs"]).await;
    assert_eq!(res.err().map(|e| e.exit_code()), Some(2));
    Ok(())
}

#[tokio::test]
async fn unknown_state_is_a_usage_error() -> TestResult {
    let (url, _) = serve().await?;
    let (res, _) = cli(&url, Some(TOKEN), &["jobs", "--state", "bogus"]).await;
    let err = res.err().ok_or("expected failure")?;
    assert_eq!(err.exit_code(), 2);
    assert!(err.to_string().contains("unknown state"), "{err}");
    Ok(())
}

#[tokio::test]
async fn server_error_text_is_sanitized_and_exit_code_is_one() -> TestResult {
    let (url, _) = serve().await?;
    let (res, _) = cli(&url, Some(TOKEN), &["status", "explode"]).await;
    let err = res.err().ok_or("expected failure")?;
    assert_eq!(err.exit_code(), 1);
    let text = err.to_string();
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("boom"), "{text}");
    Ok(())
}

#[tokio::test]
async fn job_fields_from_the_server_are_sanitized_in_status() -> TestResult {
    let (url, _) = serve().await?;
    let (res, _) = cli(
        &url,
        Some(TOKEN),
        &["submit", "--repo", "o/r", "--base", "main", "evil"],
    )
    .await;
    res?;
    let (res, out) = cli(&url, Some(TOKEN), &["status", "job-1"]).await;
    res?;
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert!(out.contains("pwned"), "{out}");
    Ok(())
}

#[tokio::test]
async fn connect_failure_has_exit_code_one() -> TestResult {
    let (res, _) = cli("http://127.0.0.1:1", Some(TOKEN), &["jobs"]).await;
    let err = res.err().ok_or("expected failure")?;
    assert!(matches!(err, CliError::Connect(_)), "{err}");
    assert_eq!(err.exit_code(), 1);
    Ok(())
}

async fn submit_n(url: &str, n: usize) -> TestResult {
    for i in 0..n {
        let prompt = format!("p{i}");
        let (res, _) = cli(
            url,
            Some(TOKEN),
            &["submit", "--repo", "o/r", "--base", "main", &prompt],
        )
        .await;
        res?;
    }
    Ok(())
}

#[tokio::test]
async fn jobs_limit_is_forwarded_and_a_full_page_prints_a_notice() -> TestResult {
    let (url, _) = serve().await?;
    submit_n(&url, 3).await?;
    let (res, out) = cli(&url, Some(TOKEN), &["jobs", "--limit", "2"]).await;
    res?;
    assert_eq!(out.lines().count(), 3, "{out}");
    assert!(out.contains("showing 2 jobs"), "{out}");
    assert!(out.contains("--limit"), "{out}");
    Ok(())
}

#[tokio::test]
async fn jobs_under_the_limit_print_no_notice() -> TestResult {
    let (url, _) = serve().await?;
    submit_n(&url, 3).await?;
    let (res, out) = cli(&url, Some(TOKEN), &["jobs", "--limit", "5"]).await;
    res?;
    assert_eq!(out.lines().count(), 3, "{out}");
    assert!(!out.contains("showing"), "{out}");
    let (res, out) = cli(&url, Some(TOKEN), &["jobs"]).await;
    res?;
    assert!(!out.contains("showing"), "{out}");
    Ok(())
}

#[tokio::test]
async fn jobs_limit_outside_the_server_range_is_a_usage_error() -> TestResult {
    let (url, _) = serve().await?;
    for bad in ["0", "201", "x"] {
        let (res, _) = cli(&url, Some(TOKEN), &["jobs", "--limit", bad]).await;
        assert!(matches!(res, Err(CliError::Usage(_))), "{bad}");
    }
    Ok(())
}
