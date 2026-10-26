//! Runs `fleet list` and `fleet watch` against in-process `FleetQuery` and `FleetJobs` stubs.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run_with};
use fleet_proto::v1::fleet_jobs_server::{FleetJobs, FleetJobsServer};
use fleet_proto::v1::fleet_query_server::{FleetQuery, FleetQueryServer};
use fleet_proto::v1::{
    BoxStatus, BoxView, CancelJobRequest, GetJobRequest, Job, JobState, ListFleetReply,
    ListFleetRequest, ListJobsReply, ListJobsRequest, ReadTranscriptReply, ReadTranscriptRequest,
    SubmitJobRequest,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

#[derive(Default, Clone)]
struct Stub {
    boxes: Vec<BoxView>,
    jobs: Vec<Job>,
    script: Arc<Mutex<Vec<Job>>>,
    polls: Arc<AtomicUsize>,
}

fn check(request: &Request<impl Sized>) -> Result<(), Status> {
    let expected = format!("Bearer {TOKEN}");
    match request.metadata().get("authorization") {
        Some(v) if v.as_bytes() == expected.as_bytes() => Ok(()),
        _ => Err(Status::unauthenticated("bad token")),
    }
}

#[tonic::async_trait]
impl FleetQuery for Stub {
    async fn list_fleet(
        &self,
        request: Request<ListFleetRequest>,
    ) -> Result<Response<ListFleetReply>, Status> {
        check(&request)?;
        Ok(Response::new(ListFleetReply {
            as_of_ms: 0,
            boxes: self.boxes.clone(),
        }))
    }
}

#[tonic::async_trait]
impl FleetJobs for Stub {
    async fn submit_job(&self, _: Request<SubmitJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
    }

    async fn get_job(&self, request: Request<GetJobRequest>) -> Result<Response<Job>, Status> {
        check(&request)?;
        let at = self.polls.fetch_add(1, Ordering::SeqCst);
        let script = self
            .script
            .lock()
            .map_err(|_| Status::internal("poisoned"))?;
        script
            .get(at.min(script.len().saturating_sub(1)))
            .cloned()
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such job"))
    }

    async fn list_jobs(
        &self,
        request: Request<ListJobsRequest>,
    ) -> Result<Response<ListJobsReply>, Status> {
        check(&request)?;
        Ok(Response::new(ListJobsReply {
            jobs: self.jobs.clone(),
        }))
    }

    async fn cancel_job(&self, _: Request<CancelJobRequest>) -> Result<Response<Job>, Status> {
        Err(Status::unimplemented("not used"))
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
        _: Request<ReadTranscriptRequest>,
    ) -> Result<Response<ReadTranscriptReply>, Status> {
        Err(Status::unimplemented("not used"))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetQueryServer::new(stub.clone()))
            .add_service(FleetJobsServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli(url: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let Ok(parsed) = Cli::try_parse_from(full) else {
        return (Err(CliError::Usage("parse".into())), String::new());
    };
    let env: HashMap<String, String> =
        HashMap::from([("FLEET_CLIENT_TOKEN".to_owned(), TOKEN.to_owned())]);
    let mut out = Vec::new();
    let result = run_with(
        parsed,
        move |name| env.get(name).cloned(),
        false,
        &mut b"".as_slice(),
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn box_view(n: u32, status: BoxStatus, age: Option<u64>) -> BoxView {
    BoxView {
        r#box: format!("box-{n}"),
        status: status as i32,
        heartbeat_age_s: age,
        ..BoxView::default()
    }
}

fn job(id: &str, state: JobState, phase: &str, progress: &str) -> Job {
    Job {
        job_id: id.to_owned(),
        state: state as i32,
        phase: phase.to_owned(),
        progress: progress.to_owned(),
        ..Job::default()
    }
}

#[tokio::test]
async fn list_shows_box() -> TestResult {
    let n = 7;
    let stub = Stub {
        boxes: vec![box_view(n, BoxStatus::Live, Some(12))],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["list"]).await;
    res?;
    let name = format!("box-{n}");
    assert!(
        out.lines().any(|l| l == format!("{name}\tLIVE\t12s ago")),
        "{out}"
    );
    Ok(())
}

#[tokio::test]
async fn list_shows_box_never_seen_and_stale() -> TestResult {
    let stub = Stub {
        boxes: vec![
            box_view(1, BoxStatus::Stale, Some(90)),
            box_view(2, BoxStatus::Unknown, None),
        ],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["list"]).await;
    res?;
    assert!(out.contains("\tSTALE\t90s ago"), "{out}");
    assert!(out.contains("\tUNKNOWN\tnever"), "{out}");
    Ok(())
}

#[tokio::test]
async fn list_shows_recent_jobs_with_box_branch_and_pr() -> TestResult {
    let n = 3;
    let done = Job {
        r#box: format!("box-{n}"),
        branch: Some("swarm/j1".into()),
        pr_url: Some("https://example.com/pr/1".into()),
        ..job("j1", JobState::Succeeded, "done", "")
    };
    let queued = job("j2", JobState::Queued, "queued", "");
    let stub = Stub {
        jobs: vec![done, queued],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["list"]).await;
    res?;
    let name = format!("box-{n}");
    let expected = format!("j1\tSUCCEEDED\t{name}\tswarm/j1\thttps://example.com/pr/1");
    assert!(out.lines().any(|l| l == expected), "{out}");
    assert!(out.lines().any(|l| l == "j2\tQUEUED\t-\t-\t-"), "{out}");
    Ok(())
}

#[tokio::test]
async fn list_strips_control_characters_from_box_names() -> TestResult {
    let mut view = box_view(1, BoxStatus::Live, Some(1));
    view.r#box = "x\u{1b}[31mred".into();
    let stub = Stub {
        boxes: vec![view],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["list"]).await;
    res?;
    assert!(!out.contains('\u{1b}'), "{out:?}");
    Ok(())
}

fn scripted(jobs: Vec<Job>) -> Stub {
    Stub {
        script: Arc::new(Mutex::new(jobs)),
        ..Stub::default()
    }
}

#[tokio::test(start_paused = true)]
async fn watch_prints_each_change_once_and_exits_ok_on_success() -> TestResult {
    let stub = scripted(vec![
        job("j1", JobState::Queued, "queued", ""),
        job("j1", JobState::Running, "agent", "starting"),
        job("j1", JobState::Running, "agent", "starting"),
        job("j1", JobState::Running, "agent", "editing"),
        Job {
            pr_url: Some("https://example.com/pr/9".into()),
            ..job("j1", JobState::Succeeded, "done", "finished")
        },
    ]);
    let polls = stub.polls.clone();
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["watch", "j1"]).await;
    res?;
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(
        lines,
        [
            "QUEUED\tqueued\t",
            "RUNNING\tagent\tstarting",
            "RUNNING\tagent\tediting",
            "SUCCEEDED\tdone\tfinished",
            "pr_url: https://example.com/pr/9",
            "error: -",
        ]
    );
    assert_eq!(polls.load(Ordering::SeqCst), 5);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn watch_exits_one_for_every_non_success_end() -> TestResult {
    for state in [JobState::Failed, JobState::Cancelled, JobState::Lost] {
        let url = serve(scripted(vec![
            job("j1", JobState::Running, "agent", ""),
            job("j1", state, "agent", ""),
        ]))
        .await?;
        let (res, out) = cli(&url, &["watch", "j1"]).await;
        let err = res.err().ok_or("expected failure")?;
        assert_eq!(err.exit_code(), 1, "{state:?}");
        assert!(matches!(err, CliError::JobEnded(_)), "{state:?}");
        assert!(out.contains("error: -"), "{out}");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn watch_unknown_job_is_a_server_error() -> TestResult {
    let url = serve(scripted(Vec::new())).await?;
    let (res, _) = cli(&url, &["watch", "nope"]).await;
    let err = res.err().ok_or("expected failure")?;
    assert!(matches!(err, CliError::Rpc(_)), "{err}");
    Ok(())
}

#[tokio::test]
async fn list_accepts_a_reply_above_the_default_decode_limit() -> TestResult {
    let big = "z".repeat(5 * 1024 * 1024);
    let stub = Stub {
        boxes: vec![BoxView {
            r#box: big.clone(),
            status: BoxStatus::Live as i32,
            ..BoxView::default()
        }],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["list"]).await;
    res?;
    assert!(out.contains(&big), "reply was cut");
    Ok(())
}

#[tokio::test]
async fn list_accepts_a_jobs_reply_above_the_default_decode_limit() -> TestResult {
    let mut huge = job("job-1", JobState::Running, "run", "");
    huge.pr_url = Some("u".repeat(5 * 1024 * 1024));
    let stub = Stub {
        jobs: vec![huge],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (res, out) = cli(&url, &["list"]).await;
    res?;
    assert!(out.contains(&"u".repeat(5 * 1024 * 1024)), "reply was cut");
    Ok(())
}
