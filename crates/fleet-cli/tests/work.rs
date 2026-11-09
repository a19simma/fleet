//! `fleet work` against an in-process `FleetWork` stub: request fields, per-invocation
//! idempotency keys, bounded evidence input, usage refusals before any connection and the
//! scrubbing of every printed server field.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_work_server::{FleetWork, FleetWorkServer};
use fleet_proto::v1::{
    AddWorkDepRequest, AddWorkItemRequest, AddWorkNoteRequest, CancelWorkRequest, ClaimWorkRequest,
    CreateWorkProjectRequest, ExportWorkReply, ExportWorkRequest, GetWorkItemReply,
    GetWorkItemRequest, ImportWorkReply, ImportWorkRequest, ListWorkDefersReply,
    ListWorkDefersRequest, ListWorkItemsReply, ListWorkItemsRequest, ListWorkProjectsReply,
    ListWorkProjectsRequest, NextWorkReply, NextWorkRequest, RecordWorkDeferRequest,
    RemoveWorkDepRequest, RenewLeaseRequest, ReportAttemptRequest, ResolveWorkDeferRequest,
    SetWorkSlicesRequest, UnblockWorkRequest, WorkAttempt, WorkDefer, WorkDeferState, WorkEvent,
    WorkItem, WorkItemState, WorkProject, WorkSlice,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

#[derive(Clone, Default)]
struct Stub {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    projects: Vec<WorkProject>,
    items: Vec<WorkItem>,
    attempts: Vec<WorkAttempt>,
    events: Vec<WorkEvent>,
    defers: Vec<WorkDefer>,
    next: Option<WorkItem>,
    import: ImportWorkReply,
    export: ExportWorkReply,
}

impl Stub {
    fn record(&self, method: &str, request: &impl std::fmt::Debug) -> Result<(), Status> {
        self.calls
            .lock()
            .map_err(|_| Status::internal("poisoned"))?
            .push((method.to_owned(), format!("{request:?}")));
        Ok(())
    }

    fn item(&self) -> WorkItem {
        self.items.first().cloned().unwrap_or_else(|| item("a1"))
    }

    fn attempt(&self) -> WorkAttempt {
        self.attempts.first().cloned().unwrap_or_else(|| attempt(1))
    }
}

fn item(key: &str) -> WorkItem {
    WorkItem {
        key: key.into(),
        title: "title".into(),
        body: "body".into(),
        state: WorkItemState::Open as i32,
        slices: vec!["core".into()],
        deps: Vec::new(),
        passes: 1,
        fails: 2,
        ready: true,
        held: false,
        created_at_ms: 0,
        updated_at_ms: 0,
    }
}

fn attempt(id: u64) -> WorkAttempt {
    WorkAttempt {
        id,
        item_key: "a1".into(),
        holder: "worker".into(),
        claimed_at_ms: 0,
        expires_at_ms: 60_000,
        verdict: None,
        note: String::new(),
        evidence_tail: String::new(),
        closed_at_ms: None,
    }
}

#[tonic::async_trait]
impl FleetWork for Stub {
    async fn create_work_project(
        &self,
        r: Request<CreateWorkProjectRequest>,
    ) -> Result<Response<WorkProject>, Status> {
        self.record("create_project", r.get_ref())?;
        Ok(Response::new(
            self.projects.first().cloned().unwrap_or_default(),
        ))
    }

    async fn list_work_projects(
        &self,
        r: Request<ListWorkProjectsRequest>,
    ) -> Result<Response<ListWorkProjectsReply>, Status> {
        self.record("list_projects", r.get_ref())?;
        Ok(Response::new(ListWorkProjectsReply {
            projects: self.projects.clone(),
        }))
    }

    async fn set_work_slices(
        &self,
        r: Request<SetWorkSlicesRequest>,
    ) -> Result<Response<WorkProject>, Status> {
        self.record("set_slices", r.get_ref())?;
        Ok(Response::new(
            self.projects.first().cloned().unwrap_or_default(),
        ))
    }

    async fn add_work_item(
        &self,
        r: Request<AddWorkItemRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        self.record("add_item", r.get_ref())?;
        Ok(Response::new(self.item()))
    }

    async fn list_work_items(
        &self,
        r: Request<ListWorkItemsRequest>,
    ) -> Result<Response<ListWorkItemsReply>, Status> {
        self.record("list_items", r.get_ref())?;
        Ok(Response::new(ListWorkItemsReply {
            items: self.items.clone(),
        }))
    }

    async fn get_work_item(
        &self,
        r: Request<GetWorkItemRequest>,
    ) -> Result<Response<GetWorkItemReply>, Status> {
        self.record("get_item", r.get_ref())?;
        Ok(Response::new(GetWorkItemReply {
            item: Some(self.item()),
            attempts: self.attempts.clone(),
            events: self.events.clone(),
        }))
    }

    async fn add_work_dep(
        &self,
        r: Request<AddWorkDepRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        self.record("add_dep", r.get_ref())?;
        Ok(Response::new(self.item()))
    }

    async fn remove_work_dep(
        &self,
        r: Request<RemoveWorkDepRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        self.record("remove_dep", r.get_ref())?;
        Ok(Response::new(self.item()))
    }

    async fn cancel_work(
        &self,
        r: Request<CancelWorkRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        self.record("cancel", r.get_ref())?;
        Ok(Response::new(self.item()))
    }

    async fn unblock_work(
        &self,
        r: Request<UnblockWorkRequest>,
    ) -> Result<Response<WorkItem>, Status> {
        self.record("unblock", r.get_ref())?;
        Ok(Response::new(self.item()))
    }

    async fn next_work(
        &self,
        r: Request<NextWorkRequest>,
    ) -> Result<Response<NextWorkReply>, Status> {
        self.record("next", r.get_ref())?;
        Ok(Response::new(NextWorkReply {
            item: self.next.clone(),
        }))
    }

    async fn claim_work(
        &self,
        r: Request<ClaimWorkRequest>,
    ) -> Result<Response<WorkAttempt>, Status> {
        self.record("claim", r.get_ref())?;
        Ok(Response::new(self.attempt()))
    }

    async fn renew_lease(
        &self,
        r: Request<RenewLeaseRequest>,
    ) -> Result<Response<WorkAttempt>, Status> {
        self.record("renew", r.get_ref())?;
        Ok(Response::new(self.attempt()))
    }

    async fn report_attempt(
        &self,
        r: Request<ReportAttemptRequest>,
    ) -> Result<Response<WorkAttempt>, Status> {
        self.record("report", r.get_ref())?;
        Ok(Response::new(self.attempt()))
    }

    async fn add_work_note(
        &self,
        r: Request<AddWorkNoteRequest>,
    ) -> Result<Response<WorkEvent>, Status> {
        self.record("note", r.get_ref())?;
        Ok(Response::new(
            self.events.first().cloned().unwrap_or_default(),
        ))
    }

    async fn record_work_defer(
        &self,
        r: Request<RecordWorkDeferRequest>,
    ) -> Result<Response<WorkDefer>, Status> {
        self.record("record_defer", r.get_ref())?;
        Ok(Response::new(WorkDefer::default()))
    }

    async fn resolve_work_defer(
        &self,
        r: Request<ResolveWorkDeferRequest>,
    ) -> Result<Response<WorkDefer>, Status> {
        self.record("resolve_defer", r.get_ref())?;
        Ok(Response::new(WorkDefer::default()))
    }

    async fn import_work(
        &self,
        r: Request<ImportWorkRequest>,
    ) -> Result<Response<ImportWorkReply>, Status> {
        self.record("import", r.get_ref())?;
        Ok(Response::new(ImportWorkReply {
            applied: r.get_ref().apply,
            ..self.import.clone()
        }))
    }

    async fn export_work(
        &self,
        r: Request<ExportWorkRequest>,
    ) -> Result<Response<ExportWorkReply>, Status> {
        self.record("export", r.get_ref())?;
        Ok(Response::new(self.export.clone()))
    }

    async fn list_work_defers(
        &self,
        r: Request<ListWorkDefersRequest>,
    ) -> Result<Response<ListWorkDefersReply>, Status> {
        self.record("list_defers", r.get_ref())?;
        Ok(Response::new(ListWorkDefersReply {
            defers: self.defers.clone(),
        }))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetWorkServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli(url: &str, args: &[&str], stdin: &[u8]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url, "work"];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let mut out = Vec::new();
    let mut stdin = stdin;
    let result = run(
        parsed,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned()),
        &mut stdin,
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn calls(stub: &Stub) -> Vec<(String, String)> {
    stub.calls.lock().unwrap().clone()
}

fn key_of(debug: &str) -> String {
    let rest = debug.split("key: \"").nth(1).unwrap();
    rest.split('"').next().unwrap().to_owned()
}

fn clean(out: &str) -> bool {
    !out.contains(TOKEN)
        && !out.contains("client-tok")
        && !out.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t') || "\u{202e}\u{2028}\u{85}".contains(c)
        })
}

fn hostile() -> String {
    format!("a\u{1b}[31m{TOKEN}\u{202e}\r\u{85}b\u{2028}c\0d")
}

#[tokio::test]
async fn project_create_sends_the_name_repo_and_a_fresh_key_per_invocation() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let args = ["project", "create", "tracker", "--repo", "github.com/o/r"];
    cli(&url, &args, b"").await.0?;
    cli(&url, &args, b"").await.0?;
    let seen = calls(&stub);
    assert_eq!(seen.len(), 2);
    assert!(seen[0].1.contains("name: \"tracker\""), "{seen:?}");
    assert!(
        seen[0].1.contains("repo: Some(\"github.com/o/r\")"),
        "{seen:?}"
    );
    let (first, second) = (key_of(&seen[0].1), key_of(&seen[1].1));
    assert!(!first.is_empty() && !second.is_empty());
    assert_ne!(first, second);
    Ok(())
}

#[tokio::test]
async fn a_passed_idempotency_key_is_sent_unchanged_and_an_empty_one_is_refused() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    cli(
        &url,
        &["--idempotency-key", "mine-1", "project", "create", "p"],
        b"",
    )
    .await
    .0?;
    assert_eq!(key_of(&calls(&stub)[0].1), "mine-1");
    let (result, _) = cli(
        &url,
        &["--idempotency-key", "", "project", "create", "p"],
        b"",
    )
    .await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    assert_eq!(calls(&stub).len(), 1);
    Ok(())
}

#[tokio::test]
async fn every_mutating_command_sends_a_nonempty_key() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let runs: [&[&str]; 9] = [
        &[
            "-p",
            "p",
            "slices",
            "--slice",
            "core=a/b,c",
            "--mergeable",
            "docs",
        ],
        &["-p", "p", "add", "a1", "title"],
        &["-p", "p", "dep", "add", "a1", "a0"],
        &["-p", "p", "dep", "remove", "a1", "a0"],
        &["-p", "p", "cancel", "a1"],
        &["-p", "p", "unblock", "a1"],
        &["-p", "p", "claim", "a1", "--holder", "w"],
        &["-p", "p", "pass", "7"],
        &["-p", "p", "note", "a1", "hello"],
    ];
    for args in runs {
        cli(&url, args, b"").await.0?;
    }
    let seen = calls(&stub);
    assert_eq!(seen.len(), 9);
    for (method, debug) in &seen {
        assert!(!key_of(debug).is_empty(), "{method}: {debug}");
    }
    Ok(())
}

#[tokio::test]
async fn slices_parses_name_paths_and_mergeable() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    cli(
        &url,
        &[
            "-p",
            "p",
            "slices",
            "--slice",
            "core=a/b,c",
            "--slice",
            "web=w",
            "--mergeable",
            "docs",
            "--mergeable",
            "README.md",
        ],
        b"",
    )
    .await
    .0?;
    let debug = calls(&stub)[0].1.clone();
    assert!(debug.contains("project: \"p\""), "{debug}");
    assert!(
        debug.contains("name: \"core\", paths: [\"a/b\", \"c\"]"),
        "{debug}"
    );
    assert!(debug.contains("name: \"web\", paths: [\"w\"]"), "{debug}");
    assert!(
        debug.contains("mergeable: [\"docs\", \"README.md\"]"),
        "{debug}"
    );
    Ok(())
}

#[tokio::test]
async fn a_malformed_slice_is_refused_before_connecting() -> TestResult {
    for bad in ["core", "=a", "core=", "core=a,,b"] {
        let (result, out) = cli(
            "http://127.0.0.1:1",
            &["-p", "p", "slices", "--slice", bad],
            b"",
        )
        .await;
        assert!(
            matches!(result, Err(CliError::Usage(_))),
            "{bad}: {result:?}"
        );
        assert_eq!(out, "");
    }
    Ok(())
}

#[tokio::test]
async fn a_command_that_needs_a_project_refuses_without_one() -> TestResult {
    let (result, _) = cli("http://127.0.0.1:1", &["list"], b"").await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn add_sends_slices_and_deps_with_an_optional_why() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    cli(
        &url,
        &[
            "-p",
            "p",
            "add",
            "a1",
            "the title",
            "--body",
            "b",
            "--slice",
            "core",
            "--slice",
            "web",
            "--dep",
            "a0",
            "--dep",
            "a9:needs: api",
        ],
        b"",
    )
    .await
    .0?;
    let debug = calls(&stub)[0].1.clone();
    assert!(debug.contains("item_key: \"a1\""), "{debug}");
    assert!(debug.contains("title: \"the title\""), "{debug}");
    assert!(debug.contains("body: \"b\""), "{debug}");
    assert!(debug.contains("slices: [\"core\", \"web\"]"), "{debug}");
    assert!(
        debug.contains("WorkDep { depends_on: \"a0\", why: \"\" }"),
        "{debug}"
    );
    assert!(
        debug.contains("WorkDep { depends_on: \"a9\", why: \"needs: api\" }"),
        "{debug}"
    );
    Ok(())
}

#[tokio::test]
async fn list_sends_the_state_filter_and_ready_flag() -> TestResult {
    let stub = Stub {
        items: vec![item("a1"), item("a2")],
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(
        &url,
        &["-p", "p", "list", "--state", "blocked", "--ready"],
        b"",
    )
    .await;
    result?;
    let debug = calls(&stub)[0].1.clone();
    assert!(debug.contains("state: Some(Blocked)"), "{debug}");
    assert!(debug.contains("ready_only: true"), "{debug}");
    assert_eq!(out.lines().count(), 2, "{out:?}");
    assert!(out.starts_with("a1\topen\tready\t1/2\t"), "{out:?}");
    let refused = Cli::try_parse_from(["fleet", "work", "list", "--state", "nope"]);
    assert!(refused.is_err());
    Ok(())
}

#[tokio::test]
async fn claim_sends_holder_and_ttl_and_prints_the_attempt() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(
        &url,
        &["-p", "p", "claim", "a1", "--holder", "w-1", "--ttl", "120"],
        b"",
    )
    .await;
    result?;
    let debug = calls(&stub)[0].1.clone();
    assert!(debug.contains("holder: \"w-1\""), "{debug}");
    assert!(debug.contains("ttl_secs: 120"), "{debug}");
    assert!(out.starts_with("attempt 1\ta1\tworker\t"), "{out:?}");
    Ok(())
}

#[tokio::test]
async fn pass_and_fail_send_the_verdict_note_and_evidence_from_stdin() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    cli(
        &url,
        &[
            "-p",
            "p",
            "pass",
            "7",
            "--note",
            "ok",
            "--evidence-file",
            "-",
        ],
        b"tail line\n",
    )
    .await
    .0?;
    cli(&url, &["-p", "p", "fail", "8", "--note", "no"], b"")
        .await
        .0?;
    let seen = calls(&stub);
    assert!(seen[0].1.contains("attempt_id: 7"), "{seen:?}");
    assert!(seen[0].1.contains("verdict: Pass"), "{seen:?}");
    assert!(
        seen[0].1.contains("evidence_tail: \"tail line\\n\""),
        "{seen:?}"
    );
    assert!(seen[1].1.contains("verdict: Fail"), "{seen:?}");
    assert!(seen[1].1.contains("evidence_tail: \"\""), "{seen:?}");
    Ok(())
}

#[tokio::test]
async fn evidence_over_the_cap_is_refused_before_connecting() -> TestResult {
    let big = vec![b'x'; 262_145];
    let (result, _) = cli(
        "http://127.0.0.1:1",
        &["-p", "p", "pass", "7", "--evidence-file", "-"],
        &big,
    )
    .await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    let (result, _) = cli(
        "http://127.0.0.1:1",
        &["-p", "p", "pass", "7", "--evidence-file", "-"],
        &[0xff, 0xfe],
    )
    .await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn evidence_at_the_cap_is_sent() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let edge = vec![b'x'; 262_144];
    cli(
        &url,
        &["-p", "p", "pass", "7", "--evidence-file", "-"],
        &edge,
    )
    .await
    .0?;
    assert_eq!(calls(&stub).len(), 1);
    Ok(())
}

#[tokio::test]
async fn next_prints_the_item_or_none() -> TestResult {
    let stub = Stub {
        next: Some(item("a5")),
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["-p", "p", "next"], b"").await;
    result?;
    assert!(out.starts_with("a5\t"), "{out:?}");
    let url = serve(Stub::default()).await?;
    let (result, out) = cli(&url, &["-p", "p", "next"], b"").await;
    result?;
    assert_eq!(out, "none\n");
    Ok(())
}

#[tokio::test]
async fn cancel_unblock_note_and_dep_send_their_fields() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    cli(&url, &["-p", "p", "cancel", "a1", "--reason", "dup"], b"")
        .await
        .0?;
    cli(
        &url,
        &["-p", "p", "unblock", "a1", "--reason", "fixed"],
        b"",
    )
    .await
    .0?;
    cli(&url, &["-p", "p", "note", "a1", "hi there"], b"")
        .await
        .0?;
    cli(
        &url,
        &["-p", "p", "dep", "add", "a1", "a0", "--why", "api"],
        b"",
    )
    .await
    .0?;
    cli(&url, &["-p", "p", "dep", "remove", "a1", "a0"], b"")
        .await
        .0?;
    let seen = calls(&stub);
    assert!(seen[0].1.contains("reason: \"dup\""), "{seen:?}");
    assert!(seen[1].1.contains("reason: \"fixed\""), "{seen:?}");
    assert!(seen[2].1.contains("note: \"hi there\""), "{seen:?}");
    assert!(
        seen[3].1.contains("depends_on: \"a0\", why: \"api\""),
        "{seen:?}"
    );
    assert!(seen[4].1.contains("depends_on: \"a0\""), "{seen:?}");
    Ok(())
}

#[tokio::test]
async fn defers_sends_the_filters_and_prints_rows() -> TestResult {
    let stub = Stub {
        defers: vec![WorkDefer {
            id: 4,
            item_key: Some("a1".into()),
            title: "later".into(),
            reason: "r".into(),
            vertical: "docs".into(),
            state: WorkDeferState::Open as i32,
            ..WorkDefer::default()
        }],
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(
        &url,
        &["-p", "p", "defers", "--vertical", "docs", "--state", "open"],
        b"",
    )
    .await;
    result?;
    let debug = calls(&stub)[0].1.clone();
    assert!(debug.contains("vertical: Some(\"docs\")"), "{debug}");
    assert!(debug.contains("state: Some(Open)"), "{debug}");
    assert_eq!(out, "4\topen\tdocs\ta1\tlater\tr\n");
    Ok(())
}

#[tokio::test]
async fn show_prints_item_attempts_and_events() -> TestResult {
    let stub = Stub {
        attempts: vec![attempt(3)],
        events: vec![WorkEvent {
            id: 1,
            kind: "note".into(),
            actor: "u".into(),
            note: "n".into(),
            ..WorkEvent::default()
        }],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["-p", "p", "show", "a1"], b"").await;
    result?;
    assert!(out.contains("a1\topen\tready\t1/2\ttitle"), "{out:?}");
    assert!(out.contains("attempt 3\ta1\tworker"), "{out:?}");
    assert!(out.contains("event 1\tnote\tu\t"), "{out:?}");
    Ok(())
}

#[tokio::test]
async fn every_printed_field_is_scrubbed_one_hostile_value_per_field() -> TestResult {
    let h = hostile();
    let slot = |set: &dyn Fn(&mut WorkItem)| {
        let mut base = item("a1");
        set(&mut base);
        base
    };
    let items = vec![
        slot(&|i| i.key = h.clone()),
        slot(&|i| i.title = h.clone()),
        slot(&|i| i.body = h.clone()),
        slot(&|i| i.slices = vec![h.clone()]),
        slot(&|i| {
            i.deps = vec![fleet_proto::v1::WorkDep {
                depends_on: h.clone(),
                why: h.clone(),
            }];
        }),
    ];
    for it in items {
        let attempts = vec![WorkAttempt {
            item_key: h.clone(),
            holder: h.clone(),
            note: h.clone(),
            evidence_tail: h.clone(),
            ..attempt(1)
        }];
        let events = vec![WorkEvent {
            kind: h.clone(),
            actor: h.clone(),
            note: h.clone(),
            item_key: Some(h.clone()),
            ..WorkEvent::default()
        }];
        let stub = Stub {
            items: vec![it.clone()],
            attempts,
            events,
            next: Some(it),
            defers: vec![WorkDefer {
                item_key: Some(h.clone()),
                title: h.clone(),
                reason: h.clone(),
                vertical: h.clone(),
                promoted_item_key: Some(h.clone()),
                ..WorkDefer::default()
            }],
            projects: vec![WorkProject {
                name: h.clone(),
                repo: Some(h.clone()),
                slices: vec![WorkSlice {
                    name: h.clone(),
                    paths: vec![h.clone()],
                }],
                mergeable: vec![h.clone()],
                created_at_ms: 0,
            }],
            ..Stub::default()
        };
        let url = serve(stub).await?;
        for args in [
            &["project", "list"][..],
            &["-p", "p", "list"],
            &["-p", "p", "show", "a1"],
            &["-p", "p", "next"],
            &["-p", "p", "claim", "a1", "--holder", "w"],
            &["-p", "p", "pass", "1"],
            &["-p", "p", "note", "a1", "x"],
            &["-p", "p", "defers"],
        ] {
            let (result, out) = cli(&url, args, b"").await;
            result?;
            assert!(clean(&out), "{args:?}: {out:?}");
            assert!(!out.is_empty(), "{args:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_multiline_field_cannot_forge_a_row() -> TestResult {
    let mut forged = item("a1");
    forged.title = "x\nforged\topen\tready\t9/9\tfake".into();
    forged.body = "line one\nattempt 99\tforged".into();
    let stub = Stub {
        items: vec![forged],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["-p", "p", "list"], b"").await;
    result?;
    assert_eq!(out.lines().count(), 1, "{out:?}");
    let (result, out) = cli(&url, &["-p", "p", "show", "a1"], b"").await;
    result?;
    assert!(out.lines().all(|l| !l.starts_with("attempt 99")), "{out:?}");
    Ok(())
}

#[tokio::test]
async fn a_server_refusal_prints_scrubbed_without_the_token() -> TestResult {
    let (result, _) = cli("http://127.0.0.1:1", &["-p", "p", "next"], b"").await;
    assert!(matches!(result, Err(CliError::Connect(_))), "{result:?}");
    Ok(())
}

fn ralph_dir(tasks: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tasks.json"), tasks).unwrap();
    dir
}

fn path_of(dir: &tempfile::TempDir) -> String {
    dir.path().to_str().unwrap().to_owned()
}

#[tokio::test]
async fn import_is_a_dry_run_unless_apply_is_given() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let dir = ralph_dir("[]");
    let path = path_of(&dir);
    let (result, out) = cli(&url, &["-p", "p", "import", &path], &[]).await;
    result?;
    assert!(out.starts_with("dry-run\t"), "{out}");
    assert!(out.contains("nothing written: pass --apply"), "{out}");
    let (result, out) = cli(&url, &["-p", "p", "import", "--apply", &path], &[]).await;
    result?;
    assert!(out.starts_with("applied\t"), "{out}");
    assert!(!out.contains("nothing written"), "{out}");
    let sent = calls(&stub);
    assert!(sent[0].1.contains("apply: false"), "{sent:?}");
    assert!(sent[1].1.contains("apply: true"), "{sent:?}");
    assert!(sent[0].1.contains("project: \"p\""), "{sent:?}");
    Ok(())
}

#[tokio::test]
async fn import_sends_every_file_and_treats_the_optional_ones_as_empty() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let dir = ralph_dir("[1]");
    std::fs::write(dir.path().join("progress.md"), "line one").unwrap();
    let path = path_of(&dir);
    cli(&url, &["-p", "p", "import", &path], &[]).await.0?;
    let sent = calls(&stub);
    assert!(sent[0].1.contains("tasks_json: \"[1]\""), "{sent:?}");
    assert!(sent[0].1.contains("slices_json: \"\""), "{sent:?}");
    assert!(sent[0].1.contains("progress_md: \"line one\""), "{sent:?}");
    assert!(sent[0].1.contains("backlog_md: \"\""), "{sent:?}");
    Ok(())
}

#[tokio::test]
async fn import_prints_counts_notes_and_every_unparsed_line_scrubbed() -> TestResult {
    let stub = Stub {
        import: ImportWorkReply {
            items_created: 3,
            items_unchanged: 4,
            items_raised: 5,
            items_differing: 6,
            slices_created: 7,
            mergeable_created: 8,
            defers_created: 9,
            notes: vec![hostile()],
            unparsed: vec!["progress.md:2: odd".into(), hostile()],
            unparsed_dropped: 11,
            ..ImportWorkReply::default()
        },
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let dir = ralph_dir("[]");
    let (result, out) = cli(&url, &["-p", "p", "import", &path_of(&dir)], &[]).await;
    result?;
    assert!(
        out.contains(
            "created=3\tunchanged=4\traised=5\tdiffering=6\tslices=7\tmergeable=8\tdefers=9"
        ),
        "{out}"
    );
    assert!(out.contains("unparsed: progress.md:2: odd\n"), "{out}");
    assert_eq!(out.matches("unparsed: ").count(), 2, "{out}");
    assert!(out.contains("note: "), "{out}");
    assert!(out.contains("unparsed dropped: 11"), "{out}");
    assert!(clean(&out), "{out:?}");
    Ok(())
}

#[tokio::test]
async fn import_refuses_bad_input_before_connecting() -> TestResult {
    let dead = "http://127.0.0.1:1";
    let empty = tempfile::tempdir().unwrap();
    let (result, _) = cli(dead, &["-p", "p", "import", &path_of(&empty)], &[]).await;
    assert!(matches!(result, Err(CliError::Io(_))), "{result:?}");
    let (result, _) = cli(dead, &["import", &path_of(&empty)], &[]).await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    let big = ralph_dir(&" ".repeat(1_048_577));
    let (result, _) = cli(dead, &["-p", "p", "import", &path_of(&big)], &[]).await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    let bad = ralph_dir("[]");
    std::fs::write(bad.path().join("progress.md"), [0xff, 0xfe]).unwrap();
    let (result, _) = cli(dead, &["-p", "p", "import", &path_of(&bad)], &[]).await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn import_reads_a_file_at_the_cap_and_refuses_a_symlink() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let edge = ralph_dir(&" ".repeat(1_048_576));
    cli(&url, &["-p", "p", "import", &path_of(&edge)], &[])
        .await
        .0?;
    assert_eq!(calls(&stub).len(), 1);
    let linked = tempfile::tempdir().unwrap();
    let real = ralph_dir("[]");
    std::os::unix::fs::symlink(
        real.path().join("tasks.json"),
        linked.path().join("tasks.json"),
    )
    .unwrap();
    let (result, _) = cli(&url, &["-p", "p", "import", &path_of(&linked)], &[]).await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    assert_eq!(calls(&stub).len(), 1);
    Ok(())
}

#[tokio::test]
async fn export_writes_both_files_and_leaves_no_temp_file() -> TestResult {
    let stub = Stub {
        export: ExportWorkReply {
            tasks_json: "[]\n".into(),
            slices_json: "{}\n".into(),
        },
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tasks.json"), "old").unwrap();
    let (result, out) = cli(&url, &["-p", "p", "export", &path_of(&dir)], &[]).await;
    result?;
    assert_eq!(
        std::fs::read_to_string(dir.path().join("tasks.json"))?,
        "[]\n"
    );
    assert_eq!(
        std::fs::read_to_string(dir.path().join("slices.json"))?,
        "{}\n"
    );
    let mut names: Vec<_> = std::fs::read_dir(dir.path())?
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, ["slices.json", "tasks.json"]);
    assert_eq!(out.matches("wrote ").count(), 2, "{out}");
    assert!(calls(&stub)[0].1.contains("project: \"p\""));
    Ok(())
}

#[tokio::test]
async fn export_refuses_a_symlink_target_and_writes_nothing_through_it() -> TestResult {
    let stub = Stub {
        export: ExportWorkReply {
            tasks_json: "[]\n".into(),
            slices_json: "{}\n".into(),
        },
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let victim = elsewhere.path().join("victim");
    std::fs::write(&victim, "keep").unwrap();
    std::os::unix::fs::symlink(&victim, dir.path().join("tasks.json")).unwrap();
    let (result, _) = cli(&url, &["-p", "p", "export", &path_of(&dir)], &[]).await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    assert_eq!(std::fs::read_to_string(&victim)?, "keep");
    Ok(())
}

#[tokio::test]
async fn export_needs_a_project_and_an_existing_directory() -> TestResult {
    let dead = "http://127.0.0.1:1";
    let dir = tempfile::tempdir().unwrap();
    let (result, _) = cli(dead, &["export", &path_of(&dir)], &[]).await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    let stub = Stub::default();
    let url = serve(stub).await?;
    let missing = dir.path().join("nope");
    let (result, _) = cli(&url, &["-p", "p", "export", missing.to_str().unwrap()], &[]).await;
    assert!(matches!(result, Err(CliError::Io(_))), "{result:?}");
    Ok(())
}
