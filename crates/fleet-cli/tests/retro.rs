//! `fleet retro`, `fleet improvement` and `fleet pitfall` against an in-process `FleetRetro`
//! stub: one test per rpc for the request fields and the printed rows, per-invocation keys,
//! usage refusals before any connection and the scrubbing of every printed field.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::v1::fleet_retro_server::{FleetRetro, FleetRetroServer};
use fleet_proto::v1::{
    CloseRetroRequest, DispositionImprovementRequest, FileImprovementRequest, GetWorkBriefReply,
    GetWorkBriefRequest, Improvement, ImprovementDisposition, ImprovementKind,
    ListImprovementsReply, ListImprovementsRequest, ListPitfallsReply, ListPitfallsRequest,
    ListRetrosReply, ListRetrosRequest, OpenRetroRequest, Pitfall, RecordPitfallRequest, Retro,
    RetroState,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

#[derive(Clone, Default)]
struct Stub {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    retro: Option<Retro>,
    improvement: Option<Improvement>,
    pitfall: Option<Pitfall>,
    brief: Option<GetWorkBriefReply>,
}

impl Stub {
    fn record(&self, method: &str, request: &impl std::fmt::Debug) {
        self.calls
            .lock()
            .unwrap()
            .push((method.to_owned(), format!("{request:?}")));
    }

    fn retro(&self) -> Retro {
        self.retro.clone().unwrap_or_else(retro)
    }

    fn improvement(&self) -> Improvement {
        self.improvement.clone().unwrap_or_else(improvement)
    }

    fn pitfall(&self) -> Pitfall {
        self.pitfall.clone().unwrap_or_else(pitfall)
    }
}

fn retro() -> Retro {
    Retro {
        id: 3,
        title: "sprint".into(),
        state: RetroState::Open as i32,
        span_from_item_key: Some("a1".into()),
        span_to_item_key: Some("a9".into()),
        opened_at_ms: 0,
        closed_at_ms: None,
    }
}

fn improvement() -> Improvement {
    Improvement {
        id: 5,
        retro_id: Some(3),
        item_key: Some("a1".into()),
        vertical: "cli".into(),
        title: "write tests first".into(),
        body: "line one\nline two".into(),
        kind: ImprovementKind::Process as i32,
        occurrences: 2,
        disposition: Some(ImprovementDisposition::Deferred as i32),
        disposition_reason: Some("later".into()),
        created_at_ms: 0,
    }
}

fn pitfall() -> Pitfall {
    Pitfall {
        id: 8,
        project: Some("p".into()),
        symptom: "clippy fails".into(),
        cause: "newer lint".into(),
        fix: "avoid it".into(),
        hits: 4,
        last_hit_at_ms: Some(0),
        created_at_ms: 0,
    }
}

#[tonic::async_trait]
impl FleetRetro for Stub {
    async fn open_retro(&self, r: Request<OpenRetroRequest>) -> Result<Response<Retro>, Status> {
        self.record("open_retro", r.get_ref());
        Ok(Response::new(self.retro()))
    }

    async fn close_retro(&self, r: Request<CloseRetroRequest>) -> Result<Response<Retro>, Status> {
        self.record("close_retro", r.get_ref());
        Ok(Response::new(self.retro()))
    }

    async fn list_retros(
        &self,
        r: Request<ListRetrosRequest>,
    ) -> Result<Response<ListRetrosReply>, Status> {
        self.record("list_retros", r.get_ref());
        Ok(Response::new(ListRetrosReply {
            retros: vec![self.retro(), self.retro()],
        }))
    }

    async fn file_improvement(
        &self,
        r: Request<FileImprovementRequest>,
    ) -> Result<Response<Improvement>, Status> {
        self.record("file_improvement", r.get_ref());
        Ok(Response::new(self.improvement()))
    }

    async fn list_improvements(
        &self,
        r: Request<ListImprovementsRequest>,
    ) -> Result<Response<ListImprovementsReply>, Status> {
        self.record("list_improvements", r.get_ref());
        Ok(Response::new(ListImprovementsReply {
            improvements: vec![self.improvement()],
        }))
    }

    async fn disposition_improvement(
        &self,
        r: Request<DispositionImprovementRequest>,
    ) -> Result<Response<Improvement>, Status> {
        self.record("disposition_improvement", r.get_ref());
        Ok(Response::new(self.improvement()))
    }

    async fn record_pitfall(
        &self,
        r: Request<RecordPitfallRequest>,
    ) -> Result<Response<Pitfall>, Status> {
        self.record("record_pitfall", r.get_ref());
        Ok(Response::new(self.pitfall()))
    }

    async fn list_pitfalls(
        &self,
        r: Request<ListPitfallsRequest>,
    ) -> Result<Response<ListPitfallsReply>, Status> {
        self.record("list_pitfalls", r.get_ref());
        Ok(Response::new(ListPitfallsReply {
            pitfalls: vec![self.pitfall()],
        }))
    }

    async fn get_work_brief(
        &self,
        r: Request<GetWorkBriefRequest>,
    ) -> Result<Response<GetWorkBriefReply>, Status> {
        self.record("get_work_brief", r.get_ref());
        Ok(Response::new(self.brief.clone().unwrap_or_else(|| {
            GetWorkBriefReply {
                text: "brief text\nsecond".into(),
                dropped: 2,
            }
        })))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetRetroServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli(url: &str, args: &[&str]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let mut out = Vec::new();
    let mut stdin: &[u8] = b"";
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

async fn one(args: &[&str]) -> Result<(String, (String, String)), Box<dyn std::error::Error>> {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(&url, args).await;
    result?;
    let seen = calls(&stub);
    assert_eq!(seen.len(), 1, "{seen:?}");
    Ok((out, seen.first().cloned().unwrap()))
}

fn has(debug: &str, fields: &[&str]) {
    for field in fields {
        assert!(debug.contains(field), "{field} in {debug}");
    }
}

#[tokio::test]
async fn retro_open_calls_open_retro_with_the_span() -> TestResult {
    let (out, (method, debug)) = one(&[
        "retro", "-p", "proj", "open", "sprint", "--from", "a1", "--to", "a9",
    ])
    .await?;
    assert_eq!(method, "open_retro");
    has(
        &debug,
        &[
            "project: \"proj\"",
            "title: \"sprint\"",
            "span_from_item_key: Some(\"a1\")",
            "span_to_item_key: Some(\"a9\")",
        ],
    );
    assert_ne!(key_of(&debug), "");
    assert!(out.starts_with("3\topen\tsprint\ta1\ta9\t"), "{out:?}");
    let (_, (_, bare)) = one(&["retro", "-p", "proj", "open", "sprint"]).await?;
    has(
        &bare,
        &["span_from_item_key: None", "span_to_item_key: None"],
    );
    Ok(())
}

#[tokio::test]
async fn retro_list_calls_list_retros_with_the_state_filter() -> TestResult {
    let (out, (method, debug)) = one(&["retro", "-p", "proj", "list", "--state", "closed"]).await?;
    assert_eq!(method, "list_retros");
    has(&debug, &["project: \"proj\"", "state: Some(Closed)"]);
    assert_eq!(out.lines().count(), 2, "{out:?}");
    let (_, (_, none)) = one(&["retro", "-p", "proj", "list"]).await?;
    has(&none, &["state: None"]);
    Ok(())
}

#[tokio::test]
async fn retro_close_calls_close_retro_with_the_id() -> TestResult {
    let (out, (method, debug)) = one(&["retro", "-p", "proj", "close", "3"]).await?;
    assert_eq!(method, "close_retro");
    has(&debug, &["project: \"proj\"", "retro_id: 3"]);
    assert_ne!(key_of(&debug), "");
    assert!(out.starts_with("3\topen\tsprint"), "{out:?}");
    Ok(())
}

#[tokio::test]
async fn retro_brief_calls_get_work_brief_and_prints_the_text_indented_with_the_drop_count()
-> TestResult {
    let (out, (method, debug)) = one(&["retro", "-p", "proj", "brief", "a1"]).await?;
    assert_eq!(method, "get_work_brief");
    has(&debug, &["project: \"proj\"", "item_key: \"a1\""]);
    assert_eq!(out, "brief:\n  brief text\n  second\ndropped: 2\n");
    Ok(())
}

#[tokio::test]
async fn improvement_file_calls_file_improvement_with_every_field() -> TestResult {
    let (out, (method, debug)) = one(&[
        "improvement",
        "-p",
        "proj",
        "file",
        "write tests first",
        "--vertical",
        "cli",
        "--kind",
        "process",
        "--body",
        "why",
        "--retro",
        "3",
        "--item",
        "a1",
        "--attempt",
        "7",
    ])
    .await?;
    assert_eq!(method, "file_improvement");
    has(
        &debug,
        &[
            "project: \"proj\"",
            "retro_id: Some(3)",
            "item_key: Some(\"a1\")",
            "attempt_id: Some(7)",
            "vertical: \"cli\"",
            "title: \"write tests first\"",
            "body: \"why\"",
            "kind: Process",
        ],
    );
    assert_ne!(key_of(&debug), "");
    assert!(
        out.starts_with("5\tprocess\tdeferred\tx2\tcli\t3\ta1\twrite tests first\n"),
        "{out:?}"
    );
    assert!(out.contains("body:\n  line one\n  line two\n"), "{out:?}");
    assert!(out.contains("reason:\n  later\n"), "{out:?}");
    let (_, (_, bare)) = one(&[
        "improvement",
        "-p",
        "p",
        "file",
        "t",
        "--vertical",
        "v",
        "--kind",
        "other",
    ])
    .await?;
    has(
        &bare,
        &[
            "retro_id: None",
            "item_key: None",
            "attempt_id: None",
            "body: \"\"",
            "kind: Other",
        ],
    );
    Ok(())
}

#[tokio::test]
async fn improvement_file_maps_every_kind_word() -> TestResult {
    for (word, kind) in [
        ("process", "Process"),
        ("tooling", "Tooling"),
        ("docs", "Docs"),
        ("test", "Test"),
        ("pitfall", "Pitfall"),
        ("other", "Other"),
    ] {
        let (_, (_, debug)) = one(&[
            "improvement",
            "-p",
            "p",
            "file",
            "t",
            "--vertical",
            "v",
            "--kind",
            word,
        ])
        .await?;
        has(&debug, &[&format!("kind: {kind}")]);
    }
    Ok(())
}

#[tokio::test]
async fn improvement_list_calls_list_improvements_with_the_filters() -> TestResult {
    let (out, (method, debug)) = one(&[
        "improvement",
        "-p",
        "proj",
        "list",
        "--vertical",
        "cli",
        "--retro",
        "3",
        "--undecided",
    ])
    .await?;
    assert_eq!(method, "list_improvements");
    has(
        &debug,
        &[
            "project: \"proj\"",
            "vertical: Some(\"cli\")",
            "retro_id: Some(3)",
            "undecided: Some(true)",
        ],
    );
    assert!(out.starts_with("5\tprocess\t"), "{out:?}");
    let (_, (_, bare)) = one(&["improvement", "-p", "proj", "list"]).await?;
    has(
        &bare,
        &["vertical: None", "retro_id: None", "undecided: None"],
    );
    Ok(())
}

#[tokio::test]
async fn improvement_disposition_calls_disposition_improvement_with_decision_and_reason()
-> TestResult {
    for (word, name) in [
        ("accepted", "Accepted"),
        ("rejected", "Rejected"),
        ("deferred", "Deferred"),
        ("applied", "Applied"),
    ] {
        let (_, (method, debug)) = one(&[
            "improvement",
            "-p",
            "proj",
            "disposition",
            "5",
            word,
            "--reason",
            "because",
        ])
        .await?;
        assert_eq!(method, "disposition_improvement");
        has(
            &debug,
            &[
                "project: \"proj\"",
                "improvement_id: 5",
                &format!("disposition: {name}"),
                "reason: \"because\"",
            ],
        );
        assert_ne!(key_of(&debug), "");
    }
    Ok(())
}

#[tokio::test]
async fn pitfall_record_calls_record_pitfall_and_project_is_optional() -> TestResult {
    let (out, (method, debug)) = one(&[
        "pitfall",
        "-p",
        "proj",
        "record",
        "clippy fails",
        "--cause",
        "newer lint",
        "--fix",
        "avoid it",
    ])
    .await?;
    assert_eq!(method, "record_pitfall");
    has(
        &debug,
        &[
            "project: Some(\"proj\")",
            "symptom: \"clippy fails\"",
            "cause: \"newer lint\"",
            "fix: \"avoid it\"",
        ],
    );
    assert_ne!(key_of(&debug), "");
    assert!(out.starts_with("8\tp\t4\tclippy fails\n"), "{out:?}");
    assert!(
        out.contains("cause:\n  newer lint\n") && out.contains("fix:\n  avoid it\n"),
        "{out:?}"
    );
    let (_, (_, user)) = one(&["pitfall", "record", "s", "--cause", "c", "--fix", "f"]).await?;
    has(&user, &["project: None"]);
    Ok(())
}

#[tokio::test]
async fn pitfall_list_calls_list_pitfalls_and_project_is_optional() -> TestResult {
    let (out, (method, debug)) = one(&["pitfall", "-p", "proj", "list"]).await?;
    assert_eq!(method, "list_pitfalls");
    has(&debug, &["project: Some(\"proj\")"]);
    assert!(out.starts_with("8\tp\t4\tclippy fails\n"), "{out:?}");
    let (_, (_, user)) = one(&["pitfall", "list"]).await?;
    has(&user, &["project: None"]);
    Ok(())
}

#[tokio::test]
async fn each_mutating_invocation_sends_a_fresh_key_and_a_given_key_is_sent_unchanged() -> TestResult
{
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let args = ["retro", "-p", "p", "open", "t"];
    cli(&url, &args).await.0?;
    cli(&url, &args).await.0?;
    cli(
        &url,
        &[
            "retro",
            "-p",
            "p",
            "--idempotency-key",
            "fixed",
            "open",
            "t",
        ],
    )
    .await
    .0?;
    let seen = calls(&stub);
    assert_ne!(key_of(&seen[0].1), key_of(&seen[1].1));
    assert_eq!(key_of(&seen[2].1), "fixed");
    Ok(())
}

#[tokio::test]
async fn usage_errors_are_refused_before_connecting() -> TestResult {
    for args in [
        &["retro", "list"][..],
        &["retro", "open", "t"],
        &["retro", "brief", "a1"],
        &["improvement", "list"],
        &[
            "improvement",
            "file",
            "t",
            "--vertical",
            "v",
            "--kind",
            "other",
        ],
        &["retro", "-p", "p", "--idempotency-key", "", "open", "t"],
        &[
            "pitfall",
            "--idempotency-key",
            "",
            "record",
            "s",
            "--cause",
            "c",
            "--fix",
            "f",
        ],
        &["pitfall", "-p", "", "list"],
    ] {
        let (result, _) = cli("http://127.0.0.1:1", args).await;
        assert!(
            matches!(result, Err(CliError::Usage(_))),
            "{args:?}: {result:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_printed_field_is_scrubbed_one_hostile_value_per_field() -> TestResult {
    let h = hostile();
    let retros: [&dyn Fn(&mut Retro); 3] = [
        &|r| r.title = h.clone(),
        &|r| r.span_from_item_key = Some(h.clone()),
        &|r| r.span_to_item_key = Some(h.clone()),
    ];
    let improvements: [&dyn Fn(&mut Improvement); 5] = [
        &|i| i.item_key = Some(h.clone()),
        &|i| i.vertical = h.clone(),
        &|i| i.title = h.clone(),
        &|i| i.body = h.clone(),
        &|i| i.disposition_reason = Some(h.clone()),
    ];
    let pitfalls: [&dyn Fn(&mut Pitfall); 4] = [
        &|p| p.project = Some(h.clone()),
        &|p| p.symptom = h.clone(),
        &|p| p.cause = h.clone(),
        &|p| p.fix = h.clone(),
    ];
    let mut stubs = Vec::new();
    for set in retros {
        let mut r = retro();
        set(&mut r);
        stubs.push(Stub {
            retro: Some(r),
            ..Stub::default()
        });
    }
    for set in improvements {
        let mut i = improvement();
        set(&mut i);
        stubs.push(Stub {
            improvement: Some(i),
            ..Stub::default()
        });
    }
    for set in pitfalls {
        let mut p = pitfall();
        set(&mut p);
        stubs.push(Stub {
            pitfall: Some(p),
            ..Stub::default()
        });
    }
    stubs.push(Stub {
        brief: Some(GetWorkBriefReply {
            text: h.clone(),
            dropped: 0,
        }),
        ..Stub::default()
    });
    for stub in stubs {
        let url = serve(stub).await?;
        for args in [
            &["retro", "-p", "p", "list"][..],
            &["retro", "-p", "p", "open", "t"],
            &["retro", "-p", "p", "close", "3"],
            &["retro", "-p", "p", "brief", "a1"],
            &["improvement", "-p", "p", "list"],
            &[
                "improvement",
                "-p",
                "p",
                "file",
                "t",
                "--vertical",
                "v",
                "--kind",
                "docs",
            ],
            &[
                "improvement",
                "-p",
                "p",
                "disposition",
                "5",
                "applied",
                "--reason",
                "r",
            ],
            &["pitfall", "-p", "p", "list"],
            &[
                "pitfall", "-p", "p", "record", "s", "--cause", "c", "--fix", "f",
            ],
        ] {
            let (result, out) = cli(&url, args).await;
            result?;
            assert!(clean(&out), "{args:?}: {out:?}");
            assert!(!out.is_empty(), "{args:?}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_multiline_body_cannot_forge_a_row() -> TestResult {
    let mut i = improvement();
    i.body = "x\n99\tprocess\taccepted\tx1\tcli\t-\t-\tforged".into();
    let url = serve(Stub {
        improvement: Some(i),
        ..Stub::default()
    })
    .await?;
    let (result, out) = cli(&url, &["improvement", "-p", "p", "list"]).await;
    result?;
    assert!(out.lines().all(|l| !l.starts_with("99\t")), "{out:?}");
    Ok(())
}
