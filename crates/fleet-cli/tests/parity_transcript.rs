//! Parity of the job transcript across `fleet logs` (the readable view) and the web job page
//! transcript pane, for one stored transcript seeded through the real `ClaimJob` and `ReportJob`
//! RPCs.
//!
//! `FACTS` lists every fact a reader can take from a transcript, each with a classification:
//! `both`, `cli-only` or `web-only`. Each fact is checked on each surface. A fact must be present
//! on the surfaces its class names and absent on the other, and every absence is a known
//! difference listed in `GAPS` with a reason. Closing a gap makes a row red until the `GAPS`
//! entry is removed and the class is changed to `both`. Hostile values in the transcript must
//! appear stripped on both surfaces. The tests need a Postgres superuser URL in `DATABASE_URL`
//! and live in their own binary because they bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, run};
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, JobState, ReportJobRequest, SubmitJobRequest, TranscriptChunk,
};
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::Endpoint;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const REPO: &str = "https://example.com/org/repo.git";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const CLIENT_TOKEN: &str = "client-token-0123456789abcdef012345";
const SESSION_SEED: char = 'a';

const SAMPLE_JOB: &str =
    include_str!("../../fleet-core/tests/fixtures/transcript/sample_job.jsonl");
const ERROR_RESULT: &str =
    include_str!("../../fleet-core/tests/fixtures/transcript/error_result.jsonl");

const HOSTILE: &[(&str, &str)] = &[
    ("H-ansi", r"red\u001b[31mX\u001b[0m end"),
    ("H-bidi", r"a\u202eb end"),
    ("H-nul", r"a\u0000b end"),
    (
        "H-osc",
        r"\u001b]8;;http://example.invalid/\u0007link\u001b]8;;\u0007 end",
    ),
    ("H-markup", "<script>alert(1)</script> end"),
];

const GAP_INPUT: &str = "the readable view prints the call summary only, not the tool input json";
const GAP_REASON: &str =
    "the result block shows a failure badge but no terminal reason when it is `completed`";
const GAP_DENIALS: &str = "the footer names denials only when there are some";

const GAPS: &[(&str, Surface, &str)] = &[
    ("call.input", Surface::Cli, GAP_INPUT),
    ("run.reason", Surface::Web, GAP_REASON),
    ("run.denials", Surface::Cli, GAP_DENIALS),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    Cli,
    Web,
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Cli => "cli",
            Self::Web => "web",
        })
    }
}

const SURFACES: [Surface; 2] = [Surface::Cli, Surface::Web];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Both,
    CliOnly,
    WebOnly,
}

impl Class {
    fn expects(self, surface: Surface) -> bool {
        matches!(
            (self, surface),
            (Self::Both, _) | (Self::CliOnly, Surface::Cli) | (Self::WebOnly, Surface::Web)
        )
    }
}

const FACTS: &[(&str, Class)] = &[
    ("system.init", Class::Both),
    ("message.assistant", Class::Both),
    ("call.summary", Class::Both),
    ("call.status", Class::Both),
    ("call.input", Class::WebOnly),
    ("result.output", Class::Both),
    ("result.error_output", Class::Both),
    ("run.failed", Class::Both),
    ("run.turns", Class::Both),
    ("run.duration", Class::Both),
    ("run.cost", Class::Both),
    ("run.tokens", Class::Both),
    ("run.reason", Class::CliOnly),
    ("run.denials", Class::WebOnly),
    ("hostile.ansi", Class::Both),
    ("hostile.bidi", Class::Both),
    ("hostile.nul", Class::Both),
    ("hostile.osc", Class::Both),
    ("hostile.markup", Class::Both),
];

struct Row {
    fact: &'static str,
    class: Class,
    surface: Surface,
}

impl Row {
    fn name(&self) -> String {
        format!("{} on {}", self.fact, self.surface)
    }

    fn gap(&self) -> Option<&'static str> {
        GAPS.iter()
            .find(|(name, surface, _)| *name == self.fact && *surface == self.surface)
            .map(|(_, _, reason)| *reason)
    }
}

fn rows() -> Vec<Row> {
    FACTS
        .iter()
        .flat_map(|(fact, class)| {
            SURFACES.into_iter().map(move |surface| Row {
                fact,
                class: *class,
                surface,
            })
        })
        .collect()
}

#[derive(Default)]
struct Rendered {
    cli: String,
    web: String,
}

fn hostile_line(index: usize, label: &str, text: &str) -> String {
    format!(
        "{{\"type\":\"assistant\",\"message\":{{\"id\":\"msg_H{index}\",\"role\":\"assistant\",\
         \"content\":[{{\"type\":\"text\",\"text\":\"{label} {text}\"}}]}},\
         \"parent_tool_use_id\":null}}"
    )
}

fn nth_line(text: &str, index: usize) -> String {
    text.lines().nth(index).unwrap().to_owned()
}

fn transcript_lines() -> Vec<String> {
    let mut lines = vec![
        nth_line(ERROR_RESULT, 0),
        nth_line(SAMPLE_JOB, 4),
        nth_line(SAMPLE_JOB, 5),
    ];
    lines.extend((1..4).map(|index| nth_line(ERROR_RESULT, index)));
    for (index, (label, text)) in HOSTILE.iter().enumerate() {
        lines.push(hostile_line(index, label, text));
    }
    lines.push(nth_line(ERROR_RESULT, 4));
    lines
}

fn bearer<T>(token: &str, mut request: Request<T>) -> Request<T> {
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

async fn http_get(addr: SocketAddr, path: &str, cookie: &str) -> String {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\n\
         Cookie: {cookie}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
        .await
        .unwrap()
        .unwrap();
    let raw = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = raw.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    body.to_owned()
}

async fn cli_logs(url: &str, token: &str, job: &str) -> String {
    let parsed = Cli::try_parse_from(["fleet", "--server", url, "logs", job]).unwrap();
    let mut out = Vec::new();
    let token = token.to_owned();
    run(
        parsed,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| token.clone()),
        &mut std::io::empty(),
        &mut out,
    )
    .await
    .unwrap();
    String::from_utf8(out).unwrap()
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear seed through the real server, kept in one place"
)]
async fn seed(pool: PgPool) -> Rendered {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let alice: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let made = users.create_api_token(alice, "cli").await.unwrap();
    let api_token = String::from_utf8(made.token.expose().to_vec()).unwrap();
    let session = SESSION_SEED.to_string().repeat(64);
    sqlx::query(
        "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
         VALUES (sha256($1::bytea), $2, 'csrf-token', now() + interval '1 hour')",
    )
    .bind(session.as_bytes())
    .bind(alice)
    .execute(&pool)
    .await
    .unwrap();
    let job = store
        .submit_job_for(
            Some(alice),
            &SubmitJobRequest {
                idempotency_key: "parity-transcript".to_owned(),
                prompt: "task".to_owned(),
                repo: REPO.to_owned(),
                base_ref: "main".to_owned(),
                open_pr: false,
                agent: String::new(),
                profile: String::new(),
            },
        )
        .await
        .unwrap();

    let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
    let web = Web::with_console(auth, None, store.clone());
    let bearer_auth = BearerAuth::new(
        &Token::new(BOX_TOKEN.to_owned()).unwrap(),
        Some(&Token::new(CLIENT_TOKEN.to_owned()).unwrap()),
    )
    .with_users(users);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let serving = store.clone();
    tokio::spawn(async move {
        serve_with_web(
            &serving,
            &bearer_auth,
            web,
            TcpIncoming::from(listener),
            std::future::pending::<()>(),
        )
        .await
    });
    let url = format!("http://{addr}");
    let channel = Endpoint::from_shared(url.clone()).unwrap().connect_lazy();

    let mut worker = FleetWorkerClient::new(channel);
    let holder = format!("box-{}", 7);
    let claimed = worker
        .claim_job(bearer(
            BOX_TOKEN,
            Request::new(ClaimJobRequest {
                r#box: holder.clone(),
            }),
        ))
        .await
        .unwrap()
        .into_inner()
        .job
        .unwrap();
    assert_eq!(claimed.job_id, job.job_id);
    let chunks: Vec<TranscriptChunk> = transcript_lines()
        .into_iter()
        .zip(1_u64..)
        .map(|(text, seq)| TranscriptChunk {
            seq,
            ts_ms: seq,
            text,
            truncated: false,
        })
        .collect();
    worker
        .report_job(bearer(
            BOX_TOKEN,
            Request::new(ReportJobRequest {
                job_id: job.job_id.clone(),
                attempt: claimed.attempt,
                r#box: holder,
                phase: String::new(),
                progress: String::new(),
                terminal_state: Some(JobState::Failed as i32),
                pr_url: None,
                error: None,
                exit_code: None,
                chunks,
                branch: None,
                events: Vec::new(),
                summary: None,
                verdict: None,
                ci: None,
            }),
        ))
        .await
        .unwrap();

    Rendered {
        cli: cli_logs(&url, &api_token, &job.job_id).await,
        web: http_get(
            addr,
            &format!("/jobs/{}", job.job_id),
            &format!("{SESSION_COOKIE}={session}"),
        )
        .await,
    }
}

fn is_hostile_char(c: char) -> bool {
    (c.is_control() && c != '\n' && c != '\t')
        || matches!(c, '\u{200b}'..='\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
}

fn web_blocks(page: &str) -> Vec<&str> {
    page.split("<li id=\"tx-")
        .skip(1)
        .map(|block| block.split("</li>").next().unwrap_or(""))
        .collect()
}

fn web_block<'a>(page: &'a str, kind: &str, needle: &str) -> &'a str {
    let marker = format!("data-kind=\"{kind}\"");
    web_blocks(page)
        .into_iter()
        .find(|block| block.contains(&marker) && block.contains(needle))
        .unwrap_or("")
}

fn has_block(page: &str, kind: &str, needle: &str) -> bool {
    !web_block(page, kind, needle).is_empty()
}

fn cli_has(cli: &str, line: &str) -> bool {
    cli.lines().any(|candidate| candidate == line)
}

fn cli_after(cli: &str, head: &str, next: &str) -> bool {
    let mut lines = cli.lines().skip_while(|line| *line != head);
    lines.next().is_some() && lines.next() == Some(next)
}

fn dd(page: &str, label: &str, value: &str) -> bool {
    let block = web_block(page, "result", "Turns");
    block.contains(&format!(">{label}</dt><dd>{value}</dd>"))
}

fn hostile_message(rendered: &Rendered, surface: Surface, label: &str, tail: &str) -> bool {
    let text = match surface {
        Surface::Cli => rendered
            .cli
            .lines()
            .find(|line| line.starts_with(&format!("assistant: {label} ")))
            .unwrap_or("")
            .to_owned(),
        Surface::Web => web_block(&rendered.web, "message", label).to_owned(),
    };
    text.ends_with(tail) || text.contains(&format!("{tail}</pre>"))
}

fn clean_message(rendered: &Rendered, surface: Surface, label: &str) -> bool {
    let (found, body) = match surface {
        Surface::Cli => {
            let line = rendered
                .cli
                .lines()
                .find(|line| line.starts_with(&format!("assistant: {label} ")))
                .unwrap_or("");
            (!line.is_empty(), line.to_owned())
        }
        Surface::Web => {
            let block = web_block(&rendered.web, "message", label);
            (!block.is_empty(), block.to_owned())
        }
    };
    found && !body.chars().any(is_hostile_char) && hostile_message(rendered, surface, label, " end")
}

fn present(fact: &str, rendered: &Rendered, surface: Surface) -> bool {
    let cli = rendered.cli.as_str();
    let web = rendered.web.as_str();
    match (fact, surface) {
        ("system.init", Surface::Cli) => cli_has(cli, "system: init"),
        ("system.init", Surface::Web) => has_block(web, "system", ">init</pre>"),
        ("message.assistant", Surface::Cli) => ["Listing the repo.", "The file is missing."]
            .iter()
            .all(|text| cli_has(cli, &format!("assistant: {text}"))),
        ("message.assistant", Surface::Web) => ["Listing the repo.", "The file is missing."]
            .iter()
            .all(|text| has_block(web, "message", &format!(">{text}</pre>"))),
        ("call.summary", Surface::Cli) => {
            cli_has(cli, "> Bash ls") && cli_has(cli, "> Bash cat missing.txt")
        }
        ("call.summary", Surface::Web) => ["ls", "cat missing.txt"].iter().all(|summary| {
            web_block(web, "tool", &format!(">{summary}</span>")).contains(">Bash</span>")
        }),
        ("call.status", Surface::Cli) => {
            cli_after(cli, "> Bash ls", "  < ok")
                && cli_after(cli, "> Bash cat missing.txt", "  < ERROR")
        }
        ("call.status", Surface::Web) => {
            web_block(web, "tool", ">ls</span>").contains("data-status=\"ok\"")
                && web_block(web, "tool", ">cat missing.txt</span>")
                    .contains("data-status=\"error\"")
        }
        ("call.input", Surface::Cli) => cli.contains("{\"command\":\"ls\"}"),
        ("call.input", Surface::Web) => web_block(web, "tool", ">ls</span>")
            .contains("aria-label=\"Tool input\">{\"command\":\"ls\"}</pre>"),
        ("result.output", Surface::Cli) => {
            cli_has(cli, "    Cargo.toml") && cli_has(cli, "    src")
        }
        ("result.output", Surface::Web) => web_block(web, "tool", ">ls</span>")
            .contains("aria-label=\"Tool output\">Cargo.toml\nsrc</pre>"),
        ("result.error_output", Surface::Cli) => {
            cli_has(cli, "    cat: missing.txt: No such file or directory")
        }
        ("result.error_output", Surface::Web) => web_block(web, "tool", ">cat missing.txt</span>")
            .contains(
                "aria-label=\"Tool output\">cat: missing.txt: No such file or directory</pre>",
            ),
        ("run.failed", Surface::Cli) => cli.lines().any(|line| line.starts_with("-- run failed: ")),
        ("run.failed", Surface::Web) => {
            web_block(web, "result", "Turns").contains("badge-error\">error</span>")
        }
        ("run.turns", Surface::Cli) => cli.contains("-- run failed: 2 turns, "),
        ("run.turns", Surface::Web) => dd(web, "Turns", "2"),
        ("run.duration", Surface::Cli) => cli.contains(", 12.345s, "),
        ("run.duration", Surface::Web) => dd(web, "Duration", "12.3 s"),
        ("run.cost", Surface::Cli) => cli.contains(", $0.0421, "),
        ("run.cost", Surface::Web) => dd(web, "Cost", "$0.0421"),
        ("run.tokens", Surface::Cli) => {
            cli.contains("tokens in 120 out 340") && !cli.contains("cache read")
        }
        ("run.tokens", Surface::Web) => {
            let block = web_block(web, "result", "Turns");
            dd(web, "Input", "120")
                && dd(web, "Output", "340")
                && !block.contains("Cache read")
                && !block.contains("Cache write")
        }
        ("run.reason", Surface::Cli) => cli.contains(", reason completed"),
        ("run.reason", Surface::Web) => web_block(web, "result", "Turns").contains("completed"),
        ("run.denials", Surface::Cli) => cli.contains("denials"),
        ("run.denials", Surface::Web) => dd(web, "Denials", "0"),
        (other, surface) => other
            .strip_prefix("hostile.")
            .is_some_and(|kind| hostile_row(rendered, surface, kind)),
    }
}

fn hostile_row(rendered: &Rendered, surface: Surface, kind: &str) -> bool {
    let label = format!("H-{kind}");
    let inert = kind != "markup"
        || match surface {
            Surface::Cli => cli_has(
                &rendered.cli,
                "assistant: H-markup <script>alert(1)</script> end",
            ),
            Surface::Web => {
                rendered
                    .web
                    .contains("&lt;script&gt;alert(1)&lt;/script&gt; end")
                    && !rendered.web.contains("<script>alert")
            }
        };
    clean_message(rendered, surface, &label) && inert
}

fn failures(rendered: &Rendered) -> Vec<String> {
    let mut out = Vec::new();
    for row in rows() {
        let found = present(row.fact, rendered, row.surface);
        let expected = row.class.expects(row.surface);
        match (expected, found, row.gap()) {
            (true, false, _) => out.push(format!("row [{}] red: fact missing", row.name())),
            (false, true, reason) => out.push(format!(
                "row [{}] gap closed, remove it from GAPS and make the class both: {}",
                row.name(),
                reason.unwrap_or("no reason listed")
            )),
            _ => {}
        }
    }
    out
}

#[sqlx::test]
async fn every_fact_matches_its_classification_on_every_surface(pool: PgPool) {
    let rendered = Box::pin(seed(pool)).await;
    let red = failures(&rendered);
    assert!(
        red.is_empty(),
        "{}\n--- cli\n{}",
        red.join("\n"),
        rendered.cli
    );
}

#[test]
fn the_gaps_table_lists_exactly_the_classified_absences() {
    for row in rows() {
        let absent = !row.class.expects(row.surface);
        assert_eq!(
            row.gap().is_some(),
            absent,
            "row [{}]: GAPS and class disagree",
            row.name()
        );
    }
    for (fact, surface, reason) in GAPS {
        assert!(
            rows()
                .iter()
                .any(|row| row.fact == *fact && row.surface == *surface),
            "GAPS names no row: {fact} on {surface}"
        );
        assert!(reason.contains(' '), "GAPS reason too short: {reason}");
    }
}

#[test]
fn every_class_has_a_fact() {
    for class in [Class::Both, Class::CliOnly, Class::WebOnly] {
        assert!(FACTS.iter().any(|(_, c)| *c == class), "{class:?}");
    }
    let mut names: Vec<&str> = FACTS.iter().map(|(name, _)| *name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), FACTS.len());
}

#[test]
fn a_blank_surface_turns_every_present_row_red() {
    let blank = Rendered::default();
    let green: Vec<String> = rows()
        .iter()
        .filter(|row| present(row.fact, &blank, row.surface))
        .map(Row::name)
        .collect();
    assert!(
        green.is_empty(),
        "rows that pass on blank output: {green:?}"
    );
}

#[sqlx::test]
async fn each_surface_fails_the_other_surfaces_checks(pool: PgPool) {
    let rendered = Box::pin(seed(pool)).await;
    let crossed = Rendered {
        cli: rendered.web,
        web: rendered.cli,
    };
    let green: Vec<String> = rows()
        .iter()
        .filter(|row| row.class.expects(row.surface))
        .filter(|row| present(row.fact, &crossed, row.surface))
        .map(Row::name)
        .collect();
    assert!(
        green.is_empty(),
        "rows that pass on the other surface: {green:?}"
    );
}

#[test]
fn the_fixture_carries_every_hostile_value_raw() {
    let lines = transcript_lines().join("\n");
    for needle in [
        r"\u001b[31m",
        r"\u202e",
        r"\u0000",
        r"\u001b]8;;",
        "<script>alert(1)</script>",
    ] {
        assert!(lines.contains(needle), "fixture lacks {needle}");
    }
    assert_eq!(HOSTILE.len(), 5);
    let hostile_rows = rows()
        .iter()
        .filter(|row| row.fact.starts_with("hostile."))
        .count();
    assert_eq!(hostile_rows, 2 * HOSTILE.len());
}

fn closing(fact: &str, surface: Surface) -> Option<Rendered> {
    let (cli, web) = match (fact, surface) {
        ("call.input", Surface::Cli) => ("{\"command\":\"ls\"}", ""),
        ("run.denials", Surface::Cli) => ("-- 1 denials --", ""),
        ("run.reason", Surface::Web) => (
            "",
            "<li id=\"tx-0\" data-kind=\"result\">Turns completed</li>",
        ),
        _ => return None,
    };
    Some(Rendered {
        cli: cli.to_owned(),
        web: web.to_owned(),
    })
}

#[test]
fn closing_a_gap_turns_its_row_red() {
    for (fact, surface, _) in GAPS {
        let rendered = closing(fact, *surface).unwrap();
        let marker = format!("row [{fact} on {surface}] gap closed");
        assert!(
            failures(&rendered)
                .iter()
                .any(|line| line.starts_with(&marker)),
            "closing {fact} on {surface} stays green"
        );
    }
}

fn unstripped(label: &str, body: &str) -> Rendered {
    Rendered {
        cli: format!("assistant: {label} {body} end"),
        web: format!("<li id=\"tx-0\" data-kind=\"message\"><pre>{label} {body} end</pre></li>"),
    }
}

#[test]
fn the_hostile_rows_reject_output_that_kept_the_hostile_value() {
    let kept = [
        ("hostile.ansi", "H-ansi", "red\u{1b}[31mX"),
        ("hostile.bidi", "H-bidi", "a\u{202e}b"),
        ("hostile.nul", "H-nul", "a\u{0}b"),
        ("hostile.osc", "H-osc", "\u{1b}]8;;x\u{7}link"),
    ];
    for (fact, label, body) in kept {
        let rendered = unstripped(label, body);
        for surface in SURFACES {
            assert!(
                !present(fact, &rendered, surface),
                "{fact} passes with the value kept on {surface}"
            );
        }
        let clean = unstripped(label, "ab");
        for surface in SURFACES {
            assert!(
                present(fact, &clean, surface),
                "{fact} fails on clean output on {surface}"
            );
        }
    }
    let raw = unstripped("H-markup", "<script>alert(1)</script>");
    assert!(!present("hostile.markup", &raw, Surface::Web));
    assert!(present("hostile.markup", &raw, Surface::Cli));
    let both = Rendered {
        cli: String::new(),
        web: format!(
            "{}<p>&lt;script&gt;alert(1)&lt;/script&gt; end</p>",
            unstripped("H-markup", "<script>alert(1)</script>").web
        ),
    };
    assert!(!present("hostile.markup", &both, Surface::Web));
}
