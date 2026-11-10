//! Parity of the job timing view across `fleet timing` text, `fleet timing --json` and the web
//! timing page, for one job seeded through the real `ClaimJob` and `ReportTiming` RPCs.
//!
//! The row table is generated from `FIELDS` and the command field list. A row asserts that one
//! field is present on one surface. A known gap is listed in `GAPS` with a reason, and its row
//! passes only while the field is still absent, so closing the gap turns the row red until the
//! entry is removed. The tests need a Postgres superuser URL in `DATABASE_URL` and live in their
//! own binary because they bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::{self, Write as _};
use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use fleet_cli::{Cli, run};
use fleet_core::timing::{
    CommandInput, CommandRow, FIELDS, Interval, MAX_COMMAND_CHARS, Span, SpanKind, Summary,
    TimingView, aggregate, human_duration_ms,
};
use fleet_proto::v1::fleet_jobs_client::FleetJobsClient;
use fleet_proto::v1::fleet_worker_client::FleetWorkerClient;
use fleet_proto::v1::{
    ClaimJobRequest, GetJobTimingRequest, ReportTimingRequest, ShellCommand, SubmitJobRequest,
    TimingSpan, TimingSpanKind, TimingSummary,
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
const WALL_MS: u64 = 20_000;
const AGENT_START_MS: u64 = 1_300;
const AGENT_END_MS: u64 = 18_200;

const GAP_START_TEXT: &str =
    "the plain form lists duration but not the command start; add a start column";
const GAP_END_TEXT: &str =
    "the plain form lists duration but not the command end; add an end column";
const GAP_END_JSON: &str = "the json command object has start_ms and duration_ms but no end_ms";

const GAPS: &[(&str, Surface, &str)] = &[
    ("command.start", Surface::CliText, GAP_START_TEXT),
    ("command.end", Surface::CliText, GAP_END_TEXT),
    ("command.end", Surface::CliJson, GAP_END_JSON),
];

const COMMAND_FIELDS: &[&str] = &[
    "command",
    "exit_code",
    "start",
    "end",
    "duration",
    "background",
    "ended_by",
    "log",
    "command_truncated",
    "log_truncated",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    CliText,
    CliJson,
    Web,
}

impl fmt::Display for Surface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CliText => "cli-text",
            Self::CliJson => "cli-json",
            Self::Web => "web",
        })
    }
}

const SURFACES: [Surface; 3] = [Surface::CliText, Surface::CliJson, Surface::Web];

#[derive(Debug, Clone, PartialEq, Eq)]
enum Subject {
    Part(&'static str),
    Total,
    Commands,
    Command(&'static str),
    Unknown(&'static str),
}

impl Subject {
    fn name(&self) -> String {
        match self {
            Self::Part(key) => format!("part.{key}"),
            Self::Total => "total".to_owned(),
            Self::Commands => "commands".to_owned(),
            Self::Command(field) => format!("command.{field}"),
            Self::Unknown(key) => format!("unknown.{key}"),
        }
    }
}

struct Row {
    subject: Subject,
    surface: Surface,
}

impl Row {
    fn name(&self) -> String {
        format!("{} on {}", self.subject.name(), self.surface)
    }

    fn gap(&self) -> Option<&'static str> {
        GAPS.iter()
            .find(|(name, surface, _)| *name == self.subject.name() && *surface == self.surface)
            .map(|(_, _, reason)| *reason)
    }
}

fn rows(view: &TimingView) -> Vec<Row> {
    let mut subjects = Vec::new();
    for field in FIELDS {
        subjects.push(match field.key {
            "total" => Subject::Total,
            "commands" => Subject::Commands,
            key if view.rows.iter().any(|row| row.key == key) => Subject::Part(field.key),
            _ => Subject::Unknown(field.key),
        });
    }
    for field in COMMAND_FIELDS {
        subjects.push(Subject::Command(field));
    }
    subjects
        .into_iter()
        .flat_map(|subject| {
            SURFACES.into_iter().map(move |surface| Row {
                subject: subject.clone(),
                surface,
            })
        })
        .collect()
}

#[derive(Default)]
struct Rendered {
    cli_text: String,
    cli_json: String,
    web: String,
}

struct Seeded {
    view: TimingView,
    reply_commands: Vec<ShellCommand>,
    sent_commands: Vec<ShellCommand>,
    sent_summary: Summary,
    rendered: Rendered,
}

fn label_of(key: &str) -> &'static str {
    FIELDS
        .iter()
        .find(|field| field.key == key)
        .map_or("", |field| field.label)
}

fn sent_commands() -> Vec<ShellCommand> {
    vec![
        ShellCommand {
            id: "cmd-one".to_owned(),
            command: "cargo build".to_owned(),
            background: false,
            started_ms: 8_000,
            ended_ms: Some(9_250),
            duration_ms: 1_250,
            exit_code: Some(3),
            log: "built ok\nline two".to_owned(),
            log_truncated: false,
            ended_by: None,
        },
        ShellCommand {
            id: "cmd-two".to_owned(),
            command: format!("echo {}", "x".repeat(MAX_COMMAND_CHARS + 44)),
            background: true,
            started_ms: 9_700,
            ended_ms: Some(13_100),
            duration_ms: 3_400,
            exit_code: Some(137),
            log: "tail of the log".to_owned(),
            log_truncated: true,
            ended_by: Some("operator-kill".to_owned()),
        },
    ]
}

const SPANS: [(SpanKind, TimingSpanKind, u64, u64); 4] = [
    (SpanKind::ApiWait, TimingSpanKind::Api, 1_300, 3_300),
    (SpanKind::Tool, TimingSpanKind::Tool, 4_000, 6_700),
    (SpanKind::Shell, TimingSpanKind::Shell, 8_000, 9_250),
    (SpanKind::BgShell, TimingSpanKind::BgShell, 9_700, 13_100),
];

fn core_summary() -> Summary {
    let spans: Vec<Span> = SPANS
        .iter()
        .map(|(kind, _, start, end)| Span {
            kind: *kind,
            interval: Interval::new(*start, *end).unwrap(),
        })
        .collect();
    aggregate(
        &spans,
        Interval::new(0, WALL_MS).unwrap(),
        Interval::new(AGENT_START_MS, AGENT_END_MS).unwrap(),
    )
}

fn wire_spans() -> Vec<TimingSpan> {
    SPANS
        .iter()
        .map(|(_, kind, start, end)| TimingSpan {
            kind: *kind as i32,
            start_ms: *start,
            end_ms: *end,
            name: "span".to_owned(),
            tool_use_id: None,
        })
        .collect()
}

fn inputs(commands: &[ShellCommand]) -> Vec<CommandInput> {
    commands
        .iter()
        .map(|c| CommandInput {
            command: c.command.clone(),
            duration_ms: c.duration_ms,
            start_ms: c.started_ms,
            exit: c.exit_code,
            truncated: false,
        })
        .collect()
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

async fn cli(url: &str, token: &str, job: &str, flags: &[&str]) -> String {
    let mut args = vec!["fleet", "--server", url, "timing", job];
    args.extend_from_slice(flags);
    let parsed = Cli::try_parse_from(args).unwrap();
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
async fn seed(pool: PgPool) -> Seeded {
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
                idempotency_key: "parity-timing".to_owned(),
                prompt: "task".to_owned(),
                repo: REPO.to_owned(),
                base_ref: "main".to_owned(),
                open_pr: false,
                agent: String::new(),
                profile: String::new(),
                environment: String::new(),
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

    let mut worker = FleetWorkerClient::new(channel.clone());
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
    let sent = sent_commands();
    let sent_summary = core_summary();
    worker
        .report_timing(bearer(
            BOX_TOKEN,
            Request::new(ReportTimingRequest {
                job_id: job.job_id.clone(),
                attempt: claimed.attempt,
                r#box: holder,
                summary: Some(TimingSummary {
                    wall_ms: WALL_MS,
                    api_wait_ms: sent_summary.api_wait_ms,
                    tool_ms: sent_summary.tool_ms,
                    shell_ms: sent_summary.shell_ms,
                    idle_ms: sent_summary.idle_ms,
                    overhead_ms: sent_summary.overhead_ms,
                }),
                spans: wire_spans(),
                shell_commands: sent.clone(),
                agent_start_ms: AGENT_START_MS,
                agent_end_ms: AGENT_END_MS,
            }),
        ))
        .await
        .unwrap();

    let reply = FleetJobsClient::new(channel)
        .get_job_timing(bearer(
            &api_token,
            Request::new(GetJobTimingRequest {
                job_id: job.job_id.clone(),
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let stored = reply.summary.unwrap();
    let summary = Summary {
        api_wait_ms: stored.api_wait_ms,
        tool_ms: stored.tool_ms,
        shell_ms: stored.shell_ms,
        idle_ms: stored.idle_ms,
        overhead_ms: stored.overhead_ms,
    };
    let view = TimingView::new(&summary, &inputs(&reply.shell_commands));
    let rendered = Rendered {
        cli_text: cli(&url, &api_token, &job.job_id, &["--commands"]).await,
        cli_json: cli(&url, &api_token, &job.job_id, &["--json"]).await,
        web: http_get(
            addr,
            &format!("/jobs/{}/timing", job.job_id),
            &format!("{SESSION_COOKIE}={session}"),
        )
        .await,
    };
    Seeded {
        view,
        reply_commands: reply.shell_commands,
        sent_commands: sent,
        sent_summary,
        rendered,
    }
}

fn need(found: bool, what: impl fmt::Display) -> Result<(), String> {
    if found {
        Ok(())
    } else {
        Err(format!("missing {what}"))
    }
}

fn json_escape(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn text_block<'a>(text: &'a str, id: &str) -> Vec<&'a str> {
    let prefix = format!("{id}\t");
    let mut lines = text.lines().skip_while(|line| !line.starts_with(&prefix));
    let mut block: Vec<&str> = lines.next().into_iter().collect();
    block.extend(lines.take_while(|line| line.starts_with("    ")));
    block
}

fn json_fragment<'a>(json: &'a str, id: &str) -> &'a str {
    let marker = format!("{{\"id\":\"{id}\"");
    let Some((_, rest)) = json.split_once(&marker) else {
        return "";
    };
    rest.split("{\"id\":\"").next().unwrap_or("")
}

fn web_blocks(page: &str) -> Vec<&str> {
    page.split("<tbody data-command=\"\">")
        .skip(1)
        .map(|block| block.split("</tbody>").next().unwrap_or(""))
        .collect()
}

fn web_cells(block: &str) -> Vec<String> {
    block
        .split("<td")
        .skip(1)
        .filter_map(|cell| {
            let (_, rest) = cell.split_once('>')?;
            Some(rest.split("</td>").next()?.trim().to_owned())
        })
        .collect()
}

fn web_part_row<'a>(page: &'a str, key: &str) -> &'a str {
    let marker = format!("<tr data-field=\"{key}\">");
    page.split_once(&marker)
        .and_then(|(_, rest)| rest.split("</tr>").next())
        .unwrap_or("")
}

fn part_check(
    seed: &Seeded,
    rendered: &Rendered,
    surface: Surface,
    key: &str,
) -> Result<(), String> {
    let Some(row) = seed.view.rows.iter().find(|row| row.key == key) else {
        return Err(format!("no view row for {key}"));
    };
    let label = label_of(key);
    match surface {
        Surface::CliText => need(
            rendered
                .cli_text
                .lines()
                .any(|line| line == format!("{label}\t{}ms\t{}", row.ms, row.percent_label())),
            format!("line {label} {}ms {}", row.ms, row.percent_label()),
        ),
        Surface::CliJson => need(
            rendered.cli_json.contains(&format!(
                "{{\"key\":\"{key}\",\"ms\":{},\"permille\":{}}}",
                row.ms, row.permille
            )),
            format!("part object {key} {} {}", row.ms, row.permille),
        ),
        Surface::Web => {
            let html = web_part_row(&rendered.web, key);
            need(
                html.contains(label)
                    && html.contains(&row.duration_label())
                    && html.contains(&row.percent_label()),
                format!(
                    "row {label} {} {}",
                    row.duration_label(),
                    row.percent_label()
                ),
            )
        }
    }
}

fn total_check(seed: &Seeded, rendered: &Rendered, surface: Surface) -> Result<(), String> {
    let total = seed.view.total_ms;
    match surface {
        Surface::CliText => need(
            rendered
                .cli_text
                .lines()
                .any(|line| line.starts_with(&format!("{}\t{total}ms\t", label_of("total")))),
            format!("total line {total}ms"),
        ),
        Surface::CliJson => need(
            rendered.cli_json.contains(&format!("\"total_ms\":{total}")),
            format!("total_ms {total}"),
        ),
        Surface::Web => {
            let html = web_part_row(&rendered.web, "total");
            need(
                html.contains(label_of("total")) && html.contains(&seed.view.total_label()),
                format!("total row {}", seed.view.total_label()),
            )
        }
    }
}

fn commands_check(seed: &Seeded, rendered: &Rendered, surface: Surface) -> Result<(), String> {
    let shown = seed.view.commands.len();
    let omitted = seed.view.commands_omitted;
    match surface {
        Surface::CliText => need(
            rendered.cli_text.lines().any(|line| {
                line == format!("{}: {shown} shown, {omitted} omitted", label_of("commands"))
            }),
            format!("commands line {shown} shown, {omitted} omitted"),
        ),
        Surface::CliJson => need(
            rendered.cli_json.contains("\"commands\":[")
                && rendered
                    .cli_json
                    .contains(&format!("\"commands_omitted\":{omitted}")),
            "commands array and commands_omitted",
        ),
        Surface::Web => {
            let html = web_part_row(&rendered.web, "commands");
            need(
                html.contains(label_of("commands"))
                    && html.contains(&format!(">{}<", shown + omitted)),
                format!("commands row {}", shown + omitted),
            )
        }
    }
}

fn exit_text(row: &CommandRow) -> String {
    row.exit.map_or_else(|| "-".to_owned(), |c| c.to_string())
}

fn command_check(
    seed: &Seeded,
    rendered: &Rendered,
    surface: Surface,
    field: &str,
) -> Result<(), String> {
    let blocks = web_blocks(&rendered.web);
    for (index, (row, cmd)) in seed
        .view
        .commands
        .iter()
        .zip(&seed.reply_commands)
        .enumerate()
    {
        let id = cmd.id.as_str();
        let outcome = match surface {
            Surface::CliText => {
                let block = text_block(&rendered.cli_text, id);
                let head = block.first().copied().unwrap_or("");
                let cells: Vec<&str> = head.split('\t').collect();
                let cell = |wanted: String| cells.contains(&wanted.as_str());
                match field {
                    "command" => cell(row.command.clone()),
                    "exit_code" => cell(exit_text(row)),
                    "start" => cell(format!("{}ms", row.start_ms)),
                    "end" => cmd.ended_ms.is_some_and(|end| cell(format!("{end}ms"))),
                    "duration" => cell(format!("{}ms", row.duration_ms)),
                    "background" => cell(if cmd.background { "bg" } else { "fg" }.to_owned()),
                    "ended_by" => cmd
                        .ended_by
                        .as_ref()
                        .is_none_or(|by| cell(format!("ended_by={by}"))),
                    "log" => cmd
                        .log
                        .lines()
                        .all(|line| block.contains(&format!("    | {line}").as_str())),
                    "command_truncated" => cell("(command cut)".to_owned()) == row.truncated,
                    "log_truncated" => block.contains(&"    -- log cut --") == cmd.log_truncated,
                    other => return Err(format!("no cli-text check for {other}")),
                }
            }
            Surface::CliJson => {
                let json = json_fragment(&rendered.cli_json, id);
                let has = |wanted: String| json.contains(&wanted);
                match field {
                    "command" => has(format!("\"command\":\"{}\"", json_escape(&row.command))),
                    "exit_code" => has(format!(
                        "\"exit_code\":{}",
                        row.exit
                            .map_or_else(|| "null".to_owned(), |c| c.to_string())
                    )),
                    "start" => has(format!("\"start_ms\":{}", row.start_ms)),
                    "end" => cmd
                        .ended_ms
                        .is_some_and(|end| has(format!("\"ended_ms\":{end}"))),
                    "duration" => has(format!("\"duration_ms\":{}", row.duration_ms)),
                    "background" => has(format!("\"background\":{}", cmd.background)),
                    "ended_by" => has(format!(
                        "\"ended_by\":{}",
                        cmd.ended_by.as_ref().map_or_else(
                            || "null".to_owned(),
                            |by| format!("\"{}\"", json_escape(by))
                        )
                    )),
                    "log" => has(format!("\"log\":\"{}\"", json_escape(&cmd.log))),
                    "command_truncated" => has(format!("\"truncated\":{}", row.truncated)),
                    "log_truncated" => has(format!("\"log_truncated\":{}", cmd.log_truncated)),
                    other => return Err(format!("no cli-json check for {other}")),
                }
            }
            Surface::Web => {
                let block = blocks.get(index).copied().unwrap_or("");
                let cells = web_cells(block);
                let cell = |wanted: String| cells.contains(&wanted);
                match field {
                    "command" => cells.first().is_some_and(|c| c.contains(&row.command)),
                    "exit_code" => cell(exit_text(row)),
                    "start" => cell(human_duration_ms(row.start_ms)),
                    "end" => cmd.ended_ms.is_some_and(|end| cell(human_duration_ms(end))),
                    "duration" => cell(human_duration_ms(row.duration_ms)),
                    "background" => cell(if cmd.background { "yes" } else { "no" }.to_owned()),
                    "ended_by" => cmd.ended_by.as_ref().is_none_or(|by| cell(by.clone())),
                    "log" => block.contains(&cmd.log),
                    "command_truncated" => {
                        block.contains("data-truncated=\"command\"") == row.truncated
                    }
                    "log_truncated" => {
                        block.contains("data-truncated=\"log\"") == cmd.log_truncated
                    }
                    other => return Err(format!("no web check for {other}")),
                }
            }
        };
        if !outcome {
            return Err(format!("command {id} lacks {field}"));
        }
    }
    need(!seed.view.commands.is_empty(), "any command row")
}

fn check(seed: &Seeded, rendered: &Rendered, row: &Row) -> Result<(), String> {
    match &row.subject {
        Subject::Part(key) => part_check(seed, rendered, row.surface, key),
        Subject::Total => total_check(seed, rendered, row.surface),
        Subject::Commands => commands_check(seed, rendered, row.surface),
        Subject::Command(field) => command_check(seed, rendered, row.surface, field),
        Subject::Unknown(key) => Err(format!("no parity check for the new FIELDS key {key}")),
    }
}

fn failures(seed: &Seeded, rendered: &Rendered) -> Vec<String> {
    let mut out = Vec::new();
    for row in rows(&seed.view) {
        let result = check(seed, rendered, &row);
        match (row.gap(), result) {
            (None, Err(why)) => out.push(format!("row [{}] red: {why}", row.name())),
            (Some(reason), Ok(())) => out.push(format!(
                "row [{}] gap closed, remove it from GAPS: {reason}",
                row.name()
            )),
            _ => {}
        }
    }
    out
}

#[sqlx::test]
async fn every_field_is_present_on_every_surface(pool: PgPool) {
    let seeded = Box::pin(seed(pool)).await;
    let red = failures(&seeded, &seeded.rendered);
    assert!(red.is_empty(), "{}", red.join("\n"));
}

#[sqlx::test]
async fn the_table_covers_every_fields_entry_and_command_field(pool: PgPool) {
    let seeded = Box::pin(seed(pool)).await;
    let table = rows(&seeded.view);
    let mut listed = String::new();
    for field in FIELDS {
        for surface in SURFACES {
            let covered = table.iter().any(|row| {
                row.surface == surface
                    && matches!(
                        &row.subject,
                        Subject::Part(key) | Subject::Unknown(key) if *key == field.key
                    )
                    || row.surface == surface
                        && row.subject == Subject::Total
                        && field.key == "total"
                    || row.surface == surface
                        && row.subject == Subject::Commands
                        && field.key == "commands"
            });
            let _ = write!(listed, "{}@{surface}={covered};", field.key);
            assert!(covered, "no row for FIELDS key {} on {surface}", field.key);
        }
    }
    for field in COMMAND_FIELDS {
        for surface in SURFACES {
            assert!(
                table
                    .iter()
                    .any(|row| row.surface == surface && row.subject == Subject::Command(field)),
                "no row for command field {field} on {surface}: {listed}"
            );
        }
    }
    assert!(
        table
            .iter()
            .all(|row| !matches!(row.subject, Subject::Unknown(_))),
        "a FIELDS key has no parity check"
    );
    let CommandRow {
        command: _,
        duration_ms: _,
        start_ms: _,
        exit: _,
        truncated: _,
    } = seeded.view.commands[0].clone();
    assert_eq!(COMMAND_FIELDS.len(), 10);
}

#[sqlx::test]
async fn a_blank_surface_turns_every_present_row_red(pool: PgPool) {
    let seeded = Box::pin(seed(pool)).await;
    let blank = Rendered::default();
    let green: Vec<String> = rows(&seeded.view)
        .iter()
        .filter(|row| row.gap().is_none())
        .filter(|row| check(&seeded, &blank, row).is_ok())
        .map(Row::name)
        .collect();
    assert!(
        green.is_empty(),
        "rows that pass on blank output: {green:?}"
    );
}

#[sqlx::test]
async fn the_seed_carries_a_value_for_every_field(pool: PgPool) {
    let seeded = Box::pin(seed(pool)).await;
    let s = seeded.sent_summary;
    let parts = [
        s.api_wait_ms,
        s.tool_ms,
        s.shell_ms,
        s.idle_ms,
        s.overhead_ms,
    ];
    assert!(parts.iter().all(|ms| *ms > 0), "{parts:?}");
    assert_eq!(seeded.view.rows.len(), parts.len());
    assert_eq!(seeded.view.total_ms, WALL_MS);
    assert_eq!(seeded.view.commands.len(), 2);
    assert_eq!(seeded.view.commands_omitted, 0);
    assert_eq!(seeded.reply_commands, seeded.sent_commands);
    let sent = &seeded.sent_commands;
    assert!(
        sent.iter()
            .all(|c| !c.command.is_empty() && !c.log.is_empty())
    );
    assert!(
        sent.iter()
            .all(|c| c.exit_code.is_some_and(|code| code != 0))
    );
    assert!(
        sent.iter()
            .all(|c| c.started_ms > 0 && c.ended_ms.is_some() && c.duration_ms > 0)
    );
    assert!(sent.iter().any(|c| c.background) && sent.iter().any(|c| !c.background));
    assert!(sent.iter().any(|c| c.ended_by.is_some()));
    assert!(sent.iter().any(|c| c.log_truncated) && sent.iter().any(|c| !c.log_truncated));
    let cut: Vec<bool> = seeded.view.commands.iter().map(|c| c.truncated).collect();
    assert_eq!(cut, [false, true]);
}
