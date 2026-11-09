//! Parity of retros, improvements, pitfalls and suggested edits between the `FleetRetro` and
//! `FleetEdit` RPC replies and the web review pages, for one project seeded through the real
//! RPCs.
//!
//! The retro and edit CLI (WRK-10) is a parallel lane, so the RPC reply is the reference
//! surface. A row asserts that one reply field appears on one web page. A known gap is listed
//! in `GAPS` with a reason and its row passes only while the field is still absent. Fields the
//! page shows in another form are listed in `NOT_COMPARED`. The tests need a Postgres
//! superuser URL in `DATABASE_URL` and live in their own binary because they bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::fleet_edit_client::FleetEditClient;
use fleet_proto::v1::fleet_retro_client::FleetRetroClient;
use fleet_proto::v1::fleet_work_client::FleetWorkClient;
use fleet_proto::v1::{
    AddWorkItemRequest, CreateWorkProjectRequest, DispositionImprovementRequest, EditKind,
    FileEditRequest, FileImprovementRequest, GetEditRequest, ImprovementDisposition,
    ImprovementKind, ListEditsReply, ListEditsRequest, ListImprovementsReply,
    ListImprovementsRequest, ListPitfallsReply, ListPitfallsRequest, ListRetrosReply,
    ListRetrosRequest, OpenRetroRequest, RecordPitfallRequest, SetWorkSlicesRequest, SuggestedEdit,
    WorkSlice,
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
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const CLIENT_TOKEN: &str = "client-token-0123456789abcdef012345";
const SESSION_SEED: char = 'a';
const PROJECT: &str = "parity-review";

const GAPS: &[(&str, &str)] = &[];

/// Reply fields the pages show in another form, so no row compares them yet: every timestamp
/// (the pages print a formatted time), `improvement.id`, `improvement.retro_id` and
/// `improvement.attempt_id` (not rendered), `improvement.kind` and `edit.kind` and
/// `edit.state` (the pages print a lowercase name, the reply an enum number), the retro state,
/// `edit.decided_by` and `edit.decided_at_ms` (not rendered), and every CLI rendering, since
/// the retro and edit commands land with WRK-10.
#[expect(dead_code, reason = "documents the fields no row compares")]
const NOT_COMPARED: &[&str] = &[
    "retro.opened_at_ms",
    "retro.closed_at_ms",
    "retro.state",
    "improvement.id",
    "improvement.retro_id",
    "improvement.attempt_id",
    "improvement.kind",
    "improvement.created_at_ms",
    "pitfall.id",
    "pitfall.created_at_ms",
    "pitfall.last_hit_at_ms",
    "edit.kind",
    "edit.state",
    "edit.decided_by",
    "edit.decided_at_ms",
    "edit.created_at_ms",
    "cli rendering",
];

struct Seeded {
    retros: ListRetrosReply,
    improvements: ListImprovementsReply,
    undecided: ListImprovementsReply,
    project_pitfalls: ListPitfallsReply,
    user_pitfalls: ListPitfallsReply,
    edits: ListEditsReply,
    edit: SuggestedEdit,
    pages: Pages,
}

struct Pages {
    retros: String,
    retro: String,
    verify: String,
    project_pitfalls: String,
    user_pitfalls: String,
    edits: String,
    edit: String,
}

struct Row {
    name: &'static str,
    page: fn(&Pages) -> &str,
    expected: fn(&Seeded) -> Vec<String>,
}

fn escaped(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn texts<T>(rows: &[T], field: fn(&T) -> String) -> Vec<String> {
    rows.iter().map(|row| escaped(&field(row))).collect()
}

const ROWS: &[Row] = &[
    Row {
        name: "retro.title",
        page: |p| &p.retros,
        expected: |s| texts(&s.retros.retros, |r| r.title.clone()),
    },
    Row {
        name: "retro.title.detail",
        page: |p| &p.retro,
        expected: |s| texts(&s.retros.retros, |r| r.title.clone()),
    },
    Row {
        name: "retro.span_from_item_key",
        page: |p| &p.retros,
        expected: |s| texts(&s.retros.retros, |r| r.span_from_item_key.clone().unwrap()),
    },
    Row {
        name: "retro.span_to_item_key",
        page: |p| &p.retros,
        expected: |s| texts(&s.retros.retros, |r| r.span_to_item_key.clone().unwrap()),
    },
    Row {
        name: "improvement.title",
        page: |p| &p.retro,
        expected: |s| texts(&s.improvements.improvements, |i| i.title.clone()),
    },
    Row {
        name: "improvement.vertical",
        page: |p| &p.retro,
        expected: |s| texts(&s.improvements.improvements, |i| i.vertical.clone()),
    },
    Row {
        name: "improvement.body",
        page: |p| &p.retro,
        expected: |s| texts(&s.improvements.improvements, |i| i.body.clone()),
    },
    Row {
        name: "improvement.disposition_reason",
        page: |p| &p.retro,
        expected: |s| {
            texts(&s.improvements.improvements, |i| {
                i.disposition_reason.clone().unwrap_or_default()
            })
        },
    },
    Row {
        name: "improvement.item_key",
        page: |p| &p.retro,
        expected: |s| {
            texts(&s.improvements.improvements, |i| {
                i.item_key.clone().unwrap_or_default()
            })
        },
    },
    Row {
        name: "improvement.undecided.title",
        page: |p| &p.verify,
        expected: |s| texts(&s.undecided.improvements, |i| i.title.clone()),
    },
    Row {
        name: "improvement.undecided.vertical",
        page: |p| &p.verify,
        expected: |s| texts(&s.undecided.improvements, |i| i.vertical.clone()),
    },
    Row {
        name: "pitfall.symptom.project",
        page: |p| &p.project_pitfalls,
        expected: |s| texts(&s.project_pitfalls.pitfalls, |x| x.symptom.clone()),
    },
    Row {
        name: "pitfall.cause.project",
        page: |p| &p.project_pitfalls,
        expected: |s| texts(&s.project_pitfalls.pitfalls, |x| x.cause.clone()),
    },
    Row {
        name: "pitfall.fix.project",
        page: |p| &p.project_pitfalls,
        expected: |s| texts(&s.project_pitfalls.pitfalls, |x| x.fix.clone()),
    },
    Row {
        name: "pitfall.symptom.user",
        page: |p| &p.user_pitfalls,
        expected: |s| texts(&s.user_pitfalls.pitfalls, |x| x.symptom.clone()),
    },
    Row {
        name: "pitfall.cause.user",
        page: |p| &p.user_pitfalls,
        expected: |s| texts(&s.user_pitfalls.pitfalls, |x| x.cause.clone()),
    },
    Row {
        name: "pitfall.fix.user",
        page: |p| &p.user_pitfalls,
        expected: |s| texts(&s.user_pitfalls.pitfalls, |x| x.fix.clone()),
    },
    Row {
        name: "edit.target",
        page: |p| &p.edits,
        expected: |s| texts(&s.edits.edits, |e| e.target.clone()),
    },
    Row {
        name: "edit.filed_by",
        page: |p| &p.edits,
        expected: |s| texts(&s.edits.edits, |e| e.filed_by.clone()),
    },
    Row {
        name: "edit.target.detail",
        page: |p| &p.edit,
        expected: |s| vec![escaped(&s.edit.target)],
    },
    Row {
        name: "edit.filed_by.detail",
        page: |p| &p.edit,
        expected: |s| vec![escaped(&s.edit.filed_by)],
    },
    Row {
        name: "edit.payload",
        page: |p| &p.edit,
        expected: |s| vec![escaped(&s.edit.payload)],
    },
    Row {
        name: "edit.base_hash",
        page: |p| &p.edit,
        expected: |s| vec![escaped(&s.edit.base_hash)],
    },
];

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
    assert!(head.starts_with("HTTP/1.1 200"), "{path}: {head}");
    body.to_owned()
}

async fn start(pool: PgPool) -> (SocketAddr, String, String) {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let alice: i64 =
        sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
            .fetch_one(&pool)
            .await
            .unwrap();
    let made = users.create_api_token(alice, "cli").await.unwrap();
    let token = String::from_utf8(made.token.expose().to_vec()).unwrap();
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
    (addr, token, format!("{SESSION_COOKIE}={session}"))
}

async fn structure(client: &mut FleetWorkClient<tonic::transport::Channel>, token: &str) {
    client
        .create_work_project(bearer(
            token,
            Request::new(CreateWorkProjectRequest {
                key: "p1".to_owned(),
                name: PROJECT.to_owned(),
                repo: None,
            }),
        ))
        .await
        .unwrap();
    client
        .set_work_slices(bearer(
            token,
            Request::new(SetWorkSlicesRequest {
                key: "p2".to_owned(),
                project: PROJECT.to_owned(),
                slices: vec![WorkSlice {
                    name: "api".to_owned(),
                    paths: vec!["src/api".to_owned()],
                }],
                mergeable: vec![],
            }),
        ))
        .await
        .unwrap();
    for (n, item_key) in [("p3", "first-item"), ("p4", "last-item")] {
        client
            .add_work_item(bearer(
                token,
                Request::new(AddWorkItemRequest {
                    key: n.to_owned(),
                    project: PROJECT.to_owned(),
                    item_key: item_key.to_owned(),
                    title: format!("{item_key} title"),
                    body: "body".to_owned(),
                    slices: vec!["api".to_owned()],
                    deps: vec![],
                }),
            ))
            .await
            .unwrap();
    }
}

async fn retro_rows(client: &mut FleetRetroClient<tonic::transport::Channel>, token: &str) {
    let retro = client
        .open_retro(bearer(
            token,
            Request::new(OpenRetroRequest {
                key: "r1".to_owned(),
                project: PROJECT.to_owned(),
                title: "Sprint parity".to_owned(),
                span_from_item_key: Some("first-item".to_owned()),
                span_to_item_key: Some("last-item".to_owned()),
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let mut ids = Vec::new();
    for (n, vertical, title, body, kind) in [
        (
            "r2",
            "server",
            "Cache the plan",
            "Plans are rebuilt per call",
            ImprovementKind::Tooling,
        ),
        (
            "r3",
            "web",
            "Name the retro columns",
            "Columns are unclear",
            ImprovementKind::Docs,
        ),
    ] {
        let made = client
            .file_improvement(bearer(
                token,
                Request::new(FileImprovementRequest {
                    key: n.to_owned(),
                    project: PROJECT.to_owned(),
                    retro_id: Some(retro.id),
                    item_key: Some("first-item".to_owned()),
                    attempt_id: None,
                    vertical: vertical.to_owned(),
                    title: title.to_owned(),
                    body: body.to_owned(),
                    kind: kind.into(),
                }),
            ))
            .await
            .unwrap()
            .into_inner();
        ids.push(made.id);
    }
    client
        .disposition_improvement(bearer(
            token,
            Request::new(DispositionImprovementRequest {
                key: "r4".to_owned(),
                project: PROJECT.to_owned(),
                improvement_id: *ids.first().unwrap(),
                disposition: ImprovementDisposition::Deferred.into(),
                reason: "after the launch".to_owned(),
            }),
        ))
        .await
        .unwrap();
    for (n, project, symptom, cause, fix) in [
        (
            "r5",
            Some(PROJECT.to_owned()),
            "project symptom",
            "project cause",
            "project fix",
        ),
        ("r6", None, "user symptom", "user cause", "user fix"),
    ] {
        client
            .record_pitfall(bearer(
                token,
                Request::new(RecordPitfallRequest {
                    key: n.to_owned(),
                    project,
                    symptom: symptom.to_owned(),
                    cause: cause.to_owned(),
                    fix: fix.to_owned(),
                }),
            ))
            .await
            .unwrap();
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one linear seed through every read RPC"
)]
async fn seed(pool: PgPool) -> Seeded {
    let (addr, token, cookie) = start(pool).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    structure(&mut FleetWorkClient::new(channel.clone()), &token).await;
    let mut retro = FleetRetroClient::new(channel.clone());
    let mut edit = FleetEditClient::new(channel);
    retro_rows(&mut retro, &token).await;
    let filed = edit
        .file_edit(bearer(
            &token,
            Request::new(FileEditRequest {
                key: "e1".to_owned(),
                project: PROJECT.to_owned(),
                kind: EditKind::SliceOp.into(),
                target: "api".to_owned(),
                base_hash: String::new(),
                payload: "add-path\tsrc/extra".to_owned(),
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let retros = retro
        .list_retros(bearer(
            &token,
            Request::new(ListRetrosRequest {
                project: PROJECT.to_owned(),
                state: None,
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let retro_id = retros.retros.first().unwrap().id;
    let improvements_of = |undecided: Option<bool>| {
        bearer(
            &token,
            Request::new(ListImprovementsRequest {
                project: PROJECT.to_owned(),
                vertical: None,
                retro_id: Some(retro_id),
                undecided,
            }),
        )
    };
    let improvements = retro
        .list_improvements(improvements_of(None))
        .await
        .unwrap()
        .into_inner();
    let undecided = retro
        .list_improvements(improvements_of(Some(true)))
        .await
        .unwrap()
        .into_inner();
    let project_pitfalls = retro
        .list_pitfalls(bearer(
            &token,
            Request::new(ListPitfallsRequest {
                project: Some(PROJECT.to_owned()),
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let user_pitfalls = retro
        .list_pitfalls(bearer(
            &token,
            Request::new(ListPitfallsRequest { project: None }),
        ))
        .await
        .unwrap()
        .into_inner();
    let edits = edit
        .list_edits(bearer(
            &token,
            Request::new(ListEditsRequest {
                project: PROJECT.to_owned(),
                state: None,
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let got = edit
        .get_edit(bearer(
            &token,
            Request::new(GetEditRequest {
                project: PROJECT.to_owned(),
                id: filed.id,
            }),
        ))
        .await
        .unwrap()
        .into_inner();

    let base = format!("/work/{PROJECT}");
    let pages = Pages {
        retros: http_get(addr, &format!("{base}/retros"), &cookie).await,
        retro: http_get(addr, &format!("{base}/retros/{retro_id}"), &cookie).await,
        verify: http_get(addr, &format!("{base}/retros/{retro_id}/verify"), &cookie).await,
        project_pitfalls: http_get(addr, &format!("{base}/pitfalls"), &cookie).await,
        user_pitfalls: http_get(addr, "/pitfalls", &cookie).await,
        edits: http_get(addr, &format!("{base}/edits"), &cookie).await,
        edit: http_get(addr, &format!("{base}/edits/{}", filed.id), &cookie).await,
    };
    Seeded {
        retros,
        improvements,
        undecided,
        project_pitfalls,
        user_pitfalls,
        edits,
        edit: got,
        pages,
    }
}

fn present(row: &Row, seed: &Seeded) -> Vec<String> {
    (row.expected)(seed)
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect()
}

fn failures(seed: &Seeded, pages: &Pages) -> Vec<String> {
    let mut failed = Vec::new();
    for row in ROWS {
        if GAPS.iter().any(|(name, _)| *name == row.name) {
            continue;
        }
        let expected = present(row, seed);
        if expected.is_empty() {
            failed.push(format!("{}: the seed holds no value", row.name));
        }
        let page = (row.page)(pages);
        for value in expected {
            if !page.contains(&value) {
                failed.push(format!("{}: page lacks {value:?}", row.name));
            }
        }
    }
    failed
}

#[sqlx::test]
async fn every_reply_field_is_present_on_its_web_page(pool: PgPool) {
    let seed = seed(pool).await;
    let failed = failures(&seed, &seed.pages);
    assert!(failed.is_empty(), "{failed:#?}");
}

#[sqlx::test]
async fn a_blank_page_turns_every_row_red(pool: PgPool) {
    let seed = seed(pool).await;
    let blank = Pages {
        retros: String::new(),
        retro: String::new(),
        verify: String::new(),
        project_pitfalls: String::new(),
        user_pitfalls: String::new(),
        edits: String::new(),
        edit: String::new(),
    };
    let failed = failures(&seed, &blank);
    for row in ROWS {
        assert!(
            failed.iter().any(|line| line.starts_with(row.name)),
            "{} stayed green on a blank page",
            row.name
        );
    }
}

#[sqlx::test]
async fn the_seed_carries_a_value_for_every_row(pool: PgPool) {
    let seed = seed(pool).await;
    for row in ROWS {
        assert!(!present(row, &seed).is_empty(), "{}", row.name);
    }
}
