//! Parity of the work tracker between the `FleetWork` RPC replies and the web work pages, for
//! one project seeded through the real RPCs.
//!
//! The CLI has no `work` command yet, so the RPC reply is the reference surface. A row asserts
//! that one reply field appears on one web page. A known gap is listed in `GAPS` with a reason
//! and its row passes only while the field is still absent. The tests need a Postgres superuser
//! URL in `DATABASE_URL` and live in their own binary because they bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::fleet_work_client::FleetWorkClient;
use fleet_proto::v1::{
    AddWorkItemRequest, AddWorkNoteRequest, ClaimWorkRequest, CreateWorkProjectRequest,
    GetWorkItemReply, GetWorkItemRequest, ListWorkDefersReply, ListWorkDefersRequest,
    RecordWorkDeferRequest, ReportAttemptRequest, SetWorkSlicesRequest, WorkDep, WorkSlice,
    WorkVerdict,
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
const PROJECT: &str = "parity-plan";

const GAPS: &[(&str, &str)] = &[];

struct Seeded {
    item: GetWorkItemReply,
    defers: ListWorkDefersReply,
    pages: Pages,
}

struct Pages {
    board: String,
    graph: String,
    locks: String,
    item: String,
    defers: String,
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

fn item(seed: &Seeded) -> &fleet_proto::v1::WorkItem {
    seed.item.item.as_ref().unwrap()
}

const ROWS: &[Row] = &[
    Row {
        name: "item.key",
        page: |p| &p.board,
        expected: |s| vec![escaped(&item(s).key)],
    },
    Row {
        name: "item.title",
        page: |p| &p.board,
        expected: |s| vec![escaped(&item(s).title)],
    },
    Row {
        name: "item.deps.depends_on",
        page: |p| &p.graph,
        expected: |s| {
            item(s)
                .deps
                .iter()
                .map(|d| escaped(&d.depends_on))
                .collect()
        },
    },
    Row {
        name: "item.deps.why",
        page: |p| &p.graph,
        expected: |s| item(s).deps.iter().map(|d| escaped(&d.why)).collect(),
    },
    Row {
        name: "item.slices",
        page: |p| &p.item,
        expected: |s| item(s).slices.iter().map(|n| escaped(n)).collect(),
    },
    Row {
        name: "item.body",
        page: |p| &p.item,
        expected: |s| vec![escaped(&item(s).body)],
    },
    Row {
        name: "attempt.holder",
        page: |p| &p.locks,
        expected: |s| s.item.attempts.iter().map(|a| escaped(&a.holder)).collect(),
    },
    Row {
        name: "attempt.holder.timeline",
        page: |p| &p.item,
        expected: |s| s.item.attempts.iter().map(|a| escaped(&a.holder)).collect(),
    },
    Row {
        name: "attempt.note",
        page: |p| &p.item,
        expected: |s| s.item.attempts.iter().map(|a| escaped(&a.note)).collect(),
    },
    Row {
        name: "attempt.evidence_tail",
        page: |p| &p.item,
        expected: |s| {
            s.item
                .attempts
                .iter()
                .map(|a| escaped(&a.evidence_tail))
                .collect()
        },
    },
    Row {
        name: "event.note",
        page: |p| &p.item,
        expected: |s| s.item.events.iter().map(|e| escaped(&e.note)).collect(),
    },
    Row {
        name: "event.kind",
        page: |p| &p.item,
        expected: |s| s.item.events.iter().map(|e| escaped(&e.kind)).collect(),
    },
    Row {
        name: "defer.title",
        page: |p| &p.defers,
        expected: |s| s.defers.defers.iter().map(|d| escaped(&d.title)).collect(),
    },
    Row {
        name: "defer.reason",
        page: |p| &p.defers,
        expected: |s| s.defers.defers.iter().map(|d| escaped(&d.reason)).collect(),
    },
    Row {
        name: "defer.vertical",
        page: |p| &p.defers,
        expected: |s| {
            s.defers
                .defers
                .iter()
                .map(|d| escaped(&d.vertical))
                .collect()
        },
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

type Client = FleetWorkClient<tonic::transport::Channel>;

async fn structure(client: &mut Client, token: &str) {
    let key = |n: &str| n.to_owned();
    let token = token.to_owned();

    client
        .create_work_project(bearer(
            &token,
            Request::new(CreateWorkProjectRequest {
                key: key("p1"),
                name: PROJECT.to_owned(),
                repo: None,
            }),
        ))
        .await
        .unwrap();
    client
        .set_work_slices(bearer(
            &token,
            Request::new(SetWorkSlicesRequest {
                key: key("p2"),
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
    for (n, item_key, title, body, deps) in [
        ("p3", "base", "Base title", "Base body", vec![]),
        (
            "p4",
            "top",
            "Top title",
            "Top body text",
            vec![WorkDep {
                depends_on: "base".to_owned(),
                why: "needs the base".to_owned(),
            }],
        ),
    ] {
        client
            .add_work_item(bearer(
                &token,
                Request::new(AddWorkItemRequest {
                    key: key(n),
                    project: PROJECT.to_owned(),
                    item_key: item_key.to_owned(),
                    title: title.to_owned(),
                    body: body.to_owned(),
                    slices: vec!["api".to_owned()],
                    deps,
                }),
            ))
            .await
            .unwrap();
    }
}

async fn activity(client: &mut Client, token: &str) {
    let key = |n: &str| n.to_owned();
    let token = token.to_owned();
    let attempt = client
        .claim_work(bearer(
            &token,
            Request::new(ClaimWorkRequest {
                key: key("p5"),
                project: PROJECT.to_owned(),
                item_key: "base".to_owned(),
                holder: "worker-parity".to_owned(),
                ttl_secs: 600,
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    client
        .add_work_note(bearer(
            &token,
            Request::new(AddWorkNoteRequest {
                key: key("p6"),
                project: PROJECT.to_owned(),
                item_key: "base".to_owned(),
                note: "halfway there".to_owned(),
            }),
        ))
        .await
        .unwrap();
    client
        .record_work_defer(bearer(
            &token,
            Request::new(RecordWorkDeferRequest {
                key: key("p7"),
                project: PROJECT.to_owned(),
                item_key: Some("base".to_owned()),
                attempt_id: Some(attempt.id),
                title: "Later title".to_owned(),
                reason: "Later reason".to_owned(),
                vertical: "server".to_owned(),
            }),
        ))
        .await
        .unwrap();
    client
        .report_attempt(bearer(
            &token,
            Request::new(ReportAttemptRequest {
                key: key("p8"),
                project: PROJECT.to_owned(),
                attempt_id: attempt.id,
                verdict: WorkVerdict::Fail.into(),
                note: "first try failed".to_owned(),
                evidence_tail: "tail of the log".to_owned(),
            }),
        ))
        .await
        .unwrap();
    let reclaim = client
        .claim_work(bearer(
            &token,
            Request::new(ClaimWorkRequest {
                key: key("p9"),
                project: PROJECT.to_owned(),
                item_key: "base".to_owned(),
                holder: "worker-parity".to_owned(),
                ttl_secs: 600,
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    assert_ne!(reclaim.id, attempt.id);
}

async fn seed(pool: PgPool) -> Seeded {
    let (addr, token, cookie) = start(pool).await;
    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect_lazy();
    let mut client = FleetWorkClient::new(channel);
    structure(&mut client, &token).await;
    activity(&mut client, &token).await;
    let item = client
        .get_work_item(bearer(
            &token,
            Request::new(GetWorkItemRequest {
                project: PROJECT.to_owned(),
                item_key: "base".to_owned(),
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let top = client
        .get_work_item(bearer(
            &token,
            Request::new(GetWorkItemRequest {
                project: PROJECT.to_owned(),
                item_key: "top".to_owned(),
            }),
        ))
        .await
        .unwrap()
        .into_inner();
    let defers = client
        .list_work_defers(bearer(
            &token,
            Request::new(ListWorkDefersRequest {
                project: PROJECT.to_owned(),
                vertical: None,
                state: None,
            }),
        ))
        .await
        .unwrap()
        .into_inner();

    let base = format!("/work/{PROJECT}");
    let mut item = item;
    item.item.as_mut().unwrap().deps = top.item.unwrap().deps;
    let pages = Pages {
        board: http_get(addr, &base, &cookie).await,
        graph: http_get(addr, &format!("{base}/graph"), &cookie).await,
        locks: http_get(addr, &format!("{base}/locks"), &cookie).await,
        item: http_get(addr, &format!("{base}/items/base"), &cookie).await,
        defers: http_get(addr, &format!("{base}/defers"), &cookie).await,
    };
    Seeded {
        item,
        defers,
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
        board: String::new(),
        graph: String::new(),
        locks: String::new(),
        item: String::new(),
        defers: String::new(),
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
