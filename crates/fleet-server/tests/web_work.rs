//! The work tracker pages over HTTP: session gate, owner scope, board, dependency graph,
//! slice-lock view, item timeline, defers by vertical, accessible markup and escaped text.
//!
//! Rows are seeded with raw SQL so a stored value can hold text the RPCs refuse, which is the
//! case the escaping must survive. The tests need a Postgres superuser URL in `DATABASE_URL`
//! and live in their own binary because they bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";

const HOSTILE: [(&str, &str); 7] = [
    ("script", "<script>alert(1)</script>"),
    ("attr", "\"><img src=x onerror=alert(1)>"),
    ("jsurl", "javascript:alert(1)"),
    ("crlf", "line\r\nSet-Cookie: a=b"),
    ("nel", "a\u{85}b"),
    ("separator", "a\u{2028}b\u{2029}c"),
    ("bidi", "a\u{202e}evil\u{202c}b"),
];

const FORBIDDEN_CHARS: [char; 7] = [
    '\r', '\u{85}', '\u{2028}', '\u{2029}', '\u{202e}', '\u{202c}', '\0',
];

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn header(&self, name: &str) -> String {
        self.head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case(name)
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_default()
    }
}

struct Session {
    cookie: String,
    user_id: i64,
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn own_script_removed(body: &str) -> String {
    body.replace("<script src=\"/static/navfocus.js\"", "")
}

fn enc(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

struct Ids {
    project: i64,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let web = Web::with_console(auth, None, store.clone());
        let bearer = BearerAuth::new(
            &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            serve_with_web(&store, &bearer, web, TcpIncoming::from(listener), async {
                let _ = rx.await;
            })
            .await
        });
        Self {
            addr,
            pool,
            stop: Some(stop),
            task,
        }
    }

    async fn session(&self, name: &str, seed: char) -> Session {
        let user_id: i64 =
            sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
                .bind(name)
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let id = seed.to_string().repeat(64);
        sqlx::query(
            "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
             VALUES (sha256($1::bytea), $2, 'csrf-token', now() + interval '1 hour')",
        )
        .bind(id.as_bytes())
        .bind(user_id)
        .execute(&self.pool)
        .await
        .unwrap();
        Session {
            cookie: format!("{SESSION_COOKIE}={id}"),
            user_id,
        }
    }

    async fn project(&self, who: &Session, name: &str) -> Ids {
        let project: i64 = sqlx::query_scalar(
            "INSERT INTO work_project (user_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(who.user_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        Ids { project }
    }

    async fn slice(&self, ids: &Ids, name: &str, paths: &[&str]) -> i64 {
        let slice: i64 = sqlx::query_scalar(
            "INSERT INTO work_slice (project_id, name) VALUES ($1, $2) RETURNING id",
        )
        .bind(ids.project)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        for path in paths {
            sqlx::query("INSERT INTO work_slice_path (slice_id, path) VALUES ($1, $2)")
                .bind(slice)
                .bind(path)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        slice
    }

    async fn mergeable(&self, ids: &Ids, path: &str) {
        sqlx::query("INSERT INTO work_mergeable_path (project_id, path) VALUES ($1, $2)")
            .bind(ids.project)
            .bind(path)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn item(&self, ids: &Ids, key: &str, title: &str, body: &str, state: &str) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO work_item (project_id, key, title, body, state) \
             VALUES ($1, $2, $3, $4, $5) RETURNING id",
        )
        .bind(ids.project)
        .bind(key)
        .bind(title)
        .bind(body)
        .bind(state)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn member(&self, ids: &Ids, item: i64, slice: i64) {
        sqlx::query(
            "INSERT INTO work_item_slice (project_id, item_id, slice_id) VALUES ($1, $2, $3)",
        )
        .bind(ids.project)
        .bind(item)
        .bind(slice)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn dep(&self, ids: &Ids, item: i64, on: i64, why: &str) {
        sqlx::query(
            "INSERT INTO work_dep (project_id, item_id, depends_on_id, why) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(ids.project)
        .bind(item)
        .bind(on)
        .bind(why)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn attempt(
        &self,
        ids: &Ids,
        item: i64,
        holder: &str,
        close: Option<(&str, &str, &str)>,
    ) -> i64 {
        let (verdict, note, evidence) = match close {
            Some((verdict, note, evidence)) => (Some(verdict), Some(note), Some(evidence)),
            None => (None, None, None),
        };
        sqlx::query_scalar(
            "INSERT INTO work_attempt (project_id, item_id, holder, expires_at, verdict, note, \
             evidence, closed_at) VALUES ($1, $2, $3, now() + interval '1 hour', $4, $5, \
             CASE WHEN $4::text IN ('pass', 'fail') THEN $6::text END, \
             CASE WHEN $4::text IS NULL THEN NULL ELSE now() END) RETURNING id",
        )
        .bind(ids.project)
        .bind(item)
        .bind(holder)
        .bind(verdict)
        .bind(note)
        .bind(evidence)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn lease(&self, ids: &Ids, slice: i64, attempt: i64) {
        sqlx::query(
            "INSERT INTO work_slice_lease (slice_id, project_id, attempt_id) VALUES ($1, $2, $3)",
        )
        .bind(slice)
        .bind(ids.project)
        .bind(attempt)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn event(
        &self,
        ids: &Ids,
        item: i64,
        attempt: Option<i64>,
        kind: &str,
        actor: &str,
        note: &str,
    ) {
        sqlx::query(
            "INSERT INTO work_event (project_id, item_id, attempt_id, kind, actor, note) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(ids.project)
        .bind(item)
        .bind(attempt)
        .bind(kind)
        .bind(actor)
        .bind(note)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn defer(&self, ids: &Ids, item: Option<i64>, text: (&str, &str, &str), state: &str) {
        sqlx::query(
            "INSERT INTO work_defer (project_id, item_id, title, reason, vertical, state) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(ids.project)
        .bind(item)
        .bind(text.0)
        .bind(text.1)
        .bind(text.2)
        .bind(state)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn get(&self, who: Option<&Session>, path: &str) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\n"
        );
        if let Some(who) = who {
            let _ = write!(request, "Cookie: {}\r\n", who.cookie);
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap()
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        Reply {
            status: head.split(' ').nth(1).unwrap().parse().unwrap(),
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    async fn finish(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(WAIT, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

fn page_paths(project: &str, item: &str) -> [(&'static str, String); 6] {
    let p = enc(project);
    [
        ("projects", "/work".to_owned()),
        ("board", format!("/work/{p}")),
        ("graph", format!("/work/{p}/graph")),
        ("locks", format!("/work/{p}/locks")),
        ("defers", format!("/work/{p}/defers")),
        ("item", format!("/work/{p}/items/{}", enc(item))),
    ]
}

fn section<'a>(body: &'a str, marker: &str) -> &'a str {
    assert!(body.contains(marker), "{marker} missing in {body}");
    let start = body.find(marker).unwrap();
    let rest = &body[start + marker.len()..];
    let end = rest.find("data-section=").unwrap_or(rest.len());
    &rest[..end]
}

struct Fixture {
    alice: Session,
}

async fn fixture(h: &Harness) -> Fixture {
    let alice = h.session("alice", 'a').await;
    let ids = h.project(&alice, "alpha-plan").await;
    let api = h.slice(&ids, "api", &["src/api"]).await;
    let web = h.slice(&ids, "web", &["src/web", "assets"]).await;
    h.slice(&ids, "free", &["docs"]).await;
    h.mergeable(&ids, "Cargo.lock").await;
    let ready = h.item(&ids, "ready-one", "Ready title", "", "open").await;
    let held = h.item(&ids, "held-one", "Held title", "", "open").await;
    let done = h.item(&ids, "done-one", "Done title", "", "open").await;
    let waiting = h
        .item(&ids, "waiting-one", "Waiting title", "", "open")
        .await;
    let blocked = h
        .item(&ids, "blocked-one", "Blocked title", "", "blocked")
        .await;
    let cancelled = h
        .item(&ids, "cancelled-one", "Cancelled title", "", "cancelled")
        .await;
    h.member(&ids, held, api).await;
    h.member(&ids, held, web).await;
    h.dep(&ids, waiting, held, "needs the held api").await;
    h.dep(&ids, ready, done, "builds on done").await;
    let open = h.attempt(&ids, held, "worker-a", None).await;
    h.lease(&ids, api, open).await;
    h.lease(&ids, web, open).await;
    h.attempt(
        &ids,
        done,
        "worker-b",
        Some(("pass", "all green", "tests passed")),
    )
    .await;
    h.event(&ids, held, Some(open), "claimed", "worker-a", "taking it")
        .await;
    h.event(&ids, held, None, "note", "user 1", "halfway").await;
    h.defer(
        &ids,
        Some(held),
        ("Later title", "Later reason", "server"),
        "open",
    )
    .await;
    h.defer(
        &ids,
        None,
        ("Other title", "Other reason", "cli"),
        "dropped",
    )
    .await;
    let _ = (blocked, cancelled);
    Fixture { alice }
}

#[sqlx::test]
async fn every_work_page_needs_a_session(pool: PgPool) {
    let h = Harness::start(pool).await;
    for (name, path) in page_paths("alpha-plan", "ready-one") {
        let reply = h.get(None, &path).await;
        assert_eq!(reply.status, 303, "{name}");
        assert_eq!(reply.header("location"), "/login", "{name}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_foreign_and_an_unknown_project_answer_the_same_not_found(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let bob = h.session("bob", 'b').await;
    h.project(&bob, "bobs-plan").await;
    for (name, path) in page_paths("alpha-plan", "ready-one").into_iter().skip(1) {
        let own = h.get(Some(&fx.alice), &path).await;
        assert_eq!(own.status, 200, "{name}");
        let foreign = h.get(Some(&bob), &path).await;
        let unknown = h
            .get(Some(&bob), &path.replacen("alpha-plan", "nothing", 1))
            .await;
        assert_eq!(foreign.status, 404, "{name}");
        assert_eq!(unknown.status, 404, "{name}");
        assert_eq!(foreign.body, unknown.body, "{name}");
        assert!(!foreign.body.contains("alpha-plan"), "{name}");
    }
    let list = h.get(Some(&bob), "/work").await;
    assert_eq!(list.status, 200);
    assert!(list.body.contains("bobs-plan"));
    assert!(!list.body.contains("alpha-plan"));
    let missing = h.get(Some(&fx.alice), "/work/alpha-plan/items/nope").await;
    let foreign_item = h.get(Some(&bob), "/work/bobs-plan/items/ready-one").await;
    assert_eq!(missing.status, 404);
    assert_eq!(foreign_item.status, 404);
    assert_eq!(missing.body, foreign_item.body);
    let long = "x".repeat(200);
    for bad in ["%3Cscript%3E", "%0D%0A", "%00", "%E2%80%AE", long.as_str()] {
        let reply = h.get(Some(&bob), &format!("/work/{bad}")).await;
        assert_eq!(reply.status, 404, "{bad}");
        assert_eq!(reply.body, missing.body, "{bad}");
    }
    h.finish().await;
}

fn row<'a>(body: &'a str, attr: &str) -> &'a str {
    assert!(body.contains(attr), "{attr} missing in {body}");
    let start = body.find(attr).unwrap();
    let rest = &body[start..];
    &rest[..rest.find("</tr>").unwrap_or(rest.len())]
}

#[sqlx::test]
async fn the_board_groups_items_by_state(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let page = h.get(Some(&fx.alice), "/work/alpha-plan").await;
    assert_eq!(page.status, 200);
    let columns = [
        ("ready", "ready-one"),
        ("held", "held-one"),
        ("waiting", "waiting-one"),
        ("done", "done-one"),
        ("blocked", "blocked-one"),
        ("cancelled", "cancelled-one"),
    ];
    for (column, key) in columns {
        let body = section(&page.body, &format!("data-section=\"{column}\""));
        assert!(body.contains(key), "{column} lacks {key}: {body}");
        for (_, other) in columns.iter().filter(|(c, _)| *c != column) {
            assert!(!body.contains(other), "{column} holds {other}");
        }
    }
    assert!(
        page.body
            .contains("href=\"/work/alpha-plan/items/ready-one\"")
    );
    assert!(page.body.contains("Ready title"));
    h.finish().await;
}

#[sqlx::test]
async fn the_graph_lists_each_edge_with_its_reason(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let page = h.get(Some(&fx.alice), "/work/alpha-plan/graph").await;
    assert_eq!(page.status, 200);
    let waiting = row(&page.body, "data-item=\"waiting-one\"");
    assert!(waiting.contains("held-one"), "{waiting}");
    assert!(waiting.contains("needs the held api"), "{waiting}");
    let held = row(&page.body, "data-item=\"held-one\"");
    assert!(held.contains("waiting-one"), "{held}");
    let ready = row(&page.body, "data-item=\"ready-one\"");
    assert!(
        ready.contains("done-one") && ready.contains("builds on done"),
        "{ready}"
    );
    h.finish().await;
}

#[sqlx::test]
async fn the_lock_view_shows_which_attempt_holds_which_slice(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let page = h.get(Some(&fx.alice), "/work/alpha-plan/locks").await;
    assert_eq!(page.status, 200);
    for slice in ["api", "web"] {
        let held = row(&page.body, &format!("data-slice=\"{slice}\""));
        assert!(held.contains(">held<"), "{held}");
        assert!(
            held.contains("held-one") && held.contains("worker-a"),
            "{held}"
        );
    }
    let free = row(&page.body, "data-slice=\"free\"");
    assert!(free.contains(">free<"), "{free}");
    assert!(
        !free.contains("worker-a") && !free.contains("held-one"),
        "{free}"
    );
    assert!(page.body.contains("src/api") && page.body.contains("docs"));
    assert!(page.body.contains("Cargo.lock"));
    h.finish().await;
}

#[sqlx::test]
async fn the_timeline_lists_attempts_and_events_in_order(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let held = h
        .get(Some(&fx.alice), "/work/alpha-plan/items/held-one")
        .await;
    assert_eq!(held.status, 200);
    assert!(held.body.contains("Held title"));
    let attempt = row(&held.body, "data-attempt=");
    assert!(
        attempt.contains("worker-a") && attempt.contains(">open<"),
        "{attempt}"
    );
    let claimed = held.body.find("taking it").unwrap();
    let noted = held.body.find("halfway").unwrap();
    assert!(claimed < noted);
    for text in ["claimed", "note", "user 1"] {
        assert!(held.body.contains(text), "{text}");
    }
    let waiting = h
        .get(Some(&fx.alice), "/work/alpha-plan/items/waiting-one")
        .await;
    assert!(waiting.body.contains("needs the held api"));
    let done = h
        .get(Some(&fx.alice), "/work/alpha-plan/items/done-one")
        .await;
    let closed = row(&done.body, "data-attempt=");
    assert!(
        closed.contains(">pass<") && closed.contains("all green"),
        "{closed}"
    );
    assert!(closed.contains("tests passed"), "{closed}");
    h.finish().await;
}

#[sqlx::test]
async fn defers_are_listed_by_vertical(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let page = h.get(Some(&fx.alice), "/work/alpha-plan/defers").await;
    assert_eq!(page.status, 200);
    let server = section(&page.body, "data-section=\"vertical-server\"");
    assert!(
        server.contains("Later title") && server.contains("Later reason"),
        "{server}"
    );
    assert!(
        server.contains(">open<") && server.contains("held-one"),
        "{server}"
    );
    assert!(!server.contains("Other title"));
    let cli = section(&page.body, "data-section=\"vertical-cli\"");
    assert!(
        cli.contains("Other title") && cli.contains(">dropped<"),
        "{cli}"
    );
    assert!(page.body.find("vertical-cli").unwrap() < page.body.find("vertical-server").unwrap());
    h.finish().await;
}

#[sqlx::test]
async fn the_markup_is_accessible_and_has_no_script_hooks(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    for (name, path) in page_paths("alpha-plan", "held-one") {
        let page = h.get(Some(&fx.alice), &path).await;
        assert_eq!(page.status, 200, "{name}");
        let body = &page.body;
        assert!(body.contains("<h1"), "{name}");
        assert!(body.contains("href=\"#app\""), "{name}");
        assert!(
            body.contains("href=\"/work\" aria-current=\"page\""),
            "{name}"
        );
        assert_eq!(
            body.matches("<table").count(),
            body.matches("<caption").count(),
            "{name}"
        );
        assert_eq!(body.matches("<th>").count(), 0, "{name}");
        assert_eq!(
            body.matches("<th ").count(),
            body.matches("<th scope=\"").count(),
            "{name}"
        );
        for banned in ["onclick", "onerror", "tabindex", "style=", "<script"] {
            assert!(
                !own_script_removed(body).contains(banned),
                "{name}: {banned}"
            );
        }
    }
    h.finish().await;
}

struct Hostile<'a> {
    value: &'a str,
}

impl Hostile<'_> {
    fn text(&self, field: &str) -> String {
        format!("F:{field}:{}", self.value)
    }

    fn key(&self, field: &str) -> String {
        let value: String = self
            .value
            .chars()
            .filter(|c| ('!'..='~').contains(c))
            .collect();
        format!("F:{field}:{value}")
    }

    fn path(&self, field: &str) -> String {
        let value: String = self
            .value
            .chars()
            .filter(|c| (' '..='~').contains(c))
            .collect();
        format!("src/F:{field}:{value}")
    }
}

const FIELD_PAGES: [(&str, &[&str]); 6] = [
    ("projects", &["pn"]),
    ("board", &["pn", "ik", "ti"]),
    ("graph", &["pn", "ik", "ti", "dw"]),
    ("locks", &["pn", "sn", "sp", "mp", "ik", "ho"]),
    (
        "item",
        &[
            "pn", "ik", "ti", "bo", "sn", "dw", "ho", "an", "ev", "ea", "en",
        ],
    ),
    ("defers", &["pn", "ik", "dv", "dt", "dr"]),
];

#[sqlx::test]
async fn hostile_text_is_escaped_and_cleaned_on_every_page_and_field(pool: PgPool) {
    let h = Harness::start(pool).await;
    for (n, (tag, value)) in HOSTILE.iter().enumerate() {
        let hostile = Hostile { value };
        let seed = char::from_digit(u32::try_from(n).unwrap() + 2, 16).unwrap();
        let who = h.session(&format!("user-{tag}"), seed).await;
        h.project(&who, &format!("{} raw", hostile.text("pn")))
            .await;
        let project = hostile.key("pn");
        let ids = h.project(&who, &project).await;
        let slice = h
            .slice(&ids, &hostile.text("sn"), &[&hostile.path("sp")])
            .await;
        h.mergeable(&ids, &hostile.path("mp")).await;
        let key = hostile.key("ik");
        let item = h
            .item(&ids, &key, &hostile.text("ti"), &hostile.text("bo"), "open")
            .await;
        let other = h.item(&ids, "plain", "plain title", "", "open").await;
        h.member(&ids, item, slice).await;
        h.dep(&ids, item, other, &hostile.text("dw")).await;
        h.attempt(
            &ids,
            item,
            &hostile.text("ho"),
            Some(("fail", &hostile.text("an"), &hostile.text("ev"))),
        )
        .await;
        let open = h.attempt(&ids, item, &hostile.text("ho"), None).await;
        h.lease(&ids, slice, open).await;
        h.event(
            &ids,
            item,
            Some(open),
            "note",
            &hostile.text("ea"),
            &hostile.text("en"),
        )
        .await;
        h.defer(
            &ids,
            Some(item),
            (
                &hostile.text("dt"),
                &hostile.text("dr"),
                &hostile.text("dv"),
            ),
            "open",
        )
        .await;
        for (page, fields) in FIELD_PAGES {
            let (_, path) = page_paths(&project, &key)
                .into_iter()
                .find(|(name, _)| *name == page)
                .unwrap();
            let reply = h.get(Some(&who), &path).await;
            assert_eq!(reply.status, 200, "{tag} {page}");
            assert!(!reply.head.contains("Set-Cookie: a=b"), "{tag} {page}");
            for field in fields {
                assert!(
                    reply.body.contains(&format!("F:{field}:")),
                    "{tag} {page} lacks {field}"
                );
            }
            for bad in FORBIDDEN_CHARS {
                assert!(!reply.body.contains(bad), "{tag} {page} holds {bad:?}");
            }
            for bad in [
                "<script",
                "<img",
                "href=\"javascript",
                "src=x onerror=alert(1)>",
            ] {
                assert!(
                    !own_script_removed(&reply.body).contains(bad),
                    "{tag} {page} holds {bad}"
                );
            }
            if *tag == "script" {
                assert!(
                    reply.body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"),
                    "{tag} {page}"
                );
            }
        }
    }
    h.finish().await;
}

#[sqlx::test]
async fn over_long_text_is_cut_at_the_display_cap(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let ids = h.project(&alice, "long").await;
    let item = h
        .item(&ids, "i", &"t".repeat(200), &"b".repeat(16384), "open")
        .await;
    let other = h.item(&ids, "j", "j", "", "open").await;
    h.dep(&ids, item, other, &"w".repeat(500)).await;
    let attempt = h
        .attempt(
            &ids,
            item,
            "h",
            Some(("fail", &"n".repeat(4096), &"e".repeat(8192))),
        )
        .await;
    h.event(&ids, item, Some(attempt), "note", "a", &"v".repeat(4096))
        .await;
    let page = h.get(Some(&alice), "/work/long/items/i").await;
    assert_eq!(page.status, 200);
    for (letter, kept) in [
        ('b', 4096),
        ('e', 4096),
        ('n', 4096),
        ('v', 4096),
        ('w', 200),
    ] {
        let run = letter.to_string();
        assert!(page.body.contains(&run.repeat(kept)), "{letter} kept");
        assert!(!page.body.contains(&run.repeat(kept + 1)), "{letter} over");
    }
    assert!(page.body.contains("data-truncated"));
    h.finish().await;
}
