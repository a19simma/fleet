//! The retro, pitfall and suggested-edit review pages over HTTP: session gate, owner scope,
//! retro list and detail, verify view, pitfall lists, edit list, diff review, the accept and
//! reject POST with its CSRF check, stale handling, row and diff caps and escaped text.
//!
//! Rows are seeded with raw SQL so a stored value can hold text the RPCs refuse, which is the
//! case the escaping must survive. The tests need a Postgres superuser URL in `DATABASE_URL`
//! and live in their own binary because they bind a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{EditKind, FileEditRequest};
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
const CLIENT_TOKEN: &str = "client-token-0123456789abcdef012345";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const ROW_CAP: usize = 200;
const DIFF_LINE_CAP: usize = 400;

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
    store: Store,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

fn own_script_removed(body: &str) -> String {
    body.replace("<script src=\"/static/navfocus.js\"", "")
}

fn numbered(prefix: &str, count: usize) -> String {
    let mut out = String::new();
    for n in 0..count {
        let _ = writeln!(out, "{prefix}{n}");
    }
    out
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
    name: String,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let web = Web::with_console(auth, None, store.clone());
        let bearer = BearerAuth::new(&Token::new(BOX_TOKEN.to_owned()).unwrap(), None);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let served = store.clone();
        let task = tokio::spawn(async move {
            serve_with_web(&served, &bearer, web, TcpIncoming::from(listener), async {
                let _ = rx.await;
            })
            .await
        });
        Self {
            addr,
            pool,
            store,
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
        self.login(user_id, seed).await
    }

    async fn login(&self, user_id: i64, seed: char) -> Session {
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
        Ids {
            project,
            name: name.to_owned(),
        }
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

    async fn slice_paths(&self, slice: i64) -> Vec<String> {
        sqlx::query_scalar("SELECT path FROM work_slice_path WHERE slice_id = $1 ORDER BY path")
            .bind(slice)
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn item(&self, ids: &Ids, key: &str) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO work_item (project_id, key, title, body, state) \
             VALUES ($1, $2, 't', '', 'open') RETURNING id",
        )
        .bind(ids.project)
        .bind(key)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn retro(&self, ids: &Ids, title: &str, state: &str, span: Option<(i64, i64)>) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO retro (project_id, title, state, span_from_item_id, span_to_item_id, \
             closed_at) VALUES ($1, $2, $3, $4, $5, CASE WHEN $3 = 'closed' THEN now() END) \
             RETURNING id",
        )
        .bind(ids.project)
        .bind(title)
        .bind(state)
        .bind(span.map(|s| s.0))
        .bind(span.map(|s| s.1))
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn improvement(
        &self,
        ids: &Ids,
        retro: Option<i64>,
        text: (&str, &str, &str),
        kind: &str,
        decided: Option<(&str, &str)>,
    ) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO improvement (project_id, retro_id, vertical, title, body, kind, \
             occurrences, disposition, disposition_reason) \
             VALUES ($1, $2, $3, $4, $5, $6, 3, $7, $8) RETURNING id",
        )
        .bind(ids.project)
        .bind(retro)
        .bind(text.0)
        .bind(text.1)
        .bind(text.2)
        .bind(kind)
        .bind(decided.map(|d| d.0))
        .bind(decided.map(|d| d.1))
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn pitfall(&self, who: &Session, ids: Option<&Ids>, text: (&str, &str, &str), hits: i32) {
        sqlx::query(
            "INSERT INTO pitfall (user_id, project_id, symptom, cause, fix, hits) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(who.user_id)
        .bind(ids.map(|i| i.project))
        .bind(text.0)
        .bind(text.1)
        .bind(text.2)
        .bind(hits)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn edit_row(&self, ids: &Ids, kind: &str, state: &str, text: (&str, &str, &str)) -> i64 {
        sqlx::query_scalar(
            "INSERT INTO suggested_edit (project_id, kind, state, target, base_hash, payload, \
             filed_by, decided_at) VALUES ($1, $2, $3, $4, 'abc123', $5, $6, \
             CASE WHEN $3 IN ('accepted', 'rejected') THEN now() END) RETURNING id",
        )
        .bind(ids.project)
        .bind(kind)
        .bind(state)
        .bind(text.0)
        .bind(text.1)
        .bind(text.2)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn filed_slice_op(&self, who: &Session, ids: &Ids, target: &str, payload: &str) -> u64 {
        let request = FileEditRequest {
            key: format!("k-{}-{}", target, payload.len()),
            project: ids.name.clone(),
            kind: EditKind::SliceOp.into(),
            target: target.to_owned(),
            base_hash: String::new(),
            payload: payload.to_owned(),
        };
        self.store
            .file_edit(who.user_id, &request, &Redactor::default(), 50)
            .await
            .unwrap()
            .id
    }

    async fn edit_state(&self, id: u64) -> String {
        sqlx::query_scalar("SELECT state FROM suggested_edit WHERE id = $1")
            .bind(i64::try_from(id).unwrap())
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn http(&self, method: &str, path: &str, headers: &[String], body: &str) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\nContent-Length: {}\r\n",
            body.len(),
        );
        for header in headers {
            let _ = write!(request, "{header}\r\n");
        }
        if method == "POST" {
            request.push_str("Content-Type: application/x-www-form-urlencoded\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let _ = stream.write_all(body.as_bytes()).await;
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        Reply {
            status: head.split(' ').nth(1).unwrap().parse().unwrap(),
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    async fn get(&self, who: Option<&Session>, path: &str) -> Reply {
        let headers: Vec<String> = who
            .map(|w| format!("Cookie: {}", w.cookie))
            .into_iter()
            .collect();
        self.http("GET", path, &headers, "").await
    }

    async fn decide(
        &self,
        who: Option<&Session>,
        project: &str,
        id: u64,
        decision: &str,
        csrf: Option<&str>,
    ) -> Reply {
        let mut body = format!("project={}&id={id}&decision={decision}", enc(project));
        if let Some(csrf) = csrf {
            let _ = write!(body, "&csrf={}", enc(csrf));
        }
        let headers: Vec<String> = who
            .map(|w| format!("Cookie: {}", w.cookie))
            .into_iter()
            .collect();
        self.http("POST", "/edits/decide", &headers, &body).await
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

fn paths(project: &str, retro: i64, edit: i64) -> [(&'static str, String); 7] {
    let p = enc(project);
    [
        ("retros", format!("/work/{p}/retros")),
        ("retro", format!("/work/{p}/retros/{retro}")),
        ("verify", format!("/work/{p}/retros/{retro}/verify")),
        ("project-pitfalls", format!("/work/{p}/pitfalls")),
        ("user-pitfalls", "/pitfalls".to_owned()),
        ("edits", format!("/work/{p}/edits")),
        ("edit", format!("/work/{p}/edits/{edit}")),
    ]
}

fn row<'a>(body: &'a str, attr: &str) -> &'a str {
    assert!(body.contains(attr), "{attr} missing in {body}");
    let start = body.find(attr).unwrap();
    let rest = &body[start..];
    &rest[..rest.find("</tr>").unwrap_or(rest.len())]
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
    ids: Ids,
    retro: i64,
    zero: i64,
    edit: i64,
}

async fn fixture(h: &Harness) -> Fixture {
    let alice = h.session("alice", 'a').await;
    let ids = h.project(&alice, "alpha-plan").await;
    let first = h.item(&ids, "first").await;
    let last = h.item(&ids, "last").await;
    let retro = h
        .retro(&ids, "Sprint one", "open", Some((first, last)))
        .await;
    let zero = h.retro(&ids, "Sprint zero", "closed", None).await;
    h.improvement(
        &ids,
        Some(retro),
        ("server", "Open title", "Open body"),
        "process",
        None,
    )
    .await;
    h.improvement(
        &ids,
        Some(retro),
        ("cli", "Accepted title", "Accepted body"),
        "tooling",
        Some(("accepted", "worth doing")),
    )
    .await;
    h.improvement(
        &ids,
        Some(retro),
        ("cli", "Rejected title", "Rejected body"),
        "docs",
        Some(("rejected", "not now")),
    )
    .await;
    h.improvement(
        &ids,
        Some(retro),
        ("web", "Deferred title", "Deferred body"),
        "test",
        Some(("deferred", "later")),
    )
    .await;
    h.improvement(
        &ids,
        Some(retro),
        ("web", "Applied title", "Applied body"),
        "other",
        Some(("applied", "done")),
    )
    .await;
    h.pitfall(&alice, None, ("User symptom", "User cause", "User fix"), 2)
        .await;
    h.pitfall(
        &alice,
        Some(&ids),
        ("Proj symptom", "Proj cause", "Proj fix"),
        5,
    )
    .await;
    h.pitfall(
        &alice,
        Some(&ids),
        ("Low symptom", "Low cause", "Low fix"),
        1,
    )
    .await;
    let edit = h
        .edit_row(
            &ids,
            "file_patch",
            "pending",
            (
                "docs/readme.md",
                "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-old line\n+new line\n",
                "worker-a",
            ),
        )
        .await;
    Fixture {
        alice,
        ids,
        retro,
        zero,
        edit,
    }
}

#[sqlx::test]
async fn every_review_page_needs_a_session(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    for (name, path) in paths("alpha-plan", fx.retro, fx.edit) {
        let reply = h.get(None, &path).await;
        assert_eq!(reply.status, 303, "{name}");
        assert_eq!(reply.header("location"), "/login", "{name}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_foreign_unknown_and_invalid_id_answer_the_same_not_found(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let bob = h.session("bob", 'b').await;
    let bobs = h.project(&bob, "bobs-plan").await;
    let bob_retro = h.retro(&bobs, "Bob retro", "open", None).await;
    let bob_edit = h
        .edit_row(&bobs, "file_patch", "pending", ("x", "y", "z"))
        .await;
    let missing = h.get(Some(&bob), "/work/nothing/retros").await;
    assert_eq!(missing.status, 404);
    for (name, path) in paths("alpha-plan", fx.retro, fx.edit)
        .into_iter()
        .filter(|(n, _)| *n != "user-pitfalls")
    {
        let own = h.get(Some(&fx.alice), &path).await;
        assert_eq!(own.status, 200, "{name}");
        let foreign = h.get(Some(&bob), &path).await;
        assert_eq!(foreign.status, 404, "{name}");
        assert_eq!(foreign.body, missing.body, "{name}");
        assert!(!foreign.body.contains("alpha-plan"), "{name}");
    }
    let mine = "/work/alpha-plan";
    let cross = [
        format!("{mine}/retros/{bob_retro}"),
        format!("{mine}/retros/{bob_retro}/verify"),
        format!("{mine}/edits/{bob_edit}"),
        format!("{mine}/retros/99999999"),
        format!("{mine}/edits/99999999"),
        format!("{mine}/retros/abc"),
        format!("{mine}/retros/0"),
        format!("{mine}/retros/-1"),
        format!("{mine}/retros/99999999999999999999999"),
        format!("{mine}/edits/%3Cscript%3E"),
        format!("{mine}/edits/%0D%0A"),
        format!("{mine}/edits/1%00"),
    ];
    for path in &cross {
        let reply = h.get(Some(&fx.alice), path).await;
        assert_eq!(reply.status, 404, "{path}");
        assert_eq!(reply.body, missing.body, "{path}");
    }
    let long = "x".repeat(200);
    for bad in ["%3Cscript%3E", "%0D%0A", "%00", "%E2%80%AE", long.as_str()] {
        for tail in ["retros", "pitfalls", "edits"] {
            let reply = h.get(Some(&bob), &format!("/work/{bad}/{tail}")).await;
            assert_eq!(reply.status, 404, "{bad} {tail}");
            assert_eq!(reply.body, missing.body, "{bad} {tail}");
        }
    }
    let list = h.get(Some(&bob), "/pitfalls").await;
    assert_eq!(list.status, 200);
    assert!(!list.body.contains("User symptom"));
    h.finish().await;
}

#[sqlx::test]
async fn the_retro_list_and_detail_group_improvements_by_disposition(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let list = h.get(Some(&fx.alice), "/work/alpha-plan/retros").await;
    assert_eq!(list.status, 200);
    let open = row(&list.body, &format!("data-retro=\"{}\"", fx.retro));
    assert!(
        open.contains("Sprint one") && open.contains(">open<"),
        "{open}"
    );
    assert!(open.contains("first") && open.contains("last"), "{open}");
    assert!(
        open.contains(&format!("href=\"/work/alpha-plan/retros/{}\"", fx.retro)),
        "{open}"
    );
    let closed = row(&list.body, &format!("data-retro=\"{}\"", fx.zero));
    assert!(closed.contains("Sprint zero"), "{closed}");
    assert!(closed.contains(">closed<"), "{closed}");
    let page = h
        .get(
            Some(&fx.alice),
            &format!("/work/alpha-plan/retros/{}", fx.retro),
        )
        .await;
    assert_eq!(page.status, 200);
    let groups = [
        ("undecided", "Open title", "Open body"),
        ("accepted", "Accepted title", "worth doing"),
        ("rejected", "Rejected title", "not now"),
        ("deferred", "Deferred title", "later"),
        ("applied", "Applied title", "done"),
    ];
    for (name, title, reason) in groups {
        let body = section(&page.body, &format!("data-section=\"disp-{name}\""));
        assert!(
            body.contains(title) && body.contains(reason),
            "{name}: {body}"
        );
        for (other, other_title, _) in groups.iter().filter(|(n, _, _)| *n != name) {
            assert!(!body.contains(other_title), "{name} holds {other}");
        }
    }
    assert!(page.body.contains("process") && page.body.contains("tooling"));
    assert!(page.body.contains(">3<") || page.body.contains("3 occurrences"));
    h.finish().await;
}

#[sqlx::test]
async fn the_verify_view_lists_what_blocks_closing_a_retro(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let page = h
        .get(
            Some(&fx.alice),
            &format!("/work/alpha-plan/retros/{}/verify", fx.retro),
        )
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("data-verify=\"blocked\""),
        "{}",
        page.body
    );
    assert!(page.body.contains("Open title"));
    assert!(!page.body.contains("Accepted title"));
    let done = h.retro(&fx.ids, "Done retro", "open", None).await;
    h.improvement(
        &fx.ids,
        Some(done),
        ("v", "Decided one", "b"),
        "docs",
        Some(("applied", "ok")),
    )
    .await;
    let ready = h
        .get(
            Some(&fx.alice),
            &format!("/work/alpha-plan/retros/{done}/verify"),
        )
        .await;
    assert!(
        ready.body.contains("data-verify=\"ready\""),
        "{}",
        ready.body
    );
    assert!(!ready.body.contains("data-verify=\"blocked\""));
    h.finish().await;
}

#[sqlx::test]
async fn pitfalls_list_by_level_most_hit_first(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let project = h.get(Some(&fx.alice), "/work/alpha-plan/pitfalls").await;
    assert_eq!(project.status, 200);
    for text in ["Proj symptom", "Proj cause", "Proj fix", "Low symptom"] {
        assert!(project.body.contains(text), "{text}");
    }
    assert!(!project.body.contains("User symptom"));
    assert!(project.body.find("Proj symptom").unwrap() < project.body.find("Low symptom").unwrap());
    let user = h.get(Some(&fx.alice), "/pitfalls").await;
    assert_eq!(user.status, 200);
    assert!(user.body.contains("User symptom") && user.body.contains("User fix"));
    assert!(!user.body.contains("Proj symptom"));
    assert!(
        user.body
            .contains("href=\"/pitfalls\" aria-current=\"page\"")
    );
    h.finish().await;
}

#[sqlx::test]
async fn the_edit_list_shows_kind_state_and_filer(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let other = h
        .edit_row(&fx.ids, "pitfall", "rejected", ("sym", "c\nf", "worker-b"))
        .await;
    let page = h.get(Some(&fx.alice), "/work/alpha-plan/edits").await;
    assert_eq!(page.status, 200);
    let pending = row(&page.body, &format!("data-edit=\"{}\"", fx.edit));
    for text in ["file_patch", ">pending<", "docs/readme.md", "worker-a"] {
        assert!(pending.contains(text), "{text}: {pending}");
    }
    assert!(
        pending.contains(&format!("href=\"/work/alpha-plan/edits/{}\"", fx.edit)),
        "{pending}"
    );
    let rejected = row(&page.body, &format!("data-edit=\"{other}\""));
    assert!(rejected.contains("worker-b"), "{rejected}");
    assert!(
        rejected.contains(">rejected<") && rejected.contains("pitfall"),
        "{rejected}"
    );
    h.finish().await;
}

#[sqlx::test]
async fn the_diff_page_shows_the_escaped_diff_with_both_buttons(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let payload = "--- a/x\n+++ b/x\n@@ -1 +1 @@\n-<b>old</b>\n+new\n";
    let id = h
        .edit_row(&fx.ids, "file_patch", "pending", ("x", payload, "w"))
        .await;
    let page = h
        .get(Some(&fx.alice), &format!("/work/alpha-plan/edits/{id}"))
        .await;
    assert_eq!(page.status, 200);
    assert!(
        page.body.contains("-&lt;b&gt;old&lt;/b&gt;"),
        "{}",
        page.body
    );
    assert!(!page.body.contains("<b>old"));
    assert!(
        page.body.contains("data-action=\"accept\"")
            && page.body.contains("data-action=\"reject\"")
    );
    assert!(page.body.contains("action=\"/edits/decide\""));
    assert!(page.body.contains("name=\"csrf\" value=\"csrf-token\""));
    assert!(!page.body.contains("data-action=\"accept\" disabled"));
    h.finish().await;
}

#[sqlx::test]
async fn a_long_diff_is_cut_at_the_line_cap_with_a_marker(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let diff = numbered("+row-", DIFF_LINE_CAP + 51);
    let id = h
        .edit_row(&fx.ids, "file_patch", "pending", ("x", &diff, "w"))
        .await;
    let page = h
        .get(Some(&fx.alice), &format!("/work/alpha-plan/edits/{id}"))
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("data-diff-truncated"));
    assert!(page.body.contains(&format!("+row-{}\n", DIFF_LINE_CAP - 1)));
    assert!(!page.body.contains(&format!("+row-{DIFF_LINE_CAP}\n")));
    let exact = numbered("+r", DIFF_LINE_CAP);
    let fits = h
        .edit_row(&fx.ids, "file_patch", "pending", ("y", &exact, "w"))
        .await;
    let page = h
        .get(Some(&fx.alice), &format!("/work/alpha-plan/edits/{fits}"))
        .await;
    assert!(!page.body.contains("data-diff-truncated"));
    assert!(page.body.contains(&format!("+r{}\n", DIFF_LINE_CAP - 1)));
    let wide = format!("+{}\n", "z".repeat(20000));
    let fat = h
        .edit_row(&fx.ids, "file_patch", "pending", ("w", &wide, "w"))
        .await;
    let page = h
        .get(Some(&fx.alice), &format!("/work/alpha-plan/edits/{fat}"))
        .await;
    assert!(page.body.contains("data-diff-truncated"));
    assert!(!page.body.contains(&"z".repeat(16385)));
    h.finish().await;
}

#[sqlx::test]
async fn accepting_a_slice_op_applies_it_and_marks_the_edit(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let core = h.slice(&fx.ids, "core", &["src/core"]).await;
    let id = h
        .filed_slice_op(&fx.alice, &fx.ids, "core", "add-path\tsrc/extra")
        .await;
    let reply = h
        .decide(
            Some(&fx.alice),
            "alpha-plan",
            id,
            "accept",
            Some("csrf-token"),
        )
        .await;
    assert_eq!(reply.status, 303, "{}", reply.body);
    assert_eq!(
        reply.header("location"),
        format!("/work/alpha-plan/edits/{id}?notice=accepted")
    );
    assert_eq!(h.edit_state(id).await, "accepted");
    assert_eq!(h.slice_paths(core).await, ["src/core", "src/extra"]);
    let page = h
        .get(
            Some(&fx.alice),
            &format!("/work/alpha-plan/edits/{id}?notice=accepted"),
        )
        .await;
    assert!(page.body.contains(">accepted<"));
    assert!(!page.body.contains("data-action=\"accept\""));
    assert!(page.body.contains("id=\"notice\""));
    h.finish().await;
}

#[sqlx::test]
async fn rejecting_marks_the_edit_and_changes_nothing_else(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let core = h.slice(&fx.ids, "core", &["src/core"]).await;
    let id = h
        .filed_slice_op(&fx.alice, &fx.ids, "core", "add-path\tsrc/extra")
        .await;
    let reply = h
        .decide(
            Some(&fx.alice),
            "alpha-plan",
            id,
            "reject",
            Some("csrf-token"),
        )
        .await;
    assert_eq!(reply.status, 303);
    assert_eq!(h.edit_state(id).await, "rejected");
    assert_eq!(h.slice_paths(core).await, ["src/core"]);
    let again = h
        .decide(
            Some(&fx.alice),
            "alpha-plan",
            id,
            "accept",
            Some("csrf-token"),
        )
        .await;
    assert_eq!(again.status, 303);
    assert!(
        again.header("location").ends_with("notice=decided"),
        "{}",
        again.head
    );
    assert_eq!(h.edit_state(id).await, "rejected");
    h.finish().await;
}

#[sqlx::test]
async fn a_file_patch_is_only_marked_accepted(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM work_slice_path")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let id = u64::try_from(fx.edit).unwrap();
    let reply = h
        .decide(
            Some(&fx.alice),
            "alpha-plan",
            id,
            "accept",
            Some("csrf-token"),
        )
        .await;
    assert_eq!(reply.status, 303);
    assert_eq!(h.edit_state(id).await, "accepted");
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM work_slice_path")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    h.finish().await;
}

#[sqlx::test]
async fn a_missing_or_wrong_csrf_token_is_refused_and_nothing_changes(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let core = h.slice(&fx.ids, "core", &["src/core"]).await;
    let id = h
        .filed_slice_op(&fx.alice, &fx.ids, "core", "add-path\tsrc/extra")
        .await;
    for csrf in [
        None,
        Some(""),
        Some("wrong"),
        Some("csrf-tokeN"),
        Some("csrf-token0"),
    ] {
        for decision in ["accept", "reject"] {
            let reply = h
                .decide(Some(&fx.alice), "alpha-plan", id, decision, csrf)
                .await;
            assert_eq!(reply.status, 403, "{csrf:?} {decision}");
            assert_eq!(h.edit_state(id).await, "pending", "{csrf:?} {decision}");
            assert_eq!(
                h.slice_paths(core).await,
                ["src/core"],
                "{csrf:?} {decision}"
            );
        }
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_client_or_box_token_is_not_accepted_on_the_decide_route(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let core = h.slice(&fx.ids, "core", &["src/core"]).await;
    let id = h
        .filed_slice_op(&fx.alice, &fx.ids, "core", "add-path\tsrc/extra")
        .await;
    let body = format!("project=alpha-plan&id={id}&decision=accept&csrf=csrf-token");
    for token in [CLIENT_TOKEN, BOX_TOKEN] {
        for header in [
            format!("Authorization: Bearer {token}"),
            format!("X-Fleet-Token: {token}"),
        ] {
            let reply = h
                .http(
                    "POST",
                    "/edits/decide",
                    std::slice::from_ref(&header),
                    &body,
                )
                .await;
            assert_eq!(reply.status, 403, "{header}");
            assert_eq!(h.edit_state(id).await, "pending", "{header}");
            assert_eq!(h.slice_paths(core).await, ["src/core"], "{header}");
        }
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_session_without_a_cookie_or_of_another_user_cannot_decide(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let id = u64::try_from(fx.edit).unwrap();
    let none = h
        .decide(None, "alpha-plan", id, "accept", Some("csrf-token"))
        .await;
    assert_eq!(none.status, 403);
    let bob = h.session("bob", 'b').await;
    let foreign = h
        .decide(Some(&bob), "alpha-plan", id, "accept", Some("csrf-token"))
        .await;
    let unknown = h
        .decide(Some(&bob), "nothing", id, "accept", Some("csrf-token"))
        .await;
    assert_eq!(foreign.status, 404);
    assert_eq!(unknown.status, 404);
    assert_eq!(foreign.body, unknown.body);
    assert_eq!(h.edit_state(id).await, "pending");
    h.finish().await;
}

#[sqlx::test]
async fn the_bootstrap_user_cannot_decide_through_the_web(pool: PgPool) {
    let h = Harness::start(pool).await;
    let boot: i64 = sqlx::query_scalar("SELECT bootstrap_user_id()")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let who = h.login(boot, 'c').await;
    let ids = h.project(&who, "boot-plan").await;
    let id = h
        .edit_row(&ids, "file_patch", "pending", ("x", "y", "z"))
        .await;
    let id = u64::try_from(id).unwrap();
    let reply = h
        .decide(Some(&who), "boot-plan", id, "accept", Some("csrf-token"))
        .await;
    assert_eq!(reply.status, 303);
    assert!(
        reply.header("location").ends_with("notice=not_interactive"),
        "{}",
        reply.head
    );
    assert_eq!(h.edit_state(id).await, "pending");
    h.finish().await;
}

#[sqlx::test]
async fn invalid_decisions_and_ids_are_refused_without_a_write(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let id = u64::try_from(fx.edit).unwrap();
    for decision in ["", "ACCEPT", "approve", "accept%0D%0A"] {
        let reply = h
            .decide(
                Some(&fx.alice),
                "alpha-plan",
                id,
                decision,
                Some("csrf-token"),
            )
            .await;
        assert!(
            matches!(reply.status, 400 | 404 | 422),
            "{decision}: {}",
            reply.status
        );
        assert_eq!(h.edit_state(id).await, "pending", "{decision}");
    }
    for bad in [0, 99_999_999] {
        let reply = h
            .decide(
                Some(&fx.alice),
                "alpha-plan",
                bad,
                "accept",
                Some("csrf-token"),
            )
            .await;
        assert_eq!(reply.status, 404, "{bad}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_stale_edit_shows_stale_with_accept_disabled_and_refuses_accept(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let core = h.slice(&fx.ids, "core", &["src/core"]).await;
    let id = h
        .filed_slice_op(&fx.alice, &fx.ids, "core", "add-path\tsrc/extra")
        .await;
    sqlx::query("INSERT INTO work_slice_path (slice_id, path) VALUES ($1, 'src/moved')")
        .bind(core)
        .execute(&h.pool)
        .await
        .unwrap();
    let page = h
        .get(Some(&fx.alice), &format!("/work/alpha-plan/edits/{id}"))
        .await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(">stale<"), "{}", page.body);
    assert!(
        page.body.contains("data-action=\"accept\" disabled"),
        "{}",
        page.body
    );
    assert!(page.body.contains("data-action=\"reject\""));
    assert!(!page.body.contains("data-action=\"reject\" disabled"));
    let list = h.get(Some(&fx.alice), "/work/alpha-plan/edits").await;
    assert!(row(&list.body, &format!("data-edit=\"{id}\"")).contains(">stale<"));
    let reply = h
        .decide(
            Some(&fx.alice),
            "alpha-plan",
            id,
            "accept",
            Some("csrf-token"),
        )
        .await;
    assert_eq!(reply.status, 303);
    assert!(
        reply.header("location").ends_with("notice=stale"),
        "{}",
        reply.head
    );
    assert_eq!(h.edit_state(id).await, "stale");
    assert_eq!(h.slice_paths(core).await, ["src/core", "src/moved"]);
    h.finish().await;
}

#[sqlx::test]
async fn an_edit_that_no_longer_applies_stays_pending_with_a_notice(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    let core = h.slice(&fx.ids, "core", &["src/core"]).await;
    h.slice(&fx.ids, "other", &["src/other"]).await;
    let id = h
        .filed_slice_op(&fx.alice, &fx.ids, "core", "add-path\tsrc/other")
        .await;
    let reply = h
        .decide(
            Some(&fx.alice),
            "alpha-plan",
            id,
            "accept",
            Some("csrf-token"),
        )
        .await;
    assert_eq!(reply.status, 303);
    assert!(
        reply.header("location").ends_with("notice=does_not_apply"),
        "{}",
        reply.head
    );
    assert_eq!(h.edit_state(id).await, "pending");
    assert_eq!(h.slice_paths(core).await, ["src/core"]);
    h.finish().await;
}

#[sqlx::test]
async fn a_list_is_cut_at_the_row_cap_with_a_marker(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let ids = h.project(&alice, "big").await;
    let retro = h.retro(&ids, "r0", "open", None).await;
    for n in 0..=ROW_CAP {
        h.retro(&ids, &format!("retro-{n:04}"), "closed", None)
            .await;
        h.improvement(
            &ids,
            Some(retro),
            ("v", &format!("imp-{n:04}"), "b"),
            "docs",
            None,
        )
        .await;
        h.pitfall(&alice, Some(&ids), (&format!("sym-{n:04}"), "c", "f"), 1)
            .await;
        h.pitfall(&alice, None, (&format!("usym-{n:04}"), "c", "f"), 1)
            .await;
        h.edit_row(
            &ids,
            "file_patch",
            "pending",
            (&format!("tgt-{n:04}"), "p", "w"),
        )
        .await;
    }
    let pages = [
        ("/work/big/retros", "data-retro=", ROW_CAP),
        (&format!("/work/big/retros/{retro}"), "imp-", ROW_CAP),
        ("/work/big/pitfalls", "sym-", ROW_CAP),
        ("/pitfalls", "usym-", ROW_CAP),
        ("/work/big/edits", "data-edit=", ROW_CAP),
    ];
    for (path, marker, cap) in pages {
        let page = h.get(Some(&alice), path).await;
        assert_eq!(page.status, 200, "{path}");
        assert!(page.body.contains("data-rows-truncated"), "{path}");
        let shown = page.body.matches(marker).count();
        assert!(shown >= cap && shown < cap + cap / 2, "{path}: {shown}");
    }
    let small = h.project(&alice, "small").await;
    h.retro(&small, "one", "open", None).await;
    let page = h.get(Some(&alice), "/work/small/retros").await;
    assert!(!page.body.contains("data-rows-truncated"));
    h.finish().await;
}

#[sqlx::test]
async fn the_markup_is_accessible_and_has_no_script_hooks(pool: PgPool) {
    let h = Harness::start(pool).await;
    let fx = fixture(&h).await;
    for (name, path) in paths("alpha-plan", fx.retro, fx.edit) {
        let page = h.get(Some(&fx.alice), &path).await;
        assert_eq!(page.status, 200, "{name}");
        let body = &page.body;
        assert!(body.contains("<h1"), "{name}");
        assert!(body.contains("href=\"#app\""), "{name}");
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
    for tab in ["retros", "pitfalls", "edits"] {
        let page = h
            .get(Some(&fx.alice), &format!("/work/alpha-plan/{tab}"))
            .await;
        assert!(
            page.body.contains(&format!(
                "href=\"/work/alpha-plan/{tab}\" aria-current=\"page\""
            )),
            "{tab}"
        );
    }
    let board = h.get(Some(&fx.alice), "/work/alpha-plan").await;
    for tab in ["retros", "pitfalls", "edits"] {
        assert!(
            board
                .body
                .contains(&format!("href=\"/work/alpha-plan/{tab}\"")),
            "{tab}"
        );
    }
    assert!(board.body.contains("href=\"/pitfalls\""));
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
}

const FIELD_PAGES: [(&str, &[&str]); 7] = [
    ("retros", &["pn", "rt", "rf", "rl"]),
    ("retro", &["pn", "rt", "iv", "it", "ib", "ir", "rf", "rl"]),
    ("verify", &["pn", "rt", "iv", "it"]),
    ("project-pitfalls", &["pn", "ps", "pc", "pf"]),
    ("user-pitfalls", &["us", "uc", "uf"]),
    ("edits", &["pn", "et", "ef"]),
    ("edit", &["pn", "et", "ep", "ef"]),
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
        let first = h.item(&ids, &hostile.key("rf")).await;
        let last = h.item(&ids, &hostile.key("rl")).await;
        let retro = h
            .retro(&ids, &hostile.text("rt"), "open", Some((first, last)))
            .await;
        h.improvement(
            &ids,
            Some(retro),
            (
                &hostile.text("iv"),
                &hostile.text("it"),
                &hostile.text("ib"),
            ),
            "process",
            Some(("deferred", &hostile.text("ir"))),
        )
        .await;
        h.improvement(
            &ids,
            Some(retro),
            (
                &hostile.text("iv"),
                &format!("U {}", hostile.text("it")),
                "b",
            ),
            "docs",
            None,
        )
        .await;
        h.pitfall(
            &who,
            Some(&ids),
            (
                &hostile.text("ps"),
                &hostile.text("pc"),
                &hostile.text("pf"),
            ),
            1,
        )
        .await;
        h.pitfall(
            &who,
            None,
            (
                &hostile.text("us"),
                &hostile.text("uc"),
                &hostile.text("uf"),
            ),
            1,
        )
        .await;
        let edit = h
            .edit_row(
                &ids,
                "file_patch",
                "pending",
                (
                    &hostile.text("et"),
                    &hostile.text("ep"),
                    &hostile.text("ef"),
                ),
            )
            .await;
        for (page, fields) in FIELD_PAGES {
            let (_, path) = paths(&project, retro, edit)
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
    let retro = h.retro(&ids, &"t".repeat(200), "open", None).await;
    h.improvement(
        &ids,
        Some(retro),
        ("v", "imp", &"b".repeat(16384)),
        "docs",
        Some(("rejected", &"r".repeat(2000))),
    )
    .await;
    let page = h
        .get(Some(&alice), &format!("/work/long/retros/{retro}"))
        .await;
    assert_eq!(page.status, 200);
    for (letter, kept) in [('b', 4096), ('r', 2000)] {
        let run = letter.to_string();
        assert!(page.body.contains(&run.repeat(kept)), "{letter} kept");
        assert!(!page.body.contains(&run.repeat(kept + 1)), "{letter} over");
    }
    assert!(page.body.contains("data-truncated"));
    h.finish().await;
}
