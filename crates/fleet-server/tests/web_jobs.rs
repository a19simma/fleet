//! The jobs pages and the API token page over HTTP: session and CSRF gates, owner scoping,
//! escaped transcripts and the token shown once. The tests need a Postgres superuser URL in
//! `DATABASE_URL` for `#[sqlx::test]` and live in their own binary because each one binds a
//! socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use fleet_proto::v1::SubmitJobRequest;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{MAX_RENDER_BYTES, SESSION_COOKIE, STYLE_CSS, Web, WebAuth};
use serde_json::{Value, json};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const REPO: &str = "https://example.com/org/repo.git";
const FORM: (&str, &str) = ("Content-Type", "application/x-www-form-urlencoded");
const SCRIPT_PROMPT: &str = "<script>alert('prompt-xss')</script>";
const IMG_CHUNK: &str = "<img src=x onerror=alert('chunk-xss')>";

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn location(&self) -> String {
        self.head
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                key.eq_ignore_ascii_case("location")
                    .then(|| value.trim().to_owned())
            })
            .unwrap_or_default()
    }
}

struct Session {
    cookie: String,
    csrf: String,
    user_id: i64,
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    store: Store,
    users: Users,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        Self::start_with(pool, true).await
    }

    async fn start_with(pool: PgPool, configured: bool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
        let web = if configured {
            Web::with_console(auth, None, store.clone())
        } else {
            Web::with_auth(auth)
        };
        let bearer = BearerAuth::new(
            &Token::new("box-token-0123456789abcdef0123456789".to_owned()).unwrap(),
            None,
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = oneshot::channel::<()>();
        let serving = store.clone();
        let task = tokio::spawn(async move {
            serve_with_web(&serving, &bearer, web, TcpIncoming::from(listener), async {
                let _ = rx.await;
            })
            .await
        });
        Self {
            addr,
            pool,
            store,
            users,
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
        let csrf = format!("csrf-{name}-token");
        sqlx::query(
            "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
             VALUES (sha256($1::bytea), $2, $3, now() + interval '1 hour')",
        )
        .bind(id.as_bytes())
        .bind(user_id)
        .bind(&csrf)
        .execute(&self.pool)
        .await
        .unwrap();
        Session {
            cookie: format!("{SESSION_COOKIE}={id}"),
            csrf,
            user_id,
        }
    }

    async fn job(&self, who: &Session, key: &str, prompt: &str) -> String {
        let request = SubmitJobRequest {
            idempotency_key: key.to_owned(),
            prompt: prompt.to_owned(),
            repo: REPO.to_owned(),
            base_ref: "main".to_owned(),
            open_pr: false,
            agent: String::new(),
            profile: String::new(),
        };
        self.store
            .submit_job_for(Some(who.user_id), &request)
            .await
            .unwrap()
            .job_id
    }

    async fn chunk(&self, job_id: &str, seq: i64, text: &str) {
        sqlx::query(
            "INSERT INTO job_transcript (job_id, seq, ts_ms, chunk, truncated) \
             VALUES ($1, $2, 1, $3, false)",
        )
        .bind(job_id)
        .bind(seq)
        .bind(text)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn lines(&self, job_id: &str, lines: &[Value]) {
        for (n, line) in lines.iter().enumerate() {
            self.chunk(job_id, i64::try_from(n).unwrap() + 1, &line.to_string())
                .await;
        }
    }

    async fn bulk(&self, job_id: &str, count: i64, text: &str) {
        sqlx::query(
            "INSERT INTO job_transcript (job_id, seq, ts_ms, chunk, truncated) \
             SELECT $1, g, 1, $2, false FROM generate_series(1::bigint, $3::bigint) g",
        )
        .bind(job_id)
        .bind(text)
        .bind(count)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn end(&self, job_id: &str) {
        sqlx::query("UPDATE jobs SET state = 'SUCCEEDED', finished_at = now() WHERE job_id = $1")
            .bind(job_id)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn send(&self, method: &str, path: &str, extra: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        if !extra
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("origin"))
        {
            let _ = write!(request, "Origin: {ORIGIN}\r\n");
        }
        for (key, value) in extra {
            let _ = write!(request, "{key}: {value}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        let _ = stream.write_all(body).await;
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().parse().unwrap();
        Reply {
            status,
            head: head.to_owned(),
            body: body.to_owned(),
        }
    }

    async fn get(&self, who: &Session, path: &str) -> Reply {
        self.send("GET", path, &[("Cookie", &who.cookie)], b"")
            .await
    }

    async fn post(&self, who: &Session, path: &str, body: &str) -> Reply {
        self.send(
            "POST",
            path,
            &[("Cookie", &who.cookie), FORM],
            body.as_bytes(),
        )
        .await
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

fn token_in(body: &str) -> Option<String> {
    let start = body.find("flt_")?;
    let rest = &body[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

#[sqlx::test]
async fn the_pages_need_a_session(pool: PgPool) {
    let h = Harness::start(pool).await;
    for path in ["/jobs", "/jobs/anything", "/tokens"] {
        let reply = h.send("GET", path, &[], b"").await;
        assert_eq!(reply.status, 303, "{path}");
        assert_eq!(reply.location(), "/login", "{path}");
    }
    let reply = h.send("POST", "/tokens/create", &[FORM], b"label=x").await;
    assert_eq!(reply.status, 403);
    h.finish().await;
}

#[sqlx::test]
async fn the_pages_are_off_when_the_console_is_not_configured(pool: PgPool) {
    let h = Harness::start_with(pool, false).await;
    let alice = h.session("alice", 'a').await;
    assert_eq!(h.get(&alice, "/jobs").await.status, 404);
    assert_eq!(h.get(&alice, "/jobs/x").await.status, 404);
    assert_eq!(h.get(&alice, "/tokens").await.status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn the_list_shows_only_the_signed_in_users_jobs(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let mine = h.job(&alice, "a1", "alice prompt").await;
    let theirs = h.job(&bob, "b1", "bob prompt").await;
    let page = h.get(&alice, "/jobs").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(&mine));
    assert!(!page.body.contains(&theirs));
    let page = h.get(&bob, "/jobs").await;
    assert!(page.body.contains(&theirs));
    assert!(!page.body.contains(&mine));
    assert!(page.head.to_ascii_lowercase().contains("no-store"));
    h.finish().await;
}

#[test]
fn table_cell_links_have_a_24px_minimum_target() {
    assert!(
        STYLE_CSS.contains(
            ".table td a.link{align-items:center;min-block-size:24px;display:inline-flex}"
        ),
        "no 24px table link rule"
    );
}

#[sqlx::test]
async fn the_job_id_links_are_table_links_in_the_first_column(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "alice prompt").await;
    let page = h.get(&alice, "/jobs").await;
    let row = page.body.split("<tr>").find(|r| r.contains(&id)).unwrap();
    let first = row.split("</td>").next().unwrap();
    assert!(
        first.starts_with("<td><a class=\"link link-primary\""),
        "{first}"
    );
    assert!(first.contains(&format!("href=\"/jobs/{id}\"")), "{first}");
    h.finish().await;
}

#[sqlx::test]
async fn another_users_job_is_not_found_exactly_like_an_unknown_id(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let theirs = h.job(&bob, "b1", "bob secret prompt").await;
    h.chunk(&theirs, 1, "bob secret transcript").await;
    let foreign = h.get(&alice, &format!("/jobs/{theirs}")).await;
    let unknown = h.get(&alice, "/jobs/job-does-not-exist").await;
    assert_eq!(foreign.status, 404);
    assert_eq!(unknown.status, 404);
    assert_eq!(foreign.body, unknown.body);
    assert!(!foreign.body.contains("bob secret"));
    let own = h.get(&bob, &format!("/jobs/{theirs}")).await;
    assert_eq!(own.status, 200);
    assert!(own.body.contains("bob secret prompt"));
    assert!(own.body.contains("bob secret transcript"));
    h.finish().await;
}

#[sqlx::test]
async fn a_malformed_job_id_is_not_found(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let long = "x".repeat(200);
    assert_eq!(h.get(&alice, &format!("/jobs/{long}")).await.status, 404);
    assert_eq!(h.get(&alice, "/jobs/a%20b").await.status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn markup_in_a_prompt_and_a_transcript_is_escaped(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", SCRIPT_PROMPT).await;
    h.chunk(&id, 1, IMG_CHUNK).await;
    sqlx::query("UPDATE jobs SET error = $2, progress = $2 WHERE job_id = $1")
        .bind(&id)
        .bind("<b onmouseover=alert('err-xss')>")
        .execute(&h.pool)
        .await
        .unwrap();
    let detail = h.get(&alice, &format!("/jobs/{id}")).await;
    assert_eq!(detail.status, 200);
    assert!(!detail.body.contains("<script>alert"));
    assert!(!detail.body.contains("<img src=x"));
    assert!(!detail.body.contains("<b onmouseover"));
    assert!(detail.body.contains("&lt;script&gt;alert("));
    assert!(detail.body.contains("&lt;img src=x onerror=alert("));
    assert!(detail.body.contains("&lt;b onmouseover=alert("));
    let list = h.get(&alice, "/jobs").await;
    assert!(!list.body.contains("<script>alert"));
    h.finish().await;
}

#[sqlx::test]
async fn a_huge_transcript_is_cut_with_a_marker(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    let piece = "A".repeat(60_000);
    for seq in 1..=12 {
        h.chunk(&id, seq, &piece).await;
    }
    let detail = h.get(&alice, &format!("/jobs/{id}")).await;
    assert_eq!(detail.status, 200);
    assert!(detail.body.len() < MAX_RENDER_BYTES + 16 * 1024);
    assert!(detail.body.contains("transcript cut"));
    h.finish().await;
}

#[sqlx::test]
async fn a_short_transcript_has_no_cut_marker(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.chunk(&id, 1, "line one").await;
    let detail = h.get(&alice, &format!("/jobs/{id}")).await;
    assert!(detail.body.contains("line one"));
    assert!(!detail.body.contains("transcript cut"));
    h.finish().await;
}

#[sqlx::test]
async fn the_token_is_shown_once_in_the_post_response_only(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let body = format!("csrf={}&label=laptop", alice.csrf);
    let made = h.post(&alice, "/tokens/create", &body).await;
    assert_eq!(made.status, 200, "{}", made.head);
    assert_eq!(made.location(), "");
    assert!(made.head.to_ascii_lowercase().contains("no-store"));
    let token = token_in(&made.body).unwrap();
    assert_eq!(
        h.users.authenticate(token.as_bytes()).await.unwrap(),
        Some(alice.user_id)
    );
    assert!(!made.head.contains(&token));
    let page = h.get(&alice, "/tokens").await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains(&token));
    assert!(page.body.contains("laptop"));
    let stored: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens WHERE hash = $1")
        .bind(token.as_bytes())
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(stored, 0);
    h.finish().await;
}

#[sqlx::test]
async fn creating_a_token_needs_the_csrf_token(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bad = h.post(&alice, "/tokens/create", "csrf=wrong&label=x").await;
    assert_eq!(bad.status, 403);
    let none = h.post(&alice, "/tokens/create", "label=x").await;
    assert_eq!(none.status, 403);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    h.finish().await;
}

#[sqlx::test]
async fn a_long_label_is_refused_and_no_token_is_made(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let body = format!("csrf={}&label={}", alice.csrf, "x".repeat(65));
    let made = h.post(&alice, "/tokens/create", &body).await;
    assert_eq!(made.status, 303);
    assert_eq!(made.location(), "/tokens?notice=invalid");
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM api_tokens")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    h.finish().await;
}

#[sqlx::test]
async fn the_token_list_is_the_users_own_and_labels_are_escaped(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    h.users
        .create_api_token(bob.user_id, "bob-laptop")
        .await
        .unwrap();
    h.users
        .create_api_token(alice.user_id, "<i onclick=alert('label-xss')>")
        .await
        .unwrap();
    let page = h.get(&alice, "/tokens").await;
    assert!(!page.body.contains("bob-laptop"));
    assert!(!page.body.contains("<i onclick"));
    assert!(page.body.contains("&lt;i onclick"));
    h.finish().await;
}

#[sqlx::test]
async fn revoking_works_for_the_owner_and_not_for_another_user(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let bobs = h.users.create_api_token(bob.user_id, "b").await.unwrap();
    let alices = h.users.create_api_token(alice.user_id, "a").await.unwrap();
    let body = format!("csrf={}&id={}", alice.csrf, bobs.id);
    let denied = h.post(&alice, "/tokens/revoke", &body).await;
    assert_eq!(denied.location(), "/tokens?notice=not_found");
    assert_eq!(
        h.users.authenticate(bobs.token.expose()).await.unwrap(),
        Some(bob.user_id)
    );
    let body = format!("csrf={}&id={}", alice.csrf, alices.id);
    let done = h.post(&alice, "/tokens/revoke", &body).await;
    assert_eq!(done.location(), "/tokens?notice=revoked");
    assert_eq!(
        h.users.authenticate(alices.token.expose()).await.unwrap(),
        None
    );
    let bad = h
        .post(&alice, "/tokens/revoke", &format!("id={}", alices.id))
        .await;
    assert_eq!(bad.status, 403);
    h.finish().await;
}

#[sqlx::test]
async fn only_an_https_pull_request_url_becomes_a_link(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    sqlx::query("UPDATE jobs SET pr_url = 'javascript:alert(1)' WHERE job_id = $1")
        .bind(&id)
        .execute(&h.pool)
        .await
        .unwrap();
    let detail = h.get(&alice, &format!("/jobs/{id}")).await;
    assert!(!detail.body.contains("href=\"javascript:"));
    assert!(detail.body.contains("javascript:alert(1)"));
    sqlx::query("UPDATE jobs SET pr_url = 'https://github.com/o/r/pull/1' WHERE job_id = $1")
        .bind(&id)
        .execute(&h.pool)
        .await
        .unwrap();
    let detail = h.get(&alice, &format!("/jobs/{id}")).await;
    assert!(
        detail
            .body
            .contains("href=\"https://github.com/o/r/pull/1\"")
    );
    h.finish().await;
}

#[sqlx::test]
async fn a_label_with_a_control_character_is_refused(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let body = format!("csrf={}&label=a%0Ab", alice.csrf);
    let made = h.post(&alice, "/tokens/create", &body).await;
    assert_eq!(made.location(), "/tokens?notice=invalid");
    h.finish().await;
}

fn said(role: &str, id: &str, block: &Value, parent: Option<&str>) -> Value {
    json!({"type": role, "message": {"id": id, "role": role, "content": [block],
        "usage": {"input_tokens": 3, "output_tokens": 20}}, "parent_tool_use_id": parent})
}

fn text(role: &str, id: &str, body: &str) -> Value {
    said(role, id, &json!({"type": "text", "text": body}), None)
}

fn call(msg: &str, tool: &str, name: &str, input: &Value, parent: Option<&str>) -> Value {
    said(
        "assistant",
        msg,
        &json!({"type": "tool_use", "id": tool, "name": name, "input": input}),
        parent,
    )
}

fn answer(tool: &str, body: &str, is_error: bool, parent: Option<&str>) -> Value {
    json!({"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": tool, "content": body, "is_error": is_error}]},
        "parent_tool_use_id": parent})
}

fn finale() -> Value {
    json!({"type": "result", "subtype": "success", "is_error": false, "duration_ms": 12345,
        "num_turns": 7, "result": "all done", "total_cost_usd": 0.4231,
        "usage": {"input_tokens": 111, "output_tokens": 222,
            "cache_read_input_tokens": 333, "cache_creation_input_tokens": 444},
        "permission_denials": [{"tool_name": "Bash"}, {"tool_name": "Edit"}]})
}

fn entries(body: &str) -> Vec<&str> {
    body.split("<li ")
        .skip(1)
        .filter(|part| part.contains("data-kind=\""))
        .collect()
}

fn kind_of<'a>(body: &'a str, kind: &str) -> Vec<&'a str> {
    let needle = format!("data-kind=\"{kind}\"");
    entries(body)
        .into_iter()
        .filter(|part| part.contains(&needle))
        .collect()
}

#[sqlx::test]
async fn the_transcript_renders_turns_pairs_and_the_result_footer(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(
        &id,
        &[
            text("user", "u1", "please fix it"),
            text("assistant", "m1", "on it"),
            call("m2", "t1", "Bash", &json!({"command": "cargo test"}), None),
            answer("t1", "all green", false, None),
            finale(),
        ],
    )
    .await;
    h.end(&id).await;
    let page = h.get(&alice, &format!("/jobs/{id}")).await;
    assert_eq!(page.status, 200);
    let body = &page.body;
    assert!(body.contains("<ol id=\"transcript\""), "{body}");
    assert!(body.contains("aria-label=\"Transcript entries\""));
    assert_eq!(kind_of(body, "message").len(), 2);
    let tool = kind_of(body, "tool");
    assert_eq!(tool.len(), 1);
    assert!(tool[0].contains("<details"));
    assert!(tool[0].contains("Bash"));
    assert!(tool[0].contains("cargo test"));
    assert!(tool[0].contains("all green"));
    assert!(tool[0].contains("data-status=\"ok\""));
    let result = kind_of(body, "result");
    assert_eq!(result.len(), 1);
    for want in [
        "$0.4231", "12.3 s", "111", "222", "333", "444", "Turns", "Denials",
    ] {
        assert!(result[0].contains(want), "{want}: {}", result[0]);
    }
    assert!(result[0].contains(">7<"));
    assert!(result[0].contains(">2<"));
    assert!(!body.contains("<pre id=\"transcript\""));
    assert!(!body.contains("id=\"cut\""));
    h.finish().await;
}

fn finale_with(usage: &Value) -> Value {
    json!({"type": "result", "subtype": "success", "is_error": false, "duration_ms": 1000,
        "num_turns": 1, "total_cost_usd": 0.5, "usage": usage, "permission_denials": []})
}

#[sqlx::test]
async fn absent_cache_figures_get_no_rows_and_a_real_zero_stays(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let cases = [
        (json!({"input_tokens": 5, "output_tokens": 6}), false, false),
        (
            json!({"input_tokens": 5, "output_tokens": 6, "cache_read_input_tokens": 0}),
            true,
            false,
        ),
        (
            json!({"input_tokens": 5, "output_tokens": 6, "cache_creation_input_tokens": 0}),
            false,
            true,
        ),
        (
            json!({"cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}),
            true,
            true,
        ),
    ];
    for (n, (usage, read, write)) in cases.iter().enumerate() {
        let id = h.job(&alice, &format!("a{n}"), "p").await;
        h.lines(&id, &[finale_with(usage)]).await;
        h.end(&id).await;
        let page = h.get(&alice, &format!("/jobs/{id}")).await;
        let result = kind_of(&page.body, "result");
        assert_eq!(result.len(), 1, "{usage}");
        assert_eq!(
            result[0].contains("Cache read"),
            *read,
            "{usage}: {}",
            result[0]
        );
        assert_eq!(
            result[0].contains("Cache write"),
            *write,
            "{usage}: {}",
            result[0]
        );
        assert!(
            result[0].contains(">Denials</dt><dd>0</dd>"),
            "{usage}: {}",
            result[0]
        );
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_result_footer_needs_a_result_entry(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(&id, &[text("assistant", "m1", "working")]).await;
    let page = h.get(&alice, &format!("/jobs/{id}")).await;
    assert_eq!(kind_of(&page.body, "result").len(), 0);
    assert!(!page.body.contains("Cost"));
    assert!(!page.body.contains("$0."));
    h.finish().await;
}

#[sqlx::test]
async fn an_error_pair_is_open_and_thinking_and_plain_pairs_are_closed(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(
        &id,
        &[
            said(
                "assistant",
                "m0",
                &json!({"type": "thinking", "thinking": "hmm", "signature": "s"}),
                None,
            ),
            call("m1", "t1", "Bash", &json!({"command": "ls"}), None),
            answer("t1", "fine", false, None),
            call("m2", "t2", "Bash", &json!({"command": "boom"}), None),
            answer("t2", "it broke", true, None),
        ],
    )
    .await;
    h.end(&id).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    let thinking = kind_of(&body, "thinking");
    assert_eq!(thinking.len(), 1);
    assert!(!thinking[0].contains("open=\"open\""));
    let tools = kind_of(&body, "tool");
    assert_eq!(tools.len(), 2);
    assert!(tools[0].contains("data-status=\"ok\""));
    assert!(!tools[0].contains("open=\"open\""));
    assert!(tools[1].contains("data-status=\"error\""));
    assert!(tools[1].contains("open=\"open\""));
    assert!(tools[1].contains("text-error"));
    assert!(tools[1].contains("border-l-error"));
    let page = text_page(&h, &alice, "assistant").await;
    let messages = kind_of(&page, "message");
    assert!(messages[0].contains("open=\"open\""));
    h.finish().await;
}

async fn text_page(h: &Harness, who: &Session, role: &str) -> String {
    let id = h.job(who, &format!("k-{role}"), "p").await;
    h.lines(&id, &[text(role, "m1", "hello")]).await;
    h.get(who, &format!("/jobs/{id}")).await.body
}

#[sqlx::test]
async fn sub_agent_children_sit_in_an_indented_wrapper(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(
        &id,
        &[
            call("m1", "t1", "Task", &json!({"description": "scan"}), None),
            call("m2", "t2", "Bash", &json!({"command": "grep"}), Some("t1")),
            answer("t2", "none", false, Some("t1")),
            text("assistant", "m3", "child said"),
        ],
    )
    .await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    let tools = kind_of(&body, "tool");
    assert_eq!(tools.len(), 2);
    assert!(!tools[0].contains("ml-4"));
    assert!(tools[1].contains("ml-4"));
    h.finish().await;
}

#[sqlx::test]
async fn a_fleet_note_is_neutral_and_a_forged_one_is_not_a_note(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.chunk(&id, 1, "fleet: no_changes").await;
    h.chunk(&id, 2, &text("assistant", "m1", "fleet: ok").to_string())
        .await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    let notes = kind_of(&body, "fleet-note");
    assert_eq!(notes.len(), 1);
    let note = notes[0];
    assert!(note.contains("tx-note"));
    assert!(note.contains(">note<"));
    assert!(note.contains("no_changes"));
    assert!(note.contains("text-base-content/60"));
    assert!(!note.contains("fleet:"));
    for banned in [
        "text-success",
        "text-warning",
        "text-error",
        "badge",
        "<details",
        "<a ",
        "font-bold",
        "text-accent",
    ] {
        assert!(!note.contains(banned), "{banned}: {note}");
    }
    assert_eq!(body.matches("tx-note").count(), 1);
    let messages = kind_of(&body, "message");
    assert_eq!(messages.len(), 1);
    assert!(messages[0].contains("fleet: ok"));
    assert!(!messages[0].contains("tx-note"));
    h.finish().await;
}

#[sqlx::test]
async fn raw_one_keeps_the_old_pre_block(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    let line = text("assistant", "m1", "hello raw");
    h.lines(&id, std::slice::from_ref(&line)).await;
    let raw = h.get(&alice, &format!("/jobs/{id}?raw=1")).await;
    assert_eq!(raw.status, 200);
    assert!(raw.body.contains("<pre id=\"transcript\""));
    assert!(raw.body.contains("hello raw"));
    assert!(!raw.body.contains("data-kind="));
    assert!(raw.body.contains("Pretty view"));
    let pretty = h.get(&alice, &format!("/jobs/{id}")).await;
    assert!(!pretty.body.contains("<pre id=\"transcript\""));
    assert!(pretty.body.contains(&format!("/jobs/{id}?raw=1")));
    let other = h.get(&alice, &format!("/jobs/{id}?raw=2")).await;
    assert!(!other.body.contains("<pre id=\"transcript\""));
    h.finish().await;
}

#[sqlx::test]
async fn raw_one_is_still_owner_scoped(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let theirs = h.job(&bob, "b1", "p").await;
    h.chunk(&theirs, 1, "bob secret raw").await;
    let reply = h.get(&alice, &format!("/jobs/{theirs}?raw=1")).await;
    assert_eq!(reply.status, 404);
    assert!(!reply.body.contains("bob secret"));
    h.finish().await;
}

#[sqlx::test]
async fn more_than_one_old_page_of_chunks_is_all_rendered(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.bulk(&id, 1_200, &text("assistant", "m1", "x").to_string())
        .await;
    h.end(&id).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    assert_eq!(kind_of(&body, "message").len(), 1_200);
    assert!(!body.contains("transcript cut"));
    assert!(!body.contains("id=\"cut\""));
    h.finish().await;
}

#[sqlx::test]
async fn the_row_ceiling_stops_paging_and_shows_the_cut(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.bulk(&id, 50_001, "").await;
    h.end(&id).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    assert!(body.contains("id=\"cut\""));
    assert!(body.contains("transcript cut"));
    assert!(body.contains("role=\"status\""));
    assert!(body.contains(&format!("/jobs/{id}?raw=1")));
    h.finish().await;
}

#[sqlx::test]
async fn exactly_the_row_ceiling_is_not_a_cut(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.bulk(&id, 50_000, "").await;
    h.end(&id).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    assert!(!body.contains("transcript cut"));
    h.finish().await;
}

#[sqlx::test]
async fn a_chunk_over_the_render_cap_is_cut_and_one_that_fits_is_not(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    let line = text("assistant", "m1", &"y".repeat(15_000)).to_string();
    let fit = MAX_RENDER_BYTES / line.len();
    h.bulk(&id, i64::try_from(fit).unwrap(), &line).await;
    h.end(&id).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    assert!(!body.contains("transcript cut"), "{fit}");
    assert_eq!(kind_of(&body, "message").len(), fit);
    let id = h.job(&alice, "a2", "p").await;
    h.bulk(&id, i64::try_from(fit).unwrap() + 1, &line).await;
    h.end(&id).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    assert!(body.contains("transcript cut"));
    assert_eq!(kind_of(&body, "message").len(), fit);
    h.finish().await;
}

#[sqlx::test]
async fn a_large_transcript_stays_small_and_fast(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    let line = json!({"type": "assistant", "message": {"id": "m", "content": [{"type": "text", "text": "a"}]}}).to_string();
    let count = i64::try_from(MAX_RENDER_BYTES / (line.len() + 1)).unwrap();
    h.bulk(&id, count, &line).await;
    h.end(&id).await;
    let start = Instant::now();
    let page = h.get(&alice, &format!("/jobs/{id}")).await;
    let took = start.elapsed();
    assert_eq!(page.status, 200);
    assert_eq!(
        kind_of(&page.body, "message").len(),
        usize::try_from(count).unwrap()
    );
    assert!(page.body.len() < 8 * 1024 * 1024, "{}", page.body.len());
    assert!(took < Duration::from_secs(15), "{took:?}");
    h.finish().await;
}

#[sqlx::test]
async fn the_empty_states_are_static_strings(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let queued = h.job(&alice, "a1", "p").await;
    let body = h.get(&alice, &format!("/jobs/{queued}")).await.body;
    assert!(body.contains("<p id=\"empty\""));
    assert!(body.contains("No transcript yet."));
    let finished = h.job(&alice, "a2", "p").await;
    h.end(&finished).await;
    let body = h.get(&alice, &format!("/jobs/{finished}")).await.body;
    assert!(body.contains("This job wrote no transcript."));
    assert!(!body.contains("No transcript yet."));
    let blank = h.job(&alice, "a3", "p").await;
    h.chunk(&blank, 1, "\n").await;
    let body = h.get(&alice, &format!("/jobs/{blank}")).await.body;
    assert!(body.contains("Transcript has no readable entries."));
    h.finish().await;
}

#[sqlx::test]
async fn hostile_values_are_escaped_on_every_field(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    let evil = |marker: &str| format!("<{marker}>\"'&<img src=x onerror=alert(1)>");
    let tool_id = format!("tid-MARK{}", "<>\"&'");
    h.lines(
        &id,
        &[
            text("assistant", "m1", &evil("MSG")),
            call(
                "m2",
                &tool_id,
                &evil("NAME"),
                &json!({"command": evil("SUMM"), "other": evil("INPUT")}),
                None,
            ),
            answer(&tool_id, &evil("OUT"), true, None),
            json!({"type": "zzz", "p": evil("UNK")}),
            said(
                "assistant",
                "m3",
                &json!({"type": "thinking", "thinking": evil("THINK"), "signature": "s"}),
                None,
            ),
        ],
    )
    .await;
    h.chunk(&id, 6, &format!("fleet: {}", evil("NOTE"))).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    for marker in ["MSG", "SUMM", "INPUT", "OUT", "UNK", "THINK", "NOTE"] {
        assert!(body.contains(&format!("&lt;{marker}&gt;")), "{marker}");
        assert!(!body.contains(&format!("<{marker}>")), "{marker}");
    }
    assert!(!body.contains("<img src=x"));
    assert!(!body.contains("onerror=alert(1)>"));
    assert!(!body.contains("tid-MARK"));
    assert!(!body.contains("<NAME>"));
    h.finish().await;
}

#[sqlx::test]
async fn line_breaks_escapes_and_length_are_neutralised(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    let hostile = "a\rb\r\nc\u{85}d\u{2028}e\u{2029}f\u{1b}[31mred\u{1b}[0m\u{202e}g";
    let long = "L".repeat(100_000);
    h.lines(
        &id,
        &[
            text("assistant", "m1", hostile),
            call("m2", "t1", "Bash", &json!({"command": hostile}), None),
            answer("t1", hostile, false, None),
            text("assistant", "m3", &long),
        ],
    )
    .await;
    h.chunk(&id, 5, &format!("fleet: {hostile}")).await;
    let page = h.get(&alice, &format!("/jobs/{id}")).await;
    assert_eq!(page.status, 200);
    for bad in ['\u{85}', '\u{2028}', '\u{2029}', '\u{1b}', '\u{202e}', '\r'] {
        assert!(!page.body.contains(bad), "{bad:?}");
    }
    assert!(page.body.contains("red"));
    assert!(page.body.matches('L').count() < 20_000);
    h.finish().await;
}

#[sqlx::test]
async fn the_transcript_page_has_no_inline_style_or_script(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(&id, &[text("assistant", "m1", "hi"), finale()])
        .await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    assert!(!body.contains(" style="));
    assert!(!body.contains("<style"));
    assert!(!body.contains(" onclick="));
    assert!(body.contains("id=\"tx-toolbar\""));
    assert!(body.contains("href=\"#tx-end\""));
    assert!(body.contains("id=\"tx-end\""));
    h.finish().await;
}

#[sqlx::test]
async fn the_raw_block_is_a_labelled_focusable_region(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(&id, &[text("assistant", "m1", "hello raw")]).await;
    let raw = h.get(&alice, &format!("/jobs/{id}?raw=1")).await.body;
    let tag = raw
        .split("<pre id=\"transcript\"")
        .nth(1)
        .and_then(|rest| rest.split('>').next())
        .unwrap_or_default();
    for want in [
        "tabindex=\"0\"",
        "role=\"region\"",
        "aria-label=\"Raw transcript\"",
    ] {
        assert!(tag.contains(want), "{want}: {tag}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn a_read_stopped_at_the_row_ceiling_says_the_count_is_unknown(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.bulk(&id, 50_001, "").await;
    h.end(&id).await;
    let page = h.get(&alice, &format!("/jobs/{id}")).await.body;
    let toolbar = page.split("id=\"tx-toolbar\"").nth(1).unwrap_or_default();
    let toolbar = toolbar.split("id=\"tx-end\"").next().unwrap_or_default();
    let cue = "the count of entries not shown is unknown";
    assert_eq!(toolbar.matches(cue).count(), 2, "{toolbar}");
    let raw = h.get(&alice, &format!("/jobs/{id}?raw=1")).await.body;
    assert!(raw.contains(cue));
    assert!(!page.contains("later entries not shown"));
    h.finish().await;
}

#[sqlx::test]
async fn a_collapsed_system_row_shows_its_subtype_in_the_summary(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(&id, &[json!({"type": "system", "subtype": "init"})])
        .await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    let system = kind_of(&body, "system");
    assert_eq!(system.len(), 1);
    let summary = system[0].split("</summary>").next().unwrap_or_default();
    assert!(
        summary.contains("<span class=\"text-xs text-base-content/60\">init</span>"),
        "{summary}"
    );
    h.finish().await;
}

#[sqlx::test]
async fn the_end_anchor_takes_focus_and_meta_values_can_shrink_and_break(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    h.lines(&id, &[text("assistant", "m1", "hi")]).await;
    let body = h.get(&alice, &format!("/jobs/{id}")).await.body;
    assert!(
        body.contains("<div id=\"tx-end\" tabindex=\"-1\">"),
        "{body}"
    );
    let meta = body
        .split("<dl class=\"grid grid-cols-[6rem_1fr]")
        .nth(1)
        .and_then(|rest| rest.split("</dl>").next())
        .unwrap_or_default();
    let cells = meta.matches("<dd").count();
    assert_eq!(cells, 9);
    assert_eq!(meta.matches("<dd class=\"min-w-0 break-all").count(), cells);
    h.finish().await;
}
