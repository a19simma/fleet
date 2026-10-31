//! The jobs pages and the API token page over HTTP: session and CSRF gates, owner scoping,
//! escaped transcripts and the token shown once. The tests need a Postgres superuser URL in
//! `DATABASE_URL` for `#[sqlx::test]` and live in their own binary because each one binds a
//! socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::time::Duration;

use fleet_proto::v1::SubmitJobRequest;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{MAX_RENDER_BYTES, SESSION_COOKIE, Web, WebAuth};
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
async fn more_chunks_than_one_page_shows_the_cut_marker(pool: PgPool) {
    let h = Harness::start(pool).await;
    let alice = h.session("alice", 'a').await;
    let id = h.job(&alice, "a1", "p").await;
    for seq in 1..=101 {
        h.chunk(&id, seq, "x").await;
    }
    let detail = h.get(&alice, &format!("/jobs/{id}")).await;
    assert!(detail.body.contains("transcript cut"));
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
