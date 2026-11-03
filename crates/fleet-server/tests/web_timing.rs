//! The job tasks page and its log stream over HTTP: session gate, owner scoping, status badges,
//! escaped and bounded log text, replay then follow, and resume by `Last-Event-ID`. The tests
//! need a Postgres superuser URL in `DATABASE_URL` and live in their own binary because they
//! bind a socket.

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
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const REPO: &str = "https://example.com/org/repo.git";
const HOSTILE: &str = "<script>alert('log-xss')</script> & \"quoted\"";

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

impl Harness {
    async fn start(pool: PgPool, configured: bool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let web = if configured {
            Web::with_console(auth, None, store.clone())
        } else {
            Web::new()
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

    async fn job(&self, who: &Session, key: &str) -> String {
        let request = SubmitJobRequest {
            idempotency_key: key.to_owned(),
            prompt: "task".to_owned(),
            repo: REPO.to_owned(),
            base_ref: "main".to_owned(),
            open_pr: false,
            agent: String::new(),
        };
        self.store
            .submit_job_for(Some(who.user_id), &request)
            .await
            .unwrap()
            .job_id
    }

    async fn chunk(&self, job_id: &str, command: &str, seq: i32, bytes: &[u8], status: &str) {
        sqlx::query(
            "INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(job_id)
        .bind(command)
        .bind(seq)
        .bind(bytes)
        .bind(status)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn command_text(&self, job_id: &str, command: &str, text: &str) {
        sqlx::query(
            "INSERT INTO job_shell_commands (job_id, seq, id, command, background, started_ms, \
             ended_ms, duration_ms, exit_code, log, log_truncated) \
             VALUES ($1, 0, $2, $3, true, 1, 2, 1, 0, '', false)",
        )
        .bind(job_id)
        .bind(command)
        .bind(text)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn get(&self, who: Option<&Session>, path: &str, extra: &[(&str, &str)]) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\n"
        );
        if let Some(who) = who {
            let _ = write!(request, "Cookie: {}\r\n", who.cookie);
        }
        for (key, value) in extra {
            let _ = write!(request, "{key}: {value}\r\n");
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

fn log_path(job: &str, command: &str) -> String {
    format!("/jobs/{job}/shell/{command}/log")
}

#[sqlx::test]
async fn the_routes_need_a_session(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let page = h.get(None, "/jobs/abc/timing", &[]).await;
    assert_eq!(page.status, 303);
    assert_eq!(page.header("location"), "/login");
    assert_eq!(h.get(None, &log_path("abc", "t1"), &[]).await.status, 401);
    h.finish().await;
}

#[sqlx::test]
async fn the_script_is_served_without_a_session(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let reply = h.get(None, "/static/tasklog.js", &[]).await;
    assert_eq!(reply.status, 200);
    assert!(reply.header("content-type").starts_with("text/javascript"));
    assert!(reply.body.contains("EventSource"));
    assert!(reply.body.contains("textContent"));
    assert!(!reply.body.contains("innerHTML"));
    h.finish().await;
}

#[sqlx::test]
async fn the_routes_are_off_when_web_auth_is_not_configured(pool: PgPool) {
    let h = Harness::start(pool, false).await;
    assert_eq!(h.get(None, "/jobs/abc/timing", &[]).await.status, 404);
    assert_eq!(h.get(None, &log_path("abc", "t1"), &[]).await.status, 404);
    assert_eq!(h.get(None, "/jobs/abc", &[]).await.status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn an_unknown_path_under_a_job_is_404(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    assert_eq!(h.get(Some(&alice), "/jobs/abc/nope", &[]).await.status, 404);
    h.finish().await;
}

#[sqlx::test]
async fn the_tasks_page_lists_each_task_with_a_status_badge(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let job = h.job(&alice, "k1").await;
    h.chunk(&job, "t-queued", 0, b"", "queued").await;
    h.chunk(&job, "t-run", 0, b"a", "running").await;
    h.chunk(&job, "t-done", 0, b"a", "running").await;
    h.chunk(&job, "t-done", 1, b"b", "done").await;
    h.chunk(&job, "t-fail", 0, b"a", "failed").await;
    h.command_text(&job, "t-run", HOSTILE).await;
    let reply = h
        .get(Some(&alice), &format!("/jobs/{job}/timing"), &[])
        .await;
    assert_eq!(reply.status, 200);
    for (task, status) in [
        ("t-queued", "queued"),
        ("t-run", "running"),
        ("t-done", "done"),
        ("t-fail", "failed"),
    ] {
        assert!(reply.body.contains(task), "{task}");
        let row = reply
            .body
            .split("<tr")
            .find(|row| row.contains(&format!("data-task=\"{task}\"")))
            .unwrap_or_else(|| panic!("no row for {task}"));
        assert!(row.contains(&format!(">{status}</span>")), "{task}: {row}");
        assert!(
            row.contains(&format!("data-log-url=\"{}\"", log_path(&job, task))),
            "{task}"
        );
    }
    assert!(!reply.body.contains("<script>alert"));
    assert!(reply.body.contains("&lt;script&gt;alert"));
    assert!(reply.body.contains("src=\"/static/tasklog.js\""));
    h.finish().await;
}

#[sqlx::test]
async fn another_users_job_is_not_found_like_an_unknown_one(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let bob = h.session("bob", 'b').await;
    let job = h.job(&alice, "k1").await;
    h.chunk(&job, "t1", 0, b"secret-output", "done").await;
    let unknown = "0".repeat(26);
    let timing = h.get(Some(&bob), &format!("/jobs/{job}/timing"), &[]).await;
    let timing_unknown = h
        .get(Some(&bob), &format!("/jobs/{unknown}/timing"), &[])
        .await;
    assert_eq!(timing.status, 404);
    assert_eq!(timing.body, timing_unknown.body);
    let stream = h.get(Some(&bob), &log_path(&job, "t1"), &[]).await;
    let stream_unknown = h.get(Some(&bob), &log_path(&unknown, "t1"), &[]).await;
    assert_eq!(stream.status, 404);
    assert_eq!(stream.status, stream_unknown.status);
    assert_eq!(stream.body, stream_unknown.body);
    assert!(!stream.body.contains("secret-output"));
    h.finish().await;
}

#[sqlx::test]
async fn a_bad_command_id_is_not_found(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let job = h.job(&alice, "k1").await;
    for command in ["a%20b", "a%3Cb", "%C3%A9", &"x".repeat(129)] {
        let reply = h.get(Some(&alice), &log_path(&job, command), &[]).await;
        assert_eq!(reply.status, 404, "{command}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn the_stream_replays_chunks_then_ends_on_done(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let job = h.job(&alice, "k1").await;
    h.chunk(&job, "t1", 0, b"first line\n", "running").await;
    h.chunk(&job, "t1", 1, b"second line\n", "done").await;
    let reply = h.get(Some(&alice), &log_path(&job, "t1"), &[]).await;
    assert_eq!(reply.status, 200);
    assert!(
        reply
            .header("content-type")
            .starts_with("text/event-stream")
    );
    assert_eq!(reply.header("x-content-type-options"), "nosniff");
    let first = reply.body.find("first line").unwrap();
    let second = reply.body.find("second line").unwrap();
    assert!(first < second);
    assert!(reply.body.contains("id: 0\n"));
    assert!(reply.body.contains("id: 1\n"));
    assert!(
        reply
            .body
            .contains("event: end\ndata: {\"status\":\"done\"}")
    );
    h.finish().await;
}

#[sqlx::test]
async fn the_stream_follows_a_chunk_that_arrives_late(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let job = h.job(&alice, "k1").await;
    h.chunk(&job, "t1", 0, b"early\n", "running").await;
    let late = {
        let pool = h.pool.clone();
        let job = job.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(700)).await;
            sqlx::query(
                "INSERT INTO job_shell_log_chunks (job_id, command_id, seq, bytes, status) \
                 VALUES ($1, 't1', 1, 'late\n', 'failed')",
            )
            .bind(&job)
            .execute(&pool)
            .await
            .unwrap();
        })
    };
    let reply = h.get(Some(&alice), &log_path(&job, "t1"), &[]).await;
    late.await.unwrap();
    assert!(reply.body.contains("early"));
    assert!(reply.body.contains("late"));
    assert!(reply.body.contains("\"status\":\"failed\""));
    assert!(
        reply
            .body
            .contains("event: end\ndata: {\"status\":\"failed\"}")
    );
    h.finish().await;
}

#[sqlx::test]
async fn last_event_id_resumes_after_that_chunk(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let job = h.job(&alice, "k1").await;
    h.chunk(&job, "t1", 0, b"seen-already\n", "running").await;
    h.chunk(&job, "t1", 1, b"new-output\n", "done").await;
    let reply = h
        .get(
            Some(&alice),
            &log_path(&job, "t1"),
            &[("Last-Event-ID", "0")],
        )
        .await;
    assert!(!reply.body.contains("seen-already"));
    assert!(reply.body.contains("new-output"));
    h.finish().await;
}

#[sqlx::test]
async fn hostile_log_text_is_stripped_and_escaped_on_the_wire(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let job = h.job(&alice, "k1").await;
    let hostile = "esc\u{1b}[31mred cr\rback nel\u{85}next ls\u{2028}x ps\u{2029}y bell\u{7} "
        .to_owned()
        + HOSTILE
        + "\n";
    h.chunk(&job, "t1", 0, hostile.as_bytes(), "done").await;
    let reply = h.get(Some(&alice), &log_path(&job, "t1"), &[]).await;
    assert_eq!(reply.status, 200);
    let data: String = reply
        .body
        .lines()
        .filter(|line| line.starts_with("data:"))
        .collect();
    assert!(data.contains("red crback"));
    for bad in ['\u{1b}', '\r', '\u{85}', '\u{2028}', '\u{2029}', '\u{7}'] {
        assert!(
            !reply.body.contains(bad) || bad == '\r',
            "raw {bad:?} reached the wire"
        );
        assert!(!data.contains(bad), "raw {bad:?} in a data line");
    }
    assert!(!reply.body.contains("<script"));
    assert!(!reply.body.contains('<'));
    assert!(!reply.body.contains("&amp"));
    assert!(reply.body.contains("\\u003cscript\\u003ealert"));
    assert!(reply.body.contains("red crback"));
    h.finish().await;
}

#[sqlx::test]
async fn a_long_line_is_cut_and_a_split_character_is_kept(pool: PgPool) {
    let h = Harness::start(pool, true).await;
    let alice = h.session("alice", 'a').await;
    let job = h.job(&alice, "k1").await;
    let long = "x".repeat(4000) + "\n";
    h.chunk(&job, "t1", 0, long.as_bytes(), "running").await;
    let euro = "\u{20ac}".as_bytes();
    let mut split_a = b"ok-".to_vec();
    split_a.extend_from_slice(&euro[..1]);
    let mut split_b = euro[1..].to_vec();
    split_b.extend_from_slice(b"-end\n");
    h.chunk(&job, "t1", 1, &split_a, "running").await;
    h.chunk(&job, "t1", 2, &split_b, "done").await;
    let reply = h.get(Some(&alice), &log_path(&job, "t1"), &[]).await;
    assert!(!reply.body.contains(&"x".repeat(2100)));
    assert!(reply.body.contains(&"x".repeat(2000)));
    assert!(reply.body.contains("\u{2026}"));
    assert!(reply.body.contains("\u{20ac}-end"));
    assert!(!reply.body.contains('\u{fffd}'));
    h.finish().await;
}
