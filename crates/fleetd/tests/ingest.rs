//! Drives the real routers over a temp SQLite file and a temp unix socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use fleet_core::{Envelope, EventId, HookAllowlist, Identity, Redactor, Source};
use fleetd::{
    AppState, Enqueued, Limits, Store, bind_socket, dump, fresh_id, hook_router, now_ms,
    socket_router,
};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tower::ServiceExt;

const BIG: Limits = Limits {
    max_bytes: u64::MAX,
    max_age: Duration::from_secs(14 * 86_400),
};

fn identity() -> Identity {
    Identity {
        box_name: "alpha".into(),
        hostname: "host".into(),
        machine_id: "machine".into(),
        boot_id: "boot".into(),
    }
}

struct Harness {
    dir: TempDir,
    queue: Store,
    state: Arc<AppState>,
}

impl Harness {
    async fn new(limits: Limits, redactor: Redactor) -> Self {
        let dir = TempDir::new().unwrap();
        let queue = Store::open(&dir.path().join("q.db"), limits).await.unwrap();
        let state = AppState::new(
            queue.clone(),
            identity(),
            HookAllowlist::default(),
            redactor,
            Duration::from_secs(10),
        );
        Self { dir, queue, state }
    }

    fn db(&self) -> std::path::PathBuf {
        self.dir.path().join("q.db")
    }

    async fn post(&self, path: &str, body: &str) -> (StatusCode, Value) {
        let response = hook_router(self.state.clone())
            .oneshot(
                Request::post(path)
                    .body(Body::from(body.to_owned()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

fn stop_body(prompt_id: &str) -> String {
    json!({
        "session_id": "s-1",
        "transcript_path": "/t.jsonl",
        "cwd": "/work/wd",
        "prompt_id": prompt_id,
        "permission_mode": "auto",
        "effort": {"level": "low"},
        "hook_event_name": "Stop",
        "stop_hook_active": false,
        "last_assistant_message": "ok",
        "background_tasks": [],
        "session_crons": []
    })
    .to_string()
}

fn prompt_body(prompt: &str) -> String {
    json!({
        "cwd": "/work/wd",
        "hook_event_name": "UserPromptSubmit",
        "permission_mode": "auto",
        "prompt": prompt,
        "prompt_id": "p-1",
        "session_id": "s-1",
        "transcript_path": "/t.jsonl"
    })
    .to_string()
}

fn envelope(kind: &str, ts: u64, pad: usize) -> Envelope {
    let mut env = Envelope::new(&identity(), fresh_id(ts), Source::Fleetd, kind, ts);
    env.payload = json!({ "pad": "x".repeat(pad) });
    env
}

async fn uds(path: &Path, target: &str, body: &str) -> (u16, Value) {
    let mut stream = UnixStream::connect(path).await.unwrap();
    let request = format!(
        "POST {target} HTTP/1.1\r\nHost: local\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8(raw).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, serde_json::from_str(body).unwrap_or(Value::Null))
}

#[tokio::test]
async fn hooks_enqueue_in_order_and_answer_empty_object() {
    let h = Harness::new(BIG, Redactor::default()).await;
    let (s1, b1) = h.post("/hook/UserPromptSubmit", &prompt_body("hi")).await;
    let (s2, b2) = h.post("/hook/Stop", &stop_body("p-1")).await;
    let end = json!({"cwd": "/w", "hook_event_name": "SessionEnd", "reason": "other", "session_id": "s-1", "transcript_path": "/t.jsonl"});
    let (s3, _) = h.post("/hook/SessionEnd", &end.to_string()).await;
    assert_eq!(
        (s1, s2, s3),
        (StatusCode::OK, StatusCode::OK, StatusCode::OK)
    );
    assert_eq!(b1, json!({}));
    assert_eq!(b2, json!({}));

    let rows = h.queue.list(None).await.unwrap();
    let kinds: Vec<_> = rows.iter().map(|r| r.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["hook.user_prompt_submit", "hook.stop", "hook.session_end"]
    );
    assert!(rows.windows(2).all(|w| w[0].seq < w[1].seq));
    assert!(rows.iter().all(|r| r.state == "pending" && r.attempts == 0));
    let stop = &rows[1].payload;
    assert_eq!(stop["box"], "alpha");
    assert_eq!(stop["session_id"], "s-1");
    assert_eq!(stop["payload"]["last_assistant_message"], "ok");
    assert_eq!(stop["payload"]["raw"]["hook_event_name"], "Stop");
}

#[tokio::test]
async fn repeated_hook_body_is_stored_once() {
    let h = Harness::new(BIG, Redactor::default()).await;
    for _ in 0..3 {
        let (status, _) = h.post("/hook/Stop", &stop_body("p-1")).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(h.queue.count().await.unwrap(), 1);
    h.post("/hook/Stop", &stop_body("p-2")).await;
    assert_eq!(h.queue.count().await.unwrap(), 2);
}

#[tokio::test]
async fn synthetic_hand_back_is_flagged() {
    let h = Harness::new(BIG, Redactor::default()).await;
    h.post(
        "/hook/UserPromptSubmit",
        &prompt_body("<agent-message from=\"x\">hi</agent-message>"),
    )
    .await;
    let rows = h.queue.list(None).await.unwrap();
    assert_eq!(rows[0].payload["payload"]["synthetic"], true);
}

#[tokio::test]
async fn unknown_event_is_dropped_with_200() {
    let h = Harness::new(BIG, Redactor::default()).await;
    let (status, body) = h
        .post(
            "/hook/PreToolUse",
            &json!({"tool_name": "Bash"}).to_string(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({}));
    let (status, _) = h.post("/hook/..weird", "{}").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.queue.count().await.unwrap(), 0);
}

#[tokio::test]
async fn malformed_bodies_get_400_and_the_server_keeps_working() {
    let h = Harness::new(BIG, Redactor::default()).await;
    for body in ["", "{not json", "[1,2]", "\"str\"", "42", "null"] {
        let (status, payload) = h.post("/hook/Stop", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body {body:?}");
        assert!(payload["error"].is_string());
    }
    assert_eq!(h.queue.count().await.unwrap(), 0);
    let (status, _) = h.post("/hook/Stop", &stop_body("p-1")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.queue.count().await.unwrap(), 1);
}

#[tokio::test]
async fn healthz_answers_ok() {
    let h = Harness::new(BIG, Redactor::default()).await;
    let response = hook_router(h.state.clone())
        .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn secrets_are_scrubbed_before_commit() {
    let h = Harness::new(BIG, Redactor::new(["sk-live-0123456789"])).await;
    h.post(
        "/hook/UserPromptSubmit",
        &prompt_body("use sk-live-0123456789 and sk-live-0123456789"),
    )
    .await;
    let rows = h.queue.list(None).await.unwrap();
    let stored = rows[0].payload.to_string();
    assert!(!stored.contains("sk-live-0123456789"));
    assert!(stored.contains("[REDACTED]"));
}

#[tokio::test]
async fn queue_ignores_a_repeated_id() {
    let h = Harness::new(BIG, Redactor::default()).await;
    let env = envelope("fleetd.started", now_ms(), 10);
    let first = h.queue.enqueue(&env, now_ms()).await.unwrap();
    let second = h.queue.enqueue(&env, now_ms()).await.unwrap();
    let Enqueued::Stored { seq } = first else {
        panic!("first enqueue not stored: {first:?}");
    };
    assert_eq!(second, Enqueued::Duplicate { seq });
    assert_eq!(h.queue.count().await.unwrap(), 1);
}

fn size_of(kind: &str, pad: usize) -> u64 {
    serde_json::to_string(&envelope(kind, now_ms(), pad))
        .unwrap()
        .len() as u64
}

#[tokio::test]
async fn full_queue_drops_tool_events_before_anything_else() {
    let now = now_ms();
    let cap = size_of("hook.stop", 200) * 4;
    let h = Harness::new(
        Limits {
            max_bytes: cap,
            ..BIG
        },
        Redactor::default(),
    )
    .await;
    for kind in ["hook.stop", "workmux.status_changed"] {
        h.queue
            .enqueue(&envelope(kind, now, 200), now)
            .await
            .unwrap();
    }
    for _ in 0..6 {
        h.queue
            .enqueue(&envelope("hook.pre_tool_use", now, 200), now)
            .await
            .unwrap();
    }
    let rows = h.queue.list(None).await.unwrap();
    let count = |kind: &str| rows.iter().filter(|r| r.kind == kind).count();
    assert_eq!(count("hook.stop"), 1);
    assert_eq!(count("workmux.status_changed"), 1);
    assert!(count("hook.pre_tool_use") < 6);
    let total: u64 = rows
        .iter()
        .map(|r| r.payload.to_string().len() as u64)
        .sum();
    assert!(total <= cap);
}

#[tokio::test]
async fn overflow_is_reported_once_and_the_count_accumulates() {
    let now = now_ms();
    let cap = size_of("hook.stop", 400) * 5;
    let h = Harness::new(
        Limits {
            max_bytes: cap,
            ..BIG
        },
        Redactor::default(),
    )
    .await;
    for kind in ["hook.stop", "workmux.status_changed"]
        .into_iter()
        .chain(std::iter::repeat_n("hook.pre_tool_use", 8))
    {
        let body = serde_json::to_string(&envelope(kind, now, 400)).unwrap();
        let (status, _) = post_event(&h, &body).await;
        assert_eq!(status, 200);
    }
    let rows = h.queue.list(None).await.unwrap();
    let tools = rows
        .iter()
        .filter(|r| r.kind == "hook.pre_tool_use")
        .count() as u64;
    assert!(rows.iter().any(|r| r.kind == "hook.stop"));
    assert!(rows.iter().any(|r| r.kind == "workmux.status_changed"));
    let overflow: Vec<_> = rows
        .iter()
        .filter(|r| r.kind == fleetd::OVERFLOW_KIND)
        .collect();
    assert_eq!(overflow.len(), 1);
    let report = &overflow[0].payload;
    assert_eq!(report["source"], "fleetd");
    assert!(tools < 8);
    assert_eq!(report["payload"]["dropped"].as_u64().unwrap() + tools, 8);
}

async fn post_event(h: &Harness, body: &str) -> (u16, Value) {
    let response = socket_router(h.state.clone())
        .oneshot(
            Request::post("/event")
                .body(Body::from(body.to_owned()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status().as_u16();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

#[tokio::test]
async fn new_event_is_dropped_when_everything_stored_outranks_it() {
    let now = now_ms();
    let size = serde_json::to_string(&envelope("hook.stop", now, 200))
        .unwrap()
        .len() as u64;
    let h = Harness::new(
        Limits {
            max_bytes: size * 2 + 50,
            ..BIG
        },
        Redactor::default(),
    )
    .await;
    for _ in 0..2 {
        h.queue
            .enqueue(&envelope("hook.stop", now, 200), now)
            .await
            .unwrap();
    }
    let outcome = h
        .queue
        .enqueue(&envelope("hook.pre_tool_use", now, 200), now)
        .await
        .unwrap();
    assert_eq!(outcome, Enqueued::Dropped);
    assert_eq!(h.queue.count().await.unwrap(), 2);
}

#[tokio::test]
async fn events_older_than_max_age_are_dropped() {
    let h = Harness::new(
        Limits {
            max_age: Duration::from_secs(1),
            ..BIG
        },
        Redactor::default(),
    )
    .await;
    h.queue
        .enqueue(&envelope("hook.stop", 1_000, 10), 1_000)
        .await
        .unwrap();
    let outcome = h
        .queue
        .enqueue(&envelope("hook.stop", 100_000, 10), 100_000)
        .await
        .unwrap();
    assert!(matches!(outcome, Enqueued::Stored { .. }));
    let rows = h.queue.list(None).await.unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].kind, "hook.stop");
    assert_eq!(rows[1].kind, fleetd::OVERFLOW_KIND);
    assert_eq!(rows[1].payload["payload"]["dropped"], 1);
}

#[tokio::test]
async fn unix_socket_accepts_envelopes_with_mode_0600() {
    let h = Harness::new(BIG, Redactor::default()).await;
    let sock = h.dir.path().join("f.sock");
    let listener = bind_socket(&sock).unwrap();
    assert_eq!(
        std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let server = tokio::spawn(axum::serve(listener, socket_router(h.state.clone())).into_future());

    let env = envelope("fleetd.started", now_ms(), 5);
    let body = serde_json::to_string(&env).unwrap();
    let (status, first) = uds(&sock, "/event", &body).await;
    assert_eq!(status, 200);
    assert_eq!(first["duplicate"], false);
    let (_, again) = uds(&sock, "/event", &body).await;
    assert_eq!(again["duplicate"], true);
    assert_eq!(again["seq"], first["seq"]);
    assert_eq!(h.queue.count().await.unwrap(), 1);

    let (status, err) = uds(&sock, "/event", "{\"kind\": 1}").await;
    assert_eq!(status, 400);
    assert!(err["error"].is_string());
    let bad_payload = json!({
        "id": EventId::new(1, 1), "box": "b", "hostname": "h", "machine_id": "m", "boot_id": "o",
        "source": "job", "kind": "job.result", "ts": 1, "payload": [1]
    });
    let (status, _) = uds(&sock, "/event", &bad_payload.to_string()).await;
    assert_eq!(status, 400);

    let (status, body) = uds(&sock, "/hook/Stop", &stop_body("p-9")).await;
    assert_eq!((status, body), (200, json!({})));
    assert_eq!(h.queue.count().await.unwrap(), 2);
    server.abort();
}

#[tokio::test]
async fn bind_replaces_a_stale_socket_file() {
    let dir = TempDir::new().unwrap();
    let sock = dir.path().join("s.sock");
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());
    assert!(bind_socket(&sock).is_ok());
}

#[tokio::test]
async fn bind_refuses_a_regular_file_and_a_live_socket() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("file");
    std::fs::write(&file, b"data").unwrap();
    assert!(bind_socket(&file).is_err());
    assert_eq!(std::fs::read(&file).unwrap(), b"data");

    let live = dir.path().join("live.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&live).unwrap();
    assert!(bind_socket(&live).is_err());
    assert!(live.exists());
}

#[tokio::test]
async fn oversized_event_is_dropped_without_wiping_the_queue() {
    let now = now_ms();
    let cap = size_of("hook.stop", 200) * 2;
    let h = Harness::new(
        Limits {
            max_bytes: cap,
            ..BIG
        },
        Redactor::default(),
    )
    .await;
    h.queue
        .enqueue(&envelope("hook.stop", now, 200), now)
        .await
        .unwrap();
    let outcome = h
        .queue
        .enqueue(&envelope("hook.stop", now, 5_000), now)
        .await
        .unwrap();
    assert_eq!(outcome, Enqueued::Dropped);
    assert_eq!(h.queue.count().await.unwrap(), 1);
}

#[tokio::test]
async fn corrupt_queue_file_is_moved_aside_and_replaced() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("q.db");
    std::fs::write(&path, vec![b'x'; 4096]).unwrap();
    let queue = Store::open(&path, BIG).await.unwrap();
    assert_eq!(queue.count().await.unwrap(), 0);
    let moved: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("q.db.corrupt-"))
        .collect();
    assert_eq!(moved.len(), 1);
}

#[tokio::test]
async fn database_from_before_migrations_opens_and_keeps_rows() {
    use sqlx::Connection;
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("q.db");
    let mut conn =
        sqlx::SqliteConnection::connect(&format!("sqlite://{}?mode=rwc", path.display()))
            .await
            .unwrap();
    for statement in [
        "CREATE TABLE events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT NOT NULL UNIQUE,
            ts INTEGER NOT NULL,
            kind TEXT NOT NULL,
            priority INTEGER NOT NULL,
            payload TEXT NOT NULL,
            state TEXT NOT NULL DEFAULT 'pending',
            attempts INTEGER NOT NULL DEFAULT 0,
            next_try_at INTEGER NOT NULL DEFAULT 0
        )",
        "CREATE INDEX events_drop_order ON events (priority, seq)",
        "CREATE INDEX events_ts ON events (ts)",
        "INSERT INTO events (id, ts, kind, priority, payload) VALUES ('old', 1, 'hook.stop', 3, '{}')",
    ] {
        sqlx::query(statement).execute(&mut conn).await.unwrap();
    }
    conn.close().await.unwrap();
    let store = Store::open(&path, BIG).await.unwrap();
    assert_eq!(store.count().await.unwrap(), 1);
    let again = Store::open(&path, BIG).await.unwrap();
    assert_eq!(again.count().await.unwrap(), 1);
}

#[tokio::test]
async fn hook_router_refuses_browser_origin_and_foreign_host() {
    let h = Harness::new(BIG, Redactor::default()).await;
    let send = |header: &'static str, value: &'static str| {
        let router = hook_router(h.state.clone());
        async move {
            router
                .oneshot(
                    Request::post("/hook/Stop")
                        .header(header, value)
                        .body(Body::from(stop_body("p-1")))
                        .unwrap(),
                )
                .await
                .unwrap()
                .status()
        }
    };
    assert_eq!(
        send("origin", "https://evil.example").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        send("host", "evil.example:7071").await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(send("host", "127.0.0.1:7071").await, StatusCode::OK);
    assert_eq!(send("host", "localhost").await, StatusCode::OK);
    assert_eq!(send("host", "[::1]:7071").await, StatusCode::OK);
    assert_eq!(h.queue.count().await.unwrap(), 1);
}

#[tokio::test]
async fn dump_writes_json_lines_in_seq_order() {
    let h = Harness::new(BIG, Redactor::default()).await;
    h.post("/hook/UserPromptSubmit", &prompt_body("hi")).await;
    h.post("/hook/Stop", &stop_body("p-1")).await;
    h.post("/hook/Stop", &stop_body("p-2")).await;

    let mut out = Vec::new();
    dump(&h.db(), Some(2), &mut out).await.unwrap();
    let lines: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["kind"], "hook.user_prompt_submit");
    assert_eq!(lines[1]["kind"], "hook.stop");
    assert!(lines[0]["seq"].as_i64() < lines[1]["seq"].as_i64());
    assert_eq!(
        lines[1]["envelope"]["payload"]["last_assistant_message"],
        "ok"
    );
}

#[tokio::test]
async fn dump_subcommand_prints_the_queue() {
    let h = Harness::new(BIG, Redactor::default()).await;
    h.post("/hook/Stop", &stop_body("p-1")).await;
    h.post("/hook/Stop", &stop_body("p-2")).await;
    let db = h.db();
    h.queue.clone().close().await.unwrap();

    let bin = env!("CARGO_BIN_EXE_fleetd");
    let run = |args: &[&str], db: &Path| {
        Command::new(bin)
            .env_clear()
            .env("FLEETD_DB", db)
            .args(args)
            .output()
            .unwrap()
    };
    let all = run(&["dump"], &db);
    assert!(all.status.success());
    assert_eq!(String::from_utf8(all.stdout).unwrap().lines().count(), 2);
    let one = run(&["dump", "--limit", "1"], &db);
    assert_eq!(String::from_utf8(one.stdout).unwrap().lines().count(), 1);
    let missing = run(&["dump"], &db.with_file_name("absent.db"));
    assert!(!missing.status.success());
}

#[test]
fn pueue_callback_is_a_stub() {
    let out = Command::new(env!("CARGO_BIN_EXE_fleetd"))
        .env_clear()
        .args(["pueue-callback", "7", "fleet"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("not implemented"));
}
