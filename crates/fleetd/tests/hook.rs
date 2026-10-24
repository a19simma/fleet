//! Drives `forward_hook` against a real listener over a temp SQLite file.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fleet_core::{HookAllowlist, Identity, Redactor};
use fleetd::{
    AppState, Config, Limits, Store, bind_socket, forward_hook, forward_hook_as, hook_router,
    socket_router,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PAYLOAD: &str = r#"{"session_id":"s1","transcript_path":"/t/s1.jsonl","cwd":"/work","hook_event_name":"SessionStart","source":"startup"}"#;

async fn state(dir: &TempDir) -> (Arc<AppState>, Store) {
    let store = Store::open(
        &dir.path().join("q.db"),
        Limits {
            max_bytes: u64::MAX,
            max_age: Duration::from_secs(86_400),
        },
    )
    .await
    .unwrap();
    let state = AppState::new(
        store.clone(),
        Identity {
            box_name: "alpha".into(),
            hostname: "host".into(),
            machine_id: "machine".into(),
            boot_id: "boot".into(),
        },
        HookAllowlist::default(),
        Redactor::default(),
        Duration::from_secs(10),
    );
    (state, store)
}

fn config(dir: &TempDir, port: u16) -> Config {
    let file = format!(
        "http_port = {port}\nsocket_path = \"{}\"\n",
        dir.path().join("fleetd.sock").display()
    );
    Config::resolve(Some(&file), &|_| None).unwrap()
}

async fn kinds(store: &Store) -> Vec<String> {
    store
        .list(None)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.kind)
        .collect()
}

#[tokio::test]
async fn posts_session_start_over_the_unix_socket() {
    let dir = TempDir::new().unwrap();
    let (state, store) = state(&dir).await;
    let config = config(&dir, 1);
    let listener = bind_socket(&config.socket_path).unwrap();
    tokio::spawn(async move { axum::serve(listener, socket_router(state)).await });
    forward_hook(&config, "SessionStart", PAYLOAD.as_bytes())
        .await
        .unwrap();
    assert_eq!(kinds(&store).await, vec!["hook.session_start".to_owned()]);
}

#[tokio::test]
async fn posts_session_start_over_loopback_tcp() {
    let dir = TempDir::new().unwrap();
    let (state, store) = state(&dir).await;
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(&dir, tcp.local_addr().unwrap().port());
    tokio::spawn(async move { axum::serve(tcp, hook_router(state)).await });
    forward_hook(&config, "SessionStart", PAYLOAD.as_bytes())
        .await
        .unwrap();
    assert_eq!(kinds(&store).await, vec!["hook.session_start".to_owned()]);
}

#[tokio::test]
async fn unreachable_server_is_an_error_the_caller_can_swallow() {
    let dir = TempDir::new().unwrap();
    let port = {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        tcp.local_addr().unwrap().port()
    };
    let config = config(&dir, port);
    let result = forward_hook(&config, "SessionStart", PAYLOAD.as_bytes()).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn rejects_oversized_input_and_bad_event_names() {
    let dir = TempDir::new().unwrap();
    let config = config(&dir, 1);
    let big = vec![b'a'; 1024 * 1024 + 1];
    assert!(
        forward_hook(&config, "SessionStart", big.as_slice())
            .await
            .is_err()
    );
    assert!(
        forward_hook(&config, "../x", PAYLOAD.as_bytes())
            .await
            .is_err()
    );
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn counting_tcp(
    status_line: &'static str,
) -> Result<(u16, Arc<AtomicUsize>), Box<dyn std::error::Error>> {
    let tcp = TcpListener::bind("127.0.0.1:0").await?;
    let port = tcp.local_addr()?.port();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = tcp.accept().await else {
                break;
            };
            seen.fetch_add(1, Ordering::SeqCst);
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(status_line.as_bytes()).await;
        }
    });
    Ok((port, count))
}

#[tokio::test]
async fn a_unix_500_is_final_and_sends_no_tcp_request() -> TestResult {
    let dir = TempDir::new()?;
    let (port, count) =
        counting_tcp("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await?;
    let config = config(&dir, port);
    let sock = bind_socket(&config.socket_path)?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = sock.accept().await else {
                break;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let result = forward_hook(&config, "SessionStart", PAYLOAD.as_bytes()).await;
    assert!(result.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn a_unix_connect_failure_falls_back_to_one_tcp_request() -> TestResult {
    let dir = TempDir::new()?;
    let (port, count) =
        counting_tcp("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await?;
    let config = config(&dir, port);
    drop(bind_socket(&config.socket_path)?);
    forward_hook(&config, "SessionStart", PAYLOAD.as_bytes()).await?;
    assert_eq!(count.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_hung_unix_server_still_lets_tcp_run() -> TestResult {
    let dir = TempDir::new()?;
    let (port, count) =
        counting_tcp("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await?;
    let config = config(&dir, port);
    let sock = bind_socket(&config.socket_path)?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = sock.accept().await {
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(30)).await;
                drop(stream);
            });
        }
    });
    let started = std::time::Instant::now();
    forward_hook(&config, "SessionStart", PAYLOAD.as_bytes()).await?;
    assert!(started.elapsed() < Duration::from_millis(2_000));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test]
async fn a_unix_close_without_a_status_line_fails_without_replay() -> TestResult {
    let dir = TempDir::new()?;
    let (port, count) =
        counting_tcp("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await?;
    let config = config(&dir, port);
    let dead = bind_socket(&config.socket_path)?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = dead.accept().await else {
                break;
            };
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf).await;
        }
    });
    let result = forward_hook(&config, "SessionStart", PAYLOAD.as_bytes()).await;
    assert!(result.is_err());
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count.load(Ordering::SeqCst), 0);
    Ok(())
}

async fn captured_request(job: Option<&str>) -> String {
    let dir = TempDir::new().unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = config(&dir, tcp.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 1024];
        while !seen.ends_with(PAYLOAD.as_bytes()) {
            let n = stream.read(&mut buf).await.unwrap();
            assert_ne!(n, 0);
            seen.extend_from_slice(buf.get(..n).unwrap());
        }
        stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        String::from_utf8(seen).unwrap()
    });
    forward_hook_as(&config, "SessionStart", PAYLOAD.as_bytes(), job)
        .await
        .unwrap();
    server.await.unwrap()
}

#[tokio::test]
async fn sends_the_job_header_when_a_job_id_is_given() {
    let request = captured_request(Some("job-42")).await;
    assert!(request.contains("X-Fleet-Job: job-42\r\n"));
}

#[tokio::test]
async fn sanitises_and_caps_the_job_header() {
    let long = format!("a\r\nb{}", "x".repeat(300));
    let request = captured_request(Some(&long)).await;
    let line = request
        .lines()
        .find(|line| line.starts_with("X-Fleet-Job: "))
        .unwrap();
    assert!(line.starts_with("X-Fleet-Job: abxxx"));
    assert_eq!(line.len(), "X-Fleet-Job: ".len() + 128);
}

#[tokio::test]
async fn omits_the_job_header_without_a_usable_job_id() {
    assert!(!captured_request(None).await.contains("X-Fleet-Job"));
    assert!(!captured_request(Some("\r\n")).await.contains("X-Fleet-Job"));
}
