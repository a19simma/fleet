//! Drives `forward_hook` against a real listener over a temp SQLite file.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::Arc;
use std::time::Duration;

use fleet_core::{HookAllowlist, Identity, Redactor};
use fleetd::{
    AppState, Config, Limits, Store, bind_socket, forward_hook, hook_router, socket_router,
};
use tempfile::TempDir;
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
