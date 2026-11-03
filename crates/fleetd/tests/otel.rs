//! Receiver rules, one negative test per rule, over a real unix socket.

#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test code asserts by panicking"
)]

use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::time::Duration;

use fleetd::otel::{
    BearerToken, Limits, MAX_FLUSH_DEADLINE, OtelReceiver, QUIET_PERIOD, SOCKET_NAME, TokenError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

const TOKEN: &str = "0123456789abcdefTOKEN";
const OVER: &str = "HTTP/1.1";

fn limits() -> Limits {
    Limits {
        max_body: 16,
        max_connections: 4,
        queue: 4,
        request_timeout: Duration::from_secs(5),
    }
}

struct Rig {
    _dir: tempfile::TempDir,
    rx: mpsc::Receiver<Vec<u8>>,
    receiver: OtelReceiver,
}

fn rig_with(limits: Limits, group: Option<u32>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SOCKET_NAME);
    let token = BearerToken::new(TOKEN).unwrap();
    let (receiver, rx) = OtelReceiver::bind(&path, token, group, limits).unwrap();
    Rig {
        _dir: dir,
        rx,
        receiver,
    }
}

fn rig() -> Rig {
    rig_with(limits(), None)
}

async fn exchange(path: &Path, raw: &[u8]) -> String {
    let mut stream = UnixStream::connect(path).await.unwrap();
    stream.write_all(raw).await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut out))
        .await
        .expect("response deadline")
        .ok();
    String::from_utf8_lossy(&out).into_owned()
}

fn status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or(0)
}

fn request(extra: &str, body: &str) -> Vec<u8> {
    format!(
        "POST /v1/logs {OVER}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

async fn code(rig: &Rig, raw: &[u8]) -> u16 {
    status(&exchange(rig.receiver.path(), raw).await)
}

#[tokio::test]
async fn a_valid_post_is_queued_and_answered_200() {
    let mut rig = rig();
    let response = exchange(rig.receiver.path(), &request("", "{\"a\":1}")).await;
    assert_eq!(status(&response), 200);
    assert!(response.contains("Content-Type: application/json"));
    assert_eq!(rig.rx.try_recv().unwrap(), b"{\"a\":1}");
}

#[tokio::test]
async fn charset_utf8_content_type_is_accepted() {
    let mut rig = rig();
    let raw = b"POST /v1/logs HTTP/1.1\r\nauthorization: bearer 0123456789abcdefTOKEN\r\ncontent-type: Application/JSON; charset=utf-8\r\ncontent-length: 2\r\n\r\n{}";
    assert_eq!(code(&rig, raw).await, 200);
    assert_eq!(rig.rx.try_recv().unwrap(), b"{}");
}

#[tokio::test]
async fn wrong_path_is_404_and_nothing_is_queued() {
    let mut rig = rig();
    for target in [
        "/",
        "/v1/logs/",
        "/v1/logs?x=1",
        "/v1/traces",
        "/V1/logs",
        "//v1/logs",
        "/v1/logs%2f",
        "http://x/v1/logs",
        "*",
    ] {
        let raw = format!(
            "POST {target} {OVER}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert_eq!(code(&rig, raw.as_bytes()).await, 404, "{target}");
    }
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn wrong_method_is_405() {
    let mut rig = rig();
    for method in ["GET", "PUT", "DELETE", "HEAD", "OPTIONS", "post", "PATCH"] {
        let raw = format!(
            "{method} /v1/logs {OVER}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert_eq!(code(&rig, raw.as_bytes()).await, 405, "{method}");
    }
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn missing_or_wrong_bearer_is_401_and_the_body_is_never_read() {
    let mut rig = rig();
    let wrong_tokens = [
        String::new(),
        "Authorization: Bearer 0123456789abcdefTOKE\r\n".to_owned(),
        "Authorization: Bearer 0123456789abcdefTOKENx\r\n".to_owned(),
        "Authorization: Bearer 0123456789abcdefTOKEn\r\n".to_owned(),
        "Authorization: Bearer \r\n".to_owned(),
        "Authorization: Bearer  0123456789abcdefTOKEN x\r\n".to_owned(),
        "Authorization: Basic 0123456789abcdefTOKEN\r\n".to_owned(),
        "Authorization: 0123456789abcdefTOKEN\r\n".to_owned(),
        "Authorization: Bearer\r\n".to_owned(),
    ];
    for auth in wrong_tokens {
        let raw = format!(
            "POST /v1/logs {OVER}\r\n{auth}Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{{}}"
        );
        assert_eq!(code(&rig, raw.as_bytes()).await, 401, "{auth:?}");
    }
    let huge = "POST /v1/logs HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\n\r\n";
    assert_eq!(code(&rig, huge.as_bytes()).await, 401);
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn a_wrong_content_type_is_415() {
    let mut rig = rig();
    for ct in [
        "",
        "Content-Type: text/plain\r\n",
        "Content-Type: application/x-protobuf\r\n",
        "Content-Type: application/jsonx\r\n",
        "Content-Type: application/json; charset=latin1\r\n",
        "Content-Type: application/json, text/plain\r\n",
        "Content-Type: application/json;boundary=x\r\n",
        "Content-Type:\r\n",
    ] {
        let raw = format!(
            "POST /v1/logs {OVER}\r\nAuthorization: Bearer {TOKEN}\r\n{ct}Content-Length: 2\r\n\r\n{{}}"
        );
        assert_eq!(code(&rig, raw.as_bytes()).await, 415, "{ct:?}");
    }
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn a_compressed_body_is_415() {
    let rig = rig();
    assert_eq!(
        code(&rig, &request("Content-Encoding: gzip\r\n", "{}")).await,
        415
    );
}

#[tokio::test]
async fn expect_continue_is_417() {
    let rig = rig();
    assert_eq!(
        code(&rig, &request("Expect: 100-continue\r\n", "{}")).await,
        417
    );
}

#[tokio::test]
async fn a_body_at_the_cap_passes_and_one_over_is_413() {
    let mut rig = rig();
    let at_cap = "x".repeat(16);
    assert_eq!(code(&rig, &request("", &at_cap)).await, 200);
    assert_eq!(rig.rx.try_recv().unwrap().len(), 16);
    let over = "x".repeat(17);
    assert_eq!(code(&rig, &request("", &over)).await, 413);
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn a_declared_length_far_over_the_cap_is_413_without_reading() {
    let rig = rig();
    for len in [
        "999999999999",
        "18446744073709551615",
        "9223372036854775807",
    ] {
        let raw = format!(
            "POST /v1/logs {OVER}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n\r\n"
        );
        assert_eq!(code(&rig, raw.as_bytes()).await, 413, "{len}");
    }
}

#[tokio::test]
async fn a_chunked_body_over_the_cap_is_413_and_one_within_passes() {
    let mut rig = rig();
    let head = format!(
        "POST /v1/logs {OVER}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    let within = format!("{head}8\r\naaaaaaaa\r\n8\r\nbbbbbbbb\r\n0\r\n\r\n");
    assert_eq!(code(&rig, within.as_bytes()).await, 200);
    assert_eq!(rig.rx.try_recv().unwrap(), b"aaaaaaaabbbbbbbb");
    let split_over = format!("{head}8\r\naaaaaaaa\r\n9\r\nbbbbbbbbb\r\n0\r\n\r\n");
    assert_eq!(code(&rig, split_over.as_bytes()).await, 413);
    let one_big = format!("{head}11\r\n{}\r\n0\r\n\r\n", "c".repeat(17));
    assert_eq!(code(&rig, one_big.as_bytes()).await, 413);
    let huge_size = format!("{head}ffffffffffffffff\r\n");
    assert_eq!(code(&rig, huge_size.as_bytes()).await, 413);
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn hostile_chunked_framing_is_400() {
    let mut rig = rig();
    let head = format!(
        "POST /v1/logs {OVER}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    let bodies = [
        "2;ext=1\r\n{}\r\n0\r\n\r\n",
        "2\r\n{}\r\n0\r\nTrailer: x\r\n\r\n",
        "-2\r\n{}\r\n0\r\n\r\n",
        "0x2\r\n{}\r\n0\r\n\r\n",
        " 2\r\n{}\r\n0\r\n\r\n",
        "\r\n2\r\n{}\r\n0\r\n\r\n",
        "2\r\n{}XX0\r\n\r\n",
        "2\n{}\n0\n\n",
        "00000000000000002\r\n{}\r\n0\r\n\r\n",
        "0\r\n\r\n",
        "g\r\n{}\r\n0\r\n\r\n",
    ];
    for body in bodies {
        assert_eq!(
            code(&rig, format!("{head}{body}").as_bytes()).await,
            400,
            "{body:?}"
        );
    }
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn framing_conflicts_and_malformed_lengths_are_refused() {
    let rig = rig();
    let base = format!(
        "POST /v1/logs {OVER}\r\nAuthorization: Bearer {TOKEN}\r\nContent-Type: application/json\r\n"
    );
    let cases: [(&str, u16); 14] = [
        (
            "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
            400,
        ),
        ("Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}", 400),
        ("Content-Length: +2\r\n\r\n{}", 400),
        ("Content-Length: -2\r\n\r\n{}", 400),
        ("Content-Length: 0x2\r\n\r\n{}", 400),
        ("Content-Length: 2 2\r\n\r\n{}", 400),
        ("Content-Length: \r\n\r\n{}", 400),
        ("Content-Length: 0\r\n\r\n", 400),
        ("Content-Length: 0000000000000000000002\r\n\r\n{}", 400),
        ("\r\n{}", 411),
        ("Transfer-Encoding: gzip, chunked\r\n\r\n", 501),
        ("Transfer-Encoding: identity\r\n\r\n", 501),
        (
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            400,
        ),
        ("Content-Length: 2\r\n\r\n{", 0),
    ];
    for (tail, want) in cases {
        let raw = format!("{base}{tail}");
        let got = tokio::time::timeout(
            Duration::from_secs(10),
            exchange(rig.receiver.path(), raw.as_bytes()),
        )
        .await;
        match (got, want) {
            (Ok(response), 0) => assert_eq!(status(&response), 0, "{tail:?}"),
            (Ok(response), want) => assert_eq!(status(&response), want, "{tail:?}"),
            (Err(_), 0) => {}
            (Err(_), _) => panic!("no reply for {tail:?}"),
        }
    }
}

#[tokio::test]
async fn hostile_head_bytes_are_400() {
    let mut rig = rig();
    let ok_tail = "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
    let auth = format!("Authorization: Bearer {TOKEN}\r\n");
    let lines: Vec<(String, u16)> = vec![
        (
            format!("POST /v1/logs HTTP/1.1\nAuthorization: Bearer {TOKEN}\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X-A: a\rb\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X-A: a\u{0}b\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X-A: a\u{85}b\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X-A: a\u{2028}b\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X-A: a\x7fb\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth} folded\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}\tfolded\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X A: b\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X-A : b\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}NoColon\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}: empty\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}Authorization: Bearer {TOKEN}\r\n{ok_tail}"),
            400,
        ),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}Content-Type: application/json\r\n{ok_tail}"),
            400,
        ),
        (format!("POST /v1/logs HTTP/2.0\r\n{auth}{ok_tail}"), 400),
        (
            format!("POST /v1/logs HTTP/1.1 extra\r\n{auth}{ok_tail}"),
            400,
        ),
        (format!("POST  /v1/logs HTTP/1.1\r\n{auth}{ok_tail}"), 400),
        (format!("POST /v1/logs\r\n{auth}{ok_tail}"), 400),
        (
            format!("POST /v1/logs HTTP/1.1\r\n{auth}X-A: caf\u{e9}\r\n{ok_tail}"),
            400,
        ),
    ];
    for (raw, want) in lines {
        assert_eq!(code(&rig, raw.as_bytes()).await, want, "{raw:?}");
    }
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn an_oversize_head_is_431() {
    let rig = rig();
    let long = "a".repeat(9000);
    let raw = format!("POST /v1/logs HTTP/1.1\r\nX-Long: {long}\r\n\r\n");
    assert_eq!(code(&rig, raw.as_bytes()).await, 431);
    let mut many = String::from("POST /v1/logs HTTP/1.1\r\n");
    many.extend((0..65).map(|i| format!("X-{i}: a\r\n")));
    many.push_str("\r\n");
    assert_eq!(code(&rig, many.as_bytes()).await, 431);
    let line = format!("POST /{} HTTP/1.1\r\n\r\n", "a".repeat(9000));
    assert_eq!(code(&rig, line.as_bytes()).await, 431);
}

#[tokio::test]
async fn connections_over_the_cap_get_503_and_a_freed_slot_serves() {
    let mut rig = rig_with(
        Limits {
            max_connections: 1,
            ..limits()
        },
        None,
    );
    let path = rig.receiver.path().to_path_buf();
    let mut holder = UnixStream::connect(&path).await.unwrap();
    holder
        .write_all(b"POST /v1/logs HTTP/1.1\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let refused = exchange(&path, &request("", "{}")).await;
    assert_eq!(status(&refused), 503);
    assert!(rig.rx.try_recv().is_err());
    drop(holder);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(status(&exchange(&path, &request("", "{}")).await), 200);
}

#[tokio::test]
async fn a_full_channel_is_429_and_draining_it_recovers() {
    let mut rig = rig_with(
        Limits {
            queue: 1,
            ..limits()
        },
        None,
    );
    assert_eq!(code(&rig, &request("", "{\"n\":1}")).await, 200);
    assert_eq!(code(&rig, &request("", "{\"n\":2}")).await, 429);
    assert_eq!(rig.rx.recv().await.unwrap(), b"{\"n\":1}");
    assert_eq!(code(&rig, &request("", "{\"n\":3}")).await, 200);
    assert_eq!(rig.rx.recv().await.unwrap(), b"{\"n\":3}");
}

#[tokio::test]
async fn a_closed_channel_is_503() {
    let Rig {
        _dir, rx, receiver, ..
    } = rig();
    drop(rx);
    let response = exchange(receiver.path(), &request("", "{}")).await;
    assert_eq!(status(&response), 503);
}

#[tokio::test]
async fn a_stalled_peer_is_dropped_at_the_deadline() {
    let rig = rig_with(
        Limits {
            max_connections: 1,
            request_timeout: Duration::from_millis(300),
            ..limits()
        },
        None,
    );
    let path = rig.receiver.path().to_path_buf();
    let mut slow = UnixStream::connect(&path).await.unwrap();
    slow.write_all(b"POST /v1/logs HTTP/1.1\r\n").await.unwrap();
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), slow.read_to_end(&mut out))
        .await
        .expect("peer closed by deadline")
        .ok();
    assert_eq!(out, Vec::<u8>::new());
    assert_eq!(status(&exchange(&path, &request("", "{}")).await), 200);
}

#[tokio::test]
async fn a_truncated_body_queues_nothing() {
    let mut rig = rig();
    let mut stream = UnixStream::connect(rig.receiver.path()).await.unwrap();
    let raw = request("", "{}");
    stream
        .write_all(raw.get(..raw.len() - 1).unwrap())
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.ok();
    assert_eq!(out, Vec::<u8>::new());
    assert!(rig.rx.try_recv().is_err());
}

#[tokio::test]
async fn the_socket_is_0600_without_a_group() {
    let rig = rig();
    let meta = std::fs::symlink_metadata(rig.receiver.path()).unwrap();
    assert!(meta.file_type().is_socket());
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
}

#[tokio::test]
async fn the_socket_takes_the_group_and_0660_with_one() {
    let gid = rustix::process::getgid().as_raw();
    let rig = rig_with(limits(), Some(gid));
    let meta = std::fs::symlink_metadata(rig.receiver.path()).unwrap();
    assert_eq!(meta.gid(), gid);
    assert_eq!(meta.permissions().mode() & 0o777, 0o660);
}

#[tokio::test]
async fn an_unusable_group_fails_the_bind_and_leaves_no_socket_or_stage() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SOCKET_NAME);
    let token = BearerToken::new(TOKEN).unwrap();
    let foreign = if rustix::process::getuid().is_root() {
        None
    } else {
        Some(1)
    };
    let Some(gid) = foreign else { return };
    let err = OtelReceiver::bind(&path, token, Some(gid), limits()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn drop_removes_the_socket_and_a_replacement_is_left_alone() {
    let rig = rig();
    let path = rig.receiver.path().to_path_buf();
    assert!(path.exists());
    drop(rig);
    assert!(!path.exists());

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SOCKET_NAME);
    let token = BearerToken::new(TOKEN).unwrap();
    let (first, _rx) = OtelReceiver::bind(&path, token, None, limits()).unwrap();
    std::fs::remove_file(&path).unwrap();
    let other = std::os::unix::net::UnixListener::bind(&path).unwrap();
    drop(first);
    assert!(path.exists());
    drop(other);
}

#[tokio::test]
async fn drop_aborts_an_in_flight_connection() {
    let rig = rig();
    let path = rig.receiver.path().to_path_buf();
    let mut stalled = UnixStream::connect(&path).await.unwrap();
    stalled
        .write_all(b"POST /v1/logs HTTP/1.1\r\n")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    drop(rig);
    let mut out = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stalled.read_to_end(&mut out))
        .await
        .expect("connection closed after drop")
        .ok();
    assert_eq!(out, Vec::<u8>::new());
}

#[tokio::test]
async fn a_stale_socket_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SOCKET_NAME);
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    let token = BearerToken::new(TOKEN).unwrap();
    let (receiver, mut rx) = OtelReceiver::bind(&path, token, None, limits()).unwrap();
    assert_eq!(
        status(&exchange(receiver.path(), &request("", "{}")).await),
        200
    );
    assert_eq!(rx.try_recv().unwrap(), b"{}");
}

#[tokio::test]
async fn a_live_socket_is_refused_and_left_serving() {
    let first = rig();
    let token = BearerToken::new(TOKEN).unwrap();
    let err = OtelReceiver::bind(first.receiver.path(), token, None, limits()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    assert_eq!(code(&first, &request("", "{}")).await, 200);
}

#[tokio::test]
async fn a_regular_file_or_symlink_at_the_path_is_refused_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SOCKET_NAME);
    std::fs::write(&path, b"keep").unwrap();
    let token = BearerToken::new(TOKEN).unwrap();
    let err = OtelReceiver::bind(&path, token.clone(), None, limits()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"keep");
    std::fs::remove_file(&path).unwrap();

    let target = dir.path().join("target");
    std::fs::write(&target, b"keep").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    let err = OtelReceiver::bind(&path, token, None, limits()).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert!(
        std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"keep");
}

#[tokio::test]
async fn zero_limits_and_bad_tokens_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(SOCKET_NAME);
    let token = BearerToken::new(TOKEN).unwrap();
    for bad in [
        Limits {
            max_body: 0,
            ..limits()
        },
        Limits {
            max_connections: 0,
            ..limits()
        },
        Limits {
            queue: 0,
            ..limits()
        },
        Limits {
            request_timeout: Duration::ZERO,
            ..limits()
        },
    ] {
        let err = OtelReceiver::bind(&path, token.clone(), None, bad).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    }
    assert!(!path.exists());
    assert_eq!(BearerToken::new(""), Err(TokenError::TooShort));
}

fn patient() -> Limits {
    Limits {
        request_timeout: Duration::from_secs(100_000),
        ..limits()
    }
}

#[tokio::test]
async fn flush_waits_for_a_slow_exporter_and_queues_every_body() {
    let mut rig = rig_with(
        Limits {
            queue: 16,
            ..limits()
        },
        None,
    );
    let path = rig.receiver.path().to_path_buf();
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let poster = tokio::spawn(async move {
        let mut first = Some(first_tx);
        for n in 0..5 {
            let body = format!("{{\"n\":{n}}}");
            assert_eq!(status(&exchange(&path, &request("", &body)).await), 200);
            if let Some(tx) = first.take() {
                tx.send(()).ok();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    first_rx.await.unwrap();
    let flush = tokio::time::timeout(
        Duration::from_secs(30),
        rig.receiver
            .flush_with(Duration::from_secs(20), Duration::from_millis(600)),
    )
    .await
    .expect("outer timeout");
    assert!(!flush.incomplete);
    assert!(poster.is_finished());
    let mut seen = 0;
    while rig.rx.try_recv().is_ok() {
        seen += 1;
    }
    assert_eq!(seen, 5);
}

#[tokio::test]
async fn flush_stops_at_the_deadline_with_a_hung_connection() {
    let rig = rig_with(patient(), None);
    let mut hung = UnixStream::connect(rig.receiver.path()).await.unwrap();
    hung.write_all(b"POST /v1/logs HTTP/1.1\r\nAuthor")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let flush = tokio::time::timeout(
        Duration::from_secs(30),
        rig.receiver
            .flush_with(Duration::from_millis(400), Duration::from_millis(50)),
    )
    .await
    .expect("outer timeout");
    assert!(flush.incomplete);
}

#[tokio::test]
async fn flush_reports_incomplete_when_bodies_never_stop() {
    let rig = rig();
    let path = rig.receiver.path().to_path_buf();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = std::sync::Arc::clone(&stop);
    let poster = tokio::spawn(async move {
        while !flag.load(std::sync::atomic::Ordering::Relaxed) {
            exchange(&path, &request("", "{}")).await;
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });
    let flush = tokio::time::timeout(
        Duration::from_secs(30),
        rig.receiver
            .flush_with(Duration::from_millis(600), Duration::from_secs(5)),
    )
    .await
    .expect("outer timeout");
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    poster.await.unwrap();
    assert!(flush.incomplete);
}

#[tokio::test(start_paused = true)]
async fn an_idle_flush_waits_the_quiet_period_and_completes() {
    let rig = rig();
    let start = tokio::time::Instant::now();
    let flush = rig.receiver.flush(Duration::from_secs(5)).await;
    let elapsed = start.elapsed();
    assert!(!flush.incomplete);
    assert!(elapsed >= QUIET_PERIOD, "{elapsed:?}");
    assert!(
        elapsed < QUIET_PERIOD + Duration::from_secs(1),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn no_flush_waits_past_the_cap() {
    let rig = rig_with(patient(), None);
    let mut hung = UnixStream::connect(rig.receiver.path()).await.unwrap();
    hung.write_all(b"POST /v1/logs HTTP/1.1\r\nAuthor")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    tokio::time::pause();
    let start = tokio::time::Instant::now();
    let flush = rig.receiver.flush(Duration::MAX).await;
    let elapsed = start.elapsed();
    assert!(flush.incomplete);
    assert!(elapsed >= MAX_FLUSH_DEADLINE, "{elapsed:?}");
    assert!(
        elapsed < MAX_FLUSH_DEADLINE + Duration::from_secs(1),
        "{elapsed:?}"
    );
}

#[tokio::test]
async fn a_dropped_flush_leaves_the_receiver_usable() {
    let mut rig = rig();
    let dropped = tokio::time::timeout(
        Duration::from_millis(100),
        rig.receiver
            .flush_with(Duration::from_secs(20), Duration::from_secs(20)),
    )
    .await;
    assert!(dropped.is_err());
    assert_eq!(code(&rig, &request("", "{}")).await, 200);
    assert_eq!(rig.rx.try_recv().unwrap(), b"{}");
    let flush = rig
        .receiver
        .flush_with(Duration::from_secs(10), Duration::from_millis(50))
        .await;
    assert!(!flush.incomplete);
}
