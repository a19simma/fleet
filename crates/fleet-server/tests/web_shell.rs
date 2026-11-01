//! The shared console shell: navigation, the stylesheet and the rules every page follows.
//! The tests need a Postgres superuser URL in `DATABASE_URL` for `#[sqlx::test]` and live in
//! their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::HashSet;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fleet_core::credential::Secret;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, Users};
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, STYLE_CSS, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const CSRF: &str = "csrf-alice-token";
const NAV: [&str; 4] = ["/jobs", "/tokens", "/credentials", "/account"];

const PUBLIC: [&str; 5] = ["/", "/login", "/setup", "/setup/code", "/enroll/code"];

struct NoGithub;

#[tonic::async_trait]
impl GithubApi for NoGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        Err(GithubError::Rejected)
    }
}

fn sealer() -> FileSealer {
    let path = std::env::temp_dir().join(format!("fleet-web-shell-{}.keys", std::process::id()));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    sealer.unwrap()
}

struct Reply {
    status: u16,
    body: String,
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl Harness {
    async fn start(pool: PgPool) -> Self {
        let store = Store::new(pool.clone());
        store.migrate().await.unwrap();
        let users = Users::new(pool.clone());
        let auth = WebAuth::new(pool.clone(), users, ORIGIN, Some("example.com")).unwrap();
        let service = CredentialService::new(
            CredentialStore::new(pool.clone(), Arc::new(sealer())),
            Arc::new(NoGithub),
        );
        let web = Web::with_console(auth, Some(service), store.clone());
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

    async fn cookie(&self) -> String {
        let user_id: i64 =
            sqlx::query_scalar("INSERT INTO users (username) VALUES ('alice') RETURNING id")
                .fetch_one(&self.pool)
                .await
                .unwrap();
        let id = "a".repeat(64);
        sqlx::query(
            "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
             VALUES (sha256($1::bytea), $2, $3, now() + interval '1 hour')",
        )
        .bind(id.as_bytes())
        .bind(user_id)
        .bind(CSRF)
        .execute(&self.pool)
        .await
        .unwrap();
        format!("{SESSION_COOKIE}={id}")
    }

    async fn send(&self, request: String) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut raw = Vec::new();
        let _ = tokio::time::timeout(WAIT, stream.read_to_end(&mut raw))
            .await
            .unwrap();
        let raw = String::from_utf8_lossy(&raw).into_owned();
        let (head, body) = raw.split_once("\r\n\r\n").unwrap();
        Reply {
            status: head.split(' ').nth(1).unwrap().parse().unwrap(),
            body: body.to_owned(),
        }
    }

    async fn get(&self, path: &str, cookie: Option<&str>) -> Reply {
        let mut request =
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        if let Some(cookie) = cookie {
            let _ = write!(request, "Cookie: {cookie}\r\n");
        }
        request.push_str("\r\n");
        self.send(request).await
    }

    async fn post(&self, path: &str, cookie: &str, form: &str) -> Reply {
        let request = format!(
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\n\
             Cookie: {cookie}\r\nContent-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: {}\r\n\r\n{form}",
            form.len()
        );
        self.send(request).await
    }

    async fn pages(&self) -> Vec<(String, String)> {
        let cookie = self.cookie().await;
        let mut pages = Vec::new();
        for path in PUBLIC {
            let page = self.get(path, None).await;
            assert_eq!(page.status, 200, "{path}");
            pages.push((path.to_owned(), page.body));
        }
        for path in NAV {
            let page = self.get(path, Some(&cookie)).await;
            assert_eq!(page.status, 200, "{path}");
            pages.push((path.to_owned(), page.body));
        }
        let code = self
            .post("/account/device-code", &cookie, &format!("csrf={CSRF}"))
            .await;
        assert_eq!(code.status, 200, "{}", code.body);
        pages.push(("/account/device-code".to_owned(), code.body));
        pages
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

fn tags<'a>(html: &'a str, name: &str) -> Vec<&'a str> {
    let open = format!("<{name}");
    let mut found = Vec::new();
    let mut rest = html;
    while let Some(at) = rest.find(&open) {
        let tail = &rest[at..];
        let after = tail.as_bytes().get(open.len()).copied().unwrap_or(b'>');
        let end = tail.find('>').map_or(tail.len(), |end| end + 1);
        if after == b' ' || after == b'>' || after == b'/' || after == b'\n' {
            found.push(&tail[..end]);
        }
        rest = &tail[open.len()..];
    }
    found
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let key = format!(" {name}=\"");
    let start = tag.find(&key)? + key.len();
    let len = tag[start..].find('"')?;
    Some(&tag[start..start + len])
}

fn inline_violations(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let mut found = Vec::new();
    if lower.contains("<style") {
        found.push("inline <style>".to_owned());
    }
    let mut cursor = 0;
    while let Some(at) = lower[cursor..].find('<') {
        let start = cursor + at;
        let end = lower[start..]
            .find('>')
            .map_or(lower.len(), |end| start + end);
        let tag = &lower[start..end];
        if tag.starts_with("</") || tag.starts_with("<!") {
            cursor = start + 1;
            continue;
        }
        let words: Vec<&str> = tag.split_whitespace().collect();
        if words.iter().any(|w| w.starts_with("style=")) {
            found.push("style attribute".to_owned());
        }
        if words
            .iter()
            .skip(1)
            .any(|w| w.starts_with("on") && w.contains('='))
        {
            found.push("event handler attribute".to_owned());
        }
        if tag.starts_with("<script") {
            let rest = lower.get(end + 1..).unwrap_or_default();
            let body = rest.split("</script>").next().unwrap_or_default();
            if !tag.contains(" src=") || !body.trim().is_empty() {
                found.push("inline script".to_owned());
            }
        }
        cursor = start + 1;
    }
    found
}

fn class_tokens(html: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut rest = html;
    while let Some(at) = rest.find(" class=\"") {
        let tail = &rest[at + " class=\"".len()..];
        let len = tail.find('"').unwrap_or(tail.len());
        out.extend(tail[..len].split_whitespace().map(str::to_owned));
        rest = &tail[len..];
    }
    out
}

fn selectors(css: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut chars = css.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '.' {
            continue;
        }
        let mut name = String::new();
        while let Some(&next) = chars.peek() {
            if next == '\\' {
                chars.next();
                if let Some(escaped) = chars.next() {
                    name.push(escaped);
                }
            } else if next.is_ascii_alphanumeric() || next == '-' || next == '_' {
                name.push(next);
                chars.next();
            } else {
                break;
            }
        }
        if !name.is_empty() {
            out.insert(name);
        }
    }
    out
}

#[test]
fn the_scanner_catches_a_planted_style_attribute() {
    assert!(
        inline_violations("<p style=\"color:red\">x</p>").contains(&"style attribute".to_owned())
    );
    assert!(inline_violations("<style>p{}</style>").contains(&"inline <style>".to_owned()));
    assert!(inline_violations("<script>alert(1)</script>").contains(&"inline script".to_owned()));
    assert!(
        inline_violations("<b onclick=\"x()\">x</b>")
            .contains(&"event handler attribute".to_owned())
    );
    assert_eq!(
        inline_violations("<script src=\"/a.js\" defer=\"\"></script>"),
        Vec::<String>::new()
    );
}

#[test]
fn the_class_check_catches_a_planted_bogus_class() {
    let known = selectors(STYLE_CSS);
    let planted = class_tokens("<p class=\"btn zz-not-a-real-class\">x</p>");
    let missing: Vec<&String> = planted.iter().filter(|c| !known.contains(*c)).collect();
    assert_eq!(missing, ["zz-not-a-real-class"]);
}

#[test]
fn the_stylesheet_is_the_generated_console_build() {
    assert!(
        STYLE_CSS.starts_with("/*! tailwindcss"),
        "{}",
        &STYLE_CSS[..40]
    );
    assert!(STYLE_CSS.contains("--color-base-100"));
    assert!(STYLE_CSS.contains(":focus-visible"));
}

#[sqlx::test]
async fn the_shell_marks_exactly_the_active_nav_item(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    for path in NAV {
        let page = h.get(path, Some(&cookie)).await;
        assert_eq!(page.status, 200, "{path}");
        assert_eq!(
            page.body.matches("aria-current=\"page\"").count(),
            1,
            "{path}"
        );
        let marked: Vec<&str> = tags(&page.body, "a")
            .into_iter()
            .filter(|tag| tag.contains("aria-current=\"page\""))
            .collect();
        assert_eq!(marked.len(), 1, "{path}");
        assert_eq!(attr(marked[0], "href"), Some(path), "{path}");
        assert!(page.body.contains("<nav"), "{path}");
        for other in NAV {
            assert!(
                page.body.contains(&format!("href=\"{other}\"")),
                "{path} {other}"
            );
        }
    }
    h.finish().await;
}

#[sqlx::test]
async fn no_page_carries_inline_style_script_or_handlers(pool: PgPool) {
    let h = Harness::start(pool).await;
    for (path, body) in h.pages().await {
        assert_eq!(inline_violations(&body), Vec::<String>::new(), "{path}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn every_class_in_a_page_exists_in_the_stylesheet(pool: PgPool) {
    let h = Harness::start(pool).await;
    let known = selectors(STYLE_CSS);
    for (path, body) in h.pages().await {
        let missing: Vec<String> = class_tokens(&body)
            .into_iter()
            .filter(|class| !known.contains(class))
            .collect();
        assert!(missing.is_empty(), "{path}: {missing:?}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn every_page_is_accessible_markup(pool: PgPool) {
    let h = Harness::start(pool).await;
    for (path, body) in h.pages().await {
        assert!(body.starts_with("<!DOCTYPE html>"), "{path}");
        assert!(body.contains("<html lang=\"en\""), "{path}");
        assert_eq!(body.matches("<h1").count(), 1, "{path}");
        assert!(body.contains("<main id=\"app\""), "{path}");
        let labels: Vec<&str> = tags(&body, "label");
        let for_ids: HashSet<&str> = labels.iter().filter_map(|tag| attr(tag, "for")).collect();
        for control in ["input", "select", "textarea"] {
            for tag in tags(&body, control) {
                if attr(tag, "type") == Some("hidden") {
                    continue;
                }
                let id = attr(tag, "id");
                assert!(id.is_some_and(|id| for_ids.contains(id)), "{path}: {tag}");
            }
        }
    }
    h.finish().await;
}

#[sqlx::test]
async fn the_account_page_carries_mode_and_csrf_on_main(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    let page = h.get("/account", Some(&cookie)).await;
    let main = tags(&page.body, "main");
    assert_eq!(main.len(), 1);
    assert_eq!(attr(main[0], "data-mode"), Some("add"));
    assert_eq!(attr(main[0], "data-csrf"), Some(CSRF));
    assert!(!tags(&page.body, "body")[0].contains("data-"));
    h.finish().await;
}
