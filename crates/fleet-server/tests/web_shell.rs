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
use fleet_proto::v1::SubmitJobRequest;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, Users};
use fleet_server::service::serve_with_web;
use fleet_server::store::Store;
use fleet_server::web::{NAV_FOCUS_JS, SESSION_COOKIE, STYLE_CSS, Web, WebAuth};
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
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("fleet-web-shell-{}-{n}.keys", std::process::id()));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    sealer.unwrap()
}

#[test]
fn sealers_built_in_parallel_do_not_share_a_key_file() {
    let threads: Vec<_> = (0..16)
        .map(|_| std::thread::spawn(|| drop(sealer())))
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

struct Reply {
    status: u16,
    content_type: String,
    body: String,
}

struct Harness {
    addr: SocketAddr,
    pool: PgPool,
    store: Store,
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
        let kept = store.clone();
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
            store: kept,
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
        let content_type = head
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.trim().to_owned())
            .unwrap_or_default();
        Reply {
            status: head.split(' ').nth(1).unwrap().parse().unwrap(),
            content_type,
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

fn hex_channel(hex: &str, at: usize) -> f64 {
    let v = u8::from_str_radix(&hex[at..at + 2], 16).unwrap();
    let c = f64::from(v) / 255.0;
    if c <= 0.03928 {
        c / 12.92
    } else {
        ((c + 0.055) / 1.055).powf(2.4)
    }
}

fn luminance(hex: &str) -> f64 {
    0.0722f64.mul_add(
        hex_channel(hex, 5),
        0.7152f64.mul_add(hex_channel(hex, 3), 0.2126 * hex_channel(hex, 1)),
    )
}

fn contrast(a: &str, b: &str) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

fn token(css: &str, name: &str) -> String {
    let start = css.find(&format!("{name}:#")).unwrap() + name.len() + 1;
    css[start..start + 7].to_owned()
}

#[test]
fn the_contrast_helper_matches_known_ratios() {
    assert!((contrast("#000000", "#ffffff") - 21.0).abs() < 0.01);
    assert!((contrast("#777777", "#ffffff") - 4.48).abs() < 0.02);
}

#[test]
fn menu_title_text_meets_aa_contrast_on_the_sidebar() {
    let rule = "menu-title{color:#";
    let at = STYLE_CSS
        .rfind(rule)
        .expect("no solid menu-title colour rule");
    let fg = &STYLE_CSS[at + rule.len() - 1..at + rule.len() + 6];
    let bg = token(STYLE_CSS, "--color-base-200");
    let ratio = contrast(fg, &bg);
    assert!(ratio >= 4.5, "{fg} on {bg} is {ratio:.2}");
}

#[test]
fn nav_links_have_a_24px_minimum_target() {
    assert!(
        STYLE_CSS.contains(".menu a{min-block-size:24px}")
            || STYLE_CSS.contains(".menu :where(a){min-block-size:24px}"),
        "no 24px nav link rule"
    );
}

#[test]
fn the_top_bar_fade_rule_masks_the_clipped_edge() {
    assert!(
        STYLE_CSS.contains(".nav-fade{") && STYLE_CSS.contains("mask-image:linear-gradient("),
        "no nav-fade mask rule"
    );
}

#[test]
fn shell_buttons_have_a_24px_minimum_target() {
    assert!(
        STYLE_CSS.contains("nav .btn-xs{min-block-size:24px}"),
        "no 24px nav button rule"
    );
}

#[sqlx::test]
async fn the_top_bar_scrolls_with_a_fade_cue_and_focus_padding(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    let page = h.get("/jobs", Some(&cookie)).await;
    let navs = tags(&page.body, "nav");
    let bar = navs.iter().find(|t| t.contains("lg:hidden")).unwrap();
    let bar_class = attr(bar, "class").unwrap();
    for want in ["nav-fade", "scroll-px-8", "overflow-x-auto", "gap-1"] {
        assert!(bar_class.split(' ').any(|c| c == want), "{bar} {want}");
    }
    assert!(!bar_class.split(' ').any(|c| c == "gap-3"), "{bar}");
    let lists = tags(&page.body, "ul");
    let list = lists
        .iter()
        .find(|t| t.contains("menu-horizontal"))
        .unwrap();
    let list_class = attr(list, "class").unwrap();
    for want in ["p-0", "pe-8"] {
        assert!(list_class.split(' ').any(|c| c == want), "{list} {want}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn the_signed_in_shell_links_the_nav_focus_script(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    let page = h.get("/jobs", Some(&cookie)).await;
    let scripts = tags(&page.body, "script");
    assert!(
        scripts
            .iter()
            .any(|t| attr(t, "src") == Some("/static/navfocus.js")),
        "{scripts:?}"
    );
    let login = h.get("/login", None).await;
    assert!(!login.body.contains("/static/navfocus.js"));
    h.finish().await;
}

#[sqlx::test]
async fn the_nav_focus_script_is_served_and_clears_the_fade_zone(pool: PgPool) {
    let h = Harness::start(pool).await;
    let reply = h.get("/static/navfocus.js", None).await;
    assert_eq!(reply.status, 200);
    assert!(reply.content_type.starts_with("text/javascript"));
    assert_eq!(reply.body, NAV_FOCUS_JS);
    for want in [
        "focusin",
        "getBoundingClientRect",
        "scrollLeft",
        "Main mobile",
    ] {
        assert!(reply.body.contains(want), "{want}");
    }
    assert!(!reply.body.contains("innerHTML"));
    assert!(!reply.body.contains("smooth"));
    h.finish().await;
}

#[sqlx::test]
async fn the_desktop_sidebar_is_sticky_and_scrolls_on_its_own(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    let page = h.get("/jobs", Some(&cookie)).await;
    let navs = tags(&page.body, "nav");
    let side = navs.iter().find(|t| t.contains("lg:w-48")).unwrap();
    let class = attr(side, "class").unwrap();
    for want in ["lg:sticky", "lg:top-0", "lg:h-screen", "lg:overflow-y-auto"] {
        assert!(class.split(' ').any(|c| c == want), "{side} {want}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn the_shell_is_a_sidebar_from_lg_and_a_top_bar_below(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    let page = h.get("/jobs", Some(&cookie)).await;
    assert_eq!(page.status, 200);
    let classes = class_tokens(&page.body);
    for want in [
        "lg:flex",
        "lg:w-48",
        "lg:hidden",
        "lg:flex-row",
        "flex-col",
        "overflow-x-auto",
    ] {
        assert!(classes.contains(want), "missing {want}");
    }
    let navs = tags(&page.body, "nav");
    assert_eq!(navs.len(), 2, "{navs:?}");
    let side = navs.iter().find(|t| t.contains("lg:w-48")).unwrap();
    let bar = navs.iter().find(|t| t.contains("lg:hidden")).unwrap();
    let bar_class = attr(bar, "class").unwrap();
    for want in [
        "flex",
        "overflow-x-auto",
        "gap-1",
        "border-b",
        "border-base-300",
    ] {
        assert!(bar_class.split(' ').any(|c| c == want), "{bar} {want}");
    }
    let side_class = attr(side, "class").unwrap();
    assert!(side_class.split(' ').any(|c| c == "hidden"), "{side}");
    assert_ne!(attr(side, "aria-label"), attr(bar, "aria-label"));
    for t in &navs {
        assert!(attr(t, "aria-label").is_some(), "{t}");
    }
    h.finish().await;
}

#[sqlx::test]
async fn the_top_bar_puts_sign_out_before_the_scrolling_nav(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    let page = h.get("/jobs", Some(&cookie)).await;
    let from = page.body.find("aria-label=\"Main mobile\"").unwrap();
    let bar = &page.body[from..from + page.body[from..].find("</nav>").unwrap()];
    let sign_out = bar.find("Sign out").unwrap();
    let list = bar.find("<ul").unwrap();
    assert!(sign_out < list, "Sign out must precede the nav list: {bar}");
    assert!(!bar.contains("ml-auto"), "{bar}");
    assert_eq!(bar.matches("name=\"csrf\"").count(), 1, "{bar}");
    h.finish().await;
}

#[sqlx::test]
async fn page_headers_wrap_and_may_shrink(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    for path in NAV {
        let page = h.get(path, Some(&cookie)).await;
        let headers = tags(&page.body, "header");
        if path == "/account" {
            continue;
        }
        assert!(!headers.is_empty(), "{path}");
        for header in headers {
            let class = attr(header, "class").unwrap();
            assert!(
                class.split(' ').any(|c| c == "flex-wrap"),
                "{path} {header}"
            );
            assert!(class.split(' ').any(|c| c == "min-w-0"), "{path} {header}");
        }
    }
    h.finish().await;
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
            2,
            "{path}"
        );
        let marked: Vec<&str> = tags(&page.body, "a")
            .into_iter()
            .filter(|tag| tag.contains("aria-current=\"page\""))
            .collect();
        assert_eq!(marked.len(), 2, "{path}");
        for tag in marked {
            assert_eq!(attr(tag, "href"), Some(path), "{path}");
        }
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

const TRANSCRIPT_HOOKS: [&str; 4] = ["tx-entry", "tx-note", "tx-result-total", "tx-list"];

#[sqlx::test]
async fn the_job_transcript_page_has_no_inline_style_and_known_classes(pool: PgPool) {
    let h = Harness::start(pool).await;
    let cookie = h.cookie().await;
    let user_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_one(&h.pool)
        .await
        .unwrap();
    let request = SubmitJobRequest {
        idempotency_key: "k1".to_owned(),
        prompt: "p".to_owned(),
        repo: "https://example.com/org/repo.git".to_owned(),
        base_ref: "main".to_owned(),
        open_pr: false,
        agent: String::new(),
        profile: String::new(),
    };
    let id = h
        .store
        .submit_job_for(Some(user_id), &request)
        .await
        .unwrap()
        .job_id;
    let lines = [
        serde_json::json!({"type": "assistant", "message": {"id": "m1", "role": "assistant",
            "content": [{"type": "tool_use", "id": "t1", "name": "Bash", "input": {"command": "ls"}}],
            "usage": {"input_tokens": 3, "output_tokens": 20}}, "parent_tool_use_id": null}),
        serde_json::json!({"type": "user", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "boom", "is_error": true}]},
            "parent_tool_use_id": null}),
        serde_json::json!({"type": "fleet_note", "text": "note"}),
        serde_json::json!({"type": "result", "subtype": "success", "is_error": false,
            "num_turns": 1, "duration_ms": 5, "total_cost_usd": 0.5,
            "usage": {"input_tokens": 3, "output_tokens": 20}}),
    ];
    for (n, line) in lines.iter().enumerate() {
        sqlx::query(
            "INSERT INTO job_transcript (job_id, seq, ts_ms, chunk, truncated) \
             VALUES ($1, $2, 1, $3, false)",
        )
        .bind(&id)
        .bind(i64::try_from(n).unwrap() + 1)
        .bind(line.to_string())
        .execute(&h.pool)
        .await
        .unwrap();
    }
    let known = selectors(STYLE_CSS);
    for path in [format!("/jobs/{id}"), format!("/jobs/{id}?raw=1")] {
        let page = h.get(&path, Some(&cookie)).await;
        assert_eq!(page.status, 200, "{path}");
        assert_eq!(
            inline_violations(&page.body),
            Vec::<String>::new(),
            "{path}"
        );
        let missing: Vec<String> = class_tokens(&page.body)
            .into_iter()
            .filter(|class| !known.contains(class) && !TRANSCRIPT_HOOKS.contains(&class.as_str()))
            .collect();
        assert!(missing.is_empty(), "{path}: {missing:?}");
    }
    let pretty = h.get(&format!("/jobs/{id}"), Some(&cookie)).await;
    assert!(pretty.body.contains("data-kind=\"tool\""));
    h.finish().await;
}
