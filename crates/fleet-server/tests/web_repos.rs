//! The repositories page over HTTP: session and CSRF gates, owner scoping, the 404 without a
//! registry, and hostile host and path values from the database. The tests need a Postgres
//! superuser URL in `DATABASE_URL` and live in their own binary because each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fleet_core::credential::Secret;
use fleet_server::auth::BearerAuth;
use fleet_server::config::{Forge, RepoHosts, Token};
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::repo_fake::FakeVerifier;
use fleet_server::cred::repo_store::RepoStore;
use fleet_server::cred::repo_verify::RepoVerifiers;
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, RepoService, Users};
use fleet_server::service::{UpdateRelay, serve_with_credentials};
use fleet_server::store::Store;
use fleet_server::web::{MAX_BODY_BYTES, SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const HOSTS: &str = "host=github.com,forge=github,api=https://api.github.com";
static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

struct NoGithub;

#[tonic::async_trait]
impl GithubApi for NoGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        Err(GithubError::Unavailable)
    }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

struct Persona {
    id: i64,
    cookie: String,
    csrf: String,
}

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
}

async fn start(pool: PgPool, configured: bool) -> Rig {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let path = std::env::temp_dir().join(format!(
        "fleet-web-repos-{}-{}.keys",
        std::process::id(),
        KEY_FILES.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, format!("k1:{}\n", "ab".repeat(32))).unwrap();
    let sealer = FileSealer::load(&path);
    std::fs::remove_file(&path).unwrap();
    let creds = CredentialStore::new(pool.clone(), Arc::new(sealer.unwrap()));
    let verifier = Arc::new(FakeVerifier::ok("octo/hello", Some(true)));
    let verifiers =
        RepoVerifiers::new(RepoHosts::parse(HOSTS).unwrap()).with(Forge::Github, verifier);
    let repos = RepoService::new(
        RepoStore::new(pool.clone(), creds.clone()),
        Arc::new(verifiers),
    );
    let base = CredentialService::new(creds, Arc::new(NoGithub));
    let service = if configured {
        base.with_repos(repos)
    } else {
        base
    };
    let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
    let web = Web::with_console(auth, Some(service.clone()), store.clone());
    let bearer =
        BearerAuth::new(&Token::new(BOX_TOKEN.to_owned()).unwrap(), None).with_users(users);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        serve_with_credentials(
            &store,
            &bearer,
            web,
            Some(service),
            UpdateRelay::default(),
            TcpIncoming::from(listener),
            std::future::pending::<()>(),
        )
        .await
    });
    Rig { addr, pool }
}

impl Rig {
    async fn persona(&self, name: &str, seed: char) -> Persona {
        let id: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
            .bind(name)
            .fetch_one(&self.pool)
            .await
            .unwrap();
        let session = seed.to_string().repeat(64);
        let csrf = format!("csrf-{name}-token");
        sqlx::query(
            "INSERT INTO web_sessions (id_hash, user_id, csrf, expires_at) \
             VALUES (sha256($1::bytea), $2, $3, now() + interval '1 hour')",
        )
        .bind(session.as_bytes())
        .bind(id)
        .bind(&csrf)
        .execute(&self.pool)
        .await
        .unwrap();
        Persona {
            id,
            cookie: format!("{SESSION_COOKIE}={session}"),
            csrf,
        }
    }

    async fn http(&self, method: &str, path: &str, cookie: &str, body: &str) -> Reply {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        let mut request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nOrigin: {ORIGIN}\r\nContent-Length: {}\r\n",
            body.len(),
        );
        if !cookie.is_empty() {
            let _ = write!(request, "Cookie: {cookie}\r\n");
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

    async fn insert(&self, user: i64, host: &str, path: &str) {
        sqlx::query(
            "INSERT INTO user_repos (user_id, host, path, forge_kind, push) VALUES ($1, $2, $3, 'github', NULL)",
        )
        .bind(user)
        .bind(host)
        .bind(path)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn count(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM user_repos")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

#[sqlx::test]
async fn the_page_needs_a_session_and_a_registry(pool: PgPool) {
    let rig = start(pool.clone(), true).await;
    let anon = rig.http("GET", "/repos", "", "").await;
    assert_eq!(anon.status, 303);
    assert!(anon.head.contains("location: /login"), "{}", anon.head);
    let who = rig.persona("olive", 'a').await;
    let page = rig.http("GET", "/repos", &who.cookie, "").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("href=\"/repos\" aria-current=\"page\""));
    assert!(page.body.contains("action=\"/repos/add\""));
    assert!(page.body.contains(">Repositories</a>"), "{}", page.body);
    assert!(
        page.body
            .contains("name=\"csrf\" value=\"csrf-olive-token\"")
    );
    assert!(!page.body.contains("<script>"));
}

#[sqlx::test]
async fn a_server_without_a_registry_answers_404_on_every_route(pool: PgPool) {
    let rig = start(pool, false).await;
    let who = rig.persona("olive", 'a').await;
    let form = format!("csrf={}&repo=github.com/octo/hello&repo=6162", who.csrf);
    assert_eq!(rig.http("GET", "/repos", &who.cookie, "").await.status, 404);
    for route in ["/repos/add", "/repos/remove"] {
        assert_eq!(
            rig.http("POST", route, &who.cookie, &form).await.status,
            404,
            "{route}"
        );
    }
    assert_eq!(rig.count().await, 0);
}

#[sqlx::test]
async fn a_post_without_the_session_csrf_token_is_refused_and_changes_nothing(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    rig.insert(who.id, "github.com", "octo/hello").await;
    let bodies = [
        "repo=github.com/octo/hello".to_owned(),
        "csrf=wrong&repo=github.com/octo/hello".to_owned(),
        "csrf=&repo=github.com/octo/hello".to_owned(),
    ];
    for body in &bodies {
        let add = rig.http("POST", "/repos/add", &who.cookie, body).await;
        assert!(
            add.status == 403 || add.status == 400 || add.status == 422,
            "{}",
            add.status
        );
    }
    for body in [
        "repo=6769746875622e636f6d-6f63746f2f68656c6c6f".to_owned(),
        "csrf=wrong&repo=6769746875622e636f6d-6f63746f2f68656c6c6f".to_owned(),
    ] {
        let removed = rig.http("POST", "/repos/remove", &who.cookie, &body).await;
        assert!(removed.status == 403 || removed.status == 400 || removed.status == 422);
    }
    assert_eq!(rig.count().await, 1);
    let no_cookie = rig
        .http(
            "POST",
            "/repos/remove",
            "",
            &format!(
                "csrf={}&repo=6769746875622e636f6d-6f63746f2f68656c6c6f",
                who.csrf
            ),
        )
        .await;
    assert_ne!(no_cookie.status, 200);
    assert_eq!(rig.count().await, 1);
}

#[sqlx::test]
async fn the_verified_time_shows_as_a_utc_stamp(pool: PgPool) {
    let rig = start(pool.clone(), true).await;
    let who = rig.persona("olive", 'a').await;
    rig.insert(who.id, "github.com", "olive/dated").await;
    sqlx::query("UPDATE user_repos SET verified_at = '2024-03-05 06:07:00+00'")
        .execute(&pool)
        .await
        .unwrap();
    let page = rig.http("GET", "/repos", &who.cookie, "").await.body;
    assert!(page.contains("2024-03-05 06:07 UTC"), "{page}");
}

#[sqlx::test]
async fn a_user_sees_and_removes_only_their_own_rows(pool: PgPool) {
    let rig = start(pool, true).await;
    let ann = rig.persona("ann", 'a').await;
    let bob = rig.persona("bob", 'b').await;
    rig.insert(ann.id, "github.com", "ann/only").await;
    rig.insert(bob.id, "github.com", "bob/only").await;
    let page = rig.http("GET", "/repos", &ann.cookie, "").await.body;
    assert!(page.contains("ann/only"));
    assert!(!page.contains("bob/only"));
    let form = format!("csrf={}&repo={}", ann.csrf, key("github.com", "bob/only"));
    let reply = rig.http("POST", "/repos/remove", &ann.cookie, &form).await;
    assert_eq!(reply.status, 303);
    assert!(
        reply.head.contains("location: /repos?notice=repo_missing"),
        "{}",
        reply.head
    );
    assert_eq!(rig.count().await, 2);
}

#[sqlx::test]
async fn an_unknown_notice_code_shows_no_notice(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    let page = rig
        .http(
            "GET",
            "/repos?notice=%3Cscript%3Ealert(1)%3C/script%3E",
            &who.cookie,
            "",
        )
        .await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains("id=\"notice\""));
    assert!(!page.body.contains("<script>alert"));
}

fn key(host: &str, path: &str) -> String {
    format!("{}-{}", hex(host), hex(path))
}

fn hex(text: &str) -> String {
    text.bytes().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

const HOSTILE: &[(&str, &str)] = &[
    ("<script>alert(1)</script>.example", "o/r"),
    ("github.com", "o\"><img src=x onerror=alert(1)>/r"),
    ("github.com", "o'><svg onload=alert(1)>/r"),
    ("github.com", "o&amp;/r&lt;"),
    ("b\u{fc}cher.example", "o/r"),
    ("\u{430}pple.example", "o/r"),
    ("github.com\u{202e}moc.evil", "o/r"),
    ("github.com", "o\u{200f}/\u{2067}r"),
    ("github.com", "o\r\nset-cookie: x=1/r"),
    ("github.com", "o\u{85}\u{2028}/r"),
];

#[sqlx::test]
async fn hostile_hosts_and_paths_are_escaped_and_shown_as_ascii(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    for (host, path) in HOSTILE {
        rig.insert(who.id, host, path).await;
    }
    rig.insert(who.id, "xn--bcher-kva.example", "o/idn").await;
    let page = rig.http("GET", "/repos", &who.cookie, "").await;
    assert_eq!(page.status, 200);
    let body = page.body;
    for raw in [
        "<script>alert",
        "<img src=x",
        "<svg onload",
        "onerror=alert(1)>",
    ] {
        assert!(
            !body.contains(raw),
            "{raw}: {}",
            &body[body.find(raw).unwrap_or(0)..][..300.min(body.len())]
        );
    }
    for forbidden in [
        '\u{fc}', '\u{430}', '\u{202e}', '\u{200f}', '\u{2067}', '\u{85}', '\u{2028}', '\r',
    ] {
        assert!(!body.contains(forbidden), "{forbidden:?}");
    }
    assert!(!body.contains("\nset-cookie"));
    assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;.example"));
    assert!(body.contains("b\\u{fc}cher.example"));
    assert!(body.contains("\\u{430}pple.example"));
    assert!(body.contains("github.com\\u{202e}moc.evil"));
    assert!(body.contains("xn--bcher-kva.example"));
    assert!(body.contains("o&amp;amp;/r&amp;lt;"));
}

#[sqlx::test]
async fn an_over_long_host_and_path_render_without_breaking_the_page(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    let host = format!("{}.example", "h".repeat(240));
    let path = format!("o/{}", "r".repeat(138));
    rig.insert(who.id, &host, &path).await;
    let page = rig.http("GET", "/repos", &who.cookie, "").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains(&host));
    assert!(page.body.contains(&path));
    assert!(page.body.contains("</html>"));
}

#[sqlx::test]
async fn a_hostile_add_input_redirects_with_a_fixed_code_and_stores_nothing(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    let inputs = [
        "<script>alert(1)</script>",
        "https://user:pw@github.com/o/r",
        "github.com/o/r%0d%0aX: y",
        "b\u{fc}cher.example/o/r",
        "github.com/o/r\u{202e}",
        &"x".repeat(5000),
    ];
    for input in inputs {
        let mut encoded = String::new();
        for byte in input.as_bytes() {
            let _ = write!(encoded, "%{byte:02X}");
        }
        let form = format!("csrf={}&repo={encoded}", who.csrf);
        let reply = rig.http("POST", "/repos/add", &who.cookie, &form).await;
        assert_eq!(reply.status, 303);
        let location = reply
            .head
            .lines()
            .find_map(|l| l.strip_prefix("location: "))
            .unwrap();
        assert!(
            location == "/repos?notice=repo_invalid"
                || location == "/repos?notice=repo_host_refused",
            "{location}"
        );
    }
    assert_eq!(rig.count().await, 0);
}

fn remove_field(page: &str) -> Vec<String> {
    page.split("name=\"repo\" value=\"")
        .skip(1)
        .filter_map(|rest| rest.split_once('"').map(|(value, _)| value.to_owned()))
        .collect()
}

#[sqlx::test]
async fn a_hostile_row_is_removed_by_its_own_form_and_the_form_value_is_inert_hex(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    for (host, path) in HOSTILE {
        rig.insert(who.id, host, path).await;
    }
    let page = rig.http("GET", "/repos", &who.cookie, "").await.body;
    let keys = remove_field(&page);
    assert_eq!(keys.len(), HOSTILE.len());
    for key in &keys {
        assert!(
            key.bytes()
                .all(|b| b == b'-' || b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "{key}"
        );
    }
    for key in &keys {
        let form = format!("csrf={}&repo={key}", who.csrf);
        let reply = rig.http("POST", "/repos/remove", &who.cookie, &form).await;
        assert!(
            reply.head.contains("location: /repos?notice=deleted"),
            "{}",
            reply.head
        );
    }
    assert_eq!(rig.count().await, 0);
}

#[sqlx::test]
async fn a_malformed_remove_value_is_repo_missing_and_deletes_nothing(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    rig.insert(who.id, "github.com", "octo/hello").await;
    let real = key("github.com", "octo/hello");
    let bad = [
        String::new(),
        "6".to_owned(),
        "zz".to_owned(),
        real.to_uppercase(),
        hex("github.com"),
        real.replace("6f", "ff"),
        format!("{}-{}", "00".repeat(300), hex("o/r")),
        "ffff-ffff".to_owned(),
        format!("{real}-{real}"),
        format!("-{}", hex("octo/hello")),
        "00".repeat(5000),
        "ffff".to_owned(),
    ];
    for value in bad {
        let form = format!("csrf={}&repo={value}", who.csrf);
        let reply = rig.http("POST", "/repos/remove", &who.cookie, &form).await;
        assert!(
            reply.head.contains("location: /repos?notice=repo_missing"),
            "{value}: {}",
            reply.head
        );
    }
    let none = rig
        .http(
            "POST",
            "/repos/remove",
            &who.cookie,
            &format!("csrf={}", who.csrf),
        )
        .await;
    assert!(none.head.contains("location: /repos?notice=repo_missing"));
    assert_eq!(rig.count().await, 1);
}

#[sqlx::test]
async fn an_attribute_value_from_the_session_is_escaped_by_the_view(pool: PgPool) {
    let rig = start(pool.clone(), true).await;
    let who = rig.persona("olive", 'a').await;
    let hostile = "\"><script>alert(1)</script><b a='&x";
    sqlx::query("UPDATE web_sessions SET csrf = $1 WHERE user_id = $2")
        .bind(hostile)
        .bind(who.id)
        .execute(&pool)
        .await
        .unwrap();
    let page = rig.http("GET", "/repos", &who.cookie, "").await;
    assert_eq!(page.status, 200);
    assert!(!page.body.contains(hostile), "{}", page.body);
    assert!(
        !page.body.contains("value=\"\"><script>"),
        "the quote closed the attribute: {}",
        page.body
    );
    assert!(
        page.body
            .contains("value=\"&quot;><script>alert(1)</script><b a='&amp;x\""),
        "{}",
        page.body
    );
}

#[sqlx::test]
async fn a_form_body_over_the_web_limit_is_refused_on_both_post_routes(pool: PgPool) {
    let rig = start(pool, true).await;
    let who = rig.persona("olive", 'a').await;
    rig.insert(who.id, "github.com", "olive/kept").await;
    let head = format!("csrf={}&repo=", who.csrf);
    let over = format!("{head}{}", "a".repeat(MAX_BODY_BYTES + 1 - head.len()));
    assert_eq!(over.len(), MAX_BODY_BYTES + 1);
    for path in ["/repos/add", "/repos/remove"] {
        let reply = rig.http("POST", path, &who.cookie, &over).await;
        assert_eq!(reply.status, 413, "{path}: {}", reply.head);
    }
    assert_eq!(rig.count().await, 1);
    let at = format!("{head}{}", "a".repeat(MAX_BODY_BYTES - head.len()));
    assert_eq!(at.len(), MAX_BODY_BYTES);
    let reply = rig.http("POST", "/repos/add", &who.cookie, &at).await;
    assert_eq!(reply.status, 303, "{}", reply.head);
    assert!(
        reply.head.contains("location: /repos?notice="),
        "{}",
        reply.head
    );
}
