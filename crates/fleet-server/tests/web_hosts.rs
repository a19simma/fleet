//! The git remotes page over HTTP: session and CSRF gates, admin gating of remove and of the
//! pending requests and approved addresses, the hostile host table, hostile stored strings in
//! every markup position, the 404 without a host service and the shared repository table. The
//! tests need a Postgres superuser URL in `DATABASE_URL` and live in their own binary because
//! each one binds a socket.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::fmt::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::credential::Secret;
use fleet_core::host::{HostKind, HostName};
use fleet_proto::{CredentialNotice, MAX_HOST_APPROVED_IPS};
use fleet_server::auth::BearerAuth;
use fleet_server::config::{Forge, RepoHosts, Token};
use fleet_server::cred::github::{GithubApi, GithubError, GithubUser};
use fleet_server::cred::repo_fake::FakeVerifier;
use fleet_server::cred::repo_store::RepoStore;
use fleet_server::cred::repo_verify::RepoVerifiers;
use fleet_server::cred::store::CredentialStore;
use fleet_server::cred::{CredentialService, FileSealer, RepoService, Users};
use fleet_server::hosts::{HostProbe, HostRefusal, HostService, HostStore};
use fleet_server::service::{UpdateRelay, serve_with_credentials};
use fleet_server::store::Store;
use fleet_server::web::{SESSION_COOKIE, Web, WebAuth};
use sqlx::PgPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tonic::transport::server::TcpIncoming;

const WAIT: Duration = Duration::from_secs(20);
const ORIGIN: &str = "https://fleet.example.com";
const BOX_TOKEN: &str = "box-token-0123456789abcdef0123456789";
const HOSTS: &str = "host=github.com,forge=github,api=https://api.github.com";
const FORGE: &str = "git.example.com";
const PRIVATE_IP: &str = "192.168.3.7";
static KEY_FILES: AtomicUsize = AtomicUsize::new(0);

struct NoGithub;

#[tonic::async_trait]
impl GithubApi for NoGithub {
    async fn user(&self, _token: &Secret) -> Result<GithubUser, GithubError> {
        Err(GithubError::Unavailable)
    }
}

struct Probe {
    verdict: Result<HostKind, HostRefusal>,
    seen: Mutex<Vec<String>>,
    resolved: Mutex<Vec<IpAddr>>,
    calls: AtomicUsize,
}

#[tonic::async_trait]
impl HostProbe for Probe {
    async fn probe(&self, host: &HostName) -> Result<HostKind, HostRefusal> {
        self.seen.lock().unwrap().push(host.as_str().to_owned());
        self.verdict
    }

    async fn resolve(&self, _host: &HostName) -> Vec<IpAddr> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.resolved.lock().unwrap().clone()
    }

    async fn probe_approved(
        &self,
        _host: &HostName,
        _approved: &[IpAddr],
    ) -> Result<HostKind, HostRefusal> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.verdict
    }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn location(&self) -> String {
        self.head
            .lines()
            .find_map(|line| line.strip_prefix("location: "))
            .unwrap_or_default()
            .to_owned()
    }

    fn notice(&self) -> String {
        self.location()
            .strip_prefix("/hosts?notice=")
            .unwrap_or_default()
            .to_owned()
    }
}

struct Persona {
    id: i64,
    cookie: String,
    csrf: String,
}

struct Rig {
    addr: SocketAddr,
    pool: PgPool,
    probe: Arc<Probe>,
}

struct Setup {
    hosts: bool,
    repos: bool,
    verdict: Result<HostKind, HostRefusal>,
}

const DEFAULT: Setup = Setup {
    hosts: true,
    repos: false,
    verdict: Ok(HostKind::Forgejo),
};

async fn start(pool: PgPool, setup: Setup) -> Rig {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let path = std::env::temp_dir().join(format!(
        "fleet-web-hosts-{}-{}.keys",
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
    let service = if setup.repos {
        base.with_repos(repos)
    } else {
        base
    };
    let probe = Arc::new(Probe {
        verdict: setup.verdict,
        seen: Mutex::new(Vec::new()),
        resolved: Mutex::new(vec![PRIVATE_IP.parse().unwrap()]),
        calls: AtomicUsize::new(0),
    });
    let hosts = setup
        .hosts
        .then(|| HostService::new(HostStore::new(pool.clone()), probe.clone()));
    let auth = WebAuth::new(pool.clone(), users.clone(), ORIGIN, Some("example.com")).unwrap();
    let web = Web::with_hosts(auth, Some(service.clone()), None, hosts, store.clone());
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
    Rig { addr, pool, probe }
}

fn enc(text: &str) -> String {
    let mut out = String::new();
    for byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.') {
            out.push(char::from(*byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

impl Rig {
    async fn persona(&self, name: &str, seed: char, admin: bool) -> Persona {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO users (username, is_admin) VALUES ($1, $2) RETURNING id",
        )
        .bind(name)
        .bind(admin)
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

    async fn post(&self, who: &Persona, path: &str, host: &str) -> Reply {
        let body = format!("csrf={}&host={}", who.csrf, enc(host));
        self.http("POST", path, &who.cookie, &body).await
    }

    async fn seed(&self, host: &str) {
        sqlx::query("INSERT INTO git_hosts (host, kind) VALUES ($1, 'forgejo')")
            .bind(host)
            .execute(&self.pool)
            .await
            .unwrap();
    }

    async fn hosts(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT host FROM git_hosts ORDER BY host")
            .fetch_all(&self.pool)
            .await
            .unwrap()
    }

    async fn pend(&self, host: &str, user: i64, ip: &str) {
        sqlx::query(
            "INSERT INTO git_host_requests (host, user_id, resolved) \
             VALUES ($1, $2, ARRAY[$3]::inet[])",
        )
        .bind(host)
        .bind(user)
        .bind(ip)
        .execute(&self.pool)
        .await
        .unwrap();
    }

    async fn grant(&self) -> (bool, Vec<String>) {
        sqlx::query_as(
            "SELECT allow_private, ARRAY(SELECT host(a) FROM unnest(approved_ips) a ORDER BY 1) \
             FROM git_hosts WHERE host = $1",
        )
        .bind(FORGE)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn post_form(&self, who: &Persona, path: &str, host: &str, addresses: &str) -> Reply {
        let body = format!(
            "csrf={}&host={}&addresses={}",
            who.csrf,
            enc(host),
            enc(addresses)
        );
        self.http("POST", path, &who.cookie, &body).await
    }

    fn calls(&self) -> usize {
        self.probe.calls.load(Ordering::Relaxed)
    }

    fn probed(&self) -> Vec<String> {
        self.probe.seen.lock().unwrap().clone()
    }

    async fn audited(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM host_audit")
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

fn refused_hosts() -> Vec<String> {
    let mut list: Vec<String> = [
        "zqxmark.example.com\r",
        "zqxmark.example.com\n",
        "zqxmark.example.com\r\n",
        "zqxmark.example.com\u{85}",
        "zqxmark.example.com\u{2028}",
        "user@zqxmark.example.com",
        "user:pass@zqxmark.example.com",
        "zqxmark.example.com\\evil",
        "[::1]",
        "[2001:db8::1]",
        "::1",
        "zqx..mark.example.com",
        ".zqxmark.example.com",
        "zqxmark.example.com ",
        " zqxmark.example.com",
        "zqx mark.example.com",
        "zqxmark.example.com:8080",
        "https://zqxmark.example.com",
        "zqxmark.example.com/path",
        "localhost",
        "",
        "   ",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    list.push(format!("{}.example.com", "a".repeat(300)));
    list
}

#[sqlx::test]
async fn the_page_needs_a_session_and_a_host_service(pool: PgPool) {
    let rig = start(pool.clone(), DEFAULT).await;
    let anon = rig.http("GET", "/hosts", "", "").await;
    assert_eq!(anon.status, 303);
    assert!(anon.head.contains("location: /login"), "{}", anon.head);
    let who = rig.persona("olive", 'a', false).await;
    let page = rig.http("GET", "/hosts", &who.cookie, "").await;
    assert_eq!(page.status, 200);
    assert!(page.body.contains("href=\"/hosts\" aria-current=\"page\""));
    assert!(page.body.contains(">Git remotes</a>"), "{}", page.body);
    assert!(page.body.contains("action=\"/hosts/add\""));
    assert!(page.body.contains("<td>github.com</td>"));
    assert!(
        page.body
            .contains("name=\"csrf\" value=\"csrf-olive-token\"")
    );
    assert!(!page.body.contains("<script>"));
    let off = start(
        pool.clone(),
        Setup {
            hosts: false,
            ..DEFAULT
        },
    )
    .await;
    let missing = off.http("GET", "/hosts", &who.cookie, "").await;
    assert_eq!(missing.status, 404);
}

#[sqlx::test]
async fn form_controls_are_labelled_and_reachable(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    let page = rig.http("GET", "/hosts", &admin.cookie, "").await;
    let body = page.body;
    let mut controls = 0;
    for tag in body.split('<').skip(1) {
        let tag = tag.split('>').next().unwrap();
        let visible = (tag.starts_with("input ") && !tag.contains("type=\"hidden\""))
            || tag.starts_with("select ")
            || tag.starts_with("textarea ");
        if !visible {
            continue;
        }
        controls += 1;
        let id = tag
            .split("id=\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .unwrap();
        assert!(body.contains(&format!("for=\"{id}\"")), "no label for {id}");
        assert!(!tag.contains("tabindex=\"-1\""));
    }
    assert_eq!(controls, 1);
    assert!(body.contains("<button class=\"btn btn-xs btn-outline btn-error\" type=\"submit\">"));
    assert!(!body.contains("onclick"));
}

#[sqlx::test]
async fn only_an_admin_sees_requests_addresses_and_remove(pool: PgPool) {
    let rig = start(pool.clone(), DEFAULT).await;
    let user = rig.persona("olive", 'a', false).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed("private.example.com").await;
    sqlx::query(
        "UPDATE git_hosts SET allow_private = true, approved_ips = ARRAY[$1]::inet[] \
         WHERE host = 'private.example.com'",
    )
    .bind(PRIVATE_IP)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("INSERT INTO git_host_requests (host, user_id, resolved) VALUES ('wish.example.com', $1, ARRAY[$2]::inet[])")
        .bind(user.id)
        .bind("10.9.8.7")
        .execute(&pool)
        .await
        .unwrap();
    let seen_by_user = rig.http("GET", "/hosts", &user.cookie, "").await.body;
    assert!(seen_by_user.contains("<td>private.example.com</td>"));
    for needle in [
        PRIVATE_IP,
        "10.9.8.7",
        "wish.example.com",
        "Pending private requests",
        "/hosts/remove",
        "Approved addresses",
    ] {
        assert!(!seen_by_user.contains(needle), "user page shows {needle}");
    }
    let seen_by_admin = rig.http("GET", "/hosts", &admin.cookie, "").await.body;
    for needle in [
        PRIVATE_IP,
        "10.9.8.7",
        "wish.example.com",
        "Pending private requests",
        "action=\"/hosts/remove\"",
        "Approved addresses",
    ] {
        assert!(seen_by_admin.contains(needle), "admin page lacks {needle}");
    }
}

#[sqlx::test]
async fn add_goes_through_the_service_with_the_normalised_host(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let who = rig.persona("olive", 'a', false).await;
    let done = rig.post(&who, "/hosts/add", FORGE).await;
    assert_eq!(done.status, 303);
    assert_eq!(done.notice(), CredentialNotice::HostAdded.code());
    assert!(rig.hosts().await.contains(&FORGE.to_owned()));
    let loud = rig.post(&who, "/hosts/add", "Code.EXAMPLE.org.").await;
    assert_eq!(loud.notice(), CredentialNotice::HostAdded.code());
    let idn = rig.post(&who, "/hosts/add", "b\u{fc}cher.example").await;
    assert_eq!(idn.notice(), CredentialNotice::HostAdded.code());
    assert_eq!(
        rig.probed(),
        [FORGE, "code.example.org", "xn--bcher-kva.example"]
    );
    let page = rig.http("GET", "/hosts?notice=host_added", &who.cookie, "");
    assert!(page.await.body.contains(CredentialNotice::HostAdded.text()));
}

#[sqlx::test]
async fn a_refusal_cause_maps_to_its_own_fixed_notice_and_never_echoes_the_host(pool: PgPool) {
    let table = [
        (HostRefusal::NotAllowedHost, CredentialNotice::HostRefused),
        (HostRefusal::NotForge, CredentialNotice::HostNotForge),
    ];
    for (n, (refusal, notice)) in table.into_iter().enumerate() {
        let rig = start(
            pool.clone(),
            Setup {
                verdict: Err(refusal),
                ..DEFAULT
            },
        )
        .await;
        let who = rig
            .persona(
                &format!("u{n}"),
                char::from(b'c' + u8::try_from(n).unwrap()),
                false,
            )
            .await;
        let reply = rig.post(&who, "/hosts/add", "nope.example.com").await;
        assert_eq!(reply.notice(), notice.code());
        assert!(!reply.location().contains("nope"));
        assert_eq!(rig.hosts().await, ["github.com"]);
    }
}

#[sqlx::test]
async fn a_hostile_host_is_refused_with_no_request_and_no_echo(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let who = rig.persona("olive", 'a', false).await;
    for host in refused_hosts() {
        let reply = rig.post(&who, "/hosts/add", &host).await;
        assert_eq!(reply.status, 303, "{host:?}");
        assert_eq!(
            reply.notice(),
            CredentialNotice::HostRefused.code(),
            "{host:?}"
        );
        let page = rig
            .http("GET", &reply.location(), &who.cookie, "")
            .await
            .body;
        let probe = host.trim();
        assert!(probe.is_empty() || !page.contains(probe), "{host:?}");
    }
    assert_eq!(rig.probed(), Vec::<String>::new());
    assert_eq!(rig.hosts().await, ["github.com"]);
}

#[sqlx::test]
async fn posts_without_a_session_or_csrf_change_nothing(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let who = rig.persona("olive", 'a', false).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    let body = format!("csrf=wrong&host={}", enc("new.example.com"));
    let bad = rig.http("POST", "/hosts/add", &who.cookie, &body).await;
    assert_eq!(bad.status, 403);
    let anon = rig
        .http(
            "POST",
            "/hosts/add",
            "",
            &format!("host={}", enc("new.example.com")),
        )
        .await;
    assert_ne!(anon.notice(), CredentialNotice::HostAdded.code());
    let no_csrf = rig
        .http(
            "POST",
            "/hosts/remove",
            &admin.cookie,
            &format!("host={FORGE}"),
        )
        .await;
    assert_eq!(no_csrf.status, 403);
    assert_eq!(rig.probed(), Vec::<String>::new());
    assert_eq!(rig.hosts().await, [FORGE, "github.com"]);
}

#[sqlx::test]
async fn remove_is_admin_only_on_the_server(pool: PgPool) {
    let rig = start(pool.clone(), DEFAULT).await;
    let user = rig.persona("olive", 'a', false).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    let denied = rig.post(&user, "/hosts/remove", FORGE).await;
    assert_eq!(denied.status, 403);
    assert_eq!(rig.hosts().await, [FORGE, "github.com"]);
    let gone = rig.post(&admin, "/hosts/remove", FORGE).await;
    assert_eq!(gone.notice(), CredentialNotice::HostRemoved.code());
    assert_eq!(rig.hosts().await, ["github.com"]);
    let again = rig.post(&admin, "/hosts/remove", FORGE).await;
    assert_eq!(again.notice(), CredentialNotice::HostMissing.code());
    let builtin = rig.post(&admin, "/hosts/remove", "github.com").await;
    assert_eq!(builtin.notice(), CredentialNotice::HostInUse.code());
    sqlx::query("UPDATE users SET is_admin = false WHERE id = $1")
        .bind(admin.id)
        .execute(&pool)
        .await
        .unwrap();
    rig.seed(FORGE).await;
    let demoted = rig.post(&admin, "/hosts/remove", FORGE).await;
    assert_eq!(demoted.status, 403);
    assert_eq!(rig.hosts().await, [FORGE, "github.com"]);
}

#[sqlx::test]
async fn a_host_in_use_is_not_removed(pool: PgPool) {
    let rig = start(pool.clone(), DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    sqlx::query(
        "INSERT INTO user_repos (user_id, host, path, forge_kind, push) \
         VALUES ($1, $2, 'o/r', 'forgejo', NULL)",
    )
    .bind(admin.id)
    .bind(FORGE)
    .execute(&pool)
    .await
    .unwrap();
    let reply = rig.post(&admin, "/hosts/remove", FORGE).await;
    assert_eq!(reply.notice(), CredentialNotice::HostInUse.code());
    assert_eq!(rig.hosts().await, [FORGE, "github.com"]);
}

#[sqlx::test]
async fn a_hostile_remove_value_is_refused_without_a_request(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    assert_eq!(rig.audited().await, 0);
    for host in refused_hosts() {
        let reply = rig.post(&admin, "/hosts/remove", &host).await;
        assert_eq!(
            reply.notice(),
            CredentialNotice::HostMissing.code(),
            "{host:?}"
        );
        assert!(!reply.location().contains("example"));
    }
    assert_eq!(rig.audited().await, 0);
    assert_eq!(rig.calls(), 0);
    assert_eq!(rig.probed(), Vec::<String>::new());
    assert_eq!(rig.hosts().await, [FORGE, "github.com"]);
    let control = rig
        .post(&admin, "/hosts/remove", "absent.example.com")
        .await;
    assert_eq!(control.notice(), CredentialNotice::HostMissing.code());
    assert_eq!(rig.audited().await, 1);
}

#[sqlx::test]
async fn an_unknown_notice_code_renders_no_notice_and_no_echo(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    let control = rig
        .http("GET", "/hosts?notice=host_added", &admin.cookie, "")
        .await
        .body;
    assert!(control.contains("id=\"notice\""));
    assert!(control.contains(CredentialNotice::HostAdded.text()));
    let long = "x".repeat(2000);
    let table = [
        "<script>alert(1)</script>",
        "\"><img src=x onerror=alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#60;b&#62;zqxmark",
        "zqxmark_unknown_code",
        "h\u{f6}st_added",
        "host_added\u{2028}zqxmark",
        long.as_str(),
        "",
    ];
    for code in table {
        let page = rig
            .http(
                "GET",
                &format!("/hosts?notice={}", enc(code)),
                &admin.cookie,
                "",
            )
            .await
            .body;
        assert!(!page.contains("id=\"notice\""), "{code:?}");
        for notice in CredentialNotice::ALL {
            assert!(!page.contains(notice.text()), "{code:?} {notice:?}");
        }
        if !code.is_empty() {
            assert!(!page.contains(code), "{code:?}");
            assert!(!page.contains(&enc(code)), "{code:?}");
        }
    }
    let raw = rig
        .http("GET", "/hosts?notice=%3Cb%3Ezqxmark", &admin.cookie, "")
        .await
        .body;
    assert!(!raw.contains("zqxmark"));
}

#[sqlx::test]
async fn hostile_stored_strings_are_escaped_in_every_position(pool: PgPool) {
    let rig = start(pool.clone(), DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    let hostile = "\"><script>alert(1)</script><x y=\"";
    rig.seed(hostile).await;
    sqlx::query("INSERT INTO git_host_requests (host, user_id, resolved) VALUES ($1, $2, '{}')")
        .bind(hostile)
        .bind(admin.id)
        .execute(&pool)
        .await
        .unwrap();
    let page = rig.http("GET", "/hosts", &admin.cookie, "").await.body;
    assert!(!page.contains("\"><script>alert"), "{page}");
    assert!(page.contains("data-host=\"&quot;><script>"), "{page}");
    assert!(
        page.contains("name=\"host\" value=\"&quot;><script>"),
        "{page}"
    );
    assert!(
        page.contains("<td>\"&gt;&lt;script&gt;alert(1)&lt;/script&gt;"),
        "{page}"
    );
}

#[sqlx::test]
async fn the_repository_table_is_the_repos_page_table(pool: PgPool) {
    let rig = start(
        pool.clone(),
        Setup {
            repos: true,
            ..DEFAULT
        },
    )
    .await;
    let who = rig.persona("olive", 'a', false).await;
    sqlx::query(
        "INSERT INTO user_repos (user_id, host, path, forge_kind, push) \
         VALUES ($1, 'github.com', 'octo/hello', 'github', true)",
    )
    .bind(who.id)
    .execute(&pool)
    .await
    .unwrap();
    let hosts = rig.http("GET", "/hosts", &who.cookie, "").await.body;
    let repos = rig.http("GET", "/repos", &who.cookie, "").await.body;
    for page in [&hosts, &repos] {
        assert!(page.contains("<th>Runnable</th>"));
        assert!(page.contains("<td>octo/hello</td>"));
        assert!(page.contains("action=\"/repos/remove\""));
    }
    let bare = start(pool, DEFAULT).await;
    let page = bare.http("GET", "/hosts", &who.cookie, "").await.body;
    assert!(!page.contains("<th>Runnable</th>"));
}

fn hostile_addresses() -> Vec<String> {
    let mut list: Vec<String> = [
        "192.168.3.7\r",
        "192.168.3.7\n",
        "192.168.3.7\r\n",
        "192.168.3.7\u{85}",
        "192.168.3.7\u{2028}",
        "user@192.168.3.7",
        "user:pass@192.168.3.7",
        "192.168.3.7\\evil",
        "[::1]",
        "fe80::1%eth0",
        "192.168.3.7:80",
        "192.168.3.7,",
        ",192.168.3.7",
        "192.168.3.7,,192.168.3.8",
        "192.168.3.7, 192.168.3.8",
        " 192.168.3.7",
        "192.168.3.7 ",
        "192.168.3 .7",
        "\u{FF11}92.168.3.7",
        "192.168.3.7/24",
        "FD00::G",
        "localhost",
        "git.example.com",
        "",
        "   ",
    ]
    .into_iter()
    .map(|text| text.replace(PRIVATE_IP, "198.51.100.9"))
    .collect();
    list.push("1".repeat(1000));
    list.push(["198.51.100.9"; 100].join(","));
    list.push(
        (1..=17)
            .map(|n| format!("10.0.0.{n}"))
            .collect::<Vec<_>>()
            .join(","),
    );
    list
}

#[sqlx::test]
async fn the_request_row_names_the_addresses_and_approve_revoke_call_the_service(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    rig.pend(FORGE, admin.id, PRIVATE_IP).await;
    let page = rig.http("GET", "/hosts", &admin.cookie, "").await.body;
    for needle in [
        "action=\"/hosts/approve\"",
        "name=\"addresses\" value=\"192.168.3.7\"",
        "Approve 192.168.3.7",
    ] {
        assert!(page.contains(needle), "page lacks {needle}");
    }
    assert!(!page.contains("action=\"/hosts/revoke\""));
    let mismatch = rig
        .post_form(&admin, "/hosts/approve", FORGE, "192.168.3.8")
        .await;
    assert_eq!(
        mismatch.notice(),
        CredentialNotice::HostAddressMismatch.code()
    );
    assert_eq!(rig.grant().await, (false, Vec::new()));
    let over_cap = [PRIVATE_IP; MAX_HOST_APPROVED_IPS + 1].join(",");
    let refused = rig
        .post_form(&admin, "/hosts/approve", FORGE, &over_cap)
        .await;
    assert_eq!(refused.notice(), CredentialNotice::HostInvalid.code());
    let page = rig
        .http("GET", &refused.location(), &admin.cookie, "")
        .await
        .body;
    assert!(page.contains(CredentialNotice::HostInvalid.text()));
    assert!(!page.contains(&over_cap));
    assert_eq!(rig.grant().await, (false, Vec::new()));
    let repeated = [PRIVATE_IP; MAX_HOST_APPROVED_IPS].join(",");
    let approved = rig
        .post_form(&admin, "/hosts/approve", FORGE, &repeated)
        .await;
    assert_eq!(approved.notice(), CredentialNotice::HostApproved.code());
    assert_eq!(rig.grant().await, (true, vec![PRIVATE_IP.to_owned()]));
    let page = rig.http("GET", "/hosts", &admin.cookie, "").await.body;
    for needle in ["action=\"/hosts/revoke\"", "Revoke 192.168.3.7"] {
        assert!(page.contains(needle), "page lacks {needle}");
    }
    let revoked = rig.post_form(&admin, "/hosts/revoke", FORGE, "").await;
    assert_eq!(revoked.notice(), CredentialNotice::HostRevoked.code());
    assert_eq!(rig.grant().await, (false, Vec::new()));
}

#[sqlx::test]
async fn approve_and_revoke_are_not_found_for_a_non_admin(pool: PgPool) {
    let rig = start(pool.clone(), DEFAULT).await;
    let user = rig.persona("olive", 'a', false).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    rig.pend(FORGE, user.id, PRIVATE_IP).await;
    sqlx::query("UPDATE git_hosts SET allow_private = true, approved_ips = ARRAY[$1]::inet[] WHERE host = $2")
        .bind(PRIVATE_IP)
        .bind(FORGE)
        .execute(&pool)
        .await
        .unwrap();
    let want = (true, vec![PRIVATE_IP.to_owned()]);
    let control = rig
        .post_form(&admin, "/hosts/approve", FORGE, "192.168.3.8")
        .await;
    assert_eq!(
        control.notice(),
        CredentialNotice::HostAddressMismatch.code()
    );
    let before = rig.calls();
    assert!(before > 0);
    for path in ["/hosts/approve", "/hosts/revoke"] {
        let denied = rig.post_form(&user, path, FORGE, PRIVATE_IP).await;
        assert_eq!(denied.status, 404, "{path}");
    }
    sqlx::query("UPDATE users SET is_admin = false WHERE id = $1")
        .bind(admin.id)
        .execute(&pool)
        .await
        .unwrap();
    for path in ["/hosts/approve", "/hosts/revoke"] {
        let demoted = rig.post_form(&admin, path, FORGE, PRIVATE_IP).await;
        assert_eq!(demoted.status, 404, "demoted {path}");
    }
    assert_eq!(rig.calls(), before);
    assert_eq!(rig.grant().await, want);
    let page = rig.http("GET", "/hosts", &user.cookie, "").await.body;
    assert!(!page.contains("/hosts/approve") && !page.contains("/hosts/revoke"));
}

#[sqlx::test]
async fn approve_and_revoke_need_the_session_csrf_token(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    rig.pend(FORGE, admin.id, PRIVATE_IP).await;
    let hostile_csrf = enc("csrf-root-token\r\nx");
    let bodies = [
        format!("host={FORGE}&addresses={PRIVATE_IP}"),
        format!("csrf=wrong&host={FORGE}&addresses={PRIVATE_IP}"),
        format!("csrf=&host={FORGE}&addresses={PRIVATE_IP}"),
        format!("csrf={hostile_csrf}&host={FORGE}&addresses={PRIVATE_IP}"),
    ];
    for path in ["/hosts/approve", "/hosts/revoke"] {
        for body in &bodies {
            let reply = rig.http("POST", path, &admin.cookie, body).await;
            assert_eq!(reply.status, 403, "{path} {body}");
        }
        let anon = rig
            .http(
                "POST",
                path,
                "",
                &format!("host={FORGE}&addresses={PRIVATE_IP}"),
            )
            .await;
        assert_eq!(anon.status, 403, "{path} anonymous");
    }
    assert_eq!(rig.calls(), 0);
    assert_eq!(rig.grant().await, (false, Vec::new()));
}

#[sqlx::test]
async fn hostile_approve_and_revoke_input_is_refused_without_a_service_call(pool: PgPool) {
    let rig = start(pool, DEFAULT).await;
    let admin = rig.persona("root", 'b', true).await;
    rig.seed(FORGE).await;
    rig.pend(FORGE, admin.id, PRIVATE_IP).await;
    for host in refused_hosts() {
        for path in ["/hosts/approve", "/hosts/revoke"] {
            let reply = rig.post_form(&admin, path, &host, PRIVATE_IP).await;
            assert_eq!(reply.status, 303, "{path} {host:?}");
            assert_eq!(
                reply.notice(),
                CredentialNotice::HostMissing.code(),
                "{path} {host:?}"
            );
        }
    }
    for addresses in hostile_addresses() {
        let reply = rig
            .post_form(&admin, "/hosts/approve", FORGE, &addresses)
            .await;
        assert_eq!(reply.status, 303, "{addresses:?}");
        assert_eq!(
            reply.notice(),
            CredentialNotice::HostInvalid.code(),
            "{addresses:?}"
        );
        let page = rig
            .http("GET", &reply.location(), &admin.cookie, "")
            .await
            .body;
        let probe = addresses.trim();
        assert!(
            probe.len() < 4 || probe == FORGE || !page.contains(probe),
            "{addresses:?}"
        );
    }
    let missing = rig
        .http(
            "POST",
            "/hosts/approve",
            &admin.cookie,
            &format!("csrf={}&host={FORGE}", admin.csrf),
        )
        .await;
    assert_eq!(missing.notice(), CredentialNotice::HostInvalid.code());
    assert_eq!(rig.calls(), 0);
    assert_eq!(rig.grant().await, (false, Vec::new()));
    for code in [
        "host_approved%0d%0ax",
        "host_approved%0A",
        "HOST_APPROVED",
        "host_approved%C2%85",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "",
        "x".repeat(2000).as_str(),
    ] {
        let page = rig
            .http("GET", &format!("/hosts?notice={code}"), &admin.cookie, "")
            .await
            .body;
        assert!(!page.contains("id=\"notice\""), "{code}");
    }
}
