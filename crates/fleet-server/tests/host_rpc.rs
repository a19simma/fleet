//! `FleetHosts` add, list and remove at the service boundary (ADR-0068): the hostile-input
//! table, the closed refusal reasons, the caps, the per-User limiter and the admin gate. The
//! tests need a Postgres superuser URL in `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fleet_core::host::{HostKind, HostName};
use fleet_proto::Reason;
use fleet_proto::v1::fleet_hosts_server::FleetHosts;
use fleet_proto::v1::{
    AddHostRequest, ApproveHostPrivateRequest, ListHostRequestsRequest, ListHostsRequest,
    RemoveHostRequest, RevokeHostPrivateRequest,
};
use fleet_server::auth::{ADMIN_REQUIRED, BearerAuth, Caller, HOST_ADMIN_RPCS};
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::cred::https::{FetchError, ForgeGet, ForgeReply, ForgeTransport};
use fleet_server::cred::limiter::Clock;
use fleet_server::cred::pinned::Resolve;
use fleet_server::cred::repo_limit::CheckLimiter;
use fleet_server::hosts::{HostProbe, HostRefusal, HostService, HostStore, PinnedProbe};
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use hyper::StatusCode;
use sqlx::PgPool;
use tonic::{Code, Request, Status};

const FORGE: &str = r#"{"version":"17.0.1"}"#;
const PUBLIC: &str = "93.184.216.34";

#[derive(Clone)]
struct Dns(Vec<IpAddr>);

#[tonic::async_trait]
impl Resolve for Dns {
    async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
        if self.0.is_empty() {
            Err(io::Error::from(io::ErrorKind::NotFound))
        } else {
            Ok(self.0.clone())
        }
    }
}

fn dns(addrs: &[&str]) -> Dns {
    Dns(addrs.iter().map(|a| a.parse().unwrap()).collect())
}

#[derive(Clone)]
struct Wire {
    reply: Result<(u16, String), FetchError>,
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
}

fn wire(status: u16, body: &str) -> Wire {
    Wire {
        reply: Ok((status, body.to_owned())),
        calls: Arc::new(AtomicUsize::new(0)),
        seen: Arc::new(Mutex::new(Vec::new())),
    }
}

#[tonic::async_trait]
impl ForgeTransport for Wire {
    async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(request.host.to_owned());
        self.reply.clone().map(|(status, body)| ForgeReply {
            status: StatusCode::from_u16(status).unwrap(),
            body: body.into_bytes(),
            location: None,
        })
    }
}

struct Fixed {
    verdict: Result<HostKind, HostRefusal>,
    calls: AtomicUsize,
}

#[tonic::async_trait]
impl HostProbe for Fixed {
    async fn probe(&self, _host: &HostName) -> Result<HostKind, HostRefusal> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.verdict
    }
}

struct Stall;

#[tonic::async_trait]
impl HostProbe for Stall {
    async fn probe(&self, _host: &HostName) -> Result<HostKind, HostRefusal> {
        tokio::time::sleep(Duration::from_secs(600)).await;
        Ok(HostKind::Forgejo)
    }
}

struct World {
    svc: FleetService,
    pool: PgPool,
    alice: i64,
    bob: i64,
    admin: i64,
}

async fn user(pool: &PgPool, name: &str, admin: bool) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username, is_admin) VALUES ($1, $2) RETURNING id")
        .bind(name)
        .bind(admin)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn world_with(pool: PgPool, build: impl FnOnce(HostStore) -> HostService) -> World {
    Store::new(pool.clone()).migrate().await.unwrap();
    let alice = user(&pool, "alice", false).await;
    let bob = user(&pool, "bob", false).await;
    let admin = user(&pool, "root", true).await;
    let hosts = build(HostStore::new(pool.clone()));
    let svc = FleetService::new(Store::new(pool.clone())).with_hosts(Some(hosts));
    World {
        svc,
        pool,
        alice,
        bob,
        admin,
    }
}

async fn world(pool: PgPool, resolver: Dns, wire: Wire) -> World {
    world_with(pool, |store| {
        HostService::new(store, Arc::new(PinnedProbe::new(resolver, wire)))
    })
    .await
}

fn as_user<T>(user_id: i64, is_admin: bool, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .extensions_mut()
        .insert(Caller { user_id, is_admin });
    request
}

async fn add(world: &World, user_id: i64, host: &str) -> Result<fleet_proto::v1::HostInfo, Status> {
    world
        .svc
        .add_host(as_user(
            user_id,
            false,
            AddHostRequest {
                host: host.to_owned(),
            },
        ))
        .await
        .map(tonic::Response::into_inner)
}

fn closed(reason: Reason) -> (Code, String) {
    let (code, message) = reason.status_parts();
    (code, message.to_owned())
}

fn parts(status: &Status) -> (Code, String) {
    (status.code(), status.message().to_owned())
}

async fn host_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM git_hosts")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn audit_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM host_audit")
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn refused_without_a_request(pool: PgPool, input: &str) {
    let net = wire(200, FORGE);
    let w = world(pool, dns(&[PUBLIC]), net.clone()).await;
    let before = host_count(&w.pool).await;
    let err = add(&w, w.alice, input).await.unwrap_err();
    assert_eq!(parts(&err), closed(Reason::RepoNotAllowedHost), "{input:?}");
    assert_eq!(net.calls.load(Ordering::SeqCst), 0, "{input:?}");
    assert_eq!(host_count(&w.pool).await, before, "{input:?}");
}

macro_rules! hostile {
    ($($name:ident: $input:expr,)*) => {$(
        #[sqlx::test(migrations = false)]
        async fn $name(pool: PgPool) {
            refused_without_a_request(pool, $input).await;
        }
    )*};
}

hostile! {
    hostile_cr: "git.example.com\r",
    hostile_crlf: "git.example.com\r\nx.example.com",
    hostile_lf: "git.example.com\n",
    hostile_nel: "git.example.com\u{85}",
    hostile_line_separator: "git.example.com\u{2028}",
    hostile_paragraph_separator: "git.example.com\u{2029}",
    hostile_nul: "git.example.com\0",
    hostile_userinfo: "user@git.example.com",
    hostile_userinfo_password: "user:pw@git.example.com",
    hostile_backslash: "git.example.com\\evil.com",
    hostile_ipv6_bracketed: "[::1]",
    hostile_ipv6_bare: "::1",
    hostile_ipv6_mapped: "[::ffff:10.0.0.1]",
    hostile_ipv4_literal: "93.184.216.34",
    hostile_ipv4_private_literal: "10.0.0.1",
    hostile_ipv4_decimal: "2130706433",
    hostile_ipv4_hex: "0x7f000001",
    hostile_empty_label: "git..example.com",
    hostile_leading_dot: ".git.example.com",
    hostile_double_trailing_dot: "git.example.com..",
    hostile_over_long: "aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.aaaaaaaaaa.com",
    hostile_over_long_label: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com",
    hostile_empty: "",
    hostile_space_inside: "git .example.com",
    hostile_space_leading: " git.example.com",
    hostile_space_trailing: "git.example.com ",
    hostile_tab: "git.example.com\t",
    hostile_ideographic_space: "git.example.com\u{3000}",
    hostile_zero_width_space: "git\u{200b}.example.com",
    hostile_bidi_override: "git.example.com\u{202e}",
    hostile_mixed_script: "g\u{0456}t.example.com",
    hostile_non_ascii_invalid_idna: "xn--.example.com",
    hostile_fullwidth_dot_ip: "10\u{3002}0\u{3002}0\u{3002}1",
    hostile_github: "github.com",
    hostile_github_upper: "GitHub.com",
    hostile_github_trailing_dot: "github.com.",
    hostile_github_subtle: "GITHUB.COM.",
    hostile_port: "git.example.com:443",
    hostile_port_empty: "git.example.com:",
    hostile_scheme: "https://git.example.com",
    hostile_scheme_relative: "//git.example.com",
    hostile_path: "git.example.com/path",
    hostile_query: "git.example.com?x=1",
    hostile_fragment: "git.example.com#x",
    hostile_wildcard: "*.example.com",
    hostile_wildcard_label: "g*t.example.com",
    hostile_localhost: "localhost",
    hostile_localhost_suffix: "git.localhost",
    hostile_local_suffix: "git.local",
    hostile_internal_suffix: "git.internal",
    hostile_single_label: "gitserver",
    hostile_leading_hyphen: "-git.example.com",
    hostile_trailing_hyphen: "git-.example.com",
}

#[sqlx::test(migrations = false)]
async fn case_and_trailing_dot_variants_add_one_normalised_row(pool: PgPool) {
    let net = wire(200, FORGE);
    let w = world(pool, dns(&[PUBLIC]), net.clone()).await;
    let first = add(&w, w.alice, "GIT.Example.COM.").await.unwrap();
    assert_eq!(first.host, "git.example.com");
    let again = add(&w, w.bob, "git.example.com").await.unwrap();
    assert_eq!(again.added_by, u64::try_from(w.alice).unwrap());
    assert_eq!(net.calls.load(Ordering::SeqCst), 1);
    assert_eq!(host_count(&w.pool).await, 2);
}

#[sqlx::test(migrations = false)]
async fn an_internationalised_name_is_stored_as_punycode(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    let added = add(&w, w.alice, "b\u{fc}cher.example.com").await.unwrap();
    assert_eq!(added.host, "xn--bcher-kva.example.com");
    let punycode = add(&w, w.alice, "XN--BCHER-KVA.example.com").await.unwrap();
    assert_eq!(punycode.host, added.host);
    assert_eq!(host_count(&w.pool).await, 2);
}

async fn private_refusal(pool: PgPool, resolver: Dns) {
    let net = wire(200, FORGE);
    let w = world(pool, resolver, net.clone()).await;
    let err = add(&w, w.alice, "git.example.com").await.unwrap_err();
    assert_eq!(parts(&err), closed(Reason::RepoNotAllowedHost));
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
    assert_eq!(host_count(&w.pool).await, 1);
}

#[sqlx::test(migrations = false)]
async fn a_public_name_with_a_private_a_record_is_refused(pool: PgPool) {
    private_refusal(pool, dns(&["192.168.1.10"])).await;
}

#[sqlx::test(migrations = false)]
async fn a_public_name_with_a_loopback_record_is_refused(pool: PgPool) {
    private_refusal(pool, dns(&["127.0.0.1"])).await;
}

#[sqlx::test(migrations = false)]
async fn a_public_name_with_a_link_local_metadata_record_is_refused(pool: PgPool) {
    private_refusal(pool, dns(&["169.254.169.254"])).await;
}

#[sqlx::test(migrations = false)]
async fn a_public_name_with_a_private_ipv6_record_is_refused(pool: PgPool) {
    private_refusal(pool, dns(&["fd00::1"])).await;
}

#[sqlx::test(migrations = false)]
async fn a_name_with_mixed_public_and_private_records_is_refused(pool: PgPool) {
    private_refusal(pool, dns(&[PUBLIC, "10.0.0.1"])).await;
}

#[sqlx::test(migrations = false)]
async fn a_name_with_mixed_records_in_the_other_order_is_refused(pool: PgPool) {
    private_refusal(pool, dns(&["10.0.0.1", PUBLIC])).await;
}

#[sqlx::test(migrations = false)]
async fn a_name_that_does_not_resolve_is_refused_like_a_private_one(pool: PgPool) {
    private_refusal(pool, dns(&[])).await;
}

#[sqlx::test(migrations = false)]
async fn a_private_refusal_is_the_same_status_as_a_grammar_refusal(pool: PgPool) {
    let net = wire(200, FORGE);
    let w = world(pool.clone(), dns(&["10.0.0.1"]), net).await;
    let private = add(&w, w.alice, "git.example.com").await.unwrap_err();
    let grammar = add(&w, w.alice, "git.example.com:80").await.unwrap_err();
    assert_eq!(parts(&private), parts(&grammar));
    assert_eq!(private.metadata().len(), grammar.metadata().len());
}

#[sqlx::test(migrations = false)]
async fn every_non_forge_answer_is_refused(pool: PgPool) {
    Store::new(pool.clone()).migrate().await.unwrap();
    for (status, body) in [(200, "<html>"), (404, ""), (200, r#"{"x":1}"#), (301, "")] {
        let w = world_nomigrate(pool.clone(), wire(status, body)).await;
        let err = add(&w, w.alice, "web.example.com").await.unwrap_err();
        assert_eq!(parts(&err), closed(Reason::HostNotForge), "{status} {body}");
    }
    assert_eq!(host_count(&pool).await, 1);
}

async fn world_nomigrate(pool: PgPool, net: Wire) -> World {
    let alice = sqlx::query_scalar("SELECT id FROM users WHERE username = 'alice'")
        .fetch_optional(&pool)
        .await
        .unwrap();
    let alice = match alice {
        Some(id) => id,
        None => user(&pool, "alice", false).await,
    };
    let hosts = HostService::new(
        HostStore::new(pool.clone()),
        Arc::new(PinnedProbe::new(dns(&[PUBLIC]), net)),
    );
    World {
        svc: FleetService::new(Store::new(pool.clone())).with_hosts(Some(hosts)),
        pool,
        alice,
        bob: 0,
        admin: 0,
    }
}

#[sqlx::test(migrations = false)]
async fn a_github_answer_is_refused_as_not_a_forgejo_host(pool: PgPool) {
    let probe = Arc::new(Fixed {
        verdict: Ok(HostKind::Github),
        calls: AtomicUsize::new(0),
    });
    let w = world_with(pool, |store| HostService::new(store, probe.clone())).await;
    let err = add(&w, w.alice, "gh.example.com").await.unwrap_err();
    assert_eq!(parts(&err), closed(Reason::HostNotForge));
    assert_eq!(host_count(&w.pool).await, 1);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
}

#[sqlx::test(migrations = false)]
async fn each_probe_refusal_maps_to_its_closed_reason(pool: PgPool) {
    let table = [
        (HostRefusal::NotAllowedHost, Reason::RepoNotAllowedHost),
        (HostRefusal::NotForge, Reason::HostNotForge),
        (HostRefusal::Unavailable, Reason::RepoUpstreamUnavailable),
        (HostRefusal::Timeout, Reason::RepoTimeout),
    ];
    Store::new(pool.clone()).migrate().await.unwrap();
    for (n, (refusal, reason)) in table.into_iter().enumerate() {
        let probe = Arc::new(Fixed {
            verdict: Err(refusal),
            calls: AtomicUsize::new(0),
        });
        let svc = FleetService::new(Store::new(pool.clone()))
            .with_hosts(Some(HostService::new(HostStore::new(pool.clone()), probe)));
        let id = user(&pool, &format!("u{n}"), false).await;
        let w = World {
            svc,
            pool: pool.clone(),
            alice: id,
            bob: 0,
            admin: 0,
        };
        let err = add(&w, id, "x.example.com").await.unwrap_err();
        assert_eq!(parts(&err), closed(reason));
    }
    assert_eq!(host_count(&pool).await, 1);
}

#[sqlx::test(migrations = false)]
async fn a_probe_over_its_budget_is_a_timeout(pool: PgPool) {
    let w = world_with(pool, |store| {
        HostService::new(store, Arc::new(Stall)).with_budget(Duration::from_millis(50))
    })
    .await;
    let err = add(&w, w.alice, "slow.example.com").await.unwrap_err();
    assert_eq!(parts(&err), closed(Reason::RepoTimeout));
    assert_eq!(host_count(&w.pool).await, 1);
}

#[sqlx::test(migrations = false)]
async fn add_audits_one_row_and_list_shows_who_added_it(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    let added = add(&w, w.alice, "git.example.com").await.unwrap();
    assert_eq!(added.kind, "forgejo");
    assert!(!added.allow_private);
    assert_eq!(audit_count(&w.pool).await, 1);
    let listed = w
        .svc
        .list_hosts(as_user(w.bob, false, ListHostsRequest {}))
        .await
        .unwrap()
        .into_inner()
        .hosts;
    let ours = listed.iter().find(|h| h.host == "git.example.com").unwrap();
    assert_eq!(ours.added_by, u64::try_from(w.alice).unwrap());
    assert!(!ours.allow_private);
    let seed = listed.iter().find(|h| h.host == "github.com").unwrap();
    assert_eq!(seed.added_by, 0);
}

#[sqlx::test(migrations = false)]
async fn list_hides_approved_addresses_from_a_user_and_shows_them_to_an_admin(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap();
    sqlx::query("UPDATE git_hosts SET allow_private = true, approved_ips = ARRAY['10.1.2.3']::inet[] WHERE host = 'git.example.com'")
        .execute(&w.pool)
        .await
        .unwrap();
    let find = |reply: fleet_proto::v1::ListHostsReply| {
        reply
            .hosts
            .into_iter()
            .find(|h| h.host == "git.example.com")
            .unwrap()
    };
    let user_view = find(
        w.svc
            .list_hosts(as_user(w.alice, false, ListHostsRequest {}))
            .await
            .unwrap()
            .into_inner(),
    );
    assert!(user_view.allow_private);
    assert_eq!(user_view.approved_ips, Vec::<String>::new());
    let admin_view = find(
        w.svc
            .list_hosts(as_user(w.admin, true, ListHostsRequest {}))
            .await
            .unwrap()
            .into_inner(),
    );
    assert_eq!(admin_view.approved_ips, ["10.1.2.3"]);
}

#[sqlx::test(migrations = false)]
async fn a_known_host_is_returned_without_a_probe(pool: PgPool) {
    let probe = Arc::new(Fixed {
        verdict: Ok(HostKind::Forgejo),
        calls: AtomicUsize::new(0),
    });
    let w = world_with(pool, |store| HostService::new(store, probe.clone())).await;
    add(&w, w.alice, "git.example.com").await.unwrap();
    let again = add(&w, w.bob, "git.example.com").await.unwrap();
    assert_eq!(again.added_by, u64::try_from(w.alice).unwrap());
    assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
    assert_eq!(audit_count(&w.pool).await, 2);
}

#[sqlx::test(migrations = false)]
async fn the_per_user_host_cap_is_resource_exhausted(pool: PgPool) {
    let probe = Arc::new(Fixed {
        verdict: Ok(HostKind::Forgejo),
        calls: AtomicUsize::new(0),
    });
    let w = world_with(pool, |store| {
        HostService::new(store.with_caps(2, 100), probe.clone())
    })
    .await;
    add(&w, w.alice, "a.example.com").await.unwrap();
    add(&w, w.alice, "b.example.com").await.unwrap();
    let err = add(&w, w.alice, "c.example.com").await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(err.message(), fleet_proto::ERR_HOST_LIMIT);
    add(&w, w.bob, "d.example.com").await.unwrap();
    assert_eq!(host_count(&w.pool).await, 4);
}

#[sqlx::test(migrations = false)]
async fn the_global_host_cap_is_resource_exhausted(pool: PgPool) {
    let probe = Arc::new(Fixed {
        verdict: Ok(HostKind::Forgejo),
        calls: AtomicUsize::new(0),
    });
    let w = world_with(pool, |store| {
        HostService::new(store.with_caps(10, 3), probe.clone())
    })
    .await;
    add(&w, w.alice, "a.example.com").await.unwrap();
    add(&w, w.bob, "b.example.com").await.unwrap();
    let err = add(&w, w.alice, "c.example.com").await.unwrap_err();
    assert_eq!(err.code(), Code::ResourceExhausted);
    assert_eq!(err.message(), fleet_proto::ERR_HOST_LIMIT);
}

#[sqlx::test(migrations = false)]
async fn the_per_user_check_limiter_covers_add(pool: PgPool) {
    let probe = Arc::new(Fixed {
        verdict: Err(HostRefusal::NotForge),
        calls: AtomicUsize::new(0),
    });
    let clock: Clock = Arc::new(std::time::Instant::now);
    let limiter = Arc::new(CheckLimiter::new(clock, 2, Duration::from_secs(3600)));
    let w = world_with(pool, |store| {
        HostService::new(store, probe.clone()).with_limiter(limiter)
    })
    .await;
    for _ in 0..2 {
        let err = add(&w, w.alice, "x.example.com").await.unwrap_err();
        assert_eq!(parts(&err), closed(Reason::HostNotForge));
    }
    let limited = add(&w, w.alice, "x.example.com").await.unwrap_err();
    assert_eq!(limited.code(), Code::ResourceExhausted);
    assert_eq!(limited.message(), fleet_proto::ERR_REPO_RATE_LIMITED);
    assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
    let other = add(&w, w.bob, "x.example.com").await.unwrap_err();
    assert_eq!(parts(&other), closed(Reason::HostNotForge));
}

#[sqlx::test(migrations = false)]
async fn concurrent_checks_past_the_cap_are_busy(pool: PgPool) {
    let w = Arc::new(
        world_with(pool, |store| {
            HostService::new(store, Arc::new(Stall)).with_concurrency(1)
        })
        .await,
    );
    let first = {
        let w = w.clone();
        tokio::spawn(async move { add(&w, w.alice, "a.example.com").await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let busy = add(&w, w.bob, "b.example.com").await.unwrap_err();
    assert_eq!(busy.code(), Code::ResourceExhausted);
    assert_eq!(busy.message(), fleet_proto::ERR_REPO_BUSY);
    first.abort();
}

#[sqlx::test(migrations = false)]
async fn a_caller_without_a_user_cannot_add_or_list(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    let bare = Request::new(AddHostRequest {
        host: "git.example.com".to_owned(),
    });
    let err = w.svc.add_host(bare).await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), fleet_proto::ERR_NEEDS_USER_TOKEN);
    let err = w
        .svc
        .list_hosts(Request::new(ListHostsRequest {}))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
}

#[sqlx::test(migrations = false)]
async fn hosts_not_configured_is_failed_precondition(pool: PgPool) {
    Store::new(pool.clone()).migrate().await.unwrap();
    let alice = user(&pool, "alice", false).await;
    let svc = FleetService::new(Store::new(pool));
    let err = svc
        .add_host(as_user(
            alice,
            false,
            AddHostRequest {
                host: "a.example.com".into(),
            },
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::FailedPrecondition);
}

#[sqlx::test(migrations = false)]
async fn remove_is_admin_only_and_audited(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap();
    let request = |is_admin, id| {
        as_user(
            id,
            is_admin,
            RemoveHostRequest {
                host: "git.example.com".into(),
            },
        )
    };
    let err = w
        .svc
        .remove_host(request(false, w.alice))
        .await
        .unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), ADMIN_REQUIRED);
    assert_eq!(host_count(&w.pool).await, 2);
    w.svc.remove_host(request(true, w.admin)).await.unwrap();
    assert_eq!(host_count(&w.pool).await, 1);
    let removed: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM host_audit WHERE action = 'remove' AND outcome = 'removed' AND user_id = $1",
    )
    .bind(w.admin)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(removed, 1);
}

#[sqlx::test(migrations = false)]
async fn remove_refuses_in_use_unknown_and_builtin_hosts(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap();
    sqlx::query(
        "INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint, host) \
         VALUES ($1, 'forgejo_pat', 'static_secret', '\\x00', 'k', 'f', 'git.example.com')",
    )
    .bind(w.alice)
    .execute(&w.pool)
    .await
    .unwrap();
    let remove = |host: &str| {
        as_user(
            w.admin,
            true,
            RemoveHostRequest {
                host: host.to_owned(),
            },
        )
    };
    let in_use = w
        .svc
        .remove_host(remove("git.example.com"))
        .await
        .unwrap_err();
    assert_eq!(parts(&in_use), closed(Reason::HostInUse));
    let seed = w.svc.remove_host(remove("github.com")).await.unwrap_err();
    assert_eq!(parts(&seed), closed(Reason::HostInUse));
    for host in ["nope.example.com", "not a host", ""] {
        let err = w.svc.remove_host(remove(host)).await.unwrap_err();
        assert_eq!(err.code(), Code::NotFound, "{host:?}");
        assert_eq!(err.message(), fleet_proto::ERR_HOST_NOT_FOUND);
    }
    assert_eq!(host_count(&w.pool).await, 2);
}

#[sqlx::test(migrations = false)]
async fn the_unbuilt_admin_rpcs_are_admin_gated_in_the_handler(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    let denied = [
        w.svc
            .approve_host_private(as_user(
                w.alice,
                false,
                ApproveHostPrivateRequest::default(),
            ))
            .await
            .unwrap_err(),
        w.svc
            .revoke_host_private(as_user(w.alice, false, RevokeHostPrivateRequest::default()))
            .await
            .unwrap_err(),
        w.svc
            .list_host_requests(as_user(w.alice, false, ListHostRequestsRequest {}))
            .await
            .unwrap_err(),
    ];
    for err in denied {
        assert_eq!(err.message(), ADMIN_REQUIRED);
    }
}

#[sqlx::test(migrations = false)]
async fn the_bearer_gate_admits_every_user_to_add_and_list_and_only_admins_to_the_rest(
    pool: PgPool,
) {
    Store::new(pool.clone()).migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let member = user(&pool, "member", false).await;
    let admin = user(&pool, "root", true).await;
    let header = |made: fleet_server::cred::NewApiToken| {
        format!(
            "Bearer {}",
            String::from_utf8(made.token.expose().to_vec()).unwrap()
        )
    };
    let member_header = header(users.create_api_token(member, "t").await.unwrap());
    let admin_header = header(users.create_api_token(admin, "t").await.unwrap());
    let box_token = Token::new("box-token-0123456789abcdef0123456789".into()).unwrap();
    let client = Token::new("client-token-0123456789abcdef012345".into()).unwrap();
    let auth = BearerAuth::new(&box_token, Some(&client)).with_users(users);
    let client_header = "Bearer client-token-0123456789abcdef012345";
    let box_header = "Bearer box-token-0123456789abcdef0123456789";
    for path in [
        "/fleet.v1.FleetHosts/AddHost",
        "/fleet.v1.FleetHosts/ListHosts",
    ] {
        for header in [&member_header, &admin_header, &client_header.to_owned()] {
            auth.authenticate(path, Some(header.as_bytes()))
                .await
                .unwrap();
        }
        let err = auth
            .authenticate(path, Some(box_header.as_bytes()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied, "{path}");
    }
    assert_eq!(HOST_ADMIN_RPCS.len(), 4);
    for path in HOST_ADMIN_RPCS {
        for header in [
            &member_header,
            &client_header.to_owned(),
            &box_header.to_owned(),
        ] {
            let err = auth
                .authenticate(path, Some(header.as_bytes()))
                .await
                .unwrap_err();
            assert_eq!(err.message(), ADMIN_REQUIRED, "{path}");
        }
        let caller = auth
            .authenticate(path, Some(admin_header.as_bytes()))
            .await
            .unwrap()
            .unwrap();
        assert!(caller.is_admin);
        assert_eq!(caller.user_id, admin);
    }
}

#[sqlx::test(migrations = false)]
async fn a_token_of_a_deleted_user_cannot_add(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    let err = add(&w, 999_999, "git.example.com").await.unwrap_err();
    assert_eq!(err.code(), Code::PermissionDenied);
    assert_eq!(err.message(), fleet_proto::ERR_NEEDS_USER_TOKEN);
    assert_eq!(host_count(&w.pool).await, 1);
}
