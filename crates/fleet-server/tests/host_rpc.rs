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
    AddHostRequest, ApproveHostPrivateRequest, HostInfo, ListHostRequestsReply,
    ListHostRequestsRequest, ListHostsRequest, RemoveHostRequest, RevokeHostPrivateRequest,
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

const PRIVATE: &str = "192.168.3.1";

#[derive(Clone)]
struct Switch(Arc<Mutex<Vec<IpAddr>>>);

#[tonic::async_trait]
impl Resolve for Switch {
    async fn resolve(&self, _host: &str) -> io::Result<Vec<IpAddr>> {
        let set = self.0.lock().unwrap().clone();
        if set.is_empty() {
            Err(io::Error::from(io::ErrorKind::NotFound))
        } else {
            Ok(set)
        }
    }
}

impl Switch {
    fn set(&self, addrs: &[&str]) {
        *self.0.lock().unwrap() = addrs.iter().map(|a| a.parse().unwrap()).collect();
    }
}

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

type Pin = (bool, Vec<IpAddr>);

#[derive(Clone)]
struct Wire {
    reply: Result<(u16, String), FetchError>,
    calls: Arc<AtomicUsize>,
    seen: Arc<Mutex<Vec<String>>>,
    pins: Arc<Mutex<Vec<Pin>>>,
}

fn wire(status: u16, body: &str) -> Wire {
    Wire {
        reply: Ok((status, body.to_owned())),
        calls: Arc::new(AtomicUsize::new(0)),
        seen: Arc::new(Mutex::new(Vec::new())),
        pins: Arc::new(Mutex::new(Vec::new())),
    }
}

#[tonic::async_trait]
impl ForgeTransport for Wire {
    async fn get(&self, request: &ForgeGet<'_>) -> Result<ForgeReply, FetchError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(request.host.to_owned());
        self.pins
            .lock()
            .unwrap()
            .push((request.allow_private, request.approved_ips.to_vec()));
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

    async fn resolve(&self, _host: &HostName) -> Vec<IpAddr> {
        Vec::new()
    }

    async fn probe_approved(
        &self,
        _host: &HostName,
        _approved: &[IpAddr],
    ) -> Result<HostKind, HostRefusal> {
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

    async fn resolve(&self, _host: &HostName) -> Vec<IpAddr> {
        Vec::new()
    }

    async fn probe_approved(
        &self,
        _host: &HostName,
        _approved: &[IpAddr],
    ) -> Result<HostKind, HostRefusal> {
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

async fn add(world: &World, user_id: i64, host: &str) -> Result<HostInfo, Status> {
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
async fn the_revoke_and_list_rpcs_are_admin_gated_in_the_handler(pool: PgPool) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    let denied = [
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

async fn approve(
    w: &World,
    caller: (i64, bool),
    host: &str,
    ips: &[&str],
) -> Result<HostInfo, Status> {
    w.svc
        .approve_host_private(as_user(
            caller.0,
            caller.1,
            ApproveHostPrivateRequest {
                host: host.to_owned(),
                approved_ips: ips.iter().map(|ip| (*ip).to_owned()).collect(),
            },
        ))
        .await
        .map(tonic::Response::into_inner)
}

async fn revoke(w: &World, caller: (i64, bool), host: &str) -> Result<HostInfo, Status> {
    w.svc
        .revoke_host_private(as_user(
            caller.0,
            caller.1,
            RevokeHostPrivateRequest {
                host: host.to_owned(),
            },
        ))
        .await
        .map(tonic::Response::into_inner)
}

async fn requests(pool: &PgPool) -> Vec<(String, i64, Vec<String>, String)> {
    sqlx::query_as(
        "SELECT host, user_id, ARRAY(SELECT host(a) FROM unnest(resolved) AS a)::text[], status \
         FROM git_host_requests ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn private_audit(pool: &PgPool) -> Vec<(i64, String, String, String, Vec<String>)> {
    sqlx::query_as(
        "SELECT user_id, host, action, outcome, \
         ARRAY(SELECT host(a) FROM unnest(addresses) AS a)::text[] \
         FROM host_audit WHERE action IN ('approve_private', 'revoke_private') ORDER BY id",
    )
    .fetch_all(pool)
    .await
    .unwrap()
}

async fn grant_state(pool: &PgPool, host: &str) -> Option<(bool, Vec<String>)> {
    sqlx::query_as(
        "SELECT allow_private, ARRAY(SELECT host(a) FROM unnest(approved_ips) AS a)::text[] \
         FROM git_hosts WHERE host = $1",
    )
    .bind(host)
    .fetch_optional(pool)
    .await
    .unwrap()
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

#[sqlx::test(migrations = false)]
async fn a_private_add_gets_the_plain_refusal_and_one_pending_request(pool: PgPool) {
    let net = wire(200, FORGE);
    let w = world(pool, dns(&[PRIVATE]), net.clone()).await;
    let first = add(&w, w.alice, "git.example.com").await.unwrap_err();
    assert_eq!(parts(&first), closed(Reason::RepoNotAllowedHost));
    let again = add(&w, w.alice, "git.example.com").await.unwrap_err();
    assert_eq!(parts(&again), closed(Reason::RepoNotAllowedHost));
    assert_eq!(
        requests(&w.pool).await,
        vec![(
            "git.example.com".to_owned(),
            w.alice,
            strings(&[PRIVATE]),
            "pending".to_owned()
        )]
    );
    assert_eq!(host_count(&w.pool).await, 1);
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
    let bob = add(&w, w.bob, "git.example.com").await.unwrap_err();
    assert_eq!(parts(&bob), closed(Reason::RepoNotAllowedHost));
    assert_eq!(requests(&w.pool).await.len(), 2);
}

#[sqlx::test(migrations = false)]
async fn only_a_private_resolution_records_a_request_and_the_reply_never_differs(pool: PgPool) {
    let cgnat = format!("{}.64.0.1", 100);
    let switch = Switch(Arc::new(Mutex::new(Vec::new())));
    let s = switch.clone();
    let w = world_with(pool, move |store| {
        HostService::new(store, Arc::new(PinnedProbe::new(s, wire(200, FORGE))))
    })
    .await;
    let cases: Vec<(&str, Vec<&str>)> = vec![
        ("unresolvable.example.com", vec![]),
        ("public.example.com", vec![PUBLIC]),
        ("loopback.example.com", vec!["127.0.0.1"]),
        ("v6loop.example.com", vec!["::1"]),
        ("linklocal.example.com", vec!["169.254.1.1"]),
        ("metadata.example.com", vec!["169.254.169.254"]),
        ("cgnat.example.com", vec![cgnat.as_str()]),
        ("mixed.example.com", vec![PRIVATE, "127.0.0.1"]),
        ("private.example.com", vec![PRIVATE]),
        ("ula.example.com", vec!["fd00::1"]),
    ];
    let mut replies = Vec::new();
    for (host, addrs) in &cases {
        switch.set(addrs);
        let net_probe = add(&w, w.alice, host).await;
        replies.push((host, net_probe.map(|_| ())));
    }
    for (host, reply) in &replies {
        if **host == "public.example.com" {
            assert!(reply.is_ok(), "{host}");
        } else {
            let err = reply.as_ref().unwrap_err();
            assert_eq!(parts(err), closed(Reason::RepoNotAllowedHost), "{host}");
        }
    }
    let recorded: Vec<String> = requests(&w.pool)
        .await
        .into_iter()
        .map(|row| row.0)
        .collect();
    assert_eq!(
        recorded,
        strings(&["private.example.com", "ula.example.com"])
    );
}

#[sqlx::test(migrations = false)]
async fn pending_requests_are_capped_per_user_without_changing_the_reply(pool: PgPool) {
    let switch = Switch(Arc::new(Mutex::new(vec![PRIVATE.parse().unwrap()])));
    let s = switch.clone();
    let w = world_with(pool, move |store| {
        HostService::new(
            store.with_caps(2, 500),
            Arc::new(PinnedProbe::new(s, wire(200, FORGE))),
        )
    })
    .await;
    for host in ["a.example.com", "b.example.com", "c.example.com"] {
        let err = add(&w, w.alice, host).await.unwrap_err();
        assert_eq!(parts(&err), closed(Reason::RepoNotAllowedHost), "{host}");
    }
    assert_eq!(requests(&w.pool).await.len(), 2);
    switch.set(&["192.168.3.9"]);
    let err = add(&w, w.alice, "a.example.com").await.unwrap_err();
    assert_eq!(parts(&err), closed(Reason::RepoNotAllowedHost));
    let held = requests(&w.pool).await;
    assert_eq!(held.len(), 2);
    assert_eq!(held[0].2, strings(&["192.168.3.9"]));
    assert_eq!(held[1].2, strings(&[PRIVATE]));
    switch.set(&[PRIVATE]);
    let other = add(&w, w.bob, "c.example.com").await.unwrap_err();
    assert_eq!(parts(&other), closed(Reason::RepoNotAllowedHost));
    assert_eq!(requests(&w.pool).await.len(), 3);
}

#[sqlx::test(migrations = false)]
async fn approve_records_the_fresh_resolve_and_audits_the_addresses(pool: PgPool) {
    let net = wire(200, FORGE);
    let w = world(pool, dns(&[PRIVATE]), net.clone()).await;
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    let info = approve(&w, (w.admin, true), "git.example.com", &[PRIVATE])
        .await
        .unwrap();
    assert_eq!(info.host, "git.example.com");
    assert_eq!(info.kind, "forgejo");
    assert!(info.allow_private);
    assert_eq!(info.approved_ips, strings(&[PRIVATE]));
    assert_eq!(info.approved_by, Some(w.admin.try_into().unwrap()));
    assert_eq!(info.added_by, u64::try_from(w.alice).unwrap());
    assert_eq!(
        grant_state(&w.pool, "git.example.com").await,
        Some((true, strings(&[PRIVATE])))
    );
    assert_eq!(
        private_audit(&w.pool).await,
        vec![(
            w.admin,
            "git.example.com".to_owned(),
            "approve_private".to_owned(),
            "approved".to_owned(),
            strings(&[PRIVATE])
        )]
    );
    assert_eq!(requests(&w.pool).await[0].3, "approved");
    let pins = net.pins.lock().unwrap().clone();
    assert_eq!(pins, vec![(true, vec![PRIVATE.parse::<IpAddr>().unwrap()])]);
}

#[sqlx::test(migrations = false)]
async fn after_approval_an_add_succeeds_and_a_second_admin_view_lists_the_grant(pool: PgPool) {
    let w = world(pool, dns(&[PRIVATE]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    approve(&w, (w.admin, true), "git.example.com", &[PRIVATE])
        .await
        .unwrap();
    let info = add(&w, w.alice, "git.example.com").await.unwrap();
    assert!(info.allow_private);
    assert_eq!(info.approved_ips, Vec::<String>::new());
    let listed = w
        .svc
        .list_hosts(as_user(w.admin, true, ListHostsRequest {}))
        .await;
    let hosts = listed.unwrap().into_inner().hosts;
    let row = hosts.iter().find(|h| h.host == "git.example.com").unwrap();
    assert_eq!(row.approved_ips, strings(&[PRIVATE]));
}

#[sqlx::test(migrations = false)]
async fn a_non_admin_and_an_unknown_host_get_the_same_not_found(pool: PgPool) {
    let w = world(pool, dns(&[PRIVATE]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    let member = approve(&w, (w.alice, false), "git.example.com", &[PRIVATE])
        .await
        .unwrap_err();
    let unknown = approve(&w, (w.admin, true), "nope.example.com", &[PRIVATE])
        .await
        .unwrap_err();
    assert_eq!(member.code(), Code::NotFound);
    assert_eq!(member.message(), fleet_proto::ERR_HOST_NOT_FOUND);
    assert_eq!(parts(&member), parts(&unknown));
    for host in [
        "",
        "not a host",
        "git.example.com\r\n",
        "git.example.com:443",
        "a/b",
        "github.com",
    ] {
        let err = approve(&w, (w.admin, true), host, &[PRIVATE])
            .await
            .unwrap_err();
        assert_eq!(parts(&err), parts(&unknown), "{host:?}");
    }
    assert_eq!(grant_state(&w.pool, "git.example.com").await, None);
    assert_eq!(
        grant_state(&w.pool, "github.com").await,
        Some((false, Vec::new()))
    );
    assert_eq!(private_audit(&w.pool).await.len(), 0);
}

#[sqlx::test(migrations = false)]
async fn approve_counts_the_raw_named_list_before_dropping_duplicates(pool: PgPool) {
    let switch = Switch(Arc::new(Mutex::new(Vec::new())));
    let s = switch.clone();
    let w = world_with(pool, move |store| {
        HostService::new(store, Arc::new(PinnedProbe::new(s, wire(200, FORGE))))
    })
    .await;
    switch.set(&[PRIVATE]);
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    let cap = fleet_proto::MAX_HOST_APPROVED_IPS;
    let over = vec![PRIVATE; cap + 1];
    let err = approve(&w, (w.admin, true), "git.example.com", &over)
        .await
        .unwrap_err();
    assert_eq!(parts(&err), closed(Reason::HostAddressMismatch));
    assert_eq!(grant_state(&w.pool, "git.example.com").await, None);
    let at = vec![PRIVATE; cap];
    approve(&w, (w.admin, true), "git.example.com", &at)
        .await
        .unwrap();
    assert!(grant_state(&w.pool, "git.example.com").await.is_some());
}

#[sqlx::test(migrations = false)]
async fn approve_refuses_a_named_set_that_differs_from_the_fresh_resolve(pool: PgPool) {
    let switch = Switch(Arc::new(Mutex::new(Vec::new())));
    let s = switch.clone();
    let w = world_with(pool, move |store| {
        HostService::new(store, Arc::new(PinnedProbe::new(s, wire(200, FORGE))))
    })
    .await;
    switch.set(&[PRIVATE]);
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    switch.set(&["192.168.3.2"]);
    let hostile: Vec<Vec<String>> = vec![
        strings(&[PRIVATE]),
        Vec::new(),
        strings(&["192.168.3.2", PRIVATE]),
        strings(&["192.168.3.2 "]),
        strings(&["192.168.3.2\r\n"]),
        strings(&["192.168.3.2\u{2028}"]),
        strings(&["192.168.3.2/32"]),
        strings(&["192.168.003.002"]),
        strings(&["0xc0.168.3.2"]),
        strings(&["[fd00::1]"]),
        strings(&["fe80::1%eth0"]),
        strings(&["\u{ff11}92.168.3.2"]),
        strings(&["1".repeat(1000).as_str()]),
        (0..65).map(|n| format!("192.168.4.{n}")).collect(),
    ];
    for named in hostile {
        let refs: Vec<&str> = named.iter().map(String::as_str).collect();
        let err = approve(&w, (w.admin, true), "git.example.com", &refs)
            .await
            .unwrap_err();
        assert_eq!(
            parts(&err),
            closed(Reason::HostAddressMismatch),
            "{named:?}"
        );
    }
    assert_eq!(grant_state(&w.pool, "git.example.com").await, None);
    assert_eq!(requests(&w.pool).await[0].3, "pending");
    let rows = private_audit(&w.pool).await;
    assert_eq!(rows.len(), 14);
    assert!(
        rows.iter()
            .all(|r| r.2 == "approve_private" && r.3 == "refused")
    );
    approve(&w, (w.admin, true), "git.example.com", &["192.168.3.2"])
        .await
        .unwrap();
    let mapped = approve(
        &w,
        (w.admin, true),
        "git.example.com",
        &["::ffff:192.168.3.2"],
    )
    .await;
    assert!(mapped.is_ok());
}

#[sqlx::test(migrations = false)]
async fn approve_stores_the_canonical_form_of_a_mapped_address(pool: PgPool) {
    let w = world(pool, dns(&["fd00::1", "10.9.8.7"]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    let info = approve(
        &w,
        (w.admin, true),
        "git.example.com",
        &[
            "FD00::1",
            "fd00:0:0:0:0:0:0:1",
            "::ffff:10.9.8.7",
            "10.9.8.7",
        ],
    )
    .await
    .unwrap();
    let canonical = strings(&["10.9.8.7", "fd00::1"]);
    assert_eq!(info.approved_ips, canonical);
    assert_eq!(
        grant_state(&w.pool, "git.example.com").await,
        Some((true, canonical))
    );
}

#[sqlx::test(migrations = false)]
async fn approve_never_grants_a_forbidden_range(pool: PgPool) {
    let cgnat = format!("{}.64.0.1", 100);
    let switch = Switch(Arc::new(Mutex::new(Vec::new())));
    let s = switch.clone();
    let net = wire(200, FORGE);
    let n = net.clone();
    let w = world_with(pool, move |store| {
        HostService::new(store, Arc::new(PinnedProbe::new(s, n)))
    })
    .await;
    sqlx::query("INSERT INTO git_host_requests (host, user_id, resolved) VALUES ('git.example.com', $1, '{}')")
        .bind(w.alice)
        .execute(&w.pool)
        .await
        .unwrap();
    let forbidden: Vec<Vec<&str>> = vec![
        vec!["127.0.0.1"],
        vec!["::1"],
        vec!["169.254.1.1"],
        vec!["fe80::1"],
        vec!["169.254.169.254"],
        vec!["fd00:ec2::254"],
        vec![cgnat.as_str()],
        vec!["0.0.0.0"],
        vec!["224.0.0.1"],
        vec!["255.255.255.255"],
        vec![PRIVATE, "127.0.0.1"],
        vec!["fd00::1", "fe80::1"],
        vec!["64:ff9b::c0a8:301"],
        vec!["2002:c0a8:301::1"],
        vec![PUBLIC],
        vec![],
    ];
    for addrs in forbidden {
        switch.set(&addrs);
        let err = approve(&w, (w.admin, true), "git.example.com", &addrs)
            .await
            .unwrap_err();
        let expected = if addrs.is_empty() {
            Reason::HostAddressMismatch
        } else {
            Reason::RepoNotAllowedHost
        };
        assert_eq!(parts(&err), closed(expected), "{addrs:?}");
        assert_eq!(
            grant_state(&w.pool, "git.example.com").await,
            None,
            "{addrs:?}"
        );
    }
    assert_eq!(net.calls.load(Ordering::SeqCst), 0);
    for addrs in [vec![PRIVATE], vec!["fd00::1"], vec![PRIVATE, PUBLIC]] {
        switch.set(&addrs);
        approve(&w, (w.admin, true), "git.example.com", &addrs)
            .await
            .unwrap();
    }
}

#[sqlx::test(migrations = false)]
async fn approve_refuses_a_host_that_is_not_a_forge_and_stores_nothing(pool: PgPool) {
    let w = world(pool, dns(&[PRIVATE]), wire(404, "")).await;
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    let err = approve(&w, (w.admin, true), "git.example.com", &[PRIVATE])
        .await
        .unwrap_err();
    assert_eq!(parts(&err), closed(Reason::HostNotForge));
    assert_eq!(grant_state(&w.pool, "git.example.com").await, None);
    assert_eq!(requests(&w.pool).await[0].3, "pending");
    let rows = private_audit(&w.pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].2.as_str(), rows[0].3.as_str()),
        ("approve_private", "refused")
    );
}

#[sqlx::test(migrations = false)]
async fn revoke_clears_the_grant_marks_repositories_stale_and_audits(pool: PgPool) {
    let w = world(pool, dns(&[PRIVATE]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    approve(&w, (w.admin, true), "git.example.com", &[PRIVATE])
        .await
        .unwrap();
    for host in ["git.example.com", "github.com"] {
        sqlx::query(
            "INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, $2, 'o/r', 'forgejo')",
        )
        .bind(w.alice)
        .bind(host)
        .execute(&w.pool)
        .await
        .unwrap();
    }
    let info = revoke(&w, (w.admin, true), "git.example.com")
        .await
        .unwrap();
    assert!(!info.allow_private);
    assert_eq!(info.approved_ips, Vec::<String>::new());
    assert_eq!(info.approved_by, None);
    assert_eq!(
        grant_state(&w.pool, "git.example.com").await,
        Some((false, Vec::new()))
    );
    let stale: Vec<(String, bool)> = sqlx::query_as(
        "SELECT host, verified_at < now() - interval '1 year' FROM user_repos ORDER BY host",
    )
    .fetch_all(&w.pool)
    .await
    .unwrap();
    assert_eq!(
        stale,
        vec![
            ("git.example.com".to_owned(), true),
            ("github.com".to_owned(), false)
        ]
    );
    let rows = private_audit(&w.pool).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[1],
        (
            w.admin,
            "git.example.com".to_owned(),
            "revoke_private".to_owned(),
            "revoked".to_owned(),
            strings(&[PRIVATE])
        )
    );
}

#[sqlx::test(migrations = false)]
async fn revoke_of_an_unknown_host_is_not_found_and_of_an_ungranted_host_changes_nothing(
    pool: PgPool,
) {
    let w = world(pool, dns(&[PUBLIC]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap();
    sqlx::query(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, 'git.example.com', 'o/r', 'forgejo')",
    )
    .bind(w.alice)
    .execute(&w.pool)
    .await
    .unwrap();
    let unknown = revoke(&w, (w.admin, true), "nope.example.com")
        .await
        .unwrap_err();
    assert_eq!(unknown.code(), Code::NotFound);
    assert_eq!(unknown.message(), fleet_proto::ERR_HOST_NOT_FOUND);
    let github = revoke(&w, (w.admin, true), "github.com").await.unwrap_err();
    assert_eq!(parts(&github), parts(&unknown));
    let info = revoke(&w, (w.admin, true), "git.example.com")
        .await
        .unwrap();
    assert!(!info.allow_private);
    let fresh: bool =
        sqlx::query_scalar("SELECT verified_at > now() - interval '1 day' FROM user_repos")
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert!(fresh);
    let rows = private_audit(&w.pool).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].2.as_str(), rows[0].3.as_str()),
        ("revoke_private", "refused")
    );
}

#[sqlx::test(migrations = false)]
async fn list_requests_shows_pending_rows_to_an_admin_only(pool: PgPool) {
    let w = world(pool, dns(&[PRIVATE, "fd00::1"]), wire(200, FORGE)).await;
    add(&w, w.alice, "a.example.com").await.unwrap_err();
    add(&w, w.bob, "b.example.com").await.unwrap_err();
    let reply: ListHostRequestsReply = w
        .svc
        .list_host_requests(as_user(w.admin, true, ListHostRequestsRequest {}))
        .await
        .unwrap()
        .into_inner();
    let seen: Vec<(String, u64, Vec<String>)> = reply
        .requests
        .iter()
        .map(|r| (r.host.clone(), r.requested_by, r.resolved_ips.clone()))
        .collect();
    assert_eq!(
        seen,
        vec![
            (
                "a.example.com".to_owned(),
                w.alice.try_into().unwrap(),
                strings(&[PRIVATE, "fd00::1"])
            ),
            (
                "b.example.com".to_owned(),
                w.bob.try_into().unwrap(),
                strings(&[PRIVATE, "fd00::1"])
            ),
        ]
    );
    assert!(reply.requests.iter().all(|r| r.requested_at_ms > 0));
    approve(&w, (w.admin, true), "a.example.com", &[PRIVATE, "fd00::1"])
        .await
        .unwrap();
    let after = w
        .svc
        .list_host_requests(as_user(w.admin, true, ListHostRequestsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(after.requests.len(), 1);
    assert_eq!(after.requests[0].host, "b.example.com");
}

#[sqlx::test(migrations = false)]
async fn approve_queues_behind_a_lock_on_the_host_row(pool: PgPool) {
    let w = world(pool, dns(&[PRIVATE]), wire(200, FORGE)).await;
    add(&w, w.alice, "git.example.com").await.unwrap_err();
    approve(&w, (w.admin, true), "git.example.com", &[PRIVATE])
        .await
        .unwrap();
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("SELECT host FROM git_hosts WHERE host = 'git.example.com' FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let svc = w.svc.clone();
    let admin = w.admin;
    let task = tokio::spawn(async move {
        svc.revoke_host_private(as_user(
            admin,
            true,
            RevokeHostPrivateRequest {
                host: "git.example.com".to_owned(),
            },
        ))
        .await
    });
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!task.is_finished());
    holder.rollback().await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn the_probe_pins_to_the_approved_addresses_only(pool: PgPool) {
    let _ = pool;
    let net = wire(200, FORGE);
    let name = HostName::normalise("git.example.com").unwrap();
    let approved: Vec<IpAddr> = vec![PRIVATE.parse().unwrap()];
    let cases: Vec<(Vec<&str>, Result<HostKind, HostRefusal>)> = vec![
        (vec![PRIVATE], Ok(HostKind::Forgejo)),
        (vec![PRIVATE, PUBLIC], Ok(HostKind::Forgejo)),
        (vec!["192.168.3.2"], Err(HostRefusal::NotAllowedHost)),
        (
            vec![PRIVATE, "192.168.3.2"],
            Err(HostRefusal::NotAllowedHost),
        ),
        (vec!["10.0.0.1"], Err(HostRefusal::NotAllowedHost)),
        (vec!["127.0.0.1"], Err(HostRefusal::NotAllowedHost)),
        (vec![PRIVATE, "127.0.0.1"], Err(HostRefusal::NotAllowedHost)),
        (vec![], Err(HostRefusal::NotAllowedHost)),
    ];
    for (resolved, expected) in cases {
        let before = net.calls.load(Ordering::SeqCst);
        let probe = PinnedProbe::new(dns(&resolved), net.clone());
        assert_eq!(
            probe.probe_approved(&name, &approved).await,
            expected,
            "{resolved:?}"
        );
        let sent = net.calls.load(Ordering::SeqCst) - before;
        assert_eq!(sent, usize::from(expected.is_ok()), "{resolved:?}");
    }
    let probe = PinnedProbe::new(dns(&["127.0.0.1"]), net.clone());
    let loopback: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
    assert_eq!(
        probe.probe_approved(&name, &loopback).await,
        Err(HostRefusal::NotAllowedHost)
    );
    let plain = PinnedProbe::new(dns(&[PRIVATE]), net.clone());
    assert_eq!(plain.probe(&name).await, Err(HostRefusal::NotAllowedHost));
}
