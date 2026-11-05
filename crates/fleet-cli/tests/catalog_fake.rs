//! `fleet catalog` and `fleet user cap` against in-process stubs: paging, the loop cap, request
//! fields, server row order and the scrubbing of every printed server field.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::DEFAULT_CATALOG_PAGE;
use fleet_proto::v1::fleet_capability_admin_server::{
    FleetCapabilityAdmin, FleetCapabilityAdminServer,
};
use fleet_proto::v1::fleet_catalog_admin_server::{FleetCatalogAdmin, FleetCatalogAdminServer};
use fleet_proto::v1::fleet_catalog_server::{FleetCatalog, FleetCatalogServer};
use fleet_proto::v1::{
    CatalogItem, CatalogKind, GrantCapabilityRequest, ListCapabilitiesReply,
    ListCapabilitiesRequest, ListCatalogReply, ListCatalogRequest, RevokeCapabilityReply,
    RevokeCapabilityRequest, SetCatalogItemEnabledRequest, UpsertCatalogItemRequest,
    UserCapability,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";

#[derive(Default, Clone)]
struct Stub {
    pages: Arc<Mutex<Vec<ListCatalogReply>>>,
    seen: Arc<Mutex<Vec<ListCatalogRequest>>>,
    item: Option<CatalogItem>,
    upserts: Arc<Mutex<Vec<UpsertCatalogItemRequest>>>,
    toggles: Arc<Mutex<Vec<SetCatalogItemEnabledRequest>>>,
    rows: Vec<UserCapability>,
    removed: bool,
    grants: Arc<Mutex<Vec<GrantCapabilityRequest>>>,
    revokes: Arc<Mutex<Vec<RevokeCapabilityRequest>>>,
    lists: Arc<Mutex<Vec<ListCapabilitiesRequest>>>,
}

fn item(id: &str, name: &str) -> CatalogItem {
    CatalogItem {
        id: id.into(),
        kind: CatalogKind::Skill as i32,
        name: name.into(),
        content: "body".into(),
        digest: vec![0; 32],
        admin_enabled: true,
    }
}

fn locked<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>, Status> {
    mutex.lock().map_err(|_| Status::internal("poisoned"))
}

#[tonic::async_trait]
impl FleetCatalog for Stub {
    async fn list_catalog(
        &self,
        request: Request<ListCatalogRequest>,
    ) -> Result<Response<ListCatalogReply>, Status> {
        locked(&self.seen)?.push(request.into_inner());
        let mut pages = locked(&self.pages)?;
        if pages.is_empty() {
            return Ok(Response::new(ListCatalogReply::default()));
        }
        Ok(Response::new(pages.remove(0)))
    }
}

#[tonic::async_trait]
impl FleetCatalogAdmin for Stub {
    async fn upsert_catalog_item(
        &self,
        request: Request<UpsertCatalogItemRequest>,
    ) -> Result<Response<CatalogItem>, Status> {
        locked(&self.upserts)?.push(request.into_inner());
        self.item
            .clone()
            .map(Response::new)
            .ok_or_else(|| Status::internal("no item"))
    }

    async fn set_catalog_item_enabled(
        &self,
        request: Request<SetCatalogItemEnabledRequest>,
    ) -> Result<Response<CatalogItem>, Status> {
        locked(&self.toggles)?.push(request.into_inner());
        self.item
            .clone()
            .map(Response::new)
            .ok_or_else(|| Status::internal("no item"))
    }
}

#[tonic::async_trait]
impl FleetCapabilityAdmin for Stub {
    async fn grant_capability(
        &self,
        request: Request<GrantCapabilityRequest>,
    ) -> Result<Response<UserCapability>, Status> {
        locked(&self.grants)?.push(request.into_inner());
        self.rows
            .first()
            .cloned()
            .map(Response::new)
            .ok_or_else(|| Status::internal("no row"))
    }

    async fn revoke_capability(
        &self,
        request: Request<RevokeCapabilityRequest>,
    ) -> Result<Response<RevokeCapabilityReply>, Status> {
        locked(&self.revokes)?.push(request.into_inner());
        Ok(Response::new(RevokeCapabilityReply {
            removed: self.removed,
        }))
    }

    async fn list_capabilities(
        &self,
        request: Request<ListCapabilitiesRequest>,
    ) -> Result<Response<ListCapabilitiesReply>, Status> {
        locked(&self.lists)?.push(request.into_inner());
        Ok(Response::new(ListCapabilitiesReply {
            capabilities: self.rows.clone(),
        }))
    }
}

fn cap(user: u64, name: &str) -> UserCapability {
    UserCapability {
        user_id: user,
        capability: name.into(),
        granted_by: 1,
        granted_at_ms: 5,
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetCatalogServer::new(stub.clone()))
            .add_service(FleetCatalogAdminServer::new(stub.clone()))
            .add_service(FleetCapabilityAdminServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli(url: &str, args: &[&str], stdin: &[u8]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let mut out = Vec::new();
    let mut stdin = stdin;
    let result = run(
        parsed,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned()),
        &mut stdin,
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn page(ids: &[&str], next: &str) -> ListCatalogReply {
    ListCatalogReply {
        items: ids.iter().map(|id| item(id, id)).collect(),
        next_id: next.into(),
    }
}

#[tokio::test]
async fn list_follows_next_id_with_the_default_page_and_stops_on_an_empty_one() -> TestResult {
    let stub = Stub::default();
    *locked(&stub.pages)? = vec![page(&["a", "b"], "b"), page(&["c"], "c"), page(&[], "c")];
    let seen = stub.seen.clone();
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["catalog", "list", "--kind", "skill"], b"").await;
    result?;
    let ids: Vec<&str> = out.lines().filter_map(|l| l.split('\t').next()).collect();
    assert_eq!(ids, ["a", "b", "c"]);
    let seen = locked(&seen)?.clone();
    let after: Vec<&str> = seen.iter().map(|r| r.after_id.as_str()).collect();
    assert_eq!(after, ["", "b", "c"]);
    assert!(seen.iter().all(|r| r.page_size == DEFAULT_CATALOG_PAGE));
    assert!(seen.iter().all(|r| r.kind == CatalogKind::Skill as i32));
    Ok(())
}

#[tokio::test]
async fn list_without_kind_asks_for_every_kind() -> TestResult {
    let stub = Stub::default();
    let seen = stub.seen.clone();
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["catalog", "list"], b"").await;
    result?;
    assert_eq!(out, "");
    let seen = locked(&seen)?.clone();
    assert_eq!(seen.len(), 1);
    assert!(
        seen.iter()
            .all(|r| r.kind == CatalogKind::Unspecified as i32)
    );
    Ok(())
}

#[tokio::test]
async fn an_empty_next_id_ends_the_listing_after_one_page() -> TestResult {
    let stub = Stub::default();
    *locked(&stub.pages)? = vec![page(&["a"], ""), page(&["z"], "z")];
    let seen = stub.seen.clone();
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["catalog", "list"], b"").await;
    result?;
    assert_eq!(out.lines().count(), 1);
    assert_eq!(locked(&seen)?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn a_server_that_never_stops_paging_hits_the_loop_cap() -> TestResult {
    let stub = Stub::default();
    *locked(&stub.pages)? = (0..6000)
        .map(|n| {
            let id = format!("i{n}");
            page(&[id.as_str()], &id)
        })
        .collect();
    let seen = stub.seen.clone();
    let url = serve(stub).await?;
    let (result, _) = cli(&url, &["catalog", "list"], b"").await;
    assert_eq!(locked(&seen)?.len(), 5_000);
    let err = result.unwrap_err();
    assert!(matches!(err, CliError::Usage(_)), "{err}");
    assert!(err.to_string().contains("too many catalog pages"), "{err}");
    assert_eq!(err.exit_code(), 2);
    Ok(())
}

#[tokio::test]
async fn every_printed_list_field_is_scrubbed_one_hostile_value_per_field() -> TestResult {
    let hostile = format!("a\u{1b}[31m{TOKEN}\u{202e}\r\nb\u{2028}c");
    let long = format!("{}{TOKEN}", "n".repeat(195));
    let stub = Stub::default();
    *locked(&stub.pages)? = vec![ListCatalogReply {
        items: vec![
            CatalogItem {
                kind: 99,
                ..item(&hostile, "plain")
            },
            item("plain", &hostile),
            item("long", &long),
        ],
        next_id: String::new(),
    }];
    let url = serve(stub).await?;
    let (result, out) = cli(&url, &["catalog", "list"], b"").await;
    result?;
    assert!(!out.contains(TOKEN), "{out:?}");
    assert!(!out.contains("client-tok"), "{out:?}");
    assert_eq!(out.lines().count(), 3, "{out:?}");
    assert!(
        !out.chars()
            .any(|c| (c.is_control() && c != '\n' && c != '\t') || "\u{202e}\u{2028}".contains(c)),
        "{out:?}"
    );
    let rows: Vec<Vec<&str>> = out.lines().map(|l| l.split('\t').collect()).collect();
    assert!(rows.iter().all(|r| r.len() == 4), "{out:?}");
    assert_eq!(rows[0][1], "unknown");
    assert!(rows[2][2].chars().count() <= 201, "{out:?}");
    assert!(rows[2][2].ends_with('\u{2026}'), "{out:?}");
    Ok(())
}

#[tokio::test]
async fn upsert_sends_the_stdin_content_and_prints_the_scrubbed_item() -> TestResult {
    let stub = Stub {
        item: Some(item(&format!("x{TOKEN}"), &format!("n\u{1b}{TOKEN}"))),
        ..Stub::default()
    };
    let upserts = stub.upserts.clone();
    let url = serve(stub).await?;
    let (result, out) = cli(
        &url,
        &["catalog", "upsert", "skill", "tdd", "TDD", "--file", "-"],
        b"the body\n",
    )
    .await;
    result?;
    assert!(!out.contains(TOKEN), "{out:?}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert_eq!(out.lines().count(), 1);
    let upserts = locked(&upserts)?.clone();
    assert_eq!(upserts.len(), 1);
    let sent = upserts.first().ok_or("no upsert")?;
    assert_eq!(sent.id, "tdd");
    assert_eq!(sent.name, "TDD");
    assert_eq!(sent.kind, CatalogKind::Skill as i32);
    assert_eq!(sent.content, "the body\n");
    Ok(())
}

#[tokio::test]
async fn enable_and_disable_send_the_flag_and_print_the_item() -> TestResult {
    let stub = Stub {
        item: Some(item("tdd", "TDD")),
        ..Stub::default()
    };
    let toggles = stub.toggles.clone();
    let url = serve(stub).await?;
    for (verb, flag) in [("enable", true), ("disable", false)] {
        let (result, out) = cli(&url, &["catalog", verb, "tdd"], b"").await;
        result?;
        assert_eq!(out.lines().count(), 1, "{verb}");
        let toggles = locked(&toggles)?.clone();
        let last = toggles.last().ok_or("no toggle")?;
        assert_eq!((last.id.as_str(), last.enabled), ("tdd", flag), "{verb}");
    }
    Ok(())
}

#[tokio::test]
async fn cap_commands_send_the_user_and_capability_and_never_an_actor() -> TestResult {
    let stub = Stub {
        rows: vec![cap(7, "profile:tools")],
        removed: true,
        ..Stub::default()
    };
    let (grants, revokes, lists) = (
        stub.grants.clone(),
        stub.revokes.clone(),
        stub.lists.clone(),
    );
    let url = serve(stub).await?;
    let (r, out) = cli(&url, &["user", "cap", "grant", "7", "profile:tools"], b"").await;
    r?;
    assert_eq!(out, "7\tprofile:tools\t1\t5\n");
    let (r, out) = cli(&url, &["user", "cap", "revoke", "7", "profile:tools"], b"").await;
    r?;
    assert_eq!(out, "revoked\t7\tprofile:tools\n");
    let (r, out) = cli(&url, &["user", "cap", "list", "7"], b"").await;
    r?;
    assert_eq!(out, "7\tprofile:tools\t1\t5\n");
    let grants = locked(&grants)?.clone();
    assert_eq!(grants.len(), 1);
    assert_eq!(
        (grants[0].user_id, grants[0].capability.as_str()),
        (7, "profile:tools")
    );
    let revokes = locked(&revokes)?.clone();
    assert_eq!(revokes.len(), 1);
    assert_eq!(
        (revokes[0].user_id, revokes[0].capability.as_str()),
        (7, "profile:tools")
    );
    let lists = locked(&lists)?.clone();
    assert_eq!(lists.len(), 1);
    assert_eq!(lists[0].user_id, 7);
    Ok(())
}

#[tokio::test]
async fn cap_list_keeps_the_server_row_order() -> TestResult {
    let stub = Stub {
        rows: vec![cap(7, "b"), cap(7, "a"), cap(7, "c")],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    let (r, out) = cli(&url, &["user", "cap", "list", "7"], b"").await;
    r?;
    let names: Vec<&str> = out.lines().filter_map(|l| l.split('\t').nth(1)).collect();
    assert_eq!(names, ["b", "a", "c"]);
    Ok(())
}

#[tokio::test]
async fn revoke_of_an_absent_grant_says_not_held() -> TestResult {
    let url = serve(Stub::default()).await?;
    let (r, out) = cli(&url, &["user", "cap", "revoke", "7", "profile:tools"], b"").await;
    r?;
    assert_eq!(out, "not held\t7\tprofile:tools\n");
    Ok(())
}

#[tokio::test]
async fn every_printed_cap_field_is_scrubbed_one_hostile_value_per_field() -> TestResult {
    let hostile = format!("a\u{1b}[31m{TOKEN}\u{202e}\r\nb\u{2028}c");
    let stub = Stub {
        rows: vec![cap(7, &hostile)],
        ..Stub::default()
    };
    let url = serve(stub).await?;
    for args in [
        &["user", "cap", "list", "7"][..],
        &["user", "cap", "grant", "7", "x"],
    ] {
        let (r, out) = cli(&url, args, b"").await;
        r?;
        assert!(!out.contains(TOKEN), "{out:?}");
        assert!(!out.contains("client-tok"), "{out:?}");
        assert_eq!(out.lines().count(), 1, "{out:?}");
        assert!(
            !out.chars()
                .any(|c| (c.is_control() && c != '\n' && c != '\t')
                    || "\u{202e}\u{2028}".contains(c)),
            "{out:?}"
        );
        assert_eq!(out.split('\t').count(), 4, "{out:?}");
    }
    let (r, out) = cli(&url, &["user", "cap", "revoke", "7", &hostile], b"").await;
    r?;
    assert!(!out.contains(TOKEN), "{out:?}");
    assert!(!out.contains('\u{1b}'), "{out:?}");
    assert_eq!(out.lines().count(), 1, "{out:?}");
    assert_eq!(out.split('\t').count(), 3, "{out:?}");
    Ok(())
}
