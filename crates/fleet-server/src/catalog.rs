//! Catalog store and RPC logic.

use fleet_core::catalog::{CatalogItem as CoreItem, CatalogKind as CoreKind};
use fleet_proto::v1::{
    CatalogItem, CatalogKind, ListCatalogReply, ListCatalogRequest, SetCatalogItemEnabledRequest,
    UpsertCatalogItemRequest,
};
use sqlx::PgPool;
use tonic::Status;

const NOT_IMPLEMENTED: &str = "the catalog is not implemented";

/// Refusal reason for a caller without the admin scope.
pub const REASON_ADMIN_REQUIRED: &str = "the catalog admin scope is required";
/// Refusal reason for an upsert that changes the kind or name of an existing id.
pub const REASON_IDENTITY_CHANGE: &str = "the kind and name of a catalog item cannot change";
/// Refusal reason for an upsert whose kind and name belong to another id.
pub const REASON_NAME_TAKEN: &str = "a catalog item with this kind and name exists";
/// Refusal reason for a request with no kind.
pub const REASON_KIND_REQUIRED: &str = "the catalog item kind is required";
/// Refusal reason for an enable request that names no item.
pub const REASON_NOT_FOUND: &str = "the catalog item does not exist";
/// Refusal reason for a storage failure.
pub const REASON_STORE: &str = "the catalog store failed";

const UPSERT: &str = "INSERT INTO catalog_items (id, kind, name, content, digest) \
    VALUES ($1, $2, $3, $4, $5) \
    ON CONFLICT (id) DO UPDATE SET content = EXCLUDED.content, digest = EXCLUDED.digest, \
    updated_at = now() \
    WHERE catalog_items.kind = EXCLUDED.kind AND catalog_items.name = EXCLUDED.name \
    RETURNING id, kind, name, content, digest, admin_enabled";

const SET_ENABLED: &str = "UPDATE catalog_items SET admin_enabled = $2, updated_at = now() \
    WHERE id = $1 \
    RETURNING id, kind, name, content, digest, admin_enabled";

const LIST_ENABLED: &str = "SELECT id, kind, name, content, digest, admin_enabled \
    FROM catalog_items \
    WHERE admin_enabled AND id > $1 AND ($2::text IS NULL OR kind = $2) \
    ORDER BY id LIMIT $3";

/// Page size used when a list request asks for 0.
pub const DEFAULT_CATALOG_PAGE: u32 = 50;
/// Largest page a list returns, for the store and every handler.
pub const MAX_CATALOG_PAGE: u32 = 200;
/// Refusal reason for a list filter naming a kind outside the closed set.
pub const REASON_KIND_UNKNOWN: &str = "the catalog item kind is unknown";

const UNIQUE_VIOLATION: &str = "23505";

type Row = (String, String, String, String, Vec<u8>, bool);

/// The scope a catalog write runs under. Only [`Scope::Admin`] may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// A catalog administrator.
    Admin,
    /// Any other caller, including an unidentified one.
    Client,
}

fn require_admin(scope: Scope) -> Result<(), Status> {
    match scope {
        Scope::Admin => Ok(()),
        Scope::Client => Err(Status::permission_denied(REASON_ADMIN_REQUIRED)),
    }
}

fn core_kind(kind: CatalogKind) -> Option<CoreKind> {
    match kind {
        CatalogKind::Unspecified => None,
        CatalogKind::Skill => Some(CoreKind::Skill),
        CatalogKind::Subagent => Some(CoreKind::Subagent),
        CatalogKind::Tool => Some(CoreKind::Tool),
        CatalogKind::Context => Some(CoreKind::Context),
    }
}

fn wire_kind(name: &str) -> Result<CatalogKind, Status> {
    match name {
        "skill" => Ok(CatalogKind::Skill),
        "subagent" => Ok(CatalogKind::Subagent),
        "tool" => Ok(CatalogKind::Tool),
        "context" => Ok(CatalogKind::Context),
        _ => Err(Status::internal(REASON_STORE)),
    }
}

fn item_of(row: Row) -> Result<CatalogItem, Status> {
    let (id, kind, name, content, digest, admin_enabled) = row;
    Ok(CatalogItem {
        id,
        kind: wire_kind(&kind)? as i32,
        name,
        content,
        digest,
        admin_enabled,
    })
}

fn store_error(err: &sqlx::Error) -> Status {
    let unique = err
        .as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|code| code == UNIQUE_VIOLATION);
    if unique {
        Status::already_exists(REASON_NAME_TAKEN)
    } else {
        Status::internal(REASON_STORE)
    }
}

/// Creates a catalog item or replaces the content of an existing one, as an admin.
///
/// The item is validated by [`CoreItem::new`] before any SQL runs, and the stored digest is
/// computed from the validated content. The kind and name of an existing id cannot change, the
/// statement matches no row in that case. `admin_enabled` is never touched.
///
/// # Errors
/// `PERMISSION_DENIED` without the admin scope, `INVALID_ARGUMENT` for an invalid item,
/// `FAILED_PRECONDITION` when the kind or name of an existing id would change,
/// `ALREADY_EXISTS` when another id holds the kind and name, `INTERNAL` on a storage failure.
pub async fn upsert_item(
    pool: &PgPool,
    scope: Scope,
    request: &UpsertCatalogItemRequest,
) -> Result<CatalogItem, Status> {
    require_admin(scope)?;
    let kind =
        core_kind(request.kind()).ok_or_else(|| Status::invalid_argument(REASON_KIND_REQUIRED))?;
    let item = CoreItem::new(kind, &request.id, &request.name, &request.content)
        .map_err(|err| Status::invalid_argument(err.to_string()))?;
    let row = sqlx::query_as::<_, Row>(UPSERT)
        .bind(item.id().as_str())
        .bind(item.kind().as_str())
        .bind(item.name())
        .bind(item.body())
        .bind(item.digest().as_slice())
        .fetch_optional(pool)
        .await
        .map_err(|err| store_error(&err))?
        .ok_or_else(|| Status::failed_precondition(REASON_IDENTITY_CHANGE))?;
    item_of(row)
}

/// Switches a catalog item on or off, as an admin.
///
/// # Errors
/// `PERMISSION_DENIED` without the admin scope, `NOT_FOUND` for an unknown id, `INTERNAL` on a
/// storage failure.
pub async fn set_enabled(
    pool: &PgPool,
    scope: Scope,
    request: &SetCatalogItemEnabledRequest,
) -> Result<CatalogItem, Status> {
    require_admin(scope)?;
    let row = sqlx::query_as::<_, Row>(SET_ENABLED)
        .bind(&request.id)
        .bind(request.enabled)
        .fetch_optional(pool)
        .await
        .map_err(|err| store_error(&err))?
        .ok_or_else(|| Status::not_found(REASON_NOT_FOUND))?;
    item_of(row)
}

/// One page of enabled catalog items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogPage {
    /// The items, ordered by id.
    pub items: Vec<CatalogItem>,
    /// The id of the last item returned, else the `after_id` of the request.
    pub next_id: String,
}

/// Lists one page of admin-enabled catalog items for any user.
///
/// `kind` is the wire value of [`CatalogKind`]: 0 lists every kind, 1 to 4 filter. `after_id` is
/// exclusive and empty starts at the first item. A `limit` of 0 means [`DEFAULT_CATALOG_PAGE`];
/// larger values are cut to [`MAX_CATALOG_PAGE`]. A client keeps `next_id` as its cursor and
/// stops on an empty page. The list takes no owner and no admin override: a disabled item never
/// appears.
///
/// # Errors
/// `INVALID_ARGUMENT` for a kind outside the closed set, `INTERNAL` on a storage failure.
pub async fn list_enabled(
    pool: &PgPool,
    kind: i32,
    after_id: &str,
    limit: u32,
) -> Result<CatalogPage, Status> {
    list_enabled_capped(pool, kind, after_id, limit, MAX_CATALOG_PAGE).await
}

/// [`list_enabled`] with an injected page cap, so tests can shrink it.
///
/// # Errors
/// The errors of [`list_enabled`].
pub async fn list_enabled_capped(
    pool: &PgPool,
    kind: i32,
    after_id: &str,
    limit: u32,
    cap: u32,
) -> Result<CatalogPage, Status> {
    let kind = match CatalogKind::try_from(kind) {
        Ok(CatalogKind::Unspecified) => None,
        Ok(known) => core_kind(known).map(CoreKind::as_str),
        Err(_) => return Err(Status::invalid_argument(REASON_KIND_UNKNOWN)),
    };
    let limit = match limit {
        0 => DEFAULT_CATALOG_PAGE.min(cap),
        n => n.min(cap),
    };
    let rows = sqlx::query_as::<_, Row>(LIST_ENABLED)
        .bind(after_id)
        .bind(kind)
        .bind(i64::from(limit))
        .fetch_all(pool)
        .await
        .map_err(|err| store_error(&err))?;
    let items = rows
        .into_iter()
        .map(item_of)
        .collect::<Result<Vec<_>, _>>()?;
    let next_id = items
        .last()
        .map_or_else(|| after_id.to_owned(), |item| item.id.clone());
    Ok(CatalogPage { items, next_id })
}

/// Lists the catalog items a client may see.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn list_catalog(_request: &ListCatalogRequest) -> Result<ListCatalogReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Creates a catalog item or adds a version of an existing one.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn upsert_catalog_item(_request: &UpsertCatalogItemRequest) -> Result<CatalogItem, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Switches a catalog item on or off.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn set_catalog_item_enabled(
    _request: &SetCatalogItemEnabledRequest,
) -> Result<CatalogItem, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}
