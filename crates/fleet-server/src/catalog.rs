//! Catalog store and RPC logic.

use fleet_core::ItemId;
use fleet_core::catalog::{CatalogItem as CoreItem, CatalogKind as CoreKind};
use fleet_proto::v1::{
    CatalogItem, CatalogKind, ListCatalogReply, ListCatalogRequest, SetCatalogItemEnabledRequest,
    UpsertCatalogItemRequest,
};
pub use fleet_proto::{DEFAULT_CATALOG_PAGE, MAX_CATALOG_CURSOR_BYTES, MAX_CATALOG_PAGE};
use sqlx::{PgPool, Postgres, Transaction};
use tonic::Status;

use crate::auth::ADMIN_REQUIRED;

/// Refusal reason for a caller that is not an admin.
pub const REASON_ADMIN_REQUIRED: &str = ADMIN_REQUIRED;
/// Refusal reason for an `after_id` that is not a legal item id cursor.
pub const REASON_CURSOR_INVALID: &str = "the catalog cursor is invalid";
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

const LIST_ALL: &str = "SELECT id, kind, name, content, digest, admin_enabled \
    FROM catalog_items \
    WHERE id > $1 AND ($2::text IS NULL OR kind = $2) \
    ORDER BY id LIMIT $3";

/// Refusal reason for a list filter naming a kind outside the closed set.
pub const REASON_KIND_UNKNOWN: &str = "the catalog item kind is unknown";

const UNIQUE_VIOLATION: &str = "23505";

type Row = (String, String, String, String, Vec<u8>, bool);

const LOCK_ACTOR: &str = "SELECT is_admin FROM users WHERE id = $1 FOR SHARE";

async fn begin_admin(pool: &PgPool, actor: i64) -> Result<Transaction<'static, Postgres>, Status> {
    let mut tx = pool.begin().await.map_err(|err| store_error(&err))?;
    let admin: Option<bool> = sqlx::query_scalar(LOCK_ACTOR)
        .bind(actor)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| store_error(&err))?;
    if admin == Some(true) {
        Ok(tx)
    } else {
        Err(Status::permission_denied(REASON_ADMIN_REQUIRED))
    }
}

/// Checks an `after_id` cursor: empty, or a legal item id of at most
/// [`MAX_CATALOG_CURSOR_BYTES`] bytes. The handler and the store both call it.
///
/// # Errors
/// `INVALID_ARGUMENT` with [`REASON_CURSOR_INVALID`] for NUL, any byte outside `[a-z0-9_-]`, a
/// leading `_` or `-`, or a cursor over the cap.
pub fn validate_after_id(after_id: &str) -> Result<(), Status> {
    let legal = after_id.is_empty()
        || (fleet_proto::validate_catalog_cursor(after_id) && ItemId::new(after_id).is_ok());
    if legal {
        Ok(())
    } else {
        Err(Status::invalid_argument(REASON_CURSOR_INVALID))
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

/// Creates a catalog item or replaces the content of an existing one, as the admin `actor`.
///
/// The transaction first takes `SELECT is_admin FROM users WHERE id = $1 FOR SHARE` on the actor
/// row, so an admin demoted after authenticating is refused and a demotion waits for the write.
///
/// The item is validated by [`CoreItem::new`] before any SQL runs, and the stored digest is
/// computed from the validated content. The kind and name of an existing id cannot change, the
/// statement matches no row in that case. `admin_enabled` is never touched.
///
/// # Errors
/// `PERMISSION_DENIED` when `actor` is not an admin, `INVALID_ARGUMENT` for an invalid item,
/// `FAILED_PRECONDITION` when the kind or name of an existing id would change,
/// `ALREADY_EXISTS` when another id holds the kind and name, `INTERNAL` on a storage failure.
pub async fn upsert_item(
    pool: &PgPool,
    actor: i64,
    request: &UpsertCatalogItemRequest,
) -> Result<CatalogItem, Status> {
    let mut tx = begin_admin(pool, actor).await?;
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
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| store_error(&err))?
        .ok_or_else(|| Status::failed_precondition(REASON_IDENTITY_CHANGE))?;
    tx.commit().await.map_err(|err| store_error(&err))?;
    item_of(row)
}

/// Switches a catalog item on or off, as the admin `actor`, under the same actor-row
/// `FOR SHARE` lock as [`upsert_item`].
///
/// # Errors
/// `PERMISSION_DENIED` when `actor` is not an admin, `NOT_FOUND` for an unknown id, `INTERNAL` on a
/// storage failure.
pub async fn set_enabled(
    pool: &PgPool,
    actor: i64,
    request: &SetCatalogItemEnabledRequest,
) -> Result<CatalogItem, Status> {
    let mut tx = begin_admin(pool, actor).await?;
    let row = sqlx::query_as::<_, Row>(SET_ENABLED)
        .bind(&request.id)
        .bind(request.enabled)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|err| store_error(&err))?
        .ok_or_else(|| Status::not_found(REASON_NOT_FOUND))?;
    tx.commit().await.map_err(|err| store_error(&err))?;
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

/// Lists one page of admin-enabled catalog items. The RPC does not use it: `list_all` answers an
/// admin.
///
/// `kind` is the wire value of [`CatalogKind`]: 0 lists every kind, 1 to 4 filter. `after_id` is
/// exclusive and empty starts at the first item. A `limit` of 0 means [`DEFAULT_CATALOG_PAGE`];
/// larger values are cut to [`MAX_CATALOG_PAGE`]. A client keeps `next_id` as its cursor and
/// stops on an empty page. The list takes no owner and no admin override: a disabled item never
/// appears.
///
/// # Errors
/// `INVALID_ARGUMENT` for a kind outside the closed set or an illegal `after_id` (see
/// [`validate_after_id`]), `INTERNAL` on a storage failure.
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
    list_page(pool, LIST_ENABLED, kind, after_id, limit, cap).await
}

/// Lists one page of every catalog item, admin-disabled ones included, like the admin web page.
///
/// Paging and errors are those of [`list_enabled`]. The caller must already be an admin.
///
/// # Errors
/// The errors of [`list_enabled`].
pub async fn list_all(
    pool: &PgPool,
    kind: i32,
    after_id: &str,
    limit: u32,
) -> Result<CatalogPage, Status> {
    list_page(pool, LIST_ALL, kind, after_id, limit, MAX_CATALOG_PAGE).await
}

async fn list_page(
    pool: &PgPool,
    query: &'static str,
    kind: i32,
    after_id: &str,
    limit: u32,
    cap: u32,
) -> Result<CatalogPage, Status> {
    validate_after_id(after_id)?;
    let kind = match CatalogKind::try_from(kind) {
        Ok(CatalogKind::Unspecified) => None,
        Ok(known) => core_kind(known).map(CoreKind::as_str),
        Err(_) => return Err(Status::invalid_argument(REASON_KIND_UNKNOWN)),
    };
    let limit = match limit {
        0 => DEFAULT_CATALOG_PAGE.min(cap),
        n => n.min(cap),
    };
    let rows = sqlx::query_as::<_, Row>(query)
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

/// Answers a `ListCatalog` request for an admin: validates `kind` and `after_id` at the edge, then
/// lists every item, as the admin catalog page does. The handler refuses a non-admin first.
///
/// # Errors
/// The errors of [`list_all`].
pub async fn list_catalog(
    pool: &PgPool,
    request: &ListCatalogRequest,
) -> Result<ListCatalogReply, Status> {
    validate_after_id(&request.after_id)?;
    let page = list_all(pool, request.kind, &request.after_id, request.page_size).await?;
    Ok(ListCatalogReply {
        items: page.items,
        next_id: page.next_id,
    })
}
