//! Catalog store and RPC logic.

use fleet_proto::v1::{
    CatalogItem, ListCatalogReply, ListCatalogRequest, SetCatalogItemEnabledRequest,
    UpsertCatalogItemRequest,
};
use tonic::Status;

const NOT_IMPLEMENTED: &str = "the catalog is not implemented";

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
