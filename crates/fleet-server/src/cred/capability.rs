//! Per-user capability grants behind `FleetCapabilityAdmin`.

use fleet_proto::v1::{
    GrantCapabilityRequest, ListCapabilitiesReply, ListCapabilitiesRequest, RevokeCapabilityReply,
    RevokeCapabilityRequest, UserCapability,
};
use tonic::Status;

const NOT_IMPLEMENTED: &str = "capabilities are not implemented";

/// Grants a capability to a user.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn grant(_request: &GrantCapabilityRequest) -> Result<UserCapability, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Revokes a capability from a user.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn revoke(_request: &RevokeCapabilityRequest) -> Result<RevokeCapabilityReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}

/// Lists the capabilities a user holds.
///
/// # Errors
/// Returns `UNIMPLEMENTED` until the store is built.
pub fn list(_request: &ListCapabilitiesRequest) -> Result<ListCapabilitiesReply, Status> {
    Err(Status::unimplemented(NOT_IMPLEMENTED))
}
