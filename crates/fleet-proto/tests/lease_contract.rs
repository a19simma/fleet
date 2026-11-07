//! The lease-mismatch text is a wire contract: fleetd and the server both depend on it.

use fleet_proto::ERR_LEASE_MISMATCH;

#[test]
fn the_lease_mismatch_text_is_pinned() {
    assert_eq!(ERR_LEASE_MISMATCH, "lease does not match");
}
