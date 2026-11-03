//! No bearer token scope reaches `FleetCapabilityAdmin`: the box and client tokens are denied
//! on every RPC and a bad token is unauthenticated.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use fleet_proto::CAPABILITY_ADMIN_PATH;
use fleet_server::auth::BearerAuth;
use fleet_server::config::Token;
use tonic::Code;

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const RPCS: [&str; 3] = ["GrantCapability", "RevokeCapability", "ListCapabilities"];

fn auth() -> BearerAuth {
    let box_token = Token::new(BOX.to_owned()).unwrap();
    let client = Token::new(CLIENT.to_owned()).unwrap();
    BearerAuth::new(&box_token, Some(&client))
}

#[test]
fn box_and_client_tokens_are_denied_on_every_capability_rpc() {
    for rpc in RPCS {
        let path = format!("{CAPABILITY_ADMIN_PATH}{rpc}");
        for token in [BOX, CLIENT] {
            let header = format!("Bearer {token}");
            let status = auth().check(&path, Some(header.as_bytes())).unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{path}");
        }
    }
}

#[test]
fn a_bad_or_missing_token_is_unauthenticated() {
    let path = format!("{CAPABILITY_ADMIN_PATH}GrantCapability");
    for header in [None, Some(&b"Bearer nope"[..])] {
        let status = auth().check(&path, header).unwrap_err();
        assert_eq!(status.code(), Code::Unauthenticated);
    }
}

#[test]
fn the_positive_control_is_a_path_the_client_token_does_reach() {
    let header = format!("Bearer {CLIENT}");
    auth()
        .check(
            "/fleet.v1.FleetProfiles/ListProfiles",
            Some(header.as_bytes()),
        )
        .unwrap();
}
