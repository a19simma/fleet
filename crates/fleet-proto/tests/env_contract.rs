//! The `FleetEnvironments` wire contract: service name, rpc set, the one message family that
//! carries a secret value, and its Debug output.

use fleet_proto::v1::PutEnvironmentSecretRequest;
use fleet_proto::v1::fleet_environments_server::SERVICE_NAME;

const MARKER: &str = "MARKER-env-secret-value-9f3a";

const RPCS: [&str; 9] = [
    "CreateEnvironment",
    "ListEnvironments",
    "GetEnvironment",
    "DeleteEnvironment",
    "PutEnvironmentSecret",
    "DeleteEnvironmentSecret",
    "SaveEnvironmentVersion",
    "GetEnvironmentVersion",
    "ListEnvironmentVersions",
];

#[test]
fn the_service_has_its_wire_name() {
    assert_eq!(SERVICE_NAME, "fleet.v1.FleetEnvironments");
}

#[test]
fn every_rpc_path_is_served() {
    let proto = include_str!("../proto/fleet/v1/fleet.proto");
    let block = proto
        .split("service FleetEnvironments {")
        .nth(1)
        .unwrap()
        .split("\n}")
        .next()
        .unwrap();
    assert_eq!(block.matches("rpc ").count(), RPCS.len());
    for rpc in RPCS {
        assert!(block.contains(&format!("rpc {rpc}(")), "{rpc}");
    }
}

#[test]
fn only_the_known_requests_carry_a_value_field() {
    let proto = include_str!("../proto/fleet/v1/fleet.proto");
    let mut holders = Vec::new();
    let mut message = "";
    for line in proto.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix("message ") {
            message = rest.trim_end_matches('{').trim();
        } else if line.starts_with("string value =") && message.ends_with("Request") {
            holders.push(message.to_owned());
        }
    }
    holders.sort();
    assert_eq!(
        holders,
        ["PutCredentialRequest", "PutEnvironmentSecretRequest"]
    );
}

#[test]
fn put_environment_secret_request_debug_hides_the_value() {
    let message = PutEnvironmentSecretRequest {
        environment: "prod".into(),
        name: "TOKEN".into(),
        value: MARKER.into(),
    };
    for text in [format!("{message:?}"), format!("{message:#?}")] {
        assert!(!text.contains(MARKER), "{text}");
        assert!(text.contains("PutEnvironmentSecretRequest"), "{text}");
        assert!(text.contains("prod"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
    }
}
