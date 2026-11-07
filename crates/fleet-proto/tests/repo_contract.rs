//! The `FleetRepos` wire contract: service name, field presence and message round trips.

use fleet_proto::v1::fleet_repos_server::SERVICE_NAME;
use fleet_proto::v1::{AddRepoRequest, ListReposReply, RemoveRepoRequest, RepoInfo};
use tonic_prost::prost::Message;

fn info(push: Option<bool>) -> RepoInfo {
    RepoInfo {
        host: "github.com".to_owned(),
        path: "owner/name".to_owned(),
        forge_kind: "github".to_owned(),
        runnable: true,
        verified_at_ms: 1_700_000_000_000,
        push,
    }
}

#[test]
fn the_service_has_its_wire_name() {
    assert_eq!(SERVICE_NAME, "fleet.v1.FleetRepos");
}

#[test]
fn push_is_optional_and_unset_differs_from_false() {
    for push in [None, Some(false), Some(true)] {
        let bytes = info(push).encode_to_vec();
        assert_eq!(RepoInfo::decode(bytes.as_slice()).unwrap().push, push);
    }
    assert_ne!(
        info(None).encode_to_vec(),
        info(Some(false)).encode_to_vec()
    );
}

#[test]
fn requests_and_the_list_reply_round_trip() {
    let add = AddRepoRequest {
        repo: "https://github.com/owner/name".to_owned(),
    };
    assert_eq!(
        AddRepoRequest::decode(add.encode_to_vec().as_slice()).unwrap(),
        add
    );
    let remove = RemoveRepoRequest {
        host: "github.com".to_owned(),
        path: "owner/name".to_owned(),
    };
    assert_eq!(
        RemoveRepoRequest::decode(remove.encode_to_vec().as_slice()).unwrap(),
        remove
    );
    let list = ListReposReply {
        repos: vec![info(None), info(Some(true))],
    };
    assert_eq!(
        ListReposReply::decode(list.encode_to_vec().as_slice()).unwrap(),
        list
    );
}
