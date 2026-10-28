//! The CI retry limits and names fleetd and the server share.

use fleet_proto::{
    CI_RETRY_KEY_PREFIX, DEFAULT_CI_RETRIES, MAX_CI_RETRIES, ci_retry_key, is_swarm_branch,
};

#[test]
fn the_default_is_off_and_inside_the_range() {
    assert_eq!(DEFAULT_CI_RETRIES, 0);
    assert_eq!(MAX_CI_RETRIES, 5);
}

#[test]
fn the_key_names_the_parent_and_the_attempt() {
    assert_eq!(ci_retry_key("01ABC", 2), "ci-retry:01ABC:2");
    assert_ne!(ci_retry_key("01ABC", 1), ci_retry_key("01ABC", 2));
    assert_ne!(ci_retry_key("01ABC", 1), ci_retry_key("01ABD", 1));
    assert!(ci_retry_key("01ABC", 1).starts_with(CI_RETRY_KEY_PREFIX));
}

#[test]
fn only_a_swarm_branch_with_a_plain_id_is_a_push_target() {
    assert!(is_swarm_branch("swarm/01J8ZABC"));
    assert!(is_swarm_branch(&format!("swarm/{}", "a".repeat(64))));
    for text in [
        "",
        "main",
        "swarm/",
        "swarm",
        "swarm/a/b",
        "swarm/../main",
        "swarm/a b",
        "swarm/a\u{e9}",
        "refs/heads/swarm/a",
        "/swarm/a",
        "swarm/-x",
        &format!("swarm/{}", "a".repeat(65)),
    ] {
        assert!(!is_swarm_branch(text), "{text:?}");
    }
}
