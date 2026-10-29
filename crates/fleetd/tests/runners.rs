//! Agent name resolution tests.

use fleetd::agent::{ERR_UNKNOWN_AGENT, resolve};

#[test]
fn an_empty_agent_name_resolves_to_claude() {
    assert_eq!(
        resolve("").map(fleetd::agent::AgentRunner::name),
        Some("claude")
    );
}

#[test]
fn the_claude_name_resolves_to_claude() {
    assert_eq!(
        resolve("claude").map(fleetd::agent::AgentRunner::name),
        Some("claude")
    );
}

#[test]
fn an_unknown_agent_name_resolves_to_nothing() {
    assert!(resolve("codex").is_none());
    assert!(resolve("Claude").is_none());
    assert_eq!(ERR_UNKNOWN_AGENT, "agent is not supported");
}
