//! Ties the CLI `--agent` list to the server's known agents.

use clap::Parser;
use fleet_cli::{AGENTS, Cli};
use fleet_server::jobs::{KNOWN_AGENTS, validate_agent};

#[test]
fn every_server_agent_parses_for_submit_and_batch_submit() {
    for name in KNOWN_AGENTS {
        let submit = Cli::try_parse_from([
            "fleet", "submit", "--repo", "o/r", "--base", "main", "--agent", name, "p",
        ]);
        assert!(submit.is_ok(), "submit rejects {name}: {submit:?}");
        let batch = Cli::try_parse_from([
            "fleet",
            "batch",
            "submit",
            "--prompt",
            "p",
            "--repo",
            "o/r",
            "--base",
            "main",
            "--profiles",
            "a",
            "--agent",
            name,
        ]);
        assert!(batch.is_ok(), "batch submit rejects {name}: {batch:?}");
    }
}

#[test]
fn every_cli_agent_passes_server_validation() {
    for name in AGENTS {
        assert!(validate_agent(name).is_ok(), "server rejects {name}");
    }
}

#[test]
fn help_names_each_agent_once() -> Result<(), Box<dyn std::error::Error>> {
    for args in [
        &["fleet", "submit", "--help"][..],
        &["fleet", "batch", "submit", "--help"][..],
    ] {
        let err = Cli::try_parse_from(args).err().ok_or("help")?;
        let text = err.to_string();
        let line = text
            .lines()
            .find(|l| l.contains("[default: claude]"))
            .ok_or("no default line")?;
        assert_eq!(line.matches("kimi").count(), 1, "{line}");
    }
    Ok(())
}
