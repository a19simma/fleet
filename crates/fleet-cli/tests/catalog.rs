//! `fleet catalog` and `fleet user cap` parse their arguments and exit with the not-implemented
//! error until the commands are built.

use clap::Parser;
use fleet_cli::{Cli, CliError, Command, run};
use tonic::Code;

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    let mut all = vec!["fleet"];
    all.extend_from_slice(args);
    Cli::try_parse_from(all)
}

#[test]
fn every_catalog_and_capability_form_parses() -> Result<(), clap::Error> {
    let catalog = [
        &["catalog", "list"][..],
        &["catalog", "upsert", "skill", "tdd", "TDD", "--file", "-"],
        &["catalog", "enable", "tdd"],
        &["catalog", "disable", "tdd"],
    ];
    for args in catalog {
        assert!(
            matches!(parse(args)?.command, Command::Catalog { .. }),
            "{args:?}"
        );
    }
    let caps = [
        &["user", "cap", "list", "7"][..],
        &["user", "cap", "grant", "7", "profile:tools"],
        &["user", "cap", "revoke", "7", "profile:tools"],
    ];
    for args in caps {
        assert!(
            matches!(parse(args)?.command, Command::UserCap { .. }),
            "{args:?}"
        );
    }
    Ok(())
}

#[test]
fn missing_arguments_are_refused() {
    for args in [
        &["catalog"][..],
        &["catalog", "enable"],
        &["catalog", "upsert", "skill"],
        &["user", "cap"],
        &["user", "cap", "grant", "7"],
        &["user", "cap", "list", "seven"],
    ] {
        assert!(parse(args).is_err(), "{args:?}");
    }
}

#[tokio::test]
async fn each_command_exits_nonzero_with_the_not_implemented_message() -> Result<(), clap::Error> {
    for (args, text) in [
        (&["catalog", "list"][..], "fleet catalog is not implemented"),
        (
            &["user", "cap", "list", "7"][..],
            "fleet user cap is not implemented",
        ),
    ] {
        let cli = parse(args)?;
        let mut stdin = std::io::empty();
        let mut out = Vec::new();
        let err = run(cli, |_| None, &mut stdin, &mut out).await.unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert_eq!(out, Vec::<u8>::new());
        assert!(
            matches!(&err, CliError::Rpc(status) if status.code() == Code::Unimplemented),
            "{err}"
        );
        assert!(err.to_string().contains(text), "{err}");
    }
    Ok(())
}
