//! `fleet timing` parses its arguments and answers a not-implemented error until the
//! command is built.

use clap::Parser;
use fleet_cli::{Cli, CliError, Command, run};
use tonic::Code;

async fn invoke(args: &[&str]) -> Result<(), CliError> {
    let mut full = vec!["fleet", "--server", "http://127.0.0.1:1"];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).map_err(|err| CliError::Usage(err.to_string()))?;
    run(parsed, |_| None, &mut b"".as_slice(), &mut Vec::new()).await
}

#[test]
fn the_command_parses_job_commands_and_json() -> Result<(), clap::Error> {
    let cli = Cli::try_parse_from(["fleet", "timing", "job-1", "--commands", "--json"])?;
    let Command::Timing {
        job,
        commands,
        json,
    } = cli.command
    else {
        return Err(clap::Error::new(clap::error::ErrorKind::InvalidValue));
    };
    assert_eq!(job, "job-1");
    assert!(commands);
    assert!(json);
    Ok(())
}

#[test]
fn the_flags_default_off() -> Result<(), clap::Error> {
    let cli = Cli::try_parse_from(["fleet", "timing", "job-1"])?;
    let Command::Timing { commands, json, .. } = cli.command else {
        return Err(clap::Error::new(clap::error::ErrorKind::InvalidValue));
    };
    assert!(!commands);
    assert!(!json);
    Ok(())
}

#[test]
fn the_job_is_required() {
    assert!(Cli::try_parse_from(["fleet", "timing"]).is_err());
}

#[tokio::test]
async fn running_it_returns_a_not_implemented_error() {
    let result = invoke(&["timing", "job-1"]).await;
    let Err(CliError::Rpc(status)) = result else {
        panic!("expected an rpc error, got {result:?}");
    };
    assert_eq!(status.code(), Code::Unimplemented);
    assert_eq!(
        CliError::Rpc(status).exit_code(),
        1,
        "a runtime failure, not a usage error"
    );
}
