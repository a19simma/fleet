//! fleet: the Fleet command line client.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;
use fleet_cli::{Cli, run};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = std::io::stdout();
    let mut stdin = std::io::stdin().lock();
    match run(cli, |name| std::env::var(name).ok(), &mut stdin, &mut out).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "fleet: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
