//! fleet: the Fleet command line client.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use fleet_cli::{Cli, color_wanted, run_with_color};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = std::io::stdout();
    let mut stdin = std::io::stdin().lock();
    let no_color = std::env::var("NO_COLOR").ok();
    let color = color_wanted(out.is_terminal(), no_color.as_deref());
    let lookup = |name: &str| std::env::var(name).ok();
    match run_with_color(cli, lookup, true, color, &mut stdin, &mut out).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "fleet: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
