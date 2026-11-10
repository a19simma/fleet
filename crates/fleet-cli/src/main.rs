//! fleet: the Fleet command line client.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;

use clap::Parser;
use fleet_cli::{Cli, color_wanted, run_with_tty};

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let mut out = std::io::stdout();
    let stdin_handle = std::io::stdin();
    let tty = stdin_handle.is_terminal();
    let mut stdin = stdin_handle.lock();
    let no_color = std::env::var("NO_COLOR").ok();
    let color = color_wanted(out.is_terminal(), no_color.as_deref());
    let lookup = |name: &str| std::env::var(name).ok();
    match run_with_tty(cli, lookup, true, color, tty, &mut stdin, &mut out).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "fleet: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
