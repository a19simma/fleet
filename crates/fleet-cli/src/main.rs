//! fleet: the Fleet command line client.

use std::io::Write;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fleet", version, about = "Fleet command line client")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List every box and what it is doing.
    List,
}

fn run(command: &Command) -> &'static str {
    match command {
        Command::List => "no boxes: fleet list is not implemented yet",
    }
}

fn main() {
    let cli = Cli::parse();
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{}", run(&cli.command));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_a_stub() {
        assert!(run(&Command::List).contains("not implemented"));
    }
}
