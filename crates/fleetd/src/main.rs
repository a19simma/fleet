//! fleetd binary: `serve` (default), `dump`, `hook`, `askpass`, `agent-exec` and `pueue-callback`.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use fleetd::agent_exec::exec_job;
use fleetd::systemd::DEFAULT_RUN_DIR;
use fleetd::{Config, Error, Signals, askpass, dump, run, run_hook};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Per-box Fleet daemon")]
struct Cli {
    /// Config file. Defaults to /etc/fleetd/config.toml when that file exists.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the daemon. This is the default.
    Serve,
    /// Print queued events as JSON lines.
    Dump {
        /// Print at most this many events.
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Forward a Claude Code hook payload from stdin to the local fleetd. Always exits 0.
    Hook {
        /// Hook event name, for example `SessionStart`.
        event: String,
    },
    /// Answer a git credential prompt for `GIT_ASKPASS`: the token from `GH_TOKEN` for a
    /// password prompt, a fixed username for a username prompt, else nothing and exit 1.
    /// Answers only when the prompt names the host in `FLEETD_ASKPASS_HOST`.
    Askpass {
        /// The prompt git passes as its only argument.
        prompt: String,
    },
    /// Run the agent for a job from its spec file, as the unit does. Replaces this process.
    /// Exits 2 when the spec is missing, mismatched or empty.
    AgentExec {
        /// Job id.
        id: String,
        /// Parent of the per-job run directories.
        #[arg(long, default_value = DEFAULT_RUN_DIR)]
        run_dir: PathBuf,
    },
    /// Report a finished pueue task. Not implemented yet.
    PueueCallback {
        /// pueue task id.
        id: String,
        /// pueue group.
        group: String,
    },
}

async fn execute(cli: Cli) -> Result<ExitCode, Error> {
    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => {
            let signals = Signals::register()?;
            let config = Config::load(cli.config.as_deref())?;
            run(config, signals.terminated())
                .await
                .map(|()| ExitCode::SUCCESS)
        }
        Command::Dump { limit } => {
            let config = Config::load(cli.config.as_deref())?;
            dump(&config.db_path, limit, &mut std::io::stdout()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Command::Hook { event } => {
            let sent = run_hook(cli.config.as_deref(), &event, tokio::io::stdin()).await;
            if let Err(err) = sent {
                eprintln!("fleetd hook: {err}");
            }
            std::process::exit(0)
        }
        Command::Askpass { prompt } => Ok(askpass_reply(&prompt)),
        Command::AgentExec { id, run_dir } => {
            eprintln!("fleetd agent-exec: {}", exec_job(&run_dir, &id));
            Ok(ExitCode::from(2))
        }
        Command::PueueCallback { id, group } => {
            eprintln!("fleetd: pueue-callback is not implemented (task {id}, group {group})");
            Ok(ExitCode::from(2))
        }
    }
}

fn askpass_reply(prompt: &str) -> ExitCode {
    let token = std::env::var("GH_TOKEN").ok();
    let host = std::env::var(askpass::HOST_ENV).unwrap_or_default();
    let printed = askpass::answer(prompt, token.as_deref(), &host)
        .is_some_and(|text| writeln!(std::io::stdout(), "{text}").is_ok());
    if printed {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn marked_askpass() -> Option<ExitCode> {
    if std::env::var_os(askpass::MARKER_ENV).is_none_or(|marker| marker != "1") {
        return None;
    }
    let mut args = std::env::args_os().skip(1);
    let (Some(prompt), None) = (args.next(), args.next()) else {
        return None;
    };
    Some(askpass_reply(&prompt.to_string_lossy()))
}

#[tokio::main]
async fn main() -> ExitCode {
    if let Some(code) = marked_askpass() {
        return code;
    }
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();
    match execute(Cli::parse()).await {
        Ok(code) => code,
        Err(err) => {
            eprintln!("fleetd: {err}");
            ExitCode::FAILURE
        }
    }
}
