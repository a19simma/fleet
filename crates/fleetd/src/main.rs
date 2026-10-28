//! fleetd binary: `serve` (default), `dump`, `hook`, `askpass`, `fetch`, `agent-exec` and
//! `pueue-callback`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use fleetd::agent_exec::exec_job;
use fleetd::fetch_policy::MAX_URL_BYTES;
use fleetd::jobsock::{ServiceName, connect, read_frame, socket_path, write_frame};
use fleetd::systemd::DEFAULT_RUN_DIR;
use fleetd::{Config, Error, Signals, askpass, dump, run, run_hook};
use serde::Deserialize;
use tokio::io::BufReader;
use tracing_subscriber::EnvFilter;

const JOB_ID_ENV: &str = "FLEET_JOB_ID";
const FETCH_REPLY_WAIT: Duration = Duration::from_secs(45);

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
    /// Fetch a web page through the daemon over the job socket and print its text. Takes one URL.
    /// Prints a fixed error line to stderr and exits 1 on any refusal or failure.
    Fetch {
        /// The URL. Any other count of arguments is refused.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, num_args = 0..)]
        args: Vec<OsString>,
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
        Command::Fetch { args } => {
            let job_id = std::env::var_os(JOB_ID_ENV);
            let fetched = run_fetch(
                Path::new(DEFAULT_RUN_DIR),
                job_id.as_deref(),
                &args,
                FETCH_REPLY_WAIT,
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            )
            .await;
            Ok(if fetched {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FetchFailure {
    Usage,
    Failed,
}

impl fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Usage => "fleetd fetch: usage: fleetd fetch <url>",
            Self::Failed => "fleetd fetch: the fetch failed",
        })
    }
}

#[derive(Deserialize)]
struct FetchReply {
    status: String,
    body: Option<String>,
}

fn fetch_url(args: &[OsString]) -> Result<&str, FetchFailure> {
    let [arg] = args else {
        return Err(FetchFailure::Usage);
    };
    arg.to_str()
        .filter(|url| {
            !url.is_empty()
                && url.len() <= MAX_URL_BYTES
                && !url.chars().any(|c| c.is_whitespace() || c.is_control())
        })
        .ok_or(FetchFailure::Usage)
}

async fn fetch_exchange(socket: &Path, url: &str) -> std::io::Result<String> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let uid = std::fs::metadata(socket.parent().ok_or_else(invalid)?)?.uid();
    let mut stream = connect(socket, ServiceName::Fetch, uid).await?;
    let request = serde_json::to_vec(&serde_json::json!({ "url": url })).map_err(|_| invalid())?;
    write_frame(&mut stream, &request).await?;
    let frame = read_frame(&mut BufReader::new(stream)).await?;
    let reply: FetchReply = serde_json::from_slice(&frame).map_err(|_| invalid())?;
    match reply.body {
        Some(body) if reply.status == "ok" => Ok(body),
        _ => Err(invalid()),
    }
}

/// Fetches the one URL in `args` over the job socket of `job_id` under `run_dir`.
///
/// Writes the page text to `out` on success. On any refusal, transport error, malformed reply
/// or `wait` timeout it writes one fixed line to `err`, never the URL or a server message, and
/// returns false. The socket owner is the uid the run dir of the job belongs to.
async fn run_fetch(
    run_dir: &Path,
    job_id: Option<&OsStr>,
    args: &[OsString],
    wait: Duration,
    out: &mut impl Write,
    err: &mut impl Write,
) -> bool {
    let fetched = async {
        let url = fetch_url(args)?;
        let socket = job_id
            .and_then(OsStr::to_str)
            .and_then(|id| socket_path(run_dir, id))
            .ok_or(FetchFailure::Failed)?;
        tokio::time::timeout(wait, fetch_exchange(&socket, url))
            .await
            .map_err(|_| FetchFailure::Failed)?
            .map_err(|_| FetchFailure::Failed)
    }
    .await;
    match fetched {
        Ok(body) => out
            .write_all(body.as_bytes())
            .and_then(|()| out.flush())
            .is_ok(),
        Err(failure) => {
            let _ = writeln!(err, "{failure}");
            false
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

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tempfile::TempDir;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixListener;
    use tokio::sync::oneshot;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    const OUTER: Duration = Duration::from_secs(20);
    const WAIT: Duration = Duration::from_secs(5);
    const FIXED: &str = "fleetd fetch: the fetch failed\n";
    const USAGE: &str = "fleetd fetch: usage: fleetd fetch <url>\n";

    enum Script {
        Reply(Vec<u8>),
        Stall,
    }

    struct Rig {
        _dir: TempDir,
        run_dir: PathBuf,
        accepted: Arc<AtomicUsize>,
        seen: oneshot::Receiver<(Vec<u8>, Vec<u8>)>,
        _gate: oneshot::Sender<()>,
    }

    fn rig(script: Script) -> Result<Rig, Box<dyn std::error::Error>> {
        rig_with_mode(script, 0o700)
    }

    fn rig_with_mode(script: Script, mode: u32) -> Result<Rig, Box<dyn std::error::Error>> {
        let dir = TempDir::new()?;
        let job = dir.path().join("j1");
        std::fs::create_dir(&job)?;
        std::fs::set_permissions(&job, std::fs::Permissions::from_mode(mode))?;
        let listener = UnixListener::bind(job.join("job.sock"))?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let (seen_tx, seen) = oneshot::channel();
        let (gate, hold) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            count.fetch_add(1, Ordering::SeqCst);
            let mut reader = BufReader::new(&mut stream);
            let handshake = read_frame(&mut reader).await.unwrap_or_default();
            let request = read_frame(&mut reader).await.unwrap_or_default();
            let _ = seen_tx.send((handshake, request));
            match script {
                Script::Reply(bytes) => {
                    let _ = stream.write_all(&bytes).await;
                    let _ = stream.flush().await;
                }
                Script::Stall => {
                    let _ = hold.await;
                }
            }
        });
        Ok(Rig {
            run_dir: dir.path().to_path_buf(),
            _dir: dir,
            accepted,
            seen,
            _gate: gate,
        })
    }

    fn framed(text: &str) -> Script {
        Script::Reply(format!("{text}\n").into_bytes())
    }

    async fn fetch(
        rig_dir: &Path,
        job: Option<&str>,
        args: &[&str],
        wait: Duration,
    ) -> (bool, String, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        fetch_os(rig_dir, job, &args, wait).await
    }

    async fn fetch_os(
        rig_dir: &Path,
        job: Option<&str>,
        args: &[OsString],
        wait: Duration,
    ) -> (bool, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let ok = tokio::time::timeout(
            OUTER,
            run_fetch(rig_dir, job.map(OsStr::new), args, wait, &mut out, &mut err),
        )
        .await
        .unwrap_or(false);
        (
            ok,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    #[tokio::test]
    async fn an_ok_reply_prints_the_body_and_the_server_saw_the_exact_request() -> TestResult {
        let rig = rig(framed(r#"{"status":"ok","body":"page text\nline two"}"#))?;
        let (ok, out, err) =
            fetch(&rig.run_dir, Some("j1"), &["https://a.example/p?q=1"], WAIT).await;
        assert!(ok, "{err}");
        assert_eq!(out, "page text\nline two");
        assert_eq!(err, "");
        let (handshake, request) = rig.seen.await?;
        assert_eq!(handshake, b"fetch");
        assert_eq!(request, br#"{"url":"https://a.example/p?q=1"}"#);
        Ok(())
    }

    #[tokio::test]
    async fn a_refusal_prints_one_fixed_line_with_no_url_and_no_server_text() -> TestResult {
        let rig = rig(framed(
            r#"{"status":"error","error":"SECRET-DETAIL https://leak.example/x"}"#,
        ))?;
        let (ok, out, err) =
            fetch(&rig.run_dir, Some("j1"), &["https://leak.example/x"], WAIT).await;
        assert!(!ok);
        assert_eq!(out, "");
        assert_eq!(err, FIXED);
        Ok(())
    }

    #[tokio::test]
    async fn hostile_replies_all_end_in_the_fixed_line_and_no_output() -> TestResult {
        let oversized_no_newline = vec![b'a'; 70_000];
        let mut oversized_line =
            format!(r#"{{"status":"ok","body":"{}"}}"#, "b".repeat(70_000)).into_bytes();
        oversized_line.push(b'\n');
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("malformed json", b"{not json\n".to_vec()),
            ("empty frame", b"\n".to_vec()),
            ("ok without body", b"{\"status\":\"ok\"}\n".to_vec()),
            (
                "unknown status",
                b"{\"status\":\"maybe\",\"body\":\"x\"}\n".to_vec(),
            ),
            (
                "body of wrong type",
                b"{\"status\":\"ok\",\"body\":7}\n".to_vec(),
            ),
            ("not an object", b"[\"ok\"]\n".to_vec()),
            ("non utf-8 body", {
                let mut raw = b"{\"status\":\"ok\",\"body\":\"".to_vec();
                raw.extend([0xff, 0xfe]);
                raw.extend(b"\"}\n");
                raw
            }),
            ("oversized without newline", oversized_no_newline),
            ("oversized line", oversized_line),
            ("closed mid reply", br#"{"status":"ok","bo"#.to_vec()),
            ("closed with no reply", Vec::new()),
        ];
        for (name, bytes) in cases {
            let rig = rig(Script::Reply(bytes))?;
            let (ok, out, err) =
                fetch(&rig.run_dir, Some("j1"), &["https://a.example/"], WAIT).await;
            assert!(!ok, "{name}");
            assert_eq!(out, "", "{name}");
            assert_eq!(err, FIXED, "{name}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_silent_server_ends_at_the_wait_with_the_fixed_line() -> TestResult {
        let rig = rig(Script::Stall)?;
        let started = std::time::Instant::now();
        let (ok, out, err) = fetch(
            &rig.run_dir,
            Some("j1"),
            &["https://a.example/"],
            Duration::from_millis(300),
        )
        .await;
        assert!(!ok);
        assert_eq!(out, "");
        assert_eq!(err, FIXED);
        assert!(started.elapsed() < OUTER);
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_socket_a_missing_or_bad_job_id_fail_with_the_fixed_line() -> TestResult {
        let dir = TempDir::new()?;
        for job in [None, Some(""), Some("../j1"), Some("a/b"), Some("j1")] {
            let (ok, out, err) = fetch(dir.path(), job, &["https://a.example/"], WAIT).await;
            assert!(!ok, "{job:?}");
            assert_eq!(out, "", "{job:?}");
            assert_eq!(err, FIXED, "{job:?}");
        }
        std::fs::create_dir(dir.path().join("j1"))?;
        let (ok, _, err) = fetch(dir.path(), Some("j1"), &["https://a.example/"], WAIT).await;
        assert!(!ok);
        assert_eq!(err, FIXED);
        Ok(())
    }

    #[tokio::test]
    async fn a_socket_in_a_group_writable_dir_is_refused_before_any_byte_is_sent() -> TestResult {
        let mut rig = rig_with_mode(framed(r#"{"status":"ok","body":"x"}"#), 0o770)?;
        let (ok, _, err) = fetch(&rig.run_dir, Some("j1"), &["https://a.example/"], WAIT).await;
        assert!(!ok);
        assert_eq!(err, FIXED);
        assert!(rig.seen.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn bad_arguments_are_refused_with_the_usage_line_and_nothing_connects() -> TestResult {
        let rig = rig(framed(r#"{"status":"ok","body":"x"}"#))?;
        let long = format!("https://a.example/{}", "a".repeat(MAX_URL_BYTES));
        let cases: Vec<Vec<OsString>> = vec![
            vec![],
            vec!["https://a.example/".into(), "https://b.example/".into()],
            vec!["".into()],
            vec!["https://a.example/ x".into()],
            vec!["https://a.example/\nx".into()],
            vec!["https://a.example/\tx".into()],
            vec!["https://a.example/\u{85}".into()],
            vec!["https://a.example/\u{1b}[31m".into()],
            vec!["https://a.example/\0".into()],
            vec![long.into()],
            vec![OsString::from_vec(b"https://a.example/\xff".to_vec())],
            vec!["--".into(), "https://a.example/".into()],
        ];
        for args in cases {
            let (ok, out, err) = fetch_os(&rig.run_dir, Some("j1"), &args, WAIT).await;
            assert!(!ok, "{args:?}");
            assert_eq!(out, "", "{args:?}");
            assert_eq!(err, USAGE, "{args:?}");
        }
        assert_eq!(rig.accepted.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_url_of_exactly_the_cap_is_sent() -> TestResult {
        let rig = rig(framed(r#"{"status":"ok","body":"x"}"#))?;
        let url = format!("https://a.example/{}", "a".repeat(MAX_URL_BYTES - 18));
        assert_eq!(url.len(), MAX_URL_BYTES);
        let (ok, out, _) = fetch(&rig.run_dir, Some("j1"), &[&url], WAIT).await;
        assert!(ok);
        assert_eq!(out, "x");
        let (_, request) = rig.seen.await?;
        assert_eq!(request, format!(r#"{{"url":"{url}"}}"#).into_bytes());
        Ok(())
    }

    #[test]
    fn the_failure_lines_are_fixed() {
        assert_eq!(FetchFailure::Usage.to_string(), USAGE.trim_end());
        assert_eq!(FetchFailure::Failed.to_string(), FIXED.trim_end());
    }
}
