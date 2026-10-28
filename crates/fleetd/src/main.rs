//! fleetd binary: `serve` (default), `dump`, `hook`, `askpass`, `fetch`, `broker`, `agent-exec`
//! and `pueue-callback`.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::Write;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};
use fleetd::agent_exec::exec_job;
use fleetd::broker::Denial;
use fleetd::fetch_policy::MAX_URL_BYTES;
use fleetd::jobsock::{ServiceName, connect, read_frame, socket_path, write_frame};
use fleetd::systemd::DEFAULT_RUN_DIR;
use fleetd::{Config, Error, Signals, askpass, dump, run, run_hook};
use serde::Deserialize;
use tokio::io::BufReader;
use tracing_subscriber::EnvFilter;

const JOB_ID_ENV: &str = "FLEET_JOB_ID";
const FETCH_REPLY_WAIT: Duration = Duration::from_secs(45);
const BROKER_REPLY_WAIT: Duration = Duration::from_secs(150);

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
    /// Ask the credential broker over the job socket: `push`, `pr_create <title> <body>`,
    /// `pr_checks` or `fetch`. Prints the broker output. Prints a fixed error line to stderr and
    /// exits 1 on any refusal or failure.
    Broker {
        /// The op and its arguments. Any other shape is refused.
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
        Command::Broker { args } => {
            let job_id = std::env::var_os(JOB_ID_ENV);
            let served = run_broker(
                Path::new(DEFAULT_RUN_DIR),
                job_id.as_deref(),
                &args,
                BROKER_REPLY_WAIT,
                &mut std::io::stdout(),
                &mut std::io::stderr(),
            )
            .await;
            Ok(if served {
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

async fn exchange(socket: &Path, service: ServiceName, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let uid = std::fs::metadata(socket.parent().ok_or_else(invalid)?)?.uid();
    let mut stream = connect(socket, service, uid).await?;
    write_frame(&mut stream, request).await?;
    read_frame(&mut BufReader::new(stream)).await
}

async fn fetch_exchange(socket: &Path, url: &str) -> std::io::Result<String> {
    let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
    let request = serde_json::to_vec(&serde_json::json!({ "url": url })).map_err(|_| invalid())?;
    let frame = exchange(socket, ServiceName::Fetch, &request).await?;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BrokerFailure {
    Usage,
    Failed,
    Denied(Denial),
}

impl fmt::Display for BrokerFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => f.write_str(
                "fleetd broker: usage: fleetd broker push | pr_create <title> <body> | pr_checks | fetch",
            ),
            Self::Failed => f.write_str("fleetd broker: the request failed"),
            Self::Denied(denial) => write!(f, "fleetd broker: {}", denial.message()),
        }
    }
}

const BROKER_DENIALS: [Denial; 7] = [
    Denial::InvalidRequest,
    Denial::UnsafeText,
    Denial::CapReached,
    Denial::RateLimited,
    Denial::NoPullRequest,
    Denial::Failed,
    Denial::TimedOut,
];

#[derive(Deserialize)]
struct BrokerReply {
    status: String,
    output: Option<String>,
    error: Option<String>,
}

fn broker_request(args: &[OsString]) -> Result<Vec<u8>, BrokerFailure> {
    let strs: Vec<&str> = args
        .iter()
        .map(|arg| arg.to_str().ok_or(BrokerFailure::Usage))
        .collect::<Result<_, _>>()?;
    let request = match strs[..] {
        ["push"] => serde_json::json!({ "op": "push" }),
        ["pr_checks"] => serde_json::json!({ "op": "pr_checks" }),
        ["fetch"] => serde_json::json!({ "op": "fetch" }),
        ["pr_create", title, body] => {
            serde_json::json!({ "op": "pr_create", "title": title, "body": body })
        }
        _ => return Err(BrokerFailure::Usage),
    };
    serde_json::to_vec(&request).map_err(|_| BrokerFailure::Failed)
}

fn broker_outcome(frame: &[u8]) -> Result<String, BrokerFailure> {
    let reply: BrokerReply = serde_json::from_slice(frame).map_err(|_| BrokerFailure::Failed)?;
    match (reply.status.as_str(), reply.output, reply.error) {
        ("done", Some(output), _) => Ok(output
            .chars()
            .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
            .collect()),
        ("denied", _, Some(code)) => BROKER_DENIALS
            .into_iter()
            .find(|denial| {
                serde_json::to_value(denial).is_ok_and(|v| v.as_str() == Some(code.as_str()))
            })
            .map_or(Err(BrokerFailure::Failed), |denial| {
                Err(BrokerFailure::Denied(denial))
            }),
        _ => Err(BrokerFailure::Failed),
    }
}

/// Sends the broker request in `args` over the job socket of `job_id` under `run_dir`.
///
/// Writes the broker output to `out` on success, control characters other than newline and tab
/// removed. On a usage error, a refusal, a transport error, a malformed or oversize reply or a
/// `wait` timeout it writes one fixed line to `err` and returns false. A denial prints the fixed
/// message of its code, never the text the socket sent.
async fn run_broker(
    run_dir: &Path,
    job_id: Option<&OsStr>,
    args: &[OsString],
    wait: Duration,
    out: &mut impl Write,
    err: &mut impl Write,
) -> bool {
    let served = async {
        let request = broker_request(args)?;
        let socket = job_id
            .and_then(OsStr::to_str)
            .and_then(|id| socket_path(run_dir, id))
            .ok_or(BrokerFailure::Failed)?;
        let frame = tokio::time::timeout(wait, exchange(&socket, ServiceName::Broker, &request))
            .await
            .map_err(|_| BrokerFailure::Failed)?
            .map_err(|_| BrokerFailure::Failed)?;
        broker_outcome(&frame)
    }
    .await;
    match served {
        Ok(text) => out
            .write_all(text.as_bytes())
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

    use fleetd::jobsock::MAX_FRAME_BYTES;

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

    const BROKER_FIXED: &str = "fleetd broker: the request failed\n";
    const BROKER_USAGE: &str =
        "fleetd broker: usage: fleetd broker push | pr_create <title> <body> | pr_checks | fetch\n";

    async fn broker_os(
        rig_dir: &Path,
        job: Option<&str>,
        args: &[OsString],
        wait: Duration,
    ) -> (bool, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let ok = tokio::time::timeout(
            OUTER,
            run_broker(rig_dir, job.map(OsStr::new), args, wait, &mut out, &mut err),
        )
        .await
        .unwrap_or(false);
        (
            ok,
            String::from_utf8_lossy(&out).into_owned(),
            String::from_utf8_lossy(&err).into_owned(),
        )
    }

    async fn broker(
        rig_dir: &Path,
        job: Option<&str>,
        args: &[&str],
        wait: Duration,
    ) -> (bool, String, String) {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        broker_os(rig_dir, job, &args, wait).await
    }

    #[tokio::test]
    async fn each_op_sends_its_exact_frame_under_the_broker_handshake_and_prints_the_output()
    -> TestResult {
        let cases: [(&[&str], &str); 4] = [
            (&["push"], r#"{"op":"push"}"#),
            (&["pr_checks"], r#"{"op":"pr_checks"}"#),
            (&["fetch"], r#"{"op":"fetch"}"#),
            (
                &["pr_create", "A \"title\"", "line\nbody"],
                r#"{"body":"line\nbody","op":"pr_create","title":"A \"title\""}"#,
            ),
        ];
        for (args, frame) in cases {
            let rig = rig(framed(r#"{"status":"done","output":"ok line\nsecond"}"#))?;
            let (ok, out, err) = broker(&rig.run_dir, Some("j1"), args, WAIT).await;
            assert!(ok, "{args:?}");
            assert_eq!(out, "ok line\nsecond", "{args:?}");
            assert_eq!(err, "", "{args:?}");
            let (handshake, request) = rig.seen.await?;
            assert_eq!(handshake, b"broker");
            assert_eq!(request, frame.as_bytes(), "{args:?}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_denied_reply_prints_the_fixed_message_of_its_code_and_fails() -> TestResult {
        for denial in BROKER_DENIALS {
            let code = serde_json::to_string(&denial)?;
            let rig = rig(framed(&format!(
                r#"{{"status":"denied","error":{code},"message":"server words"}}"#
            )))?;
            let (ok, out, err) = broker(&rig.run_dir, Some("j1"), &["push"], WAIT).await;
            assert!(!ok, "{denial:?}");
            assert_eq!(out, "", "{denial:?}");
            assert_eq!(
                err,
                format!("fleetd broker: {}\n", denial.message()),
                "{denial:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn control_characters_in_the_output_are_stripped_but_newline_and_tab_stay() -> TestResult
    {
        let rig = rig(framed(
            r#"{"status":"done","output":"a\u001b[31mred\u001b[0m\tb\r\nc\u0085d\u0000e"}"#,
        ))?;
        let (ok, out, _) = broker(&rig.run_dir, Some("j1"), &["fetch"], WAIT).await;
        assert!(ok);
        assert_eq!(out, "a[31mred[0m\tb\ncde");
        Ok(())
    }

    #[tokio::test]
    async fn a_malformed_or_hostile_reply_fails_with_the_fixed_line_and_echoes_nothing()
    -> TestResult {
        let oversize = {
            let mut line = format!(
                r#"{{"status":"done","output":"{}"#,
                "a".repeat(MAX_FRAME_BYTES)
            );
            line.push_str("\"}\n");
            line.into_bytes()
        };
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("not json", b"nope\n".to_vec()),
            ("empty line", b"\n".to_vec()),
            (
                "eof no newline",
                br#"{"status":"done","output":"x"}"#.to_vec(),
            ),
            ("no reply", Vec::new()),
            ("array", b"[\"done\"]\n".to_vec()),
            ("done no output", b"{\"status\":\"done\"}\n".to_vec()),
            (
                "output not string",
                b"{\"status\":\"done\",\"output\":5}\n".to_vec(),
            ),
            (
                "unknown status",
                b"{\"status\":\"ok\",\"output\":\"x\"}\n".to_vec(),
            ),
            (
                "unknown code",
                br#"{"status":"denied","error":"GH_TOKEN=abc","message":"GH_TOKEN=abc"}"#
                    .iter()
                    .copied()
                    .chain(*b"\n")
                    .collect(),
            ),
            (
                "denied no code",
                b"{\"status\":\"denied\",\"message\":\"x\"}\n".to_vec(),
            ),
            ("oversize", oversize),
            (
                "invalid utf8",
                b"{\"status\":\"done\",\"output\":\"\xff\"}\n".to_vec(),
            ),
        ];
        for (name, bytes) in cases {
            let rig = rig(Script::Reply(bytes))?;
            let (ok, out, err) = broker(&rig.run_dir, Some("j1"), &["push"], WAIT).await;
            assert!(!ok, "{name}");
            assert_eq!(out, "", "{name}");
            assert_eq!(err, BROKER_FIXED, "{name}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_silent_broker_ends_at_the_wait_with_the_fixed_line() -> TestResult {
        let rig = rig(Script::Stall)?;
        let (ok, out, err) = broker(
            &rig.run_dir,
            Some("j1"),
            &["push"],
            Duration::from_millis(300),
        )
        .await;
        assert!(!ok);
        assert_eq!(out, "");
        assert_eq!(err, BROKER_FIXED);
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_socket_or_job_id_and_an_unsafe_socket_dir_fail_with_the_fixed_line()
    -> TestResult {
        let dir = TempDir::new()?;
        for job in [None, Some(""), Some("../j1"), Some("a/b"), Some("j1")] {
            let (ok, out, err) = broker(dir.path(), job, &["push"], WAIT).await;
            assert!(!ok, "{job:?}");
            assert_eq!(out, "", "{job:?}");
            assert_eq!(err, BROKER_FIXED, "{job:?}");
        }
        let mut rig = rig_with_mode(framed(r#"{"status":"done","output":"x"}"#), 0o770)?;
        let (ok, _, err) = broker(&rig.run_dir, Some("j1"), &["push"], WAIT).await;
        assert!(!ok);
        assert_eq!(err, BROKER_FIXED);
        assert!(rig.seen.try_recv().is_err());
        Ok(())
    }

    #[tokio::test]
    async fn bad_arguments_get_the_usage_line_and_nothing_connects() -> TestResult {
        let rig = rig(framed(r#"{"status":"done","output":"x"}"#))?;
        let cases: Vec<Vec<OsString>> = vec![
            vec![],
            vec!["".into()],
            vec!["Push".into()],
            vec!["PUSH".into()],
            vec!["merge".into()],
            vec!["push ".into()],
            vec!["push\",\"title\":\"x".into()],
            vec!["push\n".into()],
            vec!["--help".into()],
            vec!["--".into(), "push".into()],
            vec!["push".into(), "extra".into()],
            vec!["pr_checks".into(), "extra".into()],
            vec!["fetch".into(), "extra".into()],
            vec!["pr_create".into()],
            vec!["pr_create".into(), "t".into()],
            vec!["pr_create".into(), "t".into(), "b".into(), "c".into()],
            vec![OsString::from_vec(b"push\xff".to_vec())],
            vec![
                "pr_create".into(),
                "t".into(),
                OsString::from_vec(b"b\xff".to_vec()),
            ],
        ];
        for args in cases {
            let (ok, out, err) = broker_os(&rig.run_dir, Some("j1"), &args, WAIT).await;
            assert!(!ok, "{args:?}");
            assert_eq!(out, "", "{args:?}");
            assert_eq!(err, BROKER_USAGE, "{args:?}");
        }
        assert_eq!(rig.accepted.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_title_or_body_over_the_frame_cap_fails_with_the_fixed_line() -> TestResult {
        let rig = rig(framed(r#"{"status":"done","output":"x"}"#))?;
        let big = "a".repeat(MAX_FRAME_BYTES);
        let (ok, out, err) =
            broker(&rig.run_dir, Some("j1"), &["pr_create", "t", &big], WAIT).await;
        assert!(!ok);
        assert_eq!(out, "");
        assert_eq!(err, BROKER_FIXED);
        Ok(())
    }

    #[test]
    fn the_broker_failure_lines_are_fixed() {
        assert_eq!(BrokerFailure::Usage.to_string(), BROKER_USAGE.trim_end());
        assert_eq!(BrokerFailure::Failed.to_string(), BROKER_FIXED.trim_end());
    }
}
