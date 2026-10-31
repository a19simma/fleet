//! Startup check of the installed managed settings for dead `http` hooks.
//!
//! Jobs run in a namespace that cannot reach the loopback hook port, so an `http` hook there
//! never fires. A hand-installed copy from before the command hooks can still hold them. The
//! check only logs: any failure to read or parse the file is its own line and never blocks
//! startup.

use std::io::Read;
use std::path::Path;

/// The installed managed settings path.
pub const DEFAULT_PATH: &str = "/etc/claude-code/managed-settings.json";

/// What the check found in the managed settings file.
#[derive(Debug, PartialEq, Eq)]
pub enum Finding {
    /// The file parses and holds no `http` hook.
    Clean,
    /// The file parses and holds this many `http` hooks.
    HttpHooks(usize),
    /// No file at the path.
    Missing,
    /// The file exists and could not be read.
    Unreadable,
    /// The file is not valid JSON.
    Invalid,
}

/// The most bytes read from the file.
const MAX_BYTES: usize = 1024 * 1024;

/// Inspects the managed settings file at `path` without logging.
#[must_use]
pub fn inspect(path: &Path) -> Finding {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Finding::Missing,
        Err(_) => return Finding::Unreadable,
    };
    let mut bytes = Vec::new();
    if file
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
        || bytes.len() > MAX_BYTES
    {
        return Finding::Unreadable;
    }
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Finding::Invalid;
    };
    match root.get("hooks").map_or(0, count_http) {
        0 => Finding::Clean,
        n => Finding::HttpHooks(n),
    }
}

fn count_http(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Object(map) => {
            let own = map
                .get("type")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|kind| kind.eq_ignore_ascii_case("http"));
            usize::from(own) + map.values().map(count_http).sum::<usize>()
        }
        serde_json::Value::Array(items) => items.iter().map(count_http).sum(),
        _ => 0,
    }
}

/// Logs one line for the managed settings file at `path`: a warning when it holds `http` hooks.
pub fn audit(path: &Path) {
    match inspect(path) {
        Finding::Clean => tracing::info!("managed settings hold no http hooks"),
        Finding::HttpHooks(count) => tracing::warn!(
            count,
            "managed settings hold http hooks that never fire in a job namespace; reinstall deploy/managed-settings.json"
        ),
        Finding::Missing => tracing::info!("managed settings not installed"),
        Finding::Unreadable => {
            tracing::warn!("managed settings unreadable, http hooks not checked");
        }
        Finding::Invalid => {
            tracing::warn!("managed settings are not valid json, the CLI will not start");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    use tempfile::TempDir;

    use super::*;

    fn write(dir: &TempDir, text: &str) -> std::path::PathBuf {
        let path = dir.path().join("managed-settings.json");
        std::fs::write(&path, text).unwrap();
        path
    }

    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .map_err(|_| std::io::Error::other("poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    fn logged(path: &Path) -> String {
        let sink = Sink::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || audit(path));
        String::from_utf8(sink.0.lock().unwrap().clone()).unwrap()
    }

    const HTTP: &str = r#"{"hooks":{"PostToolUse":[{"matcher":"","hooks":[{"type":"http","url":"http://127.0.0.1:7071/x"}]}]}}"#;
    const COMMAND: &str =
        r#"{"hooks":{"PostToolUse":[{"hooks":[{"type":"command","command":"fleetd hook x"}]}]}}"#;

    #[test]
    fn an_http_hook_is_found_and_warned() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, HTTP);
        assert_eq!(inspect(&path), Finding::HttpHooks(1));
        let out = logged(&path);
        assert!(out.contains("WARN") && out.contains("http hooks"), "{out}");
    }

    #[test]
    fn a_command_only_file_is_clean_and_does_not_warn() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, COMMAND);
        assert_eq!(inspect(&path), Finding::Clean);
        let out = logged(&path);
        assert!(!out.contains("WARN"), "{out}");
    }

    #[test]
    fn a_missing_file_has_its_own_line() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("absent.json");
        assert_eq!(inspect(&path), Finding::Missing);
        let out = logged(&path);
        assert!(
            out.contains("not installed") && !out.contains("http hooks"),
            "{out}"
        );
    }

    #[test]
    fn an_unreadable_path_has_its_own_line() {
        let dir = TempDir::new().unwrap();
        assert_eq!(inspect(dir.path()), Finding::Unreadable);
        let out = logged(dir.path());
        assert!(out.contains("WARN") && out.contains("unreadable"), "{out}");
    }

    #[test]
    fn invalid_json_has_its_own_line() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, "{\"hooks\": [");
        assert_eq!(inspect(&path), Finding::Invalid);
        let out = logged(&path);
        assert!(
            out.contains("WARN") && out.contains("not valid json"),
            "{out}"
        );
    }

    #[test]
    fn hostile_nesting_and_case_count_every_http_hook() {
        let dir = TempDir::new().unwrap();
        let text = r#"{"hooks":{
            "Stop":[{"hooks":[{"type":"HTTP"},{"type":"command"}]}],
            "SessionStart":[{"hooks":[{"type":"Http"}]},{"hooks":[{"type":"http"}]}],
            "Deep":[[{"a":{"b":[{"type":"hTTp"}]}}]]
        },"env":{"type":"http"}}"#;
        let path = write(&dir, text);
        assert_eq!(inspect(&path), Finding::HttpHooks(4));
    }

    #[test]
    fn a_file_over_the_cap_is_unreadable_and_one_at_the_cap_parses() {
        let dir = TempDir::new().unwrap();
        let pad = |n: usize| format!("{{}}{}", " ".repeat(n - 2));
        let path = write(&dir, &pad(MAX_BYTES));
        assert_eq!(inspect(&path), Finding::Clean);
        let path = write(&dir, &pad(MAX_BYTES + 1));
        assert_eq!(inspect(&path), Finding::Unreadable);
    }

    #[test]
    fn a_non_string_type_and_a_non_object_root_are_clean() {
        let dir = TempDir::new().unwrap();
        let path = write(&dir, r#"{"hooks":{"Stop":[{"type":1},{"type":null}]}}"#);
        assert_eq!(inspect(&path), Finding::Clean);
        let path = write(&dir, "[1,2]");
        assert_eq!(inspect(&path), Finding::Clean);
    }
}
