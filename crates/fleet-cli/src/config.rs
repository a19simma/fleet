//! Server URL, token and TLS settings for the client.

use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use tonic::codegen::http::Uri;

/// Environment variable holding the client bearer token.
pub const TOKEN_VAR: &str = "FLEET_CLIENT_TOKEN";
/// Environment variable holding the server URL.
pub const SERVER_VAR: &str = "FLEET_SERVER_URL";
/// Environment variable holding the path of an extra CA certificate in PEM form.
pub const CA_VAR: &str = "FLEET_CA_CERT";
/// Environment variable that set to `1` allows plain http to a non-loopback host.
pub const INSECURE_VAR: &str = "FLEET_INSECURE";
/// Environment variable that overrides the base directory of the token file.
pub const XDG_VAR: &str = "XDG_CONFIG_HOME";
/// Environment variable holding the home directory.
pub const HOME_VAR: &str = "HOME";

/// A configuration error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// A required variable, flag or token file is unset or empty.
    Missing(&'static str),
    /// The server URL is not an http or https URL with a host.
    InvalidServer,
    /// Plain http to a non-loopback host while a token is set, without `--insecure`.
    InsecureHttp,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "{name} is not set"),
            Self::InvalidServer => write!(f, "server URL must be an http or https URL"),
            Self::InsecureHttp => write!(
                f,
                "refusing to send the token over plain http to a non-loopback host; \
                 use https or pass --insecure"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Client settings. `Debug` hides the token.
#[derive(Clone)]
pub struct Config {
    /// Server URL, `http://` or `https://`.
    pub server: String,
    /// Optional CA certificate file for `https://` servers.
    pub ca_cert: Option<PathBuf>,
    tls: bool,
    token: String,
    token_warning: Option<String>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.filter(|v| !v.trim().is_empty())
}

/// Path of the token file: `$XDG_CONFIG_HOME/fleet/token`, else `$HOME/.config/fleet/token`.
pub fn token_path(lookup: &impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let base = match non_empty(lookup(XDG_VAR)) {
        Some(xdg) => PathBuf::from(xdg),
        None => PathBuf::from(non_empty(lookup(HOME_VAR))?).join(".config"),
    };
    Some(base.join("fleet").join("token"))
}

struct TokenFile {
    token: String,
    warning: Option<String>,
}

#[cfg(unix)]
fn permissive_mode_warning(path: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).ok()?.permissions().mode();
    (mode & 0o077 != 0).then(|| {
        format!(
            "token file {} is accessible by group or other (mode {:03o}); run chmod 600 on it",
            path.display(),
            mode & 0o777
        )
    })
}

#[cfg(not(unix))]
fn permissive_mode_warning(_: &std::path::Path) -> Option<String> {
    None
}

fn read_token_file(lookup: &impl Fn(&str) -> Option<String>) -> Option<TokenFile> {
    let path = token_path(lookup)?;
    let text = std::fs::read_to_string(&path).ok()?;
    let token = non_empty(text.lines().next().map(|l| l.trim().to_owned()))?;
    Some(TokenFile {
        token,
        warning: permissive_mode_warning(&path),
    })
}

fn is_loopback_host(host: &str) -> bool {
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.eq_ignore_ascii_case("localhost") {
        return true;
    }
    bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

impl Config {
    /// Builds a config from the `--server` and `--insecure` flags and a variable lookup.
    ///
    /// The token comes from `FLEET_CLIENT_TOKEN`, else the first line of the token file.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the server URL or token is missing, the URL is not
    /// http or https, or the URL is plain http to a non-loopback host without insecure mode.
    pub fn from_lookup(
        server_flag: Option<String>,
        insecure_flag: bool,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Self, ConfigError> {
        let server = non_empty(server_flag)
            .or_else(|| non_empty(lookup(SERVER_VAR)))
            .ok_or(ConfigError::Missing(SERVER_VAR))?;
        let (token, token_warning) = if let Some(env_token) = non_empty(lookup(TOKEN_VAR)) {
            (env_token.trim().to_owned(), None)
        } else {
            let file = read_token_file(&lookup).ok_or(ConfigError::Missing(TOKEN_VAR))?;
            (file.token, file.warning)
        };
        let ca_cert = non_empty(lookup(CA_VAR)).map(PathBuf::from);
        let insecure = insecure_flag || lookup(INSECURE_VAR).as_deref() == Some("1");
        let uri: Uri = server.parse().map_err(|_| ConfigError::InvalidServer)?;
        let host = uri.host().ok_or(ConfigError::InvalidServer)?;
        let scheme = uri.scheme_str().ok_or(ConfigError::InvalidServer)?;
        let tls = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            if !insecure && !is_loopback_host(host) {
                return Err(ConfigError::InsecureHttp);
            }
            false
        } else {
            return Err(ConfigError::InvalidServer);
        };
        Ok(Self {
            server,
            ca_cert,
            tls,
            token,
            token_warning,
        })
    }

    /// Whether the server URL uses https.
    pub(crate) fn uses_tls(&self) -> bool {
        self.tls
    }

    /// A warning about the token file, set when the token came from a file that group or
    /// other users can access.
    pub fn token_warning(&self) -> Option<&str> {
        self.token_warning.as_deref()
    }

    /// The `authorization` header value for requests.
    pub(crate) fn bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("server", &self.server)
            .field("ca_cert", &self.ca_cert)
            .field("tls", &self.tls)
            .field("token", &"[REDACTED]")
            .field("token_warning", &self.token_warning)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn debug_redacts_the_token() -> TestResult {
        let config = Config::from_lookup(
            None,
            false,
            env(&[
                (TOKEN_VAR, "tok-super-secret"),
                (SERVER_VAR, "http://localhost:1"),
            ]),
        )?;
        let shown = format!("{config:?}");
        assert!(!shown.contains("tok-super-secret"));
        assert!(shown.contains("[REDACTED]"));
        Ok(())
    }

    #[test]
    fn flag_beats_env() -> TestResult {
        let config = Config::from_lookup(
            Some("http://127.0.0.1:2".into()),
            false,
            env(&[(TOKEN_VAR, "t"), (SERVER_VAR, "http://127.0.0.1:1")]),
        )?;
        assert_eq!(config.server, "http://127.0.0.1:2");
        Ok(())
    }

    #[test]
    fn missing_token_is_an_error() {
        let err = Config::from_lookup(
            None,
            false,
            env(&[
                (SERVER_VAR, "http://localhost:1"),
                (HOME_VAR, "/nonexistent-home"),
            ]),
        )
        .err();
        assert_eq!(err, Some(ConfigError::Missing(TOKEN_VAR)));
    }

    #[test]
    fn token_file_is_the_fallback_and_first_line_is_trimmed() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("fleet");
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join("token"), "  file-token  \nsecond line\n")?;
        let base = dir.path().to_str().ok_or("utf8")?;
        let config = Config::from_lookup(
            None,
            false,
            env(&[(SERVER_VAR, "http://localhost:1"), (XDG_VAR, base)]),
        )?;
        assert_eq!(config.bearer(), "Bearer file-token");
        Ok(())
    }

    #[test]
    fn token_file_falls_back_to_home_config() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join(".config").join("fleet");
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join("token"), "home-token\n")?;
        let base = dir.path().to_str().ok_or("utf8")?;
        let config = Config::from_lookup(
            None,
            false,
            env(&[(SERVER_VAR, "http://localhost:1"), (HOME_VAR, base)]),
        )?;
        assert_eq!(config.bearer(), "Bearer home-token");
        Ok(())
    }

    #[test]
    fn env_token_beats_the_file() -> TestResult {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("fleet");
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join("token"), "file-token\n")?;
        let base = dir.path().to_str().ok_or("utf8")?;
        let config = Config::from_lookup(
            None,
            false,
            env(&[
                (SERVER_VAR, "http://localhost:1"),
                (XDG_VAR, base),
                (TOKEN_VAR, "env-token"),
            ]),
        )?;
        assert_eq!(config.bearer(), "Bearer env-token");
        Ok(())
    }

    #[test]
    fn env_token_is_trimmed_like_the_file() -> TestResult {
        let config = Config::from_lookup(
            None,
            false,
            env(&[(SERVER_VAR, "http://localhost:1"), (TOKEN_VAR, " tok\n")]),
        )?;
        assert_eq!(config.bearer(), "Bearer tok");
        Ok(())
    }

    #[cfg(unix)]
    fn file_config(mode: u32, with_env: bool) -> Result<Config, Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("fleet");
        std::fs::create_dir_all(&path)?;
        std::fs::write(path.join("token"), "file-token\n")?;
        std::fs::set_permissions(path.join("token"), std::fs::Permissions::from_mode(mode))?;
        let base = dir.path().to_str().ok_or("utf8")?;
        let mut pairs = vec![(SERVER_VAR, "http://localhost:1"), (XDG_VAR, base)];
        if with_env {
            pairs.push((TOKEN_VAR, "env-token"));
        }
        Ok(Config::from_lookup(None, false, env(&pairs))?)
    }

    #[cfg(unix)]
    #[test]
    fn token_file_with_group_or_other_bits_warns() -> TestResult {
        for mode in [0o644, 0o640, 0o604, 0o660, 0o601] {
            let warning = file_config(mode, false)?.token_warning().map(str::to_owned);
            let text = warning.ok_or("expected a warning")?;
            assert!(text.contains("chmod 600"), "{text}");
            assert!(!text.contains("file-token"), "{text}");
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn private_token_file_and_env_token_do_not_warn() -> TestResult {
        assert_eq!(file_config(0o600, false)?.token_warning(), None);
        assert_eq!(file_config(0o400, false)?.token_warning(), None);
        assert_eq!(file_config(0o644, true)?.token_warning(), None);
        Ok(())
    }

    #[test]
    fn plain_http_to_a_remote_host_is_refused() {
        for url in [
            "http://example.com",
            "HTTP://example.com:80",
            "http://10.1.2.3:7070",
        ] {
            let err = Config::from_lookup(Some(url.into()), false, env(&[(TOKEN_VAR, "t")])).err();
            assert_eq!(err, Some(ConfigError::InsecureHttp), "{url}");
        }
    }

    #[test]
    fn insecure_flag_or_env_allows_plain_http() -> TestResult {
        Config::from_lookup(
            Some("http://example.com".into()),
            true,
            env(&[(TOKEN_VAR, "t")]),
        )?;
        Config::from_lookup(
            Some("HTTP://example.com".into()),
            false,
            env(&[(TOKEN_VAR, "t"), (INSECURE_VAR, "1")]),
        )?;
        Ok(())
    }

    #[test]
    fn loopback_hosts_and_https_need_no_insecure() -> TestResult {
        for url in [
            "http://127.0.0.1:1",
            "http://127.9.9.9:1",
            "http://[::1]:1",
            "http://localhost:1",
            "HTTP://LOCALHOST:1",
            "https://example.com",
            "HTTPS://example.com",
        ] {
            Config::from_lookup(Some(url.into()), false, env(&[(TOKEN_VAR, "t")]))?;
        }
        Ok(())
    }

    #[test]
    fn https_is_detected_case_insensitively() -> TestResult {
        let config = Config::from_lookup(
            Some("HTTPS://example.com".into()),
            false,
            env(&[(TOKEN_VAR, "t")]),
        )?;
        assert!(config.uses_tls());
        Ok(())
    }

    #[test]
    fn non_http_schemes_are_invalid() {
        let err = Config::from_lookup(
            Some("ftp://example.com".into()),
            false,
            env(&[(TOKEN_VAR, "t")]),
        )
        .err();
        assert_eq!(err, Some(ConfigError::InvalidServer));
    }
}
