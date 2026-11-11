//! The `GIT_ASKPASS` answer for the finish step's push.
//!
//! git runs the helper with the prompt as its only argument. The token comes from the
//! helper's own environment, never from argv, and nothing here logs or formats it. The
//! helper answers only when the prompt names the one host in [`HOST_ENV`], the Job repository
//! host with the token held for it. A job that points git at another host, even one in
//! `repo_hosts`, gets no token.

use std::ffi::OsStr;
use std::path::Path;

use fleet_core::host::HostName;

/// Environment variable that carries the one host the helper answers for.
pub const HOST_ENV: &str = "FLEETD_ASKPASS_HOST";

/// Environment variable that makes the fleetd binary answer as the askpass helper.
pub const MARKER_ENV: &str = "FLEETD_ASKPASS";

/// The variables that make git run `bin` as its askpass helper.
///
/// `GIT_ASKPASS` is the bare path, which git execs without a shell and so cannot carry a
/// subcommand. [`MARKER_ENV`] tells the binary to treat its one argument as the prompt.
#[must_use]
pub fn env(bin: &Path) -> [(&'static str, &OsStr); 2] {
    [
        ("GIT_ASKPASS", bin.as_os_str()),
        (MARKER_ENV, OsStr::new("1")),
    ]
}

/// The fixed username GitHub accepts for a token over https.
pub const USERNAME: &str = "x-access-token";

/// The host a git credential prompt names, from its quoted `https` url, normalised.
///
/// The url must be printable ASCII with no backslash. Its authority holds no port, no
/// trailing dot and no userinfo other than [`USERNAME`], the one git adds itself after the
/// username answer. Anything else names no host, so `https://github.com@other.example` and
/// `https://other.example\\@github.com` get no token.
fn prompt_host(prompt: &str) -> Option<HostName> {
    let start = prompt.find('\'')? + 1;
    let end = start + prompt[start..].rfind('\'')?;
    let rest = prompt[start..end].strip_prefix("https://")?;
    if !rest.bytes().all(|b| b.is_ascii_graphic() && b != b'\\') {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = match authority.split_once('@') {
        Some((USERNAME, host)) => host,
        Some(_) => return None,
        None => authority,
    };
    if host.ends_with('.') || host.contains('@') {
        return None;
    }
    HostName::normalise(host).ok()
}

/// The text to print for `prompt`, or `None` when it is not a credential prompt, it does
/// not name `token_host`, `token_host` is empty or not a plain host name, or the token is
/// missing or empty.
#[must_use]
pub fn answer(prompt: &str, token: Option<&str>, token_host: &str) -> Option<String> {
    let wanted = if token_host.ends_with('.') {
        None
    } else {
        HostName::normalise(token_host).ok()
    }?;
    if prompt_host(prompt)? != wanted {
        None
    } else if prompt.starts_with("Username") {
        Some(USERNAME.to_owned())
    } else if prompt.starts_with("Password") {
        token.filter(|t| !t.is_empty()).map(str::to_owned)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "github.com";

    #[test]
    fn a_password_prompt_gets_the_token() {
        let prompt = "Password for 'https://x-access-token@github.com': ";
        assert_eq!(answer(prompt, Some("tok"), HOST).as_deref(), Some("tok"));
    }

    #[test]
    fn a_username_prompt_gets_the_fixed_username() {
        let prompt = "Username for 'https://github.com': ";
        assert_eq!(answer(prompt, Some("tok"), HOST).as_deref(), Some(USERNAME));
        assert_eq!(answer(prompt, None, HOST).as_deref(), Some(USERNAME));
    }

    #[test]
    fn anything_else_gets_nothing() {
        let host = "for 'https://github.com': ";
        assert_eq!(answer("Passphrase for key: ", Some("tok"), HOST), None);
        assert_eq!(answer("", Some("tok"), HOST), None);
        assert_eq!(answer("Enter token", Some("tok"), HOST), None);
        assert_eq!(answer(&format!("Other {host}"), Some("tok"), HOST), None);
    }

    #[test]
    fn a_missing_or_empty_token_gets_nothing() {
        let prompt = "Password for 'https://github.com': ";
        assert_eq!(answer(prompt, None, HOST), None);
        assert_eq!(answer(prompt, Some(""), HOST), None);
    }

    #[test]
    fn a_prompt_naming_another_host_gets_nothing() {
        let prompts = [
            "Password for 'https://attacker.example': ",
            "Username for 'https://attacker.example': ",
            "Password for 'https://x-access-token@attacker.example': ",
            "Password for 'https://github.com@attacker.example': ",
            "Password for 'https://github.com.attacker.example': ",
            "Password for 'https://attacker.example/github.com': ",
            "Password for 'https://github.com:8443': ",
            "Password for 'http://github.com': ",
            "Password for 'ssh://github.com': ",
            "Password for 'github.com': ",
            "Password for : ",
            "Password for 'https://': ",
            "Password for 'https://github.com'@attacker.example': ",
        ];
        for prompt in prompts {
            assert_eq!(answer(prompt, Some("tok"), HOST), None, "{prompt}");
        }
    }

    const FORGEJO: &str = "git.example.org";

    #[test]
    fn hostile_prompts_never_get_a_token_for_a_forgejo_host() {
        let ok = [
            "Password for 'https://git.example.org': ",
            "Password for 'https://git.example.org/o/r.git': ",
            "Password for 'https://x-access-token@git.example.org': ",
            "Password for 'https://x-access-token@GIT.Example.ORG/o/r': ",
            "Username for 'https://git.example.org': ",
        ];
        for prompt in ok {
            assert!(answer(prompt, Some("tok"), FORGEJO).is_some(), "{prompt}");
        }
        let hostile = [
            "Password for 'https://git.example.org.evil.example': ",
            "Password for 'https://evil.example@git.example.org': ",
            "Password for 'https://x-access-token:pw@git.example.org': ",
            "Password for 'https://@git.example.org': ",
            "Password for 'https://a@b@git.example.org': ",
            "Password for 'https://git.example.org@evil.example': ",
            "Password for 'https://evil.example\\@git.example.org': ",
            "Password for 'https://git.example.org.': ",
            "Password for 'https://git.example.org:443': ",
            "Password for 'https://git.example.org:8443/o/r': ",
            "Password for 'https://git.example.org\r\n': ",
            "Password for 'https://git.example.org\n@evil.example': ",
            "Password for 'https://git.example.org\t': ",
            "Password for 'https://git.example.org evil.example': ",
            "Password for 'https://git.ex\u{e4}mple.org': ",
            "Password for 'https://\u{ff47}it.example.org': ",
            "Password for 'https://': ",
            "Password for 'https://[::1]': ",
            "Password for 'https://10.0.0.1': ",
            "Password for 'http://git.example.org': ",
            "Password for 'https://github.com': ",
        ];
        for prompt in hostile {
            assert_eq!(answer(prompt, Some("tok"), FORGEJO), None, "{prompt:?}");
        }
    }

    #[test]
    fn a_hostile_token_host_answers_nothing() {
        let prompt = "Password for 'https://git.example.org': ";
        for host in [
            "",
            "git.example.org.",
            "git.example.org:443",
            "x@git.example.org",
            "git.example.org\n",
            "git.ex\u{e4}mple.org",
        ] {
            assert_eq!(answer(prompt, Some("tok"), host), None, "{host:?}");
        }
    }

    #[test]
    fn only_the_token_host_gets_the_token() {
        let gitlab = "Password for 'https://gitlab.com/o/r.git': ";
        assert_eq!(answer(gitlab, Some("tok"), HOST), None);
        assert_eq!(
            answer("Username for 'https://gitlab.com': ", Some("tok"), HOST),
            None
        );
        assert_eq!(
            answer(gitlab, Some("tok"), "gitlab.com").as_deref(),
            Some("tok")
        );
        let github = "Password for 'https://github.com/o/r.git': ";
        assert_eq!(answer(github, Some("tok"), "gitlab.com"), None);
    }

    #[test]
    fn an_empty_token_host_answers_nothing() {
        let prompt = "Password for 'https://github.com': ";
        assert_eq!(answer(prompt, Some("tok"), ""), None);
        assert_eq!(answer("Password for 'https://': ", Some("tok"), ""), None);
    }

    #[test]
    fn the_host_match_ignores_case_and_userinfo_on_the_token_host() {
        let prompt = "Password for 'https://x-access-token@GitHub.com/org/repo.git': ";
        assert_eq!(answer(prompt, Some("tok"), HOST).as_deref(), Some("tok"));
        let other = "Password for 'https://x@GitHub.com/org/repo.git': ";
        assert_eq!(answer(other, Some("tok"), HOST), None);
    }

    #[test]
    fn the_env_passes_the_binary_path_unquoted_with_the_marker() {
        let bin = Path::new("/it's a/fleetd");
        assert_eq!(
            env(bin),
            [
                ("GIT_ASKPASS", OsStr::new("/it's a/fleetd")),
                (MARKER_ENV, OsStr::new("1"))
            ]
        );
    }
}
