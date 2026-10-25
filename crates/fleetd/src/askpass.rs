//! The `GIT_ASKPASS` answer for the finish step's push.
//!
//! git runs the helper with the prompt as its only argument. The token comes from the
//! helper's own environment, never from argv, and nothing here logs or formats it. The
//! helper answers only when the prompt names the one token host, so a job that points git at
//! another host, even one in `repo_hosts`, gets no token.

use std::path::Path;

/// Environment variable that carries the token host to the helper.
pub const HOST_ENV: &str = "FLEETD_ASKPASS_HOST";

/// The `GIT_ASKPASS` value that runs `<bin> askpass`, with `bin` shell-quoted.
#[must_use]
pub fn command(bin: &Path) -> String {
    format!("'{}' askpass", bin.to_string_lossy().replace('\'', "'\\''"))
}

/// The fixed username GitHub accepts for a token over https.
pub const USERNAME: &str = "x-access-token";

/// The host a git credential prompt names, from its quoted `https` url. Userinfo is
/// dropped at the last `@`, so `https://github.com@other.example` names `other.example`.
fn prompt_host(prompt: &str) -> Option<&str> {
    let start = prompt.find('\'')? + 1;
    let end = start + prompt[start..].rfind('\'')?;
    let rest = prompt[start..end].strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    authority.rsplit('@').next()
}

/// The text to print for `prompt`, or `None` when it is not a credential prompt, it does
/// not name `token_host`, `token_host` is empty, or the token is missing or empty.
#[must_use]
pub fn answer(prompt: &str, token: Option<&str>, token_host: &str) -> Option<String> {
    let named = prompt_host(prompt).is_some_and(|host| host.eq_ignore_ascii_case(token_host));
    if token_host.is_empty() || !named {
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
        let prompt = "Password for 'https://x@GitHub.com/org/repo.git': ";
        assert_eq!(answer(prompt, Some("tok"), HOST).as_deref(), Some("tok"));
    }

    #[test]
    fn the_command_quotes_the_binary_path() {
        assert_eq!(command(Path::new("/a b/fleetd")), "'/a b/fleetd' askpass");
        assert_eq!(
            command(Path::new("/it's/fleetd")),
            "'/it'\\''s/fleetd' askpass"
        );
    }
}
