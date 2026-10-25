//! The `GIT_ASKPASS` answer for the finish step's push.
//!
//! git runs the helper with the prompt as its only argument. The token comes from the
//! helper's own environment, never from argv, and nothing here logs or formats it. The
//! helper answers only when the prompt names a host the [`RepoPolicy`] allows, so a job
//! that points git at another host gets no token.

use crate::workspace::RepoPolicy;

/// Environment variable that carries the allowed hosts to the helper, comma separated.
pub const HOSTS_ENV: &str = "FLEETD_ASKPASS_HOSTS";

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
/// not name a host `policy` allows, or the token is missing or empty.
#[must_use]
pub fn answer(prompt: &str, token: Option<&str>, policy: &RepoPolicy) -> Option<String> {
    if !prompt_host(prompt).is_some_and(|host| policy.allows_host(host)) {
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

    fn policy() -> RepoPolicy {
        RepoPolicy::new(["github.com"])
    }

    #[test]
    fn a_password_prompt_gets_the_token() {
        let prompt = "Password for 'https://x-access-token@github.com': ";
        assert_eq!(
            answer(prompt, Some("tok"), &policy()).as_deref(),
            Some("tok")
        );
    }

    #[test]
    fn a_username_prompt_gets_the_fixed_username() {
        let prompt = "Username for 'https://github.com': ";
        assert_eq!(
            answer(prompt, Some("tok"), &policy()).as_deref(),
            Some(USERNAME)
        );
        assert_eq!(answer(prompt, None, &policy()).as_deref(), Some(USERNAME));
    }

    #[test]
    fn anything_else_gets_nothing() {
        let host = "for 'https://github.com': ";
        assert_eq!(answer("Passphrase for key: ", Some("tok"), &policy()), None);
        assert_eq!(answer("", Some("tok"), &policy()), None);
        assert_eq!(answer("Enter token", Some("tok"), &policy()), None);
        assert_eq!(
            answer(&format!("Other {host}"), Some("tok"), &policy()),
            None
        );
    }

    #[test]
    fn a_missing_or_empty_token_gets_nothing() {
        let prompt = "Password for 'https://github.com': ";
        assert_eq!(answer(prompt, None, &policy()), None);
        assert_eq!(answer(prompt, Some(""), &policy()), None);
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
            assert_eq!(answer(prompt, Some("tok"), &policy()), None, "{prompt}");
        }
    }

    #[test]
    fn an_empty_policy_answers_nothing() {
        let prompt = "Password for 'https://github.com': ";
        assert_eq!(
            answer(prompt, Some("tok"), &RepoPolicy::new(Vec::<String>::new())),
            None
        );
    }

    #[test]
    fn the_host_match_ignores_case_and_userinfo_on_an_allowed_host() {
        let prompt = "Password for 'https://x@GitHub.com/org/repo.git': ";
        assert_eq!(
            answer(prompt, Some("tok"), &policy()).as_deref(),
            Some("tok")
        );
    }
}
