//! Content rules of a [`Profile`] that hold on every Floor (ADR-0034).

use std::collections::BTreeSet;
use std::fmt;

use crate::profile::{ContextFile, Profile};

/// Most entries in a Profile.
///
/// An entry is one [`ContextFile`] of `context_files` or one file of any skill. A skill itself,
/// `claude_md`, `prompt_prefix` and `prompt_template` are not entries. Mirrors the bundle
/// `MAX_ENTRIES` of fleetd.
pub const MAX_ENTRIES: usize = 64;

/// Most text bytes in a Profile, summed over `claude_md`, `prompt_prefix`, `prompt_template`,
/// every context file and every skill file. Mirrors the bundle `MAX_BYTES` of fleetd.
pub const MAX_TOTAL_BYTES: usize = 4 * 1024 * 1024;

/// Most text bytes in `claude_md`, one context file or one skill file.
pub const MAX_FILE_BYTES: usize = 256 * 1024;

/// Most bytes in a path or a skill name.
pub const MAX_PATH_BYTES: usize = 256;

/// Most bytes in one path component.
pub const MAX_COMPONENT_BYTES: usize = 64;

/// Most characters in a skill name.
pub const MAX_SKILL_NAME_LEN: usize = 64;

/// Most bytes in a model name.
pub const MAX_MODEL_BYTES: usize = 128;

/// Most entries in one allow or deny list.
pub const MAX_RULES: usize = 256;

/// Most bytes in one allow or deny rule.
pub const MAX_RULE_BYTES: usize = 256;

/// Largest accepted `max_turns`.
pub const MAX_TURNS: u32 = 1000;

/// Largest accepted `max_budget_usd`, in whole US cents.
pub const MAX_BUDGET_CENTS: u64 = 1_000_000;

/// Environment flag names a Profile may set.
///
/// A choice to confirm: the first two are the flags fleetd and the deploy docs already set for
/// the agent, the last two are Claude Code switches of the same kind.
pub const ENV_FLAG_ALLOWLIST: [&str; 4] = [
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    "DISABLE_TELEMETRY",
    "DISABLE_AUTOUPDATER",
    "DISABLE_NON_ESSENTIAL_MODEL_CALLS",
];

const CREDENTIAL_MARKERS: [&str; 10] = [
    ".credentials",
    ".claude/.credentials.json",
    "oauth",
    ".ssh",
    ".aws",
    ".netrc",
    ".gnupg",
    ".config/gh",
    "id_rsa",
    "id_ed25519",
];

const PROMPT_PLACEHOLDER: &str = "{prompt}";

/// Why a [`Profile`] failed [`Profile::validate`].
///
/// Messages are fixed and never echo the offending key, path, value or text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProfileInvalid {
    /// More than [`MAX_ENTRIES`] entries.
    TooManyEntries,
    /// Text adds up to more than [`MAX_TOTAL_BYTES`].
    TotalTooLarge,
    /// One file text is longer than [`MAX_FILE_BYTES`].
    FileTooLarge,
    /// A text field holds a NUL byte.
    NulByte,
    /// `model` or `settings.model` is empty, too long or holds a control character.
    Model,
    /// `max_turns` is outside 1 to [`MAX_TURNS`].
    MaxTurns,
    /// `max_budget_usd` is above [`MAX_BUDGET_CENTS`].
    Budget,
    /// A path or skill name breaks the path rules.
    Path,
    /// Two context files, two files of one skill or two skills share a path or name.
    Duplicate,
    /// `prompt_template` does not hold `{prompt}` exactly once with no other brace.
    Template,
    /// An allow or deny list or rule is empty, too long, too many or holds a control character.
    Rule,
    /// An allow or deny rule names an MCP tool.
    McpRule,
    /// A path or allow rule references a credential location.
    CredentialPath,
    /// An env flag name is not in [`ENV_FLAG_ALLOWLIST`].
    EnvName,
    /// `settings.model` is set and differs from `model`.
    ModelMismatch,
    /// A text field looks like it holds a secret.
    SecretLike,
}

impl fmt::Display for ProfileInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooManyEntries => "profile holds too many files",
            Self::TotalTooLarge => "profile text is too large",
            Self::FileTooLarge => "a profile file is too large",
            Self::NulByte => "profile text holds a NUL byte",
            Self::Model => "profile model name is not allowed",
            Self::MaxTurns => "profile max_turns is out of range",
            Self::Budget => "profile max_budget_usd is out of range",
            Self::Path => "a profile path or skill name is not allowed",
            Self::Duplicate => "a profile path or skill name is repeated",
            Self::Template => "profile prompt_template is not allowed",
            Self::Rule => "a profile permission rule is not allowed",
            Self::McpRule => "a profile permission rule names an MCP tool",
            Self::CredentialPath => "a profile path or rule references a credential location",
            Self::EnvName => "a profile env flag name is not allowed",
            Self::ModelMismatch => "profile settings.model differs from model",
            Self::SecretLike => "profile text looks like a secret",
        })
    }
}

impl std::error::Error for ProfileInvalid {}

fn has_control(text: &str) -> bool {
    text.chars().any(char::is_control)
}

fn valid_model(name: &str) -> bool {
    !name.is_empty() && name.len() <= MAX_MODEL_BYTES && !has_control(name)
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && !has_control(path)
        && !path.contains('\\')
        && path.split('/').all(|part| {
            !part.is_empty() && part.len() <= MAX_COMPONENT_BYTES && !part.starts_with('.')
        })
}

fn valid_skill_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_SKILL_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn names_credential(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    CREDENTIAL_MARKERS
        .iter()
        .any(|marker| lower.contains(marker))
}

fn check_rules(rules: &[String]) -> Result<(), ProfileInvalid> {
    if rules.len() > MAX_RULES {
        return Err(ProfileInvalid::Rule);
    }
    for rule in rules {
        if rule.is_empty() || rule.len() > MAX_RULE_BYTES || has_control(rule) {
            return Err(ProfileInvalid::Rule);
        }
        if rule.trim_start().to_ascii_lowercase().starts_with("mcp__") {
            return Err(ProfileInvalid::McpRule);
        }
    }
    Ok(())
}

fn is_b64url(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

fn run_len(bytes: &[u8], from: usize, pred: fn(u8) -> bool) -> usize {
    bytes
        .get(from..)
        .map_or(0, |rest| rest.iter().take_while(|b| pred(**b)).count())
}

fn has_prefixed(text: &str, prefix: &str, min: usize, pred: fn(u8) -> bool) -> bool {
    text.match_indices(prefix)
        .any(|(at, _)| run_len(text.as_bytes(), at + prefix.len(), pred) >= min)
}

fn has_jwt(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut covered = 0;
    for (start, _) in text.match_indices("eyJ") {
        if start < covered {
            continue;
        }
        let first = run_len(bytes, start, is_b64url);
        let first_end = start + first;
        covered = first_end;
        if first < 10 || bytes.get(first_end) != Some(&b'.') {
            continue;
        }
        let second_start = first_end + 1;
        let second = run_len(bytes, second_start, is_b64url);
        let second_end = second_start + second;
        if second < 10 || bytes.get(second_end) != Some(&b'.') {
            continue;
        }
        if run_len(bytes, second_end + 1, is_b64url) >= 10 {
            return true;
        }
    }
    false
}

fn secret_like(text: &str) -> bool {
    text.contains("github_pat_")
        || text.contains("-----BEGIN")
        || has_prefixed(text, "ghp_", 20, |b| b.is_ascii_alphanumeric())
        || has_prefixed(text, "sk-", 20, is_b64url)
        || has_prefixed(text, "AKIA", 16, |b| {
            b.is_ascii_uppercase() || b.is_ascii_digit()
        })
        || has_jwt(text)
}

impl Profile {
    fn files(&self) -> impl Iterator<Item = &ContextFile> {
        self.context_files
            .iter()
            .chain(self.skills.iter().flat_map(|skill| skill.files.iter()))
    }

    fn texts(&self) -> impl Iterator<Item = &str> {
        let attribution = self
            .settings
            .iter()
            .filter_map(|settings| settings.attribution.as_ref())
            .flat_map(|a| [a.commit.as_deref(), a.pr.as_deref()])
            .flatten();
        [
            self.claude_md.as_deref(),
            self.prompt_prefix.as_deref(),
            self.prompt_template.as_deref(),
        ]
        .into_iter()
        .flatten()
        .chain(self.files().map(|file| file.text.as_str()))
        .chain(attribution)
    }

    fn check_caps(&self) -> Result<(), ProfileInvalid> {
        if self.files().count() > MAX_ENTRIES {
            return Err(ProfileInvalid::TooManyEntries);
        }
        let file_texts = self
            .claude_md
            .iter()
            .map(String::as_str)
            .chain(self.files().map(|file| file.text.as_str()));
        if file_texts
            .into_iter()
            .any(|text| text.len() > MAX_FILE_BYTES)
        {
            return Err(ProfileInvalid::FileTooLarge);
        }
        let total: usize = [
            self.claude_md.as_deref(),
            self.prompt_prefix.as_deref(),
            self.prompt_template.as_deref(),
        ]
        .into_iter()
        .flatten()
        .map(str::len)
        .chain(self.files().map(|file| file.text.len()))
        .sum();
        if total > MAX_TOTAL_BYTES {
            return Err(ProfileInvalid::TotalTooLarge);
        }
        Ok(())
    }

    fn check_scalars(&self) -> Result<(), ProfileInvalid> {
        if let Some(model) = &self.model
            && !valid_model(model)
        {
            return Err(ProfileInvalid::Model);
        }
        if let Some(turns) = self.max_turns
            && !(1..=MAX_TURNS).contains(&turns)
        {
            return Err(ProfileInvalid::MaxTurns);
        }
        if self
            .max_budget_usd
            .is_some_and(|cents| cents > MAX_BUDGET_CENTS)
        {
            return Err(ProfileInvalid::Budget);
        }
        Ok(())
    }

    fn check_paths(&self) -> Result<(), ProfileInvalid> {
        let mut seen = BTreeSet::new();
        for file in &self.context_files {
            check_path(&file.path)?;
            if !seen.insert(file.path.as_str()) {
                return Err(ProfileInvalid::Duplicate);
            }
        }
        let mut names = BTreeSet::new();
        for skill in &self.skills {
            if !valid_skill_name(&skill.name) {
                return Err(ProfileInvalid::Path);
            }
            if names_credential(&skill.name) {
                return Err(ProfileInvalid::CredentialPath);
            }
            if !names.insert(skill.name.as_str()) {
                return Err(ProfileInvalid::Duplicate);
            }
            let mut files = BTreeSet::new();
            for file in &skill.files {
                check_path(&file.path)?;
                if !files.insert(file.path.as_str()) {
                    return Err(ProfileInvalid::Duplicate);
                }
            }
        }
        Ok(())
    }

    fn check_rules(&self) -> Result<(), ProfileInvalid> {
        check_rules(&self.allow)?;
        check_rules(&self.deny)?;
        if self.allow.iter().any(|rule| names_credential(rule)) {
            return Err(ProfileInvalid::CredentialPath);
        }
        let Some(settings) = &self.settings else {
            return Ok(());
        };
        if let Some(permissions) = &settings.permissions {
            check_rules(&permissions.allow)?;
            check_rules(&permissions.deny)?;
            if permissions.allow.iter().any(|rule| names_credential(rule)) {
                return Err(ProfileInvalid::CredentialPath);
            }
        }
        if let Some(model) = &settings.model {
            if !valid_model(model) {
                return Err(ProfileInvalid::Model);
            }
            if self.model.as_deref() != Some(model.as_str()) {
                return Err(ProfileInvalid::ModelMismatch);
            }
        }
        Ok(())
    }

    fn check_template(&self) -> Result<(), ProfileInvalid> {
        let Some(template) = &self.prompt_template else {
            return Ok(());
        };
        let braces = template
            .bytes()
            .filter(|b| matches!(b, b'{' | b'}'))
            .count();
        if template.matches(PROMPT_PLACEHOLDER).count() != 1 || braces != 2 {
            return Err(ProfileInvalid::Template);
        }
        Ok(())
    }

    fn check_text(&self) -> Result<(), ProfileInvalid> {
        if self.texts().any(|text| text.contains('\0')) {
            return Err(ProfileInvalid::NulByte);
        }
        if self.texts().any(secret_like) {
            return Err(ProfileInvalid::SecretLike);
        }
        Ok(())
    }

    /// Checks the content rules of ADR-0034 that hold on every Floor.
    ///
    /// Checked, in this order:
    ///
    /// - Caps: at most [`MAX_ENTRIES`] entries (a context file or a skill file), at most
    ///   [`MAX_TOTAL_BYTES`] text bytes over `claude_md`, `prompt_prefix`, `prompt_template` and
    ///   every file, and at most [`MAX_FILE_BYTES`] for `claude_md` and each file.
    /// - Scalars: `model` is non-empty, at most [`MAX_MODEL_BYTES`] bytes, with no control
    ///   character; `max_turns` is 1 to [`MAX_TURNS`]; `max_budget_usd` (whole US cents) is at
    ///   most [`MAX_BUDGET_CENTS`].
    /// - Paths: a context file path and a skill file path are relative, use `/` only, have no
    ///   control character, no empty component, no component starting with `.` (so no `.` and
    ///   no `..`), at most [`MAX_PATH_BYTES`] bytes and [`MAX_COMPONENT_BYTES`] per component. A
    ///   skill name is one component of `[A-Za-z0-9_-]` up to [`MAX_SKILL_NAME_LEN`] characters.
    ///   Paths are unique among context files and within one skill, and skill names are unique.
    ///   Only syntax is checked here: refusing symlinks is the job of the code that writes the
    ///   files to disk.
    /// - Rules: allow and deny lists, top level and in `settings.permissions`, hold at most
    ///   [`MAX_RULES`] entries of 1 to [`MAX_RULE_BYTES`] bytes with no control character, and no
    ///   entry starts with `mcp__`. Settings carry only `permissions` (allow and deny),
    ///   `model` and `attribution`: the typed form already rejects `defaultMode`, `hooks`,
    ///   `mcp`, `mcpServers` and any other key when parsed with [`Profile::from_json`].
    /// - Model: `settings.model`, when set, equals `model`.
    /// - Credentials: no path, skill name or allow rule contains, ignoring ASCII case, one of
    ///   `.credentials`, `.claude/.credentials.json`, `oauth`, `.ssh`, `.aws`, `.netrc`,
    ///   `.gnupg`, `.config/gh`, `id_rsa` or `id_ed25519`. This is a best-effort lint, not a
    ///   guarantee.
    /// - Env: every `env_flags` name is in [`ENV_FLAG_ALLOWLIST`]. Values are `"0"` or `"1"` by
    ///   type.
    /// - Template: `prompt_template` holds `{prompt}` once and no other `{` or `}`.
    /// - Text: no NUL byte, and no text that looks like a secret: `ghp_` plus 20 alphanumerics,
    ///   `github_pat_`, `sk-` plus 20 of `[A-Za-z0-9_-]`, `-----BEGIN`, `AKIA` plus 16 uppercase
    ///   alphanumerics, or a JWT shape. This is a best-effort lint, not a guarantee. It covers
    ///   the text fields and the attribution text.
    ///
    /// Neither the hash nor the canonical form changes.
    ///
    /// # Errors
    ///
    /// Returns the first rule that fails as a [`ProfileInvalid`] with a fixed message.
    pub fn validate(&self) -> Result<(), ProfileInvalid> {
        self.check_caps()?;
        self.check_scalars()?;
        self.check_paths()?;
        self.check_rules()?;
        for name in self.env_flags.keys() {
            if !ENV_FLAG_ALLOWLIST.contains(&name.as_str()) {
                return Err(ProfileInvalid::EnvName);
            }
        }
        self.check_template()?;
        self.check_text()
    }
}

fn check_path(path: &str) -> Result<(), ProfileInvalid> {
    if !valid_path(path) {
        return Err(ProfileInvalid::Path);
    }
    if names_credential(path) {
        return Err(ProfileInvalid::CredentialPath);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{Attribution, ProfileError, Settings, SettingsPermissions, Skill};
    use serde_json::json;

    const MARK: &str = "zqxjmarkerkvw";

    fn parse(value: &serde_json::Value) -> Profile {
        Profile::from_json(value.to_string().as_bytes()).unwrap()
    }

    fn reject(value: &serde_json::Value) -> ProfileInvalid {
        let err = parse(value).validate().unwrap_err();
        assert!(!err.to_string().contains(MARK), "{err}");
        assert!(!format!("{err:?}").contains(MARK), "{err:?}");
        err
    }

    fn ok(value: &serde_json::Value) {
        assert_eq!(parse(value).validate(), Ok(()));
    }

    fn files(n: usize) -> serde_json::Value {
        let list: Vec<_> = (0..n)
            .map(|i| json!({"path": format!("f{i}.md"), "text": "x"}))
            .collect();
        json!(list)
    }

    fn text(n: usize) -> String {
        "a".repeat(n)
    }

    #[test]
    fn rich_profile_accepted() {
        let value = json!({
            "claude_md": "# hi",
            "context_files": [{"path": "docs/a.md", "text": "A"}],
            "prompt_prefix": "pre",
            "prompt_template": "do {prompt} now",
            "skills": [{"name": "my-skill_1", "files": [{"path": "SKILL.md", "text": "x"}]}],
            "allow": ["Read", "Bash(git status)"],
            "deny": ["Bash(rm:*)"],
            "model": "sonnet",
            "max_turns": 1000,
            "max_budget_usd": 1_000_000,
            "env_flags": {"DISABLE_TELEMETRY": "1", "DISABLE_AUTOUPDATER": "0"},
            "settings": {
                "permissions": {"allow": ["Read"], "deny": ["Edit"]},
                "model": "sonnet",
                "attribution": {"commit": "c", "pr": "p"}
            }
        });
        let profile = parse(&value);
        assert_eq!(profile.validate(), Ok(()));
        let hash = profile.hash();
        assert_eq!(profile.canonical_json(), parse(&value).canonical_json());
        assert_eq!(profile.hash(), hash);
        ok(&json!({}));
    }

    #[test]
    fn entries_cap_boundary() {
        ok(&json!({"context_files": files(64)}));
        assert_eq!(
            reject(&json!({"context_files": files(65)})),
            ProfileInvalid::TooManyEntries
        );
        let skill = |n| json!([{"name": "s", "files": files(n)}]);
        ok(&json!({"skills": skill(64)}));
        assert_eq!(
            reject(&json!({"skills": skill(65)})),
            ProfileInvalid::TooManyEntries
        );
        assert_eq!(
            reject(&json!({"context_files": files(33), "skills": skill(32)})),
            ProfileInvalid::TooManyEntries
        );
        ok(&json!({"context_files": files(32), "skills": skill(32)}));
    }

    #[test]
    fn per_file_cap_boundary() {
        let file = |n| json!([{"path": "a.md", "text": text(n)}]);
        ok(&json!({"context_files": file(MAX_FILE_BYTES)}));
        assert_eq!(
            reject(&json!({"context_files": file(MAX_FILE_BYTES + 1)})),
            ProfileInvalid::FileTooLarge
        );
        let skill = |n| json!([{"name": "s", "files": file(n)}]);
        assert_eq!(
            reject(&json!({"skills": skill(MAX_FILE_BYTES + 1)})),
            ProfileInvalid::FileTooLarge
        );
        ok(&json!({"claude_md": text(MAX_FILE_BYTES)}));
        assert_eq!(
            reject(&json!({"claude_md": text(MAX_FILE_BYTES + 1)})),
            ProfileInvalid::FileTooLarge
        );
    }

    #[test]
    fn total_cap_boundary() {
        let full: Vec<_> = (0..16)
            .map(|i| json!({"path": format!("f{i}.md"), "text": text(MAX_FILE_BYTES)}))
            .collect();
        ok(&json!({"context_files": full}));
        assert_eq!(
            reject(&json!({"context_files": full, "prompt_prefix": "x"})),
            ProfileInvalid::TotalTooLarge
        );
        assert_eq!(
            reject(&json!({"context_files": full, "prompt_template": "{prompt}"})),
            ProfileInvalid::TotalTooLarge
        );
        let half: Vec<_> = full.iter().take(15).cloned().collect();
        ok(&json!({"context_files": half, "claude_md": text(MAX_FILE_BYTES)}));
        assert_eq!(
            reject(
                &json!({"context_files": half, "claude_md": text(MAX_FILE_BYTES), "prompt_prefix": "x"})
            ),
            ProfileInvalid::TotalTooLarge
        );
    }

    #[test]
    fn nul_byte_rejected() {
        for value in [
            json!({"claude_md": format!("{MARK}\u{0}")}),
            json!({"prompt_prefix": "a\u{0}"}),
            json!({"prompt_template": "{prompt}\u{0}"}),
            json!({"context_files": [{"path": "a", "text": "\u{0}"}]}),
            json!({"skills": [{"name": "s", "files": [{"path": "a", "text": "\u{0}"}]}]}),
        ] {
            assert_eq!(reject(&value), ProfileInvalid::NulByte);
        }
    }

    #[test]
    fn model_rules() {
        ok(&json!({"model": text(128)}));
        for bad in [String::new(), text(129), format!("{MARK}\n")] {
            assert_eq!(reject(&json!({"model": bad})), ProfileInvalid::Model);
        }
        assert_eq!(
            reject(&json!({"model": "a", "settings": {"model": format!("{MARK}\u{7}")}})),
            ProfileInvalid::Model
        );
    }

    #[test]
    fn model_mismatch_rejected_and_equal_accepted() {
        assert_eq!(
            reject(&json!({"model": "opus", "settings": {"model": "sonnet"}})),
            ProfileInvalid::ModelMismatch
        );
        assert_eq!(
            reject(&json!({"settings": {"model": "sonnet"}})),
            ProfileInvalid::ModelMismatch
        );
        ok(&json!({"model": "opus", "settings": {"model": "opus"}}));
        ok(&json!({"model": "opus", "settings": {"permissions": {"allow": ["Read"]}}}));
    }

    #[test]
    fn turns_and_budget_ranges() {
        ok(&json!({"max_turns": 1}));
        ok(&json!({"max_turns": 1000}));
        for bad in [0, 1001] {
            assert_eq!(reject(&json!({"max_turns": bad})), ProfileInvalid::MaxTurns);
        }
        ok(&json!({"max_budget_usd": 0}));
        ok(&json!({"max_budget_usd": 1_000_000}));
        assert_eq!(
            reject(&json!({"max_budget_usd": 1_000_001})),
            ProfileInvalid::Budget
        );
    }

    #[test]
    fn bad_paths_rejected() {
        let long_component = text(65);
        let long_path = vec!["abcdefgh"; 40].join("/");
        let bad = [
            String::new(),
            format!("/{MARK}"),
            format!("{MARK}\\x"),
            format!("{MARK}\u{0}"),
            format!("{MARK}\n"),
            format!("a//{MARK}"),
            format!("{MARK}/"),
            format!("./{MARK}"),
            format!("{MARK}/../x"),
            format!("{MARK}/./x"),
            format!(".{MARK}"),
            format!("a/.{MARK}"),
            format!("{MARK}/{long_component}"),
            format!("{MARK}{long_path}"),
        ];
        for path in bad {
            assert_eq!(
                reject(&json!({"context_files": [{"path": path, "text": "x"}]})),
                ProfileInvalid::Path,
                "{path:?}"
            );
            assert_eq!(
                reject(&json!({"skills": [{"name": "s", "files": [{"path": path, "text": "x"}]}]})),
                ProfileInvalid::Path,
                "{path:?}"
            );
        }
        ok(&json!({"context_files": [{"path": text(64), "text": "x"}]}));
        ok(
            &json!({"context_files": [{"path": vec![text(64); 4].join("/").get(..255).unwrap(), "text": "x"}]}),
        );
    }

    #[test]
    fn bad_skill_names_rejected() {
        for name in [
            String::new(),
            format!("{MARK}/x"),
            format!("{MARK}.x"),
            format!(".{MARK}"),
            format!("{MARK} x"),
            format!("{MARK}\u{e9}"),
            text(65),
        ] {
            assert_eq!(
                reject(&json!({"skills": [{"name": name}]})),
                ProfileInvalid::Path
            );
        }
        ok(&json!({"skills": [{"name": text(64)}]}));
        ok(&json!({"skills": [{"name": "A-z_9"}]}));
    }

    #[test]
    fn duplicates_rejected() {
        let file = json!({"path": format!("{MARK}.md"), "text": "x"});
        assert_eq!(
            reject(&json!({"context_files": [file, file]})),
            ProfileInvalid::Duplicate
        );
        assert_eq!(
            reject(&json!({"skills": [{"name": "s", "files": [file, file]}]})),
            ProfileInvalid::Duplicate
        );
        assert_eq!(
            reject(&json!({"skills": [{"name": MARK}, {"name": MARK}]})),
            ProfileInvalid::Duplicate
        );
        ok(&json!({
            "context_files": [file],
            "skills": [{"name": "s", "files": [file]}, {"name": "t", "files": [file]}]
        }));
    }

    #[test]
    fn template_rules() {
        ok(&json!({"prompt_template": "{prompt}"}));
        ok(&json!({"prompt_template": "a {prompt} b"}));
        for bad in [
            String::new(),
            format!("{MARK} no placeholder"),
            "{prompt} {prompt}".into(),
            format!("{{prompt}} {MARK} {{x}}"),
            format!("{{{{prompt}}}} {MARK}"),
            format!("{{prompt}} {MARK} }}"),
            format!("{{prompt}} {MARK} {{"),
            format!("{MARK} {{ {{prompt}}"),
            format!("{{ prompt }} {MARK}"),
        ] {
            assert_eq!(
                reject(&json!({"prompt_template": bad})),
                ProfileInvalid::Template,
                "{bad}"
            );
        }
    }

    #[test]
    fn rule_shape_rejected() {
        let many: Vec<_> = (0..257).map(|i| format!("Tool{i}")).collect();
        let most: Vec<_> = (0..256).map(|i| format!("Tool{i}")).collect();
        for list in ["allow", "deny"] {
            for bad in [
                json!([""]),
                json!([text(257)]),
                json!([format!("{MARK}\n")]),
                json!(many),
            ] {
                assert_eq!(reject(&json!({ list: bad })), ProfileInvalid::Rule);
                assert_eq!(
                    reject(&json!({"settings": {"permissions": { list: bad }}})),
                    ProfileInvalid::Rule
                );
            }
            ok(&json!({ list: most }));
            ok(&json!({ list: [text(256)] }));
        }
    }

    #[test]
    fn mcp_rules_rejected() {
        for list in ["allow", "deny"] {
            for rule in [
                format!("mcp__{MARK}"),
                format!("MCP__{MARK}__x"),
                format!("  mcp__{MARK}"),
            ] {
                assert_eq!(reject(&json!({ list: [rule] })), ProfileInvalid::McpRule);
                assert_eq!(
                    reject(&json!({"settings": {"permissions": { list: [rule] }}})),
                    ProfileInvalid::McpRule
                );
            }
        }
        ok(&json!({"allow": ["Read(mcp__ok)"]}));
    }

    #[test]
    fn credential_references_rejected() {
        let bad = ProfileInvalid::CredentialPath;
        for marker in [
            ".credentials",
            ".claude/.credentials.json",
            "OAuth",
            ".SSH",
            ".aws",
            ".netrc",
            ".gnupg",
            ".config/gh",
            "ID_RSA",
            "id_ed25519",
        ] {
            assert_eq!(
                reject(&json!({"allow": [format!("Read({MARK}{marker})")]})),
                bad
            );
            assert_eq!(
                reject(
                    &json!({"settings": {"permissions": {"allow": [format!("Read({MARK}{marker})")]}}})
                ),
                bad
            );
        }
        for path in [
            "a/oauth.txt",
            "keys/id_rsa",
            "x/ID_ED25519",
            "a/b/x.ssh",
            "a/b_netrc.aws",
            "a/x.credentials",
            "a/x.gnupg",
            "a/x.config/gh",
        ] {
            assert_eq!(
                reject(
                    &json!({"context_files": [{"path": format!("{MARK}/{path}"), "text": "x"}]})
                ),
                bad,
                "{path}"
            );
            assert_eq!(
                reject(
                    &json!({"skills": [{"name": "s", "files": [{"path": format!("{MARK}/{path}"), "text": "x"}]}]})
                ),
                bad,
                "{path}"
            );
        }
        assert_eq!(
            reject(&json!({"skills": [{"name": format!("{MARK}-OAuth")}]})),
            bad
        );
        ok(&json!({"deny": ["Read(~/.ssh/*)"]}));
    }

    #[test]
    fn env_names_restricted() {
        for name in ENV_FLAG_ALLOWLIST {
            ok(&json!({"env_flags": {name: "1"}}));
        }
        for name in [
            MARK.to_owned(),
            "disable_telemetry".into(),
            "ANTHROPIC_API_KEY".into(),
            format!("DISABLE_TELEMETRY{MARK}"),
        ] {
            assert_eq!(
                reject(&json!({"env_flags": {name: "1"}})),
                ProfileInvalid::EnvName
            );
        }
    }

    #[test]
    fn secret_lint_rejects() {
        let a20 = text(20);
        let samples = [
            format!("{MARK} ghp_{a20}"),
            format!("{MARK} ghp_{}", text(40)),
            format!("{MARK} github_pat_x"),
            format!("{MARK} sk-{}", "a_-".repeat(7)),
            format!("{MARK}\n-----BEGIN PRIVATE KEY-----"),
            format!("{MARK} AKIA{}", "A0".repeat(8)),
            format!("{MARK} eyJ{}.{}.{}", text(7), text(10), text(10)),
            format!("{MARK} ghp_short sk-{a20}"),
            format!(
                "{MARK} eyJxx eyJ{}.{}.{}",
                text(9),
                "b-_".repeat(4),
                text(10)
            ),
        ];
        for sample in &samples {
            for value in [
                json!({"claude_md": sample}),
                json!({"prompt_prefix": sample}),
                json!({"prompt_template": format!("{{prompt}} {sample}")}),
                json!({"context_files": [{"path": "a", "text": sample}]}),
                json!({"skills": [{"name": "s", "files": [{"path": "a", "text": sample}]}]}),
                json!({"settings": {"attribution": {"pr": sample}}}),
            ] {
                assert_eq!(reject(&value), ProfileInvalid::SecretLike, "{sample}");
            }
        }
    }

    #[test]
    fn secret_lint_accepts_near_misses() {
        let a19 = text(19);
        for sample in [
            format!("ghp_{a19}"),
            format!("ghp_{a19}-"),
            "github_pat".to_owned(),
            format!("sk-{a19}"),
            format!("sk-{a19}!"),
            "----BEGIN".to_owned(),
            format!("AKIA{}", text(15)),
            format!("AKIA{}", "a".repeat(16)),
            format!("eyJ{}.{}.{}", text(6), text(10), text(10)),
            format!("eyJ{}.{}.{}", text(9), text(9), text(10)),
            format!("eyJ{}.{}", text(9), text(10)),
            format!("eyJ{}.{}.{}", text(9), text(10), text(9)),
            "task-sk-".to_owned(),
        ] {
            ok(&json!({"claude_md": sample}));
        }
    }

    #[test]
    fn secret_scan_is_linear_on_hostile_input() {
        let big = "eyJ".repeat(80_000);
        ok(&json!({"claude_md": big}));
        let big = "sk-!".repeat(60_000);
        ok(&json!({"claude_md": big}));
    }

    #[test]
    fn settings_forbidden_keys_rejected_at_parse() {
        let cases = [
            r#"{"settings":{"hooks":{}}}"#,
            r#"{"settings":{"mcp":{}}}"#,
            r#"{"settings":{"mcpServers":{}}}"#,
            r#"{"settings":{"env":{}}}"#,
            r#"{"settings":{"permissions":{"defaultMode":"bypassPermissions"}}}"#,
            r#"{"settings":{"permissions":{"defaultMode":"dontAsk"}}}"#,
            r#"{"settings":{"permissions":{"hooks":{}}}}"#,
            r#"{"settings":{"permissions":{"mcpServers":{}}}}"#,
            r#"{"settings":{"attribution":{"hooks":{}}}}"#,
            r#"{"hooks":{}}"#,
            r#"{"mcp":{}}"#,
            r#"{"mcpServers":{}}"#,
            r#"{"defaultMode":"x"}"#,
        ];
        for case in cases {
            assert_eq!(
                Profile::from_json(case.as_bytes()),
                Err(ProfileError::Malformed),
                "{case}"
            );
        }
        assert!(
            Profile::from_json(br#"{"settings":{"permissions":{"allow":["a"]},"model":"m"}}"#)
                .is_ok()
        );
    }

    #[test]
    fn constructed_profiles_validate_too() {
        let profile = Profile {
            settings: Some(Settings {
                permissions: Some(SettingsPermissions::default()),
                model: None,
                attribution: Some(Attribution::default()),
            }),
            skills: vec![Skill {
                name: "s".into(),
                files: Vec::new(),
            }],
            ..Profile::default()
        };
        assert_eq!(profile.validate(), Ok(()));
    }

    #[test]
    fn errors_never_echo_input() {
        let hostile = [
            json!({"context_files": [{"path": format!("../{MARK}"), "text": "x"}]}),
            json!({"context_files": [{"path": format!("{MARK}/.ssh/id_rsa"), "text": "x"}]}),
            json!({"skills": [{"name": format!("{MARK}!")}]}),
            json!({"env_flags": {MARK: "1"}}),
            json!({"allow": [format!("mcp__{MARK}")]}),
            json!({"allow": [format!("{MARK}\n")]}),
            json!({"prompt_template": format!("{MARK} {{")}),
            json!({"claude_md": format!("{MARK} -----BEGIN")}),
            json!({"claude_md": format!("{MARK}\u{0}")}),
            json!({"model": format!("{MARK}\n")}),
            json!({"model": "a", "settings": {"model": MARK}}),
            json!({"model": MARK, "settings": {"model": "b"}}),
        ];
        for value in hostile {
            let err = parse(&value).validate().unwrap_err();
            assert!(!err.to_string().contains(MARK), "{value}");
            assert!(!format!("{err:?}").contains(MARK), "{value}");
        }
    }

    #[test]
    fn every_variant_has_a_distinct_message() {
        let all = [
            ProfileInvalid::TooManyEntries,
            ProfileInvalid::TotalTooLarge,
            ProfileInvalid::FileTooLarge,
            ProfileInvalid::NulByte,
            ProfileInvalid::Model,
            ProfileInvalid::MaxTurns,
            ProfileInvalid::Budget,
            ProfileInvalid::Path,
            ProfileInvalid::Duplicate,
            ProfileInvalid::Template,
            ProfileInvalid::Rule,
            ProfileInvalid::McpRule,
            ProfileInvalid::CredentialPath,
            ProfileInvalid::EnvName,
            ProfileInvalid::ModelMismatch,
            ProfileInvalid::SecretLike,
        ];
        let messages: BTreeSet<_> = all.iter().map(ToString::to_string).collect();
        assert_eq!(messages.len(), all.len());
    }
}
