//! A validated Profile laid over the default [`Bundle`], as a pure function.
//!
//! No IO, clock or environment is read here. [`apply_profile`] returns the effective bundle,
//! the argv pieces and the final prompt (ADR-0034). [`load`] first checks the blob the server
//! sent against the Job's `ProfileRef` and fails closed (ADR-0035): the runner calls it before
//! the clone and never falls back to the default bundle.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use fleet_core::{Profile, ProfileHash, ProfileInvalid};
use fleet_proto::MAX_PROFILE_JSON_BYTES;
use fleet_proto::v1::{GetProfileBlobReply, ProfileRef};
use serde_json::{Map, Value, json};

use crate::agent_config::{Bundle, BundleError};
use crate::floor::{self, BoxCeilings};

const CLAUDE_MD: &str = "CLAUDE.md";
const SETTINGS: &str = "settings.json";
const CTX_DIR: &str = ".claude/ctx";
const SKILLS_DIR: &str = "skills";
const PLACEHOLDER: &str = "{prompt}";

/// Why a Profile could not be laid over the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyError {
    /// Two overlay paths are equal when compared without case.
    Collision,
    /// A context file path holds whitespace, which an `@` import line cannot carry.
    ImportPath,
    /// The assembled files were rejected by [`Bundle::from_files`].
    Bundle(BundleError),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collision => f.write_str("profile paths collide when compared without case"),
            Self::ImportPath => f.write_str("profile context file path holds whitespace"),
            Self::Bundle(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for ApplyError {}

impl From<BundleError> for ApplyError {
    fn from(err: BundleError) -> Self {
        Self::Bundle(err)
    }
}

/// The result of laying a Profile over the default bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// The effective bundle.
    pub bundle: Bundle,
    /// The Profile-driven flags: `--model`, `--allowedTools`, `--disallowedTools`,
    /// `--max-turns` and `--max-budget-usd`. `--model` and `--allowedTools` are omitted when
    /// they hold no value.
    pub argv: Vec<String>,
    /// The Profile prefix followed by the template with the job prompt substituted once.
    pub prompt: String,
    /// The allow entries the Floor removed, without repeats.
    pub dropped_allows: Vec<String>,
    /// The permission mode of the Effective settings, always [`floor::PERMISSION_MODE`].
    pub permission_mode: &'static str,
}

fn dollars(cents: u64) -> String {
    format!("{}.{:02}", cents / 100, cents % 100)
}

fn default_allow(default: &Bundle) -> Vec<String> {
    default
        .files()
        .get(std::path::Path::new(SETTINGS))
        .and_then(|raw| serde_json::from_slice::<Value>(raw).ok())
        .and_then(|value| value.pointer("/permissions/allow").cloned())
        .and_then(|allow| serde_json::from_value(allow).ok())
        .unwrap_or_default()
}

fn settings_json(
    default: &Bundle,
    profile: &Profile,
    allow: &[String],
    deny: &[String],
) -> Vec<u8> {
    let mut root: Map<String, Value> = default
        .files()
        .get(std::path::Path::new(SETTINGS))
        .and_then(|raw| serde_json::from_slice(raw).ok())
        .unwrap_or_default();
    root.insert(
        "permissions".to_owned(),
        json!({ "allow": allow, "deny": deny }),
    );
    if let Some(model) = &profile.model {
        root.insert("model".to_owned(), json!(model));
    }
    if let Some(attribution) = profile
        .settings
        .as_ref()
        .and_then(|s| s.attribution.as_ref())
    {
        root.insert("attribution".to_owned(), json!(attribution));
    }
    let mut out = serde_json::to_vec_pretty(&Value::Object(root)).unwrap_or_default();
    out.push(b'\n');
    out
}

fn claude_md(default: &Bundle, profile: &Profile) -> Vec<u8> {
    let mut text = profile.claude_md.clone().unwrap_or_else(|| {
        default
            .files()
            .get(std::path::Path::new(CLAUDE_MD))
            .map(|raw| String::from_utf8_lossy(raw).into_owned())
            .unwrap_or_default()
    });
    if !profile.context_files.is_empty() && !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for file in &profile.context_files {
        text.push('@');
        text.push_str(CTX_DIR);
        text.push('/');
        text.push_str(&file.path);
        text.push('\n');
    }
    text.into_bytes()
}

fn overlay(
    default: &Bundle,
    profile: &Profile,
    settings: Vec<u8>,
) -> Result<BTreeMap<PathBuf, Vec<u8>>, ApplyError> {
    if profile
        .context_files
        .iter()
        .any(|file| file.path.chars().any(char::is_whitespace))
    {
        return Err(ApplyError::ImportPath);
    }
    let mut added: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for file in &profile.context_files {
        added.push((
            PathBuf::from(format!("{CTX_DIR}/{}", file.path)),
            file.text.clone().into_bytes(),
        ));
    }
    for skill in &profile.skills {
        for file in &skill.files {
            added.push((
                PathBuf::from(format!("{SKILLS_DIR}/{}/{}", skill.name, file.path)),
                file.text.clone().into_bytes(),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    for (path, _) in &added {
        if !seen.insert(path.to_string_lossy().to_lowercase()) {
            return Err(ApplyError::Collision);
        }
    }
    let mut files: BTreeMap<PathBuf, Vec<u8>> = default
        .files()
        .iter()
        .map(|(path, data)| (path.clone(), data.clone()))
        .collect();
    files.insert(PathBuf::from(CLAUDE_MD), claude_md(default, profile));
    files.insert(PathBuf::from(SETTINGS), settings);
    files.extend(added);
    Ok(files)
}

/// Lays `profile` over `default` and derives the argv pieces and the prompt for `job_prompt`.
///
/// `CLAUDE.md` is replaced by the Profile text when present, then one `@.claude/ctx/<path>`
/// line per context file is appended. Context files land at `.claude/ctx/<path>` and skill
/// files at `skills/<name>/<path>`, both inside the bundle root, so the import resolves from
/// `CLAUDE.md`. `settings.json` is generated: permissions from [`floor::apply`], the Profile
/// model and attribution. Rules in `settings.permissions` join `allow` and `deny` before the
/// Floor. A Profile with no allow rules keeps the default bundle's allow list.
///
/// # Errors
///
/// Returns [`ApplyError`] when two overlay paths collide without case, a context path holds
/// whitespace, or [`Bundle::from_files`] rejects the files.
pub fn apply_profile(
    profile: &Profile,
    default: &Bundle,
    ceilings: &BoxCeilings,
    job_prompt: &str,
) -> Result<Applied, ApplyError> {
    let mut merged = profile.clone();
    if let Some(perms) = profile
        .settings
        .as_ref()
        .and_then(|s| s.permissions.as_ref())
    {
        merged.allow.extend(perms.allow.iter().cloned());
        merged.deny.extend(perms.deny.iter().cloned());
    }
    let mut effective = floor::apply(&merged, ceilings);
    if effective.allow.is_empty() {
        effective.allow = default_allow(default);
    }
    let settings_allow = floor::with_floor_allow(&effective.allow);
    let settings = settings_json(default, profile, &settings_allow, &effective.deny);
    let bundle = Bundle::from_files(overlay(default, profile, settings)?)?;
    let mut argv = Vec::new();
    if let Some(model) = &effective.model {
        argv.extend(["--model".to_owned(), model.clone()]);
    }
    if !effective.allow.is_empty() {
        argv.push("--allowedTools".to_owned());
        argv.extend(effective.allow.iter().cloned());
    }
    argv.push("--disallowedTools".to_owned());
    argv.extend(effective.deny.iter().cloned());
    argv.extend([
        "--max-turns".to_owned(),
        effective.max_turns.to_string(),
        "--max-budget-usd".to_owned(),
        dollars(effective.max_budget_cents),
    ]);
    let template = profile.prompt_template.as_deref().unwrap_or(PLACEHOLDER);
    let prompt = format!(
        "{}{}",
        profile.prompt_prefix.as_deref().unwrap_or(""),
        template.replacen(PLACEHOLDER, job_prompt, 1)
    );
    Ok(Applied {
        bundle,
        argv,
        prompt,
        dropped_allows: effective.dropped_allows,
        permission_mode: effective.permission_mode,
    })
}

/// Why a Profile blob was refused. Every reason is a fixed message that starts with
/// `profile invalid:` and never echoes the blob, the name or the hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadError {
    /// The blob could not be fetched from the server.
    Fetch,
    /// The reply names another Profile than the Job's `ProfileRef`.
    Mismatch,
    /// The hash in the Job's `ProfileRef` is not 64 lowercase hex characters.
    RefHash,
    /// The blob is longer than [`MAX_PROFILE_JSON_BYTES`].
    TooLarge,
    /// The blob is not Profile JSON.
    Malformed,
    /// The blob is not the canonical JSON of its Profile.
    NotCanonical,
    /// The Profile hash differs from the hash in the Job's `ProfileRef`.
    HashMismatch,
    /// The shared validator refused the Profile.
    Invalid(ProfileInvalid),
    /// The Profile could not be laid over the bundle.
    Apply(ApplyError),
}

fn invalid_reason(err: ProfileInvalid) -> &'static str {
    match err {
        ProfileInvalid::TooManyEntries => "profile invalid: profile holds too many files",
        ProfileInvalid::TotalTooLarge => "profile invalid: profile text is too large",
        ProfileInvalid::FileTooLarge => "profile invalid: a profile file is too large",
        ProfileInvalid::NulByte => "profile invalid: profile text holds a NUL byte",
        ProfileInvalid::Model => "profile invalid: profile model name is not allowed",
        ProfileInvalid::MaxTurns => "profile invalid: profile max_turns is out of range",
        ProfileInvalid::Budget => "profile invalid: profile max_budget_usd is out of range",
        ProfileInvalid::Path => "profile invalid: a profile path or skill name is not allowed",
        ProfileInvalid::Duplicate => "profile invalid: a profile path or skill name is repeated",
        ProfileInvalid::Template => "profile invalid: profile prompt_template is not allowed",
        ProfileInvalid::Rule => "profile invalid: a profile permission rule is not allowed",
        ProfileInvalid::McpRule => "profile invalid: a profile permission rule names an MCP tool",
        ProfileInvalid::CredentialPath => {
            "profile invalid: a profile path or rule references a credential location"
        }
        ProfileInvalid::EnvName => "profile invalid: a profile env flag name is not allowed",
        ProfileInvalid::ModelMismatch => {
            "profile invalid: profile settings.model differs from model"
        }
        ProfileInvalid::SecretLike => "profile invalid: profile text looks like a secret",
        _ => "profile invalid: profile failed validation",
    }
}

impl LoadError {
    /// The fixed reason a failed Job reports.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Fetch => "profile invalid: profile could not be fetched",
            Self::Mismatch => "profile invalid: server sent another profile than the job names",
            Self::RefHash => "profile invalid: job profile hash is malformed",
            Self::TooLarge => "profile invalid: profile blob is too large",
            Self::Malformed => "profile invalid: profile blob is not profile JSON",
            Self::NotCanonical => "profile invalid: profile blob is not canonical",
            Self::HashMismatch => "profile invalid: profile hash does not match the job",
            Self::Invalid(err) => invalid_reason(*err),
            Self::Apply(ApplyError::Collision) => {
                "profile invalid: profile paths collide when compared without case"
            }
            Self::Apply(ApplyError::ImportPath) => {
                "profile invalid: profile context file path holds whitespace"
            }
            Self::Apply(_) => "profile invalid: profile could not be laid over the bundle",
        }
    }
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for LoadError {}

/// Checks the blob `reply` against the Job's `expected` reference, then lays the Profile over
/// `default` with [`apply_profile`].
///
/// The reply must name `expected` exactly. The blob must fit [`MAX_PROFILE_JSON_BYTES`], parse
/// as a Profile, equal that Profile's canonical JSON and hash to the hash in `expected`. The
/// shared validator runs last, before the overlay, so fleetd does not trust the server's check.
///
/// # Errors
///
/// Returns the [`LoadError`] of the first check that fails.
pub fn load(
    expected: &ProfileRef,
    reply: &GetProfileBlobReply,
    default: &Bundle,
    ceilings: &BoxCeilings,
    job_prompt: &str,
) -> Result<Applied, LoadError> {
    if reply.profile.as_ref() != Some(expected) {
        return Err(LoadError::Mismatch);
    }
    let want = ProfileHash::from_hex(&expected.hash).map_err(|_| LoadError::RefHash)?;
    if reply.content.len() > MAX_PROFILE_JSON_BYTES {
        return Err(LoadError::TooLarge);
    }
    let profile = Profile::from_json(&reply.content).map_err(|_| LoadError::Malformed)?;
    if profile.canonical_json() != reply.content {
        return Err(LoadError::NotCanonical);
    }
    if profile.hash() != want {
        return Err(LoadError::HashMismatch);
    }
    profile.validate().map_err(LoadError::Invalid)?;
    apply_profile(&profile, default, ceilings, job_prompt).map_err(LoadError::Apply)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use fleet_core::{ContextFile, Skill};

    use super::*;

    fn ceilings() -> BoxCeilings {
        BoxCeilings {
            default_max_turns: 30,
            max_turns: 50,
            default_max_budget_cents: 500,
            max_budget_cents: 1000,
        }
    }

    fn file(path: &str, text: &str) -> ContextFile {
        ContextFile {
            path: path.to_owned(),
            text: text.to_owned(),
        }
    }

    fn run(profile: &Profile) -> Result<Applied, ApplyError> {
        apply_profile(profile, &Bundle::default(), &ceilings(), "fix it")
    }

    fn body(applied: &Applied, path: &str) -> Option<String> {
        applied
            .bundle
            .files()
            .get(Path::new(path))
            .map(|raw| String::from_utf8_lossy(raw).into_owned())
    }

    fn full() -> Profile {
        Profile {
            claude_md: Some("be brief".to_owned()),
            context_files: vec![file("a/x.md", "X"), file("y.md", "Y")],
            prompt_prefix: Some("PRE ".to_owned()),
            prompt_template: Some("do: {prompt}!".to_owned()),
            skills: vec![Skill {
                name: "lint".to_owned(),
                files: vec![file("SKILL.md", "S"), file("ref/r.md", "R")],
            }],
            allow: vec!["Read".to_owned(), "Bash(git push*)".to_owned()],
            deny: vec!["Bash(rm *)".to_owned()],
            model: Some("opus".to_owned()),
            max_turns: Some(900),
            max_budget_usd: Some(250),
            ..Profile::default()
        }
    }

    #[test]
    fn argv_and_prompt_match_the_spec() -> Result<(), ApplyError> {
        let applied = run(&full())?;
        let mut want: Vec<String> = ["--model", "opus", "--allowedTools", "Read"]
            .map(str::to_owned)
            .to_vec();
        want.push("--disallowedTools".to_owned());
        want.extend(floor::FLOOR_DENY.iter().map(|d| (*d).to_owned()));
        want.push("Bash(rm *)".to_owned());
        want.extend(["--max-turns", "50", "--max-budget-usd", "2.50"].map(str::to_owned));
        assert_eq!(applied.argv, want);
        assert_eq!(applied.prompt, "PRE do: fix it!");
        assert_eq!(applied.dropped_allows, vec!["Bash(git push*)".to_owned()]);
        Ok(())
    }

    #[test]
    fn the_job_prompt_is_substituted_once_and_not_rescanned() -> Result<(), ApplyError> {
        let profile = Profile {
            prompt_template: Some("{prompt}".to_owned()),
            ..Profile::default()
        };
        let applied = apply_profile(
            &profile,
            &Bundle::default(),
            &ceilings(),
            "{prompt}{prompt}",
        )?;
        assert_eq!(applied.prompt, "{prompt}{prompt}");
        Ok(())
    }

    #[test]
    fn an_empty_profile_passes_the_prompt_and_clamped_defaults() -> Result<(), ApplyError> {
        let applied = run(&Profile::default())?;
        assert_eq!(applied.prompt, "fix it");
        assert!(!applied.argv.iter().any(|a| a == "--model"));
        assert!(applied.argv.windows(2).any(|w| w == ["--max-turns", "30"]));
        assert!(
            applied
                .argv
                .windows(2)
                .any(|w| w == ["--max-budget-usd", "5.00"])
        );
        Ok(())
    }

    #[test]
    fn the_bundle_sha_differs_from_the_default() -> Result<(), ApplyError> {
        let default = Bundle::default().sha256();
        assert_ne!(run(&full())?.bundle.sha256(), default);
        assert_ne!(run(&Profile::default())?.bundle.sha256(), default);
        Ok(())
    }

    #[test]
    fn claude_md_is_replaced_when_present_and_kept_otherwise() -> Result<(), ApplyError> {
        assert_eq!(
            body(&run(&full())?, "CLAUDE.md").as_deref(),
            Some("be brief\n@.claude/ctx/a/x.md\n@.claude/ctx/y.md\n")
        );
        let kept = body(&run(&Profile::default())?, "CLAUDE.md");
        let default = Bundle::default();
        let want = default
            .files()
            .get(Path::new("CLAUDE.md"))
            .map(|raw| String::from_utf8_lossy(raw).into_owned());
        assert_eq!(kept, want);
        Ok(())
    }

    #[test]
    fn context_and_skill_files_land_under_their_roots() -> Result<(), ApplyError> {
        let applied = run(&full())?;
        assert_eq!(body(&applied, ".claude/ctx/a/x.md").as_deref(), Some("X"));
        assert_eq!(body(&applied, ".claude/ctx/y.md").as_deref(), Some("Y"));
        assert_eq!(body(&applied, "skills/lint/SKILL.md").as_deref(), Some("S"));
        assert_eq!(body(&applied, "skills/lint/ref/r.md").as_deref(), Some("R"));
        Ok(())
    }

    #[test]
    fn settings_carry_the_floor_deny_and_the_model() -> Result<(), ApplyError> {
        let applied = run(&full())?;
        let raw = body(&applied, "settings.json").unwrap_or_default();
        let value: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
        assert_eq!(value["model"], json!("opus"));
        assert_eq!(
            value["permissions"]["allow"],
            json!(["Bash(fleetd fetch *)", "Read"])
        );
        let deny = value["permissions"]["deny"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        for entry in floor::FLOOR_DENY {
            assert!(deny.contains(&json!(entry)));
        }
        assert!(deny.contains(&json!("Bash(rm *)")));
        Ok(())
    }

    #[test]
    fn settings_allow_always_holds_the_floor_allow_with_or_without_a_profile_allow()
    -> Result<(), ApplyError> {
        for profile in [
            Profile::default(),
            full(),
            Profile {
                allow: vec!["Bash(fleetd fetch *)".to_owned(), "Edit".to_owned()],
                ..Profile::default()
            },
        ] {
            let applied = run(&profile)?;
            let raw = body(&applied, "settings.json").unwrap_or_default();
            let value: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            let allow = value["permissions"]["allow"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert_eq!(
                allow
                    .iter()
                    .filter(|entry| **entry == json!("Bash(fleetd fetch *)"))
                    .count(),
                1
            );
            assert!(!allow.contains(&json!("Edit")));
        }
        let defaults = body(&run(&Profile::default())?, "settings.json").unwrap_or_default();
        assert!(defaults.contains("\"Glob\""));
        Ok(())
    }

    #[test]
    fn no_profile_allow_keeps_the_default_allow_list() -> Result<(), ApplyError> {
        let applied = run(&Profile::default())?;
        assert!(
            applied
                .argv
                .windows(2)
                .any(|w| w == ["--allowedTools", "Read"])
        );
        Ok(())
    }

    #[test]
    fn dropped_allows_have_no_repeats() -> Result<(), ApplyError> {
        let profile = Profile {
            allow: vec!["Edit".to_owned(), "Edit".to_owned()],
            ..Profile::default()
        };
        assert_eq!(run(&profile)?.dropped_allows, vec!["Edit".to_owned()]);
        Ok(())
    }

    #[test]
    fn paths_that_differ_only_in_case_collide() {
        let profile = Profile {
            context_files: vec![file("A.md", "1"), file("a.md", "2")],
            ..Profile::default()
        };
        assert_eq!(run(&profile), Err(ApplyError::Collision));
        let skills = Profile {
            skills: vec![
                Skill {
                    name: "Lint".to_owned(),
                    files: vec![file("SKILL.md", "1")],
                },
                Skill {
                    name: "lint".to_owned(),
                    files: vec![file("SKILL.md", "2")],
                },
            ],
            ..Profile::default()
        };
        assert_eq!(run(&skills), Err(ApplyError::Collision));
    }

    #[test]
    fn a_context_path_with_whitespace_is_refused() {
        let profile = Profile {
            context_files: vec![file("a b.md", "1")],
            ..Profile::default()
        };
        assert_eq!(run(&profile), Err(ApplyError::ImportPath));
    }

    #[test]
    fn bundle_caps_still_apply() {
        let profile = Profile {
            context_files: (0..70).map(|i| file(&format!("f{i}.md"), "x")).collect(),
            ..Profile::default()
        };
        assert_eq!(run(&profile), Err(ApplyError::Bundle(BundleError::TooMany)));
    }

    fn blob(profile: &Profile) -> (ProfileRef, GetProfileBlobReply) {
        let reference = ProfileRef {
            name: "p".to_owned(),
            version: 1,
            hash: profile.hash().to_string(),
        };
        let reply = GetProfileBlobReply {
            profile: Some(reference.clone()),
            content: profile.canonical_json(),
        };
        (reference, reply)
    }

    fn loaded(reference: &ProfileRef, reply: &GetProfileBlobReply) -> Result<Applied, LoadError> {
        load(reference, reply, &Bundle::default(), &ceilings(), "fix it")
    }

    #[test]
    fn a_blob_that_matches_its_ref_is_applied_with_the_floor_last() -> Result<(), LoadError> {
        let (reference, reply) = blob(&full());
        let applied = loaded(&reference, &reply)?;
        assert_eq!(applied.permission_mode, floor::PERMISSION_MODE);
        assert_eq!(applied.prompt, "PRE do: fix it!");
        assert_eq!(applied.dropped_allows, vec!["Bash(git push*)".to_owned()]);
        assert!(applied.argv.windows(2).any(|w| w == ["--max-turns", "50"]));
        Ok(())
    }

    #[test]
    fn a_tampered_blob_fails_on_the_hash() {
        let (reference, mut reply) = blob(&full());
        let other = Profile {
            model: Some("haiku".to_owned()),
            ..full()
        };
        reply.content = other.canonical_json();
        assert_eq!(loaded(&reference, &reply), Err(LoadError::HashMismatch));
    }

    #[test]
    fn a_flipped_byte_never_applies() {
        let (reference, reply) = blob(&full());
        for at in 0..reply.content.len() {
            let mut tampered = reply.clone();
            tampered.content[at] ^= 1;
            assert!(loaded(&reference, &tampered).is_err(), "byte {at}");
        }
    }

    #[test]
    fn a_blob_for_another_ref_is_refused() {
        let (reference, reply) = blob(&full());
        for change in [
            |r: &mut ProfileRef| r.version = 2,
            |r: &mut ProfileRef| r.name = "q".to_owned(),
            |r: &mut ProfileRef| r.hash = "0".repeat(64),
        ] {
            let mut asked = reference.clone();
            change(&mut asked);
            assert_eq!(loaded(&asked, &reply), Err(LoadError::Mismatch));
        }
        let mut bare = reply;
        bare.profile = None;
        assert_eq!(loaded(&reference, &bare), Err(LoadError::Mismatch));
    }

    #[test]
    fn a_malformed_hash_in_the_ref_is_refused() {
        let (mut reference, mut reply) = blob(&full());
        for hash in ["", "abc", &"A".repeat(64), &"g".repeat(64)] {
            hash.clone_into(&mut reference.hash);
            reply.profile = Some(reference.clone());
            assert_eq!(loaded(&reference, &reply), Err(LoadError::RefHash));
        }
    }

    #[test]
    fn a_blob_over_the_cap_is_refused() {
        let (reference, mut reply) = blob(&full());
        reply.content = vec![b' '; MAX_PROFILE_JSON_BYTES + 1];
        assert_eq!(loaded(&reference, &reply), Err(LoadError::TooLarge));
    }

    #[test]
    fn a_blob_that_is_not_profile_json_is_refused() {
        let (reference, mut reply) = blob(&full());
        for text in ["", "[]", "{\"nope\":1}", "not json"] {
            reply.content = text.as_bytes().to_vec();
            assert_eq!(loaded(&reference, &reply), Err(LoadError::Malformed));
        }
    }

    #[test]
    fn a_non_canonical_blob_is_refused() {
        let (reference, mut reply) = blob(&full());
        reply.content = serde_json::to_vec_pretty(&full()).unwrap_or_default();
        assert_eq!(loaded(&reference, &reply), Err(LoadError::NotCanonical));
    }

    #[test]
    fn a_profile_the_validator_refuses_fails_even_with_a_matching_hash() {
        let profile = Profile {
            model: Some(String::new()),
            ..Profile::default()
        };
        let (reference, reply) = blob(&profile);
        assert_eq!(
            loaded(&reference, &reply),
            Err(LoadError::Invalid(ProfileInvalid::Model))
        );
    }

    #[test]
    fn a_profile_that_cannot_be_laid_over_the_bundle_fails() {
        let profile = Profile {
            context_files: vec![file("a b.md", "1")],
            ..Profile::default()
        };
        let (reference, reply) = blob(&profile);
        assert_eq!(
            loaded(&reference, &reply),
            Err(LoadError::Apply(ApplyError::ImportPath))
        );
    }

    #[test]
    fn every_reason_starts_with_profile_invalid_and_keeps_the_validator_text() {
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
        for err in all {
            assert_eq!(
                LoadError::Invalid(err).reason(),
                format!("profile invalid: {err}")
            );
        }
        for err in [
            LoadError::Fetch,
            LoadError::Mismatch,
            LoadError::RefHash,
            LoadError::TooLarge,
            LoadError::Malformed,
            LoadError::NotCanonical,
            LoadError::HashMismatch,
            LoadError::Apply(ApplyError::Collision),
            LoadError::Apply(ApplyError::ImportPath),
            LoadError::Apply(ApplyError::Bundle(BundleError::TooMany)),
        ] {
            assert!(err.reason().starts_with("profile invalid: "));
            assert_eq!(err.to_string(), err.reason());
        }
    }
}
