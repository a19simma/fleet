//! A validated Profile laid over the default [`Bundle`], as a pure function.
//!
//! No IO, clock or environment is read here. [`apply_profile`] returns the effective bundle,
//! the argv pieces and the final prompt (ADR-0034). [`load`] first checks the blob the server
//! sent against the Job's `ProfileRef` and fails closed (ADR-0035): the runner calls it before
//! the clone and never falls back to the default bundle.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::PathBuf;

use fleet_core::catalog::{CatalogEntry, CatalogError, CatalogItem, CatalogKind};
use fleet_core::model_allowlist::ModelAllowlist;
use fleet_core::tools::ToolSpec;
use fleet_core::{Profile, ProfileHash, ProfileInvalid};
use fleet_proto::v1::{GetProfileBlobReply, ProfileRef};
use fleet_proto::{
    MAX_PROFILE_JSON_BYTES, ProfileConvertError, catalog_entry_from_wire, validate_blob_catalog,
};
use serde_json::{Map, Value, json};

use crate::agent_config::{Bundle, BundleError};
use crate::floor::{self, BoxCeilings};

const CLAUDE_MD: &str = "CLAUDE.md";
const SETTINGS: &str = "settings.json";
const CTX_DIR: &str = ".claude/ctx";
const SKILLS_DIR: &str = "skills";
const AGENTS_DIR: &str = "agents";
const SKILL_FILE: &str = "SKILL.md";
const PLACEHOLDER: &str = "{prompt}";

/// Why a Profile could not be laid over the bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApplyError {
    /// Two overlay paths are equal when compared without case.
    Collision,
    /// A context file path holds whitespace, which an `@` import line cannot carry.
    ImportPath,
    /// A catalog item would overwrite a file of the default bundle.
    DefaultPath,
    /// A subagent file has frontmatter outside the strict allowlist, or lists a tool the Floor
    /// denies.
    Subagent,
    /// A catalog tool is not a registry pin, or a tool is pinned twice.
    Tool,
    /// The assembled files were rejected by [`Bundle::from_files`].
    Bundle(BundleError),
}

impl fmt::Display for ApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Collision => f.write_str("profile paths collide when compared without case"),
            Self::ImportPath => f.write_str("profile context file path holds whitespace"),
            Self::DefaultPath => f.write_str("catalog item path collides with the default bundle"),
            Self::Subagent => f.write_str("catalog subagent loosens the floor"),
            Self::Tool => f.write_str("catalog tool is not a valid or unique pin"),
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
    /// The validated tool pins in canonical order, empty when the Profile has none. Nothing
    /// from the tool section reaches the settings, the overlay or the argv.
    pub tools: Vec<ToolSpec>,
}

fn sorted_tools(tools: &[ToolSpec]) -> Vec<ToolSpec> {
    let mut sorted = tools.to_vec();
    sorted.sort_by(|a, b| (a.name(), a.version().as_str()).cmp(&(b.name(), b.version().as_str())));
    sorted
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

fn item_path(item: &CatalogItem) -> Option<PathBuf> {
    match item.kind() {
        CatalogKind::Skill => Some(PathBuf::from(format!(
            "{SKILLS_DIR}/{}/{SKILL_FILE}",
            item.name()
        ))),
        CatalogKind::Subagent => Some(PathBuf::from(format!("{AGENTS_DIR}/{}.md", item.name()))),
        CatalogKind::Context => Some(PathBuf::from(format!("{CTX_DIR}/{}.md", item.name()))),
        CatalogKind::Tool => None,
    }
}

const SUBAGENT_KEYS: [&str; 4] = ["name", "description", "color", "tools"];
const SCALAR_FORBIDDEN: &str = "#&*!|>{}[]\"'`";
const SCALAR_FIRST_FORBIDDEN: &str = "-?:,%@";

/// A YAML plain scalar on one line, narrowed to printable ASCII. `ns-plain-first` excludes the
/// indicators `- ? : , [ ] { } # & * ! | > ' " % @` and the backtick; `ns-plain-char` excludes
/// `: ` and ` #`. This also refuses every flow, quote, anchor, alias, tag and block-scalar
/// indicator anywhere in the value, a leading or trailing space, and a trailing colon.
fn plain_scalar(value: &str) -> bool {
    let Some(first) = value.chars().next() else {
        return false;
    };
    value.chars().all(|c| matches!(c, ' '..='~'))
        && !value.starts_with(' ')
        && !value.ends_with([' ', ':'])
        && !value.contains(": ")
        && !SCALAR_FIRST_FORBIDDEN.contains(first)
        && !value.chars().any(|c| SCALAR_FORBIDDEN.contains(c))
}

fn tool_name(entry: &str) -> bool {
    !entry.is_empty()
        && entry
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
}

fn tool_denied(entry: &str) -> bool {
    floor::FLOOR_DENY
        .iter()
        .any(|deny| deny.eq_ignore_ascii_case(entry))
}

fn fence_candidate(body: &str) -> bool {
    body.trim_start().starts_with("---")
}

/// Whether a subagent body stays inside the Floor. The claude runner parses the frontmatter as
/// YAML, so only a strict subset is accepted and everything else is refused. The body must start
/// with `---\n`, then hold one line per key, each `key: value` with the key one of
/// [`SUBAGENT_KEYS`] at most once and the value a [`plain_scalar`], then a `---\n` line that no
/// further `---` line follows. No CR, tab, NUL, indentation, blank line or second document start can occur in that region, so no
/// line break YAML knows (CR, NEL, U+2028, U+2029) hides a key. `tools` is a comma-separated
/// list of tool names, none in the Floor deny set. A body with no frontmatter is accepted only
/// when it has no BOM and its first non-whitespace line does not start with `---`.
fn subagent_within_floor(body: &str) -> bool {
    let Some(rest) = body.strip_prefix("---\n") else {
        return !body.starts_with('\u{feff}') && !fence_candidate(body);
    };
    let mut seen: Vec<&str> = Vec::new();
    let mut consumed = 0;
    for raw in rest.split_inclusive('\n') {
        let Some(line) = raw.strip_suffix('\n') else {
            return false;
        };
        if line == "---" {
            let after = &rest[consumed + raw.len()..];
            return !seen.is_empty() && !after.starts_with("---");
        }
        consumed += raw.len();
        let Some((key, value)) = line.split_once(": ") else {
            return false;
        };
        if !SUBAGENT_KEYS.contains(&key) || seen.contains(&key) || !plain_scalar(value) {
            return false;
        }
        if key == "tools"
            && value
                .split(',')
                .map(str::trim)
                .any(|entry| !tool_name(entry) || tool_denied(entry))
        {
            return false;
        }
        seen.push(key);
    }
    false
}

fn catalog_tools(items: &[CatalogItem]) -> Result<Vec<ToolSpec>, ApplyError> {
    items
        .iter()
        .filter(|item| item.kind() == CatalogKind::Tool)
        .map(|item| ToolSpec::new(item.name(), item.body()).map_err(|_| ApplyError::Tool))
        .collect()
}

fn claude_md(default: &Bundle, profile: &Profile, items: &[CatalogItem]) -> Vec<u8> {
    let mut text = profile.claude_md.clone().unwrap_or_else(|| {
        default
            .files()
            .get(std::path::Path::new(CLAUDE_MD))
            .map(|raw| String::from_utf8_lossy(raw).into_owned())
            .unwrap_or_default()
    });
    let has_imports =
        !profile.context_files.is_empty() || items.iter().any(|i| i.kind() == CatalogKind::Context);
    if has_imports && !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    for file in &profile.context_files {
        text.push('@');
        text.push_str(CTX_DIR);
        text.push('/');
        text.push_str(&file.path);
        text.push('\n');
    }
    for item in items.iter().filter(|i| i.kind() == CatalogKind::Context) {
        text.push('@');
        text.push_str(CTX_DIR);
        text.push('/');
        text.push_str(item.name());
        text.push_str(".md\n");
    }
    text.into_bytes()
}

fn overlay(
    default: &Bundle,
    profile: &Profile,
    items: &[CatalogItem],
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
    let taken: BTreeSet<String> = default
        .files()
        .keys()
        .map(|path| path.to_string_lossy().to_lowercase())
        .collect();
    for item in items {
        if item.kind() == CatalogKind::Subagent && !subagent_within_floor(item.body()) {
            return Err(ApplyError::Subagent);
        }
        if let Some(path) = item_path(item) {
            if taken.contains(&path.to_string_lossy().to_lowercase()) {
                return Err(ApplyError::DefaultPath);
            }
            added.push((path, item.body().as_bytes().to_vec()));
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
    files.insert(PathBuf::from(CLAUDE_MD), claude_md(default, profile, items));
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
/// Floor. A Profile with no allow rules left after the Floor drops its own keeps the default
/// bundle's allow list, which includes bare `Bash`.
///
/// The returned [`Applied`] carries no permission mode: the runner adds `dontAsk` itself. The
/// collision check compares whole lowercased paths, so directories that differ only in case, a
/// file against a directory and NFC against NFD forms are not detected. A `claude_md` that ends
/// inside a code fence also fences the appended `@` imports, and it may carry its own `@`
/// lines; nothing here rejects either. Skill discovery under `CLAUDE_CONFIG_DIR` and the
/// relative `@.claude/ctx` import are unverified against a live `claude`.
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
    apply_effective(profile, &[], default, ceilings, job_prompt)
}

/// Lays `profile` and the frozen effective set `items` over `default`.
///
/// `items` is the set the server froze at submit; it is applied as given and never resolved
/// again. A skill lands at `skills/<name>/SKILL.md`, a subagent at `agents/<name>.md` and a
/// context item at `.claude/ctx/<name>.md` with an `@` import line in `CLAUDE.md`, each with the
/// item body as the file text. A tool item joins [`Applied::tools`] as a pin. Item names have
/// the [`CatalogItem`] id shape, so no name holds a separator, dot, space or non-ASCII byte.
///
/// # Errors
///
/// Returns [`ApplyError`] as [`apply_profile`] does, [`ApplyError::DefaultPath`] when an item
/// would overwrite a default bundle file, [`ApplyError::Subagent`] for a subagent whose
/// frontmatter is not the strict allowlist of `name`, `description`, `color` and `tools`
/// plain-scalar lines, sets `model` (only the Profile model is checked against the box
/// allowlist), or lists a tool in [`floor::FLOOR_DENY`], and [`ApplyError::Tool`] for a
/// catalog tool that is not a valid registry pin or a tool pinned twice.
pub fn apply_effective(
    profile: &Profile,
    items: &[CatalogItem],
    default: &Bundle,
    ceilings: &BoxCeilings,
    job_prompt: &str,
) -> Result<Applied, ApplyError> {
    let mut tools = profile.tools.clone();
    tools.extend(catalog_tools(items)?);
    let mut names = BTreeSet::new();
    if !tools.iter().all(|tool| names.insert(tool.name())) {
        return Err(ApplyError::Tool);
    }
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
    let bundle = Bundle::from_files(overlay(default, profile, items, settings)?)?;
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
        tools: sorted_tools(&tools),
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
    /// The catalog snapshot holds an item the core rules refuse, other than a name or body.
    Catalog,
    /// The catalog snapshot holds more than
    /// [`MAX_BLOB_CATALOG_ITEMS`](fleet_proto::MAX_BLOB_CATALOG_ITEMS) items or more than
    /// [`MAX_BLOB_CATALOG_BYTES`](fleet_proto::MAX_BLOB_CATALOG_BYTES) content bytes.
    CatalogTooLarge,
    /// The catalog snapshot names one item id twice.
    CatalogDuplicate,
    /// An item digest differs from the digest of its fields.
    CatalogDigest,
    /// An item name is empty, over-long or outside the name shape.
    CatalogName,
    /// An item body is empty or over-long.
    CatalogBody,
    /// The blob is longer than [`MAX_PROFILE_JSON_BYTES`].
    TooLarge,
    /// A `tools` entry names a tool outside the registry, has a version that is not an exact
    /// pin, or is not a `{name, version}` pair.
    ToolEntry,
    /// The blob is not Profile JSON.
    Malformed,
    /// The blob is not the canonical JSON of its Profile.
    NotCanonical,
    /// The Profile hash differs from the hash in the Job's `ProfileRef`.
    HashMismatch,
    /// The shared validator refused the Profile.
    Invalid(ProfileInvalid),
    /// The Profile model is outside the box allowlist, [`floor::MODEL_DENIED_REASON`].
    ModelDenied,
    /// The Profile holds tools and the server did not stamp them granted,
    /// [`floor::TOOLS_DENIED_REASON`].
    ToolsNotGranted,
    /// The Profile could not be laid over the bundle.
    Apply(ApplyError),
}

const TOOL_ENTRY_REASON: &str =
    "profile invalid: a profile tool is not in the registry or its version is not an exact pin";
const TOO_MANY_TOOLS_REASON: &str = "profile invalid: a profile holds too many tools";
const DUPLICATE_TOOL_REASON: &str = "profile invalid: a profile names a tool twice";

fn tool_entry_refused(content: &[u8]) -> bool {
    serde_json::from_slice::<Value>(content)
        .ok()
        .and_then(|v| v.get("tools").and_then(|t| t.as_array().cloned()))
        .is_some_and(|entries| {
            entries
                .into_iter()
                .any(|e| serde_json::from_value::<ToolSpec>(e).is_err())
        })
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
        ProfileInvalid::TooManyTools => TOO_MANY_TOOLS_REASON,
        ProfileInvalid::DuplicateTool => DUPLICATE_TOOL_REASON,
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
            Self::Catalog => "profile invalid: the catalog snapshot is not valid",
            Self::CatalogTooLarge => "profile invalid: the catalog snapshot is too large",
            Self::CatalogDuplicate => "profile invalid: the catalog snapshot repeats an item id",
            Self::CatalogDigest => "profile invalid: a catalog item digest does not match",
            Self::CatalogName => "profile invalid: a catalog item name is not allowed",
            Self::CatalogBody => "profile invalid: a catalog item body is not allowed",
            Self::TooLarge => "profile invalid: profile blob is too large",
            Self::ToolEntry => TOOL_ENTRY_REASON,
            Self::Malformed => "profile invalid: profile blob is not profile JSON",
            Self::NotCanonical => "profile invalid: profile blob is not canonical",
            Self::HashMismatch => "profile invalid: profile hash does not match the job",
            Self::Invalid(err) => invalid_reason(*err),
            Self::ModelDenied => floor::MODEL_DENIED_REASON,
            Self::ToolsNotGranted => floor::TOOLS_DENIED_REASON,
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

/// Checks the catalog snapshot of a blob reply and returns its entries in wire order.
///
/// The snapshot must fit `MAX_BLOB_CATALOG_ITEMS` items and `MAX_BLOB_CATALOG_BYTES` content
/// bytes, checked before any item is read. Every item goes through the core rules, its digest
/// must equal the digest of its fields, and no id may repeat.
///
/// # Errors
///
/// Returns [`LoadError::CatalogTooLarge`] over either cap, [`LoadError::CatalogName`] and
/// [`LoadError::CatalogBody`] for a refused name or body, [`LoadError::CatalogDigest`] for a
/// digest that does not match, [`LoadError::CatalogDuplicate`] for a repeated id and
/// [`LoadError::Catalog`] for any other refused item.
pub fn validated_catalog(
    wire: &[fleet_proto::v1::CatalogItem],
) -> Result<Vec<CatalogEntry>, LoadError> {
    if !validate_blob_catalog(wire) {
        return Err(LoadError::CatalogTooLarge);
    }
    let mut seen = BTreeSet::new();
    let mut entries = Vec::with_capacity(wire.len());
    for raw in wire {
        let entry = catalog_entry_from_wire(raw).map_err(|err| match err {
            ProfileConvertError::Catalog(CatalogError::InvalidName) => LoadError::CatalogName,
            ProfileConvertError::Catalog(CatalogError::InvalidBody) => LoadError::CatalogBody,
            _ => LoadError::Catalog,
        })?;
        if raw.digest.as_slice() != entry.item().digest().as_slice() {
            return Err(LoadError::CatalogDigest);
        }
        if !seen.insert(entry.item().id().clone()) {
            return Err(LoadError::CatalogDuplicate);
        }
        entries.push(entry);
    }
    Ok(entries)
}

fn effective_items(
    profile: &Profile,
    wire: &[fleet_proto::v1::CatalogItem],
) -> Result<Vec<CatalogItem>, LoadError> {
    let mut kept = Vec::new();
    for entry in validated_catalog(wire)? {
        let item = entry.item();
        let off = profile.selection.ids().any(|id| id == item.id());
        if entry.enabled() && !off {
            kept.push(item.clone());
        }
    }
    kept.sort_by(|a, b| (a.kind(), a.name(), a.id()).cmp(&(b.kind(), b.name(), b.id())));
    Ok(kept)
}

/// Checks the blob `reply` against the Job's `expected` reference, then lays the Profile over
/// `default` with [`apply_profile`].
///
/// The reply must name `expected` exactly. The blob must fit [`MAX_PROFILE_JSON_BYTES`], parse
/// as a Profile, equal that Profile's canonical JSON and hash to the hash in `expected`. The
/// shared validator runs next, so fleetd does not trust the server's check. Then `allowlist`
/// re-checks the Profile model with [`floor::check_model`], before the overlay is built, so a
/// refused model leaves no bundle, argv or prompt behind (ADR-0054).
///
/// The catalog snapshot in `reply` is the effective set frozen at submit and is applied as
/// sent, with [`apply_effective`]. An item that is not admin-enabled or that the Profile
/// selection switched off is left out again here, so a snapshot cannot carry one in. An item
/// the core rules refuse, a digest that does not match, a repeated id or a snapshot over the
/// caps is refused by [`validated_catalog`]. A tool item needs the tools stamp like a Profile
/// tool.
///
/// `tools_granted` is the Job's `profile_tools_granted`. A Profile with tools and `false` is
/// refused with [`LoadError::ToolsNotGranted`] after the validator and before the model check,
/// the overlay or any install.
///
/// # Errors
///
/// Returns the [`LoadError`] of the first check that fails, [`LoadError::ToolsNotGranted`] for
/// unstamped tools and [`LoadError::ModelDenied`] for a model outside `allowlist`.
pub fn load_stamped(
    expected: &ProfileRef,
    reply: &GetProfileBlobReply,
    default: &Bundle,
    ceilings: &BoxCeilings,
    allowlist: Option<&ModelAllowlist>,
    tools_granted: bool,
    job_prompt: &str,
) -> Result<Applied, LoadError> {
    if reply.profile.as_ref() != Some(expected) {
        return Err(LoadError::Mismatch);
    }
    let want = ProfileHash::from_hex(&expected.hash).map_err(|_| LoadError::RefHash)?;
    if reply.content.len() > MAX_PROFILE_JSON_BYTES {
        return Err(LoadError::TooLarge);
    }
    let profile = Profile::from_stored_json(&reply.content).map_err(|_| {
        if tool_entry_refused(&reply.content) {
            LoadError::ToolEntry
        } else {
            LoadError::Malformed
        }
    })?;
    if profile.canonical_json() != reply.content {
        return Err(LoadError::NotCanonical);
    }
    if profile.hash() != want {
        return Err(LoadError::HashMismatch);
    }
    profile.validate().map_err(LoadError::Invalid)?;
    let items = effective_items(&profile, &reply.catalog)?;
    let has_tools =
        !profile.tools.is_empty() || items.iter().any(|item| item.kind() == CatalogKind::Tool);
    floor::check_tools_stamp(has_tools, tools_granted).map_err(|_| {
        tracing::warn!("profile tools carry no server stamp");
        LoadError::ToolsNotGranted
    })?;
    floor::check_model(allowlist, profile.model.as_deref()).map_err(|denied| {
        tracing::warn!(
            model = denied.model(),
            "profile model is outside the box allowlist"
        );
        LoadError::ModelDenied
    })?;
    apply_effective(&profile, &items, default, ceilings, job_prompt).map_err(LoadError::Apply)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use fleet_core::{ContextFile, Selection, Skill};
    use fleet_proto::{MAX_BLOB_CATALOG_BYTES, MAX_BLOB_CATALOG_ITEMS, catalog_kind_from_wire, v1};

    use super::*;

    fn stamped(
        reference: &ProfileRef,
        reply: &GetProfileBlobReply,
        granted: bool,
    ) -> Result<Applied, LoadError> {
        load_stamped(
            reference,
            reply,
            &Bundle::default(),
            &ceilings(),
            None,
            granted,
            "fix it",
        )
    }

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
            json!(["Bash(fleetd fetch *)", "Bash(fleetd broker *)", "Read"])
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
    fn the_broker_allow_is_in_settings_only_never_in_the_allowed_tools_argv()
    -> Result<(), ApplyError> {
        for profile in [
            Profile::default(),
            Profile {
                allow: vec!["Read".to_owned(), "Bash(gh *)".to_owned()],
                ..Profile::default()
            },
        ] {
            let applied = run(&profile)?;
            assert!(applied.argv.iter().all(|arg| !arg.contains("broker")));
            let raw = body(&applied, "settings.json").unwrap_or_default();
            let value: Value = serde_json::from_str(&raw).unwrap_or(Value::Null);
            assert!(
                value["permissions"]["allow"]
                    .as_array()
                    .is_some_and(|allow| allow.contains(&json!("Bash(fleetd broker *)")))
            );
            let deny = value["permissions"]["deny"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            assert!(deny.contains(&json!("Bash(git push *)")));
            assert!(deny.contains(&json!("Bash(gh *)")));
        }
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
            catalog: Vec::new(),
        };
        (reference, reply)
    }

    fn loaded(reference: &ProfileRef, reply: &GetProfileBlobReply) -> Result<Applied, LoadError> {
        stamped(reference, reply, true)
    }

    fn loaded_with(
        reference: &ProfileRef,
        reply: &GetProfileBlobReply,
        allowlist: Option<&ModelAllowlist>,
    ) -> Result<Applied, LoadError> {
        load_stamped(
            reference,
            reply,
            &Bundle::default(),
            &ceilings(),
            allowlist,
            true,
            "fix it",
        )
    }

    fn allow(entries: &[&str]) -> ModelAllowlist {
        ModelAllowlist::new(entries.iter().copied()).unwrap_or_else(|e| panic!("{e}"))
    }

    fn with_model(model: &str) -> Profile {
        Profile {
            model: Some(model.to_owned()),
            ..Profile::default()
        }
    }

    #[test]
    fn a_model_outside_the_box_allowlist_is_refused_with_the_fixed_reason() {
        let (reference, reply) = blob(&with_model("claude-haiku-4-5"));
        let list = allow(&["claude-opus-4-1"]);
        let out = loaded_with(&reference, &reply, Some(&list));
        assert_eq!(out, Err(LoadError::ModelDenied));
        assert_eq!(
            LoadError::ModelDenied.reason(),
            "profile invalid: profile model is not in the box allowlist"
        );
        assert!(!LoadError::ModelDenied.reason().contains("haiku"));
    }

    #[test]
    fn a_listed_model_is_applied_and_reaches_the_argv() -> Result<(), LoadError> {
        let (reference, reply) = blob(&with_model("claude-opus-4-1"));
        let list = allow(&["claude-sonnet-4-5", "claude-opus-4-1"]);
        let applied = loaded_with(&reference, &reply, Some(&list))?;
        assert!(
            applied
                .argv
                .windows(2)
                .any(|w| w == ["--model", "claude-opus-4-1"])
        );
        Ok(())
    }

    #[test]
    fn no_box_allowlist_trusts_the_server() -> Result<(), LoadError> {
        let (reference, reply) = blob(&with_model("claude-haiku-4-5"));
        loaded_with(&reference, &reply, None)?;
        loaded(&reference, &reply)?;
        Ok(())
    }

    #[test]
    fn a_profile_without_a_model_passes_a_box_allowlist() -> Result<(), LoadError> {
        let (reference, reply) = blob(&Profile::default());
        let list = allow(&["claude-opus-4-1"]);
        let applied = loaded_with(&reference, &reply, Some(&list))?;
        assert!(!applied.argv.iter().any(|a| a == "--model"));
        Ok(())
    }

    #[test]
    fn the_model_check_runs_before_the_overlay_is_built() {
        let profile = Profile {
            model: Some("claude-haiku-4-5".to_owned()),
            context_files: vec![file("A.md", "x"), file("a.md", "y")],
            ..Profile::default()
        };
        let (reference, reply) = blob(&profile);
        let open = loaded_with(&reference, &reply, None);
        assert_eq!(open, Err(LoadError::Apply(ApplyError::Collision)));
        let list = allow(&["claude-opus-4-1"]);
        let shut = loaded_with(&reference, &reply, Some(&list));
        assert_eq!(shut, Err(LoadError::ModelDenied));
    }

    #[test]
    fn the_model_check_runs_after_the_hash_and_validator_checks() {
        let list = allow(&["claude-opus-4-1"]);
        let (reference, mut reply) = blob(&with_model("claude-haiku-4-5"));
        reply.content = with_model("other").canonical_json();
        assert_eq!(
            loaded_with(&reference, &reply, Some(&list)),
            Err(LoadError::HashMismatch)
        );
        let hostile = with_model("claude-opus-4-1\r\n");
        let (reference, reply) = blob(&hostile);
        assert_eq!(
            loaded_with(&reference, &reply, Some(&list)),
            Err(LoadError::Invalid(ProfileInvalid::Model))
        );
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

    fn tool_profile(tools: &[(&str, &str)]) -> Profile {
        Profile {
            model: Some("opus".to_owned()),
            tools: tools
                .iter()
                .map(|(n, v)| ToolSpec::new(n, v).expect("spec"))
                .collect(),
            ..Profile::default()
        }
    }

    fn tool_blob(tools_json: &str) -> (ProfileRef, GetProfileBlobReply) {
        let content = format!("{{\"model\":\"opus\",\"tools\":{tools_json}}}").into_bytes();
        let reference = ProfileRef {
            name: "p".to_owned(),
            version: 1,
            hash: "0".repeat(64),
        };
        let reply = GetProfileBlobReply {
            profile: Some(reference.clone()),
            content,
            catalog: Vec::new(),
        };
        (reference, reply)
    }

    fn pairs(applied: &Applied) -> Vec<(String, String)> {
        applied
            .tools
            .iter()
            .map(|t| {
                (
                    t.name().as_str().to_owned(),
                    t.version().as_str().to_owned(),
                )
            })
            .collect()
    }

    #[test]
    fn a_profile_with_tools_surfaces_the_validated_list() -> Result<(), LoadError> {
        let profile = tool_profile(&[("node", "20.11.1"), ("jq", "1.7.1")]);
        let (reference, reply) = blob(&profile);
        let applied = loaded(&reference, &reply)?;
        assert_eq!(
            pairs(&applied),
            vec![
                ("node".to_owned(), "20.11.1".to_owned()),
                ("jq".to_owned(), "1.7.1".to_owned())
            ]
        );
        Ok(())
    }

    #[test]
    fn tools_with_the_stamp_load() -> Result<(), LoadError> {
        let (reference, reply) = blob(&tool_profile(&[("jq", "1.7.1")]));
        assert_eq!(stamped(&reference, &reply, true)?.tools.len(), 1);
        Ok(())
    }

    #[test]
    fn tools_without_the_stamp_are_refused_with_the_fixed_reason() {
        let (reference, reply) = blob(&tool_profile(&[("jq", "1.7.1")]));
        let out = stamped(&reference, &reply, false);
        assert_eq!(out, Err(LoadError::ToolsNotGranted));
        assert_eq!(
            LoadError::ToolsNotGranted.reason(),
            "profile invalid: profile tools are not granted by the server"
        );
    }

    #[test]
    fn no_tools_load_with_or_without_the_stamp() -> Result<(), LoadError> {
        let (reference, reply) = blob(&full());
        assert_eq!(
            stamped(&reference, &reply, false)?.tools,
            Vec::<ToolSpec>::new()
        );
        assert_eq!(
            stamped(&reference, &reply, true)?.tools,
            Vec::<ToolSpec>::new()
        );
        Ok(())
    }

    #[test]
    fn the_stamp_check_runs_before_the_model_check() {
        let mut profile = tool_profile(&[("jq", "1.7.1")]);
        profile.model = Some("haiku".to_owned());
        let (reference, reply) = blob(&profile);
        let list = allow(&["opus"]);
        let out = load_stamped(
            &reference,
            &reply,
            &Bundle::default(),
            &ceilings(),
            Some(&list),
            false,
            "fix it",
        );
        assert_eq!(out, Err(LoadError::ToolsNotGranted));
    }

    #[test]
    fn a_profile_without_tools_has_an_empty_list() -> Result<(), LoadError> {
        let (reference, reply) = blob(&full());
        assert_eq!(loaded(&reference, &reply)?.tools, Vec::<ToolSpec>::new());
        Ok(())
    }

    #[test]
    fn tools_never_reach_the_settings_or_the_overlay() -> Result<(), LoadError> {
        let plain = Profile {
            model: Some("opus".to_owned()),
            ..Profile::default()
        };
        let with = tool_profile(&[("node", "20.11.1")]);
        let (r1, b1) = blob(&plain);
        let (r2, b2) = blob(&with);
        let a = loaded(&r1, &b1)?;
        let b = loaded(&r2, &b2)?;
        assert_eq!(a.bundle, b.bundle);
        assert_eq!(a.argv, b.argv);
        assert_eq!(a.prompt, b.prompt);
        assert_eq!(
            body(&a, ".claude/settings.json"),
            body(&b, ".claude/settings.json")
        );
        for raw in b.bundle.files().values() {
            assert!(!String::from_utf8_lossy(raw).contains("20.11.1"));
        }
        Ok(())
    }

    #[test]
    fn a_hostile_tool_entry_is_a_fixed_error() {
        let long = "1".repeat(300);
        let over_name = "n".repeat(300);
        let versions = [
            "",
            "latest",
            "1/2",
            "1..2",
            "1\\u0000",
            "1\\n",
            "1.0\\u00e9",
            "1 ",
            "v1",
            "x",
            &long,
        ];
        let names = [
            "",
            "emacs",
            "NODE",
            "Node",
            "no/de",
            "..",
            "node\\u0000",
            "node\\n",
            "n\\u00f6de",
            &over_name,
        ];
        let mut rows: Vec<String> = Vec::new();
        for v in versions {
            rows.push(format!(r#"[{{"name":"node","version":"{v}"}}]"#));
        }
        for n in names {
            rows.push(format!(r#"[{{"name":"{n}","version":"1.0.0"}}]"#));
        }
        rows.push(r#"[{"name":"node"}]"#.to_owned());
        rows.push(r#"[{"name":"node","version":"1","x":1}]"#.to_owned());
        rows.push(r#"[{"name":"node","version":1}]"#.to_owned());
        for row in rows {
            let (reference, reply) = tool_blob(&row);
            assert_eq!(
                loaded(&reference, &reply),
                Err(LoadError::ToolEntry),
                "{row}"
            );
        }
        assert_eq!(
            LoadError::ToolEntry.reason(),
            "profile invalid: a profile tool is not in the registry or its version is not an exact pin"
        );
    }

    #[test]
    fn duplicate_and_excess_tools_are_fixed_errors() {
        let dup = tool_profile(&[("node", "20.11.1"), ("node", "18.0.0")]);
        let (reference, reply) = blob(&dup);
        assert_eq!(
            loaded(&reference, &reply),
            Err(LoadError::Invalid(ProfileInvalid::DuplicateTool))
        );
        assert_eq!(
            LoadError::Invalid(ProfileInvalid::DuplicateTool).reason(),
            "profile invalid: a profile names a tool twice"
        );
        let names = fleet_core::tools::ToolName::ALL;
        let many = Profile {
            tools: (0..=fleet_core::MAX_TOOLS)
                .map(|i| ToolSpec::new(names[i % names.len()].as_str(), "1.0.0").expect("spec"))
                .collect(),
            ..Profile::default()
        };
        let (reference, reply) = blob(&many);
        assert_eq!(
            loaded(&reference, &reply),
            Err(LoadError::Invalid(ProfileInvalid::TooManyTools))
        );
        assert_eq!(
            LoadError::Invalid(ProfileInvalid::TooManyTools).reason(),
            "profile invalid: a profile holds too many tools"
        );
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
            LoadError::Catalog,
            LoadError::CatalogTooLarge,
            LoadError::CatalogDuplicate,
            LoadError::CatalogDigest,
            LoadError::CatalogName,
            LoadError::CatalogBody,
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

    fn wire(kind: i32, id: &str, name: &str, content: &str, enabled: bool) -> v1::CatalogItem {
        v1::CatalogItem {
            id: id.to_owned(),
            kind,
            name: name.to_owned(),
            content: content.to_owned(),
            digest: digest_of(kind, id, name, content),
            admin_enabled: enabled,
        }
    }

    fn digest_of(kind: i32, id: &str, name: &str, content: &str) -> Vec<u8> {
        catalog_kind_from_wire(kind)
            .ok()
            .and_then(|k| CatalogItem::new(k, id, name, content).ok())
            .map(|item| item.digest().to_vec())
            .unwrap_or_default()
    }

    const SKILL: i32 = v1::CatalogKind::Skill as i32;
    const SUBAGENT: i32 = v1::CatalogKind::Subagent as i32;
    const TOOL: i32 = v1::CatalogKind::Tool as i32;
    const CONTEXT: i32 = v1::CatalogKind::Context as i32;

    fn with_catalog(
        profile: &Profile,
        catalog: Vec<v1::CatalogItem>,
        granted: bool,
    ) -> Result<Applied, LoadError> {
        let (reference, mut reply) = blob(profile);
        reply.catalog = catalog;
        stamped(&reference, &reply, granted)
    }

    fn four() -> Vec<v1::CatalogItem> {
        vec![
            wire(SKILL, "s1", "lint", "---\nname: lint\n---\nbody", true),
            wire(
                SUBAGENT,
                "a1",
                "review",
                "---\nname: review\n---\nrev",
                true,
            ),
            wire(CONTEXT, "c1", "rules", "CTX", true),
            wire(TOOL, "t1", "jq", "1.7.1", true),
        ]
    }

    #[test]
    fn the_frozen_set_lands_in_the_agent_config() -> Result<(), LoadError> {
        let applied = with_catalog(&Profile::default(), four(), true)?;
        assert_eq!(
            body(&applied, "skills/lint/SKILL.md").as_deref(),
            Some("---\nname: lint\n---\nbody")
        );
        assert_eq!(
            body(&applied, "agents/review.md").as_deref(),
            Some("---\nname: review\n---\nrev")
        );
        assert_eq!(
            body(&applied, ".claude/ctx/rules.md").as_deref(),
            Some("CTX")
        );
        let md = body(&applied, "CLAUDE.md").unwrap_or_default();
        assert!(md.ends_with("@.claude/ctx/rules.md\n"), "{md:?}");
        assert_eq!(
            applied.tools,
            vec![ToolSpec::new("jq", "1.7.1").unwrap_or_else(|e| panic!("{e}"))]
        );
        Ok(())
    }

    #[test]
    fn admin_disabled_and_switched_off_items_are_absent() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut catalog = four();
        catalog.push(wire(SKILL, "s2", "gone", "G", false));
        catalog.push(wire(SKILL, "s3", "off", "O", true));
        catalog.push(wire(SUBAGENT, "a2", "offagent", "O", true));
        catalog.push(wire(CONTEXT, "c2", "offctx", "O", true));
        catalog.push(wire(TOOL, "t2", "node", "20.11.1", true));
        let profile = Profile {
            selection: Selection::from_json(
                br#"[{"item_id":"s3"},{"item_id":"a2"},{"item_id":"c2"},{"item_id":"t2"}]"#,
            )?,
            ..Profile::default()
        };
        let applied = with_catalog(&profile, catalog, true)?;
        for path in [
            "skills/gone/SKILL.md",
            "skills/off/SKILL.md",
            "agents/offagent.md",
            ".claude/ctx/offctx.md",
        ] {
            assert_eq!(body(&applied, path), None, "{path}");
        }
        let md = body(&applied, "CLAUDE.md").unwrap_or_default();
        assert!(!md.contains("offctx"), "{md:?}");
        assert_eq!(applied.tools.len(), 1);
        assert!(body(&applied, "skills/lint/SKILL.md").is_some());
        Ok(())
    }

    #[test]
    fn a_context_item_after_profile_context_files_keeps_import_order() -> Result<(), LoadError> {
        let profile = Profile {
            claude_md: Some("base".to_owned()),
            context_files: vec![file("y.md", "Y")],
            ..Profile::default()
        };
        let applied = with_catalog(
            &profile,
            vec![wire(CONTEXT, "c1", "rules", "C", true)],
            true,
        )?;
        assert_eq!(
            body(&applied, "CLAUDE.md").as_deref(),
            Some("base\n@.claude/ctx/y.md\n@.claude/ctx/rules.md\n")
        );
        let only = with_catalog(
            &Profile {
                claude_md: Some("base".to_owned()),
                ..Profile::default()
            },
            vec![wire(CONTEXT, "c1", "rules", "C", true)],
            true,
        )?;
        assert_eq!(
            body(&only, "CLAUDE.md").as_deref(),
            Some("base\n@.claude/ctx/rules.md\n")
        );
        Ok(())
    }

    fn hostile_names() -> Vec<String> {
        [
            "",
            "a\r",
            "a\r\nb",
            "a\nb",
            "a\u{85}b",
            "a\u{2028}b",
            "a\\b",
            "a/b",
            "../x",
            "..",
            ".",
            "a\0b",
            " a",
            "a b",
            "a\tb",
            "caf\u{e9}",
            "\u{ff41}",
            "Abc",
            "ABC",
            "a.b",
        ]
        .into_iter()
        .map(str::to_owned)
        .chain([String::from_utf8(vec![b'a'; 65]).unwrap_or_default()])
        .collect()
    }

    #[test]
    fn hostile_item_names_and_ids_fail_closed() {
        for kind in [SKILL, SUBAGENT, CONTEXT, TOOL] {
            for raw in hostile_names() {
                let by_name = vec![wire(kind, "ok", &raw, "1.0.0", true)];
                assert_eq!(
                    with_catalog(&Profile::default(), by_name, true).err(),
                    Some(LoadError::CatalogName),
                    "name {raw:?} kind {kind}"
                );
                let by_id = vec![wire(kind, &raw, "jq", "1.0.0", true)];
                assert_eq!(
                    with_catalog(&Profile::default(), by_id, true).err(),
                    Some(LoadError::Catalog),
                    "id {raw:?} kind {kind}"
                );
            }
        }
    }

    #[test]
    fn a_bad_kind_body_tool_or_repeated_id_fails_closed() {
        let cases = [
            vec![wire(0, "a", "a", "x", true)],
            vec![wire(9, "a", "a", "x", true)],
            vec![wire(TOOL, "a", "jq", "latest", true)],
            vec![wire(TOOL, "a", "not-a-tool", "1.0.0", true)],
        ];
        for catalog in cases {
            assert_eq!(
                with_catalog(&Profile::default(), catalog, true).err(),
                Some(LoadError::Catalog)
            );
        }
        assert_eq!(
            with_catalog(
                &Profile::default(),
                vec![wire(SKILL, "a", "a", "", true)],
                true
            )
            .err(),
            Some(LoadError::CatalogBody)
        );
        assert_eq!(
            LoadError::Catalog.reason(),
            "profile invalid: the catalog snapshot is not valid"
        );
    }

    fn skills(count: usize) -> Vec<v1::CatalogItem> {
        (0..count)
            .map(|n| wire(SKILL, &format!("s{n}"), &format!("n{n}"), "x", true))
            .collect()
    }

    #[test]
    fn a_catalog_at_the_item_cap_loads() -> Result<(), LoadError> {
        let entries = validated_catalog(&skills(MAX_BLOB_CATALOG_ITEMS))?;
        assert_eq!(entries.len(), MAX_BLOB_CATALOG_ITEMS);
        assert_eq!(entries[0].item().id().as_str(), "s0");
        Ok(())
    }

    #[test]
    fn a_catalog_one_item_over_the_cap_is_refused() {
        assert_eq!(
            validated_catalog(&skills(MAX_BLOB_CATALOG_ITEMS + 1)).err(),
            Some(LoadError::CatalogTooLarge)
        );
        assert_eq!(
            with_catalog(
                &Profile::default(),
                skills(MAX_BLOB_CATALOG_ITEMS + 1),
                true
            )
            .err(),
            Some(LoadError::CatalogTooLarge)
        );
    }

    #[test]
    fn a_catalog_at_the_byte_cap_loads_and_one_byte_over_is_refused() -> Result<(), LoadError> {
        let per = MAX_BLOB_CATALOG_BYTES / 16;
        let at: Vec<_> = (0..16)
            .map(|n| {
                wire(
                    SKILL,
                    &format!("s{n}"),
                    &format!("n{n}"),
                    &"x".repeat(per),
                    true,
                )
            })
            .collect();
        validated_catalog(&at)?;
        let mut over = at;
        over[0] = wire(SKILL, "s0", "n0", &"x".repeat(per + 1), true);
        assert_eq!(
            validated_catalog(&over).err(),
            Some(LoadError::CatalogTooLarge)
        );
        Ok(())
    }

    #[test]
    fn a_repeated_id_is_refused_with_its_own_reason() {
        let twice = vec![
            wire(SKILL, "a", "one", "x", true),
            wire(SKILL, "a", "two", "x", true),
        ];
        let mixed = vec![
            wire(SKILL, "a", "one", "x", false),
            wire(SKILL, "a", "two", "x", true),
        ];
        assert_eq!(
            with_catalog(&Profile::default(), mixed, true).err(),
            Some(LoadError::CatalogDuplicate)
        );
        assert_eq!(
            validated_catalog(&twice).err(),
            Some(LoadError::CatalogDuplicate)
        );
        assert_eq!(
            LoadError::CatalogDuplicate.reason(),
            "profile invalid: the catalog snapshot repeats an item id"
        );
    }

    #[test]
    fn a_tampered_digest_is_refused_and_fails_the_load() {
        let mut flips = Vec::new();
        for field in 0..4 {
            let mut items = four();
            match field {
                0 => items[0].content.push('x'),
                1 => items[0].name = "other".to_owned(),
                2 => items[0].digest[0] ^= 1,
                _ => items[0].digest.clear(),
            }
            flips.push(items);
        }
        for items in flips {
            assert_eq!(
                validated_catalog(&items).err(),
                Some(LoadError::CatalogDigest)
            );
            assert_eq!(
                with_catalog(&Profile::default(), items, true).err(),
                Some(LoadError::CatalogDigest)
            );
        }
        let mut short = four();
        short[0].digest.pop();
        assert_eq!(
            validated_catalog(&short).err(),
            Some(LoadError::CatalogDigest)
        );
        assert_eq!(
            LoadError::CatalogDigest.reason(),
            "profile invalid: a catalog item digest does not match"
        );
    }

    #[test]
    fn a_name_at_the_limit_loads_and_one_byte_over_is_refused() -> Result<(), LoadError> {
        let at = "a".repeat(fleet_core::catalog::MAX_NAME_BYTES);
        validated_catalog(&[wire(SKILL, "a", &at, "x", true)])?;
        let over = "a".repeat(fleet_core::catalog::MAX_NAME_BYTES + 1);
        assert_eq!(
            validated_catalog(&[wire(SKILL, "a", &over, "x", true)]).err(),
            Some(LoadError::CatalogName)
        );
        assert_eq!(
            LoadError::CatalogName.reason(),
            "profile invalid: a catalog item name is not allowed"
        );
        Ok(())
    }

    #[test]
    fn hostile_names_get_the_name_reason() {
        for raw in hostile_names() {
            assert_eq!(
                validated_catalog(&[wire(SKILL, "a", &raw, "x", true)]).err(),
                Some(LoadError::CatalogName),
                "name {raw:?}"
            );
        }
    }

    #[test]
    fn a_body_at_the_limit_loads_and_one_byte_over_is_refused() -> Result<(), LoadError> {
        let at = "x".repeat(fleet_core::catalog::MAX_BODY_BYTES);
        validated_catalog(&[wire(SKILL, "a", "one", &at, true)])?;
        let over = "x".repeat(fleet_core::catalog::MAX_BODY_BYTES + 1);
        assert_eq!(
            validated_catalog(&[wire(SKILL, "a", "one", &over, true)]).err(),
            Some(LoadError::CatalogBody)
        );
        assert_eq!(
            validated_catalog(&[wire(SKILL, "a", "one", "", true)]).err(),
            Some(LoadError::CatalogBody)
        );
        assert_eq!(
            LoadError::CatalogBody.reason(),
            "profile invalid: a catalog item body is not allowed"
        );
        Ok(())
    }

    #[test]
    fn a_subagent_cannot_loosen_the_floor() {
        let bad = [
            "---\nname: a\npermissionMode: bypassPermissions\n---\nx",
            "---\nname: a\nPERMISSIONMODE: acceptEdits\n---\nx",
            "---\nname: a\nhooks:\n  Stop: x\n---\nx",
            "---\nname: a\nmcpServers: [x]\n---\nx",
            "---\nname: a\ntools: Read, Edit\n---\nx",
            "---\nname: a\ntools: [Read, \"Write\"]\n---\nx",
            "---\nname: a\ntools: write\n---\nx",
            "---\r\nname: a\r\ntools: MultiEdit\r\n---\r\nx",
            "\u{feff}---\nname: a\ntools: Edit\n---\nx",
            "---\nname: a\ntools:\n  - Read\n  - NotebookEdit\n---\nx",
            "---\nname: a\ntools: Bash(gh pr *)\n---\nx",
            "---\nname: a\ntools: WebFetch\n---\nx",
            "---\nname: a\ntools:\n- Edit\n---\nx",
            "---\nTools: Write\n---\nx",
            "---\nname: a\nmodel: opus\n---\nx",
            "---\nname: a\nmodel: haiku\n---\nx",
            "---  \nname: a\npermissionMode: x\n---\nb",
            "---\nname: a\u{85}permissionMode: x\n---\nb",
            "---\nname: a\u{2028}permissionMode: x\n---\nb",
            "---\nname: a\u{2029}permissionMode: x\n---\nb",
            "\u{85}---\nname: a\npermissionMode: x\n---\nb",
            "\u{2028}---\nname: a\npermissionMode: x\n---\nb",
            "\u{2029}---\nname: a\npermissionMode: x\n---\nb",
        ];
        for text in bad {
            assert_eq!(
                with_catalog(
                    &Profile::default(),
                    vec![wire(SUBAGENT, "a", "a", text, true)],
                    true
                )
                .err(),
                Some(LoadError::Apply(ApplyError::Subagent)),
                "{text:?}"
            );
        }
        let good = [
            "---\nname: a\ntools: Read, Grep, Bash\n---\nx",
            "---\nname: a\ndescription: Edit, Write\n---\nWrite hooks: and permissionMode: later",
            "no frontmatter permissionMode: x",
            "---\nname: a\n---\ntools: Edit\npermissionMode: x\nx",
        ];
        for text in good {
            assert!(
                with_catalog(
                    &Profile::default(),
                    vec![wire(SUBAGENT, "a", "a", text, true)],
                    true
                )
                .is_ok(),
                "{text:?}"
            );
        }
        let skill = "---\nname: a\npermissionMode: x\ntools: Edit\n---\nx";
        assert!(
            with_catalog(
                &Profile::default(),
                vec![wire(SKILL, "a", "a", skill, true)],
                true
            )
            .is_ok()
        );
    }

    #[test]
    fn an_item_cannot_overwrite_a_default_bundle_file() {
        let skill = vec![wire(SKILL, "a", "fetch", "x", true)];
        assert_eq!(
            with_catalog(&Profile::default(), skill, true).err(),
            Some(LoadError::Apply(ApplyError::DefaultPath))
        );
        let broker = vec![wire(SKILL, "a", "broker", "x", true)];
        assert_eq!(
            with_catalog(&Profile::default(), broker, true).err(),
            Some(LoadError::Apply(ApplyError::DefaultPath))
        );
    }

    #[test]
    fn item_paths_collide_with_profile_paths_without_case() {
        let profile = Profile {
            context_files: vec![file("rules.md", "Y")],
            ..Profile::default()
        };
        assert_eq!(
            with_catalog(&profile, vec![wire(CONTEXT, "c", "rules", "C", true)], true).err(),
            Some(LoadError::Apply(ApplyError::Collision))
        );
        let skills = Profile {
            skills: vec![Skill {
                name: "lint".to_owned(),
                files: vec![file("SKILL.md", "S")],
            }],
            ..Profile::default()
        };
        assert_eq!(
            with_catalog(&skills, vec![wire(SKILL, "s", "lint", "C", true)], true).err(),
            Some(LoadError::Apply(ApplyError::Collision))
        );
    }

    #[test]
    fn catalog_tools_need_the_stamp_and_never_repeat_a_pin() {
        let tool = vec![wire(TOOL, "t", "jq", "1.7.1", true)];
        assert_eq!(
            with_catalog(&Profile::default(), tool.clone(), false).err(),
            Some(LoadError::ToolsNotGranted)
        );
        let off = vec![wire(TOOL, "t", "jq", "1.7.1", false)];
        assert!(with_catalog(&Profile::default(), off, false).is_ok());
        let pinned = Profile {
            tools: vec![ToolSpec::new("jq", "1.7.1").unwrap_or_else(|e| panic!("{e}"))],
            ..Profile::default()
        };
        assert_eq!(
            with_catalog(&pinned, tool, true).err(),
            Some(LoadError::Apply(ApplyError::Tool))
        );
        let forward = vec![
            wire(TOOL, "t2", "node", "20.11.1", true),
            wire(TOOL, "t1", "jq", "1.7.1", true),
        ];
        let mut backward = forward.clone();
        backward.reverse();
        let a = with_catalog(&Profile::default(), forward, true).map(|a| a.tools);
        let b = with_catalog(&Profile::default(), backward, true).map(|a| a.tools);
        assert_eq!(a.as_ref().map(Vec::len), Ok(2));
        assert_eq!(a, b);
    }

    #[test]
    fn an_empty_catalog_changes_nothing() -> Result<(), LoadError> {
        let plain = with_catalog(&full(), Vec::new(), false)?;
        let (reference, reply) = blob(&full());
        assert_eq!(plain, loaded(&reference, &reply)?);
        assert_eq!(
            plain
                .bundle
                .files()
                .keys()
                .filter(|p| p.starts_with("agents"))
                .count(),
            0
        );
        Ok(())
    }
}
