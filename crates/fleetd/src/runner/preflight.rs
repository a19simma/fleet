//! The tool pre-flight of the runner (ADR-0048).
//!
//! A job whose Profile carries `tools` must find each tool in the [`ToolCache`] before its agent
//! starts. A hit is used as is. A miss goes to the [`ToolInstaller`], which stands for the
//! sandboxed install unit, and the cache is read again afterwards. Any failure ends the job with
//! [`TOOL_PREFLIGHT_FAILED`]: no tool name, path or stderr reaches that text, and the detail
//! goes to the log as a closed reason only.
//!
//! The agent `PATH` is built from the resolved tools by [`build_agent_path`] and replaces
//! whatever the parent environment held ([`apply_agent_path_env`]). A job without tools never
//! passes through here, so its environment is unchanged.
//!
//! Nothing here is verified on a live box. No production [`ToolInstaller`] exists yet: a box
//! with `[mise]` configured serves cache hits and fails every miss.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, PoisonError};

use fleet_core::tools::ToolSpec;
use fleet_proto::v1::Job;

use crate::agent_exec::{AgentPathError, build_agent_path, refuse_path_override};
use crate::runner::{AgentRunner, Reporter};
use crate::tools::ToolCache;

/// The one error text of a job whose tools could not be resolved. It never names a tool.
pub const TOOL_PREFLIGHT_FAILED: &str = "tool preflight failed";

/// The future an install returns.
pub type InstallFuture<'a> = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>>;

/// Installs missing tools into the cache the pre-flight reads.
///
/// An implementation runs the install through the launcher path (the sandboxed install unit)
/// and returns once the cache holds the entries or the install failed. The runner re-reads the
/// cache afterwards and trusts nothing the installer reports beyond success or failure.
pub trait ToolInstaller: Send + Sync + fmt::Debug {
    /// Installs `tools` for job `job_id`.
    ///
    /// # Errors
    ///
    /// Returns the I/O error of a failed install.
    fn install<'a>(&'a self, job_id: &'a str, tools: &'a [ToolSpec]) -> InstallFuture<'a>;
}

/// The cache and the optional installer the pre-flight uses.
#[derive(Debug, Clone)]
pub struct ToolPreflight {
    cache: ToolCache,
    installer: Option<Arc<dyn ToolInstaller>>,
}

impl ToolPreflight {
    /// A pre-flight over `cache` with no installer: every miss fails.
    #[must_use]
    pub const fn new(cache: ToolCache) -> Self {
        Self {
            cache,
            installer: None,
        }
    }

    /// Installs misses through `installer`.
    #[must_use]
    pub fn with_installer(mut self, installer: Arc<dyn ToolInstaller>) -> Self {
        self.installer = Some(installer);
        self
    }
}

/// Why a pre-flight failed. Logged as its [`fmt::Display`] text, never sent to the server.
#[derive(Debug)]
#[non_exhaustive]
pub enum PreflightError {
    /// The box has no pre-flight configured.
    NotConfigured,
    /// A tool is missing and no installer is configured.
    NoInstaller,
    /// The installer failed.
    Install(io::ErrorKind),
    /// The cache lookup or the `PATH` build failed.
    Path(AgentPathError),
}

impl fmt::Display for PreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured => f.write_str("no mise pins are configured on this box"),
            Self::NoInstaller => f.write_str("a tool is not cached and no installer is wired"),
            Self::Install(kind) => write!(f, "install failed: {kind}"),
            Self::Path(err) => write!(f, "agent path refused: {err}"),
        }
    }
}

impl ToolPreflight {
    pub(crate) async fn resolve(
        &self,
        job_id: &str,
        tools: &[ToolSpec],
        passthrough: &[String],
    ) -> Result<String, PreflightError> {
        refuse_path_override(passthrough.iter().map(String::as_str))
            .map_err(PreflightError::Path)?;
        let mut missing = Vec::new();
        for tool in tools {
            let hit = self
                .cache
                .lookup(tool.name().as_str(), tool.version().as_str())
                .map_err(|_| PreflightError::Path(AgentPathError::Cache))?;
            if hit.is_none() {
                missing.push(tool.clone());
            }
        }
        if !missing.is_empty() {
            let installer = self.installer.as_ref().ok_or(PreflightError::NoInstaller)?;
            installer
                .install(job_id, &missing)
                .await
                .map_err(|err| PreflightError::Install(err.kind()))?;
        }
        let pairs: Vec<(String, String)> = tools
            .iter()
            .map(|tool| {
                (
                    tool.name().as_str().to_owned(),
                    tool.version().as_str().to_owned(),
                )
            })
            .collect();
        build_agent_path(&self.cache, &pairs).map_err(PreflightError::Path)
    }
}

/// Replaces every `PATH` key of `env`, in any letter case, with `path`.
pub(super) fn apply_agent_path_env(env: &mut BTreeMap<OsString, OsString>, path: &str) {
    env.retain(|key, _| !key.to_str().is_some_and(|k| k.eq_ignore_ascii_case("PATH")));
    env.insert(OsString::from("PATH"), OsString::from(path));
}

impl<R: Reporter> AgentRunner<R> {
    /// Resolves the tools of `job`'s Profile before its agent starts.
    ///
    /// A job with no kept Profile or no tools returns `Ok` and changes nothing. Otherwise every
    /// tool must be cached or installable, and the resulting `PATH` is kept for
    /// [`AgentRunner::agent_spec`] until [`AgentRunner::clear_profile`].
    ///
    /// # Errors
    ///
    /// Returns [`TOOL_PREFLIGHT_FAILED`]. The caller must end the job with it and must not run
    /// the agent. The reason is logged without any tool name.
    pub async fn preflight_tools(&self, job: &Job) -> Result<(), &'static str> {
        let tools = self
            .profile_for(job)
            .map(|applied| applied.tools.clone())
            .unwrap_or_default();
        if tools.is_empty() {
            return Ok(());
        }
        let outcome = match &self.tool_preflight {
            Some(preflight) => {
                preflight
                    .resolve(&job.job_id, &tools, &self.config.env_passthrough)
                    .await
            }
            None => Err(PreflightError::NotConfigured),
        };
        match outcome {
            Ok(path) => {
                self.tool_paths
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(Self::carry_key(job), path);
                Ok(())
            }
            Err(err) => {
                tracing::warn!(reason = %err, "tool preflight failed");
                Err(TOOL_PREFLIGHT_FAILED)
            }
        }
    }

    pub(crate) fn tool_path_for(&self, job: &Job) -> Option<String> {
        self.tool_paths
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&Self::carry_key(job))
            .cloned()
    }

    pub(crate) fn clear_tool_path(&self, job: &Job) {
        self.tool_paths
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&Self::carry_key(job));
    }
}
