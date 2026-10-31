//! The Codex job path of the runner (ADR-0044).
//!
//! A Codex job runs the argv and environment of [`crate::agent::codex`]. Its one secret is the
//! `codex_api_key` the credential holder gave this job, and its `CODEX_HOME` lives in the
//! runner until [`AgentRunner::end_job`] drops it.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use fleet_core::credential::CredentialKind;
use fleet_proto::v1::{Job, JobKind};

use crate::agent::codex::{self, CodexHome, CodexJob};
use crate::runner::{AgentRunner, AgentSpec, Reporter, VersionStamp};

impl<R: Reporter> AgentRunner<R> {
    /// True when `job` runs under the Codex runner. A judge job always runs under Claude.
    pub(crate) fn is_codex(job: &Job) -> bool {
        job.kind() != JobKind::Judge
            && crate::agent::resolve(&job.agent).is_some_and(|runner| runner.name() == codex::NAME)
    }

    /// The per-job `CODEX_HOME` of `job_id`, built under the jobs root on the first call and
    /// kept until [`AgentRunner::end_job`].
    pub(crate) fn codex_home(&self, job_id: &str, cwd: &Path) -> io::Result<PathBuf> {
        let mut homes = self
            .codex_homes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(home) = homes.get(job_id) {
            return Ok(home.path().to_path_buf());
        }
        let home = CodexHome::create(self.jobs_root(cwd), job_id)?;
        let path = home.path().to_path_buf();
        homes.insert(job_id.to_owned(), home);
        drop(homes);
        Ok(path)
    }

    pub(crate) fn forget_codex_home(&self, job_id: &str) {
        self.codex_homes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }

    fn codex_api_key(&self, job_id: &str) -> Option<String> {
        let held = self.credentials.as_ref()?.get(job_id)?;
        let secret = held.get(CredentialKind::CodexApiKey)?;
        std::str::from_utf8(secret.expose()).ok().map(str::to_owned)
    }

    /// The command line and environment of a Codex job.
    ///
    /// The environment is [`codex::env`] over the base environment: no box secret passes, and
    /// `CODEX_API_KEY` is set from the held `codex_api_key` only. A job with none held, or a
    /// runner with no credential book, gets no key.
    pub(crate) fn codex_spec(&self, job: &Job, cwd: &Path, home: &Path) -> AgentSpec {
        let applied = self.profile_for(job);
        let prompt = applied
            .as_deref()
            .map_or(job.prompt.as_str(), |applied| applied.prompt.as_str());
        let model = applied.as_deref().and_then(|applied| {
            let at = applied.argv.iter().position(|arg| arg == "--model")?;
            applied.argv.get(at + 1).map(String::as_str)
        });
        let argv = codex::argv(
            self.config.codex_bin.as_path(),
            &CodexJob { prompt, cwd, model },
        );
        let codex_home = self
            .codex_home(&job.job_id, cwd)
            .unwrap_or_else(|_| self.jobs_root(cwd).join(".codex").join(&job.job_id));
        let key = self.codex_api_key(&job.job_id);
        let mut env = codex::env(
            &self.config.base_env,
            key.as_deref().unwrap_or_default(),
            &job.job_id,
            home,
            &codex_home,
        );
        if key.is_none() {
            env.remove(&OsString::from(codex::API_KEY_ENV));
        }
        let bundle = applied
            .as_deref()
            .map_or(&self.config.bundle, |applied| &applied.bundle);
        AgentSpec {
            argv,
            env,
            cwd: cwd.to_path_buf(),
            stamp: VersionStamp {
                bundle_sha: bundle.sha256(),
                ..VersionStamp::default()
            },
        }
    }
}
