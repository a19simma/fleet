//! The Kimi job path of the runner (ADR-0044).
//!
//! A Kimi job runs the argv and environment of [`crate::agent::kimi`]. Its one secret is the
//! `kimi_membership_key` or `kimi_platform_key` the credential holder gave this job, and its
//! `KIMI_CODE_HOME` lives in the runner until [`AgentRunner::end_job`] drops it.
//!
//! `-p` mode runs under the auto policy and asks for no approval, so a Kimi job runs only on a
//! disposable box ([`crate::agent::kimi::ERR_NOT_DISPOSABLE`] otherwise).

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::PoisonError;

use fleet_core::credential::CredentialKind;
use fleet_proto::v1::{Job, JobKind};

use crate::agent::kimi::{self, KimiHome, KimiJob};
use crate::runner::{AgentRunner, AgentSpec, Reporter, VersionStamp};

impl<R: Reporter> AgentRunner<R> {
    /// True when `job` runs under the Kimi runner. A judge job always runs under Claude.
    pub(crate) fn is_kimi(job: &Job) -> bool {
        job.kind() != JobKind::Judge
            && crate::agent::resolve(&job.agent).is_some_and(|runner| runner.name() == kimi::NAME)
    }

    /// The fixed failure text for a job no runner may start, or `None` when it may start.
    ///
    /// An agent no runner claims is refused with [`crate::agent::ERR_UNKNOWN_AGENT`]. A Kimi job
    /// on a box that is not disposable is refused with [`kimi::ERR_NOT_DISPOSABLE`], and one
    /// whose Profile model is not a plain name with [`kimi::ERR_BAD_MODEL`].
    pub(crate) fn agent_refusal(&self, job: &Job) -> Option<&'static str> {
        if crate::agent::resolve(&job.agent).is_none() {
            return Some(crate::agent::ERR_UNKNOWN_AGENT);
        }
        if !Self::is_kimi(job) {
            return None;
        }
        if !self.config.disposable {
            return Some(kimi::ERR_NOT_DISPOSABLE);
        }
        let applied = self.profile_for(job);
        let model = applied.as_deref().and_then(Self::kimi_model);
        kimi::resolve_model(model)
            .is_none()
            .then_some(kimi::ERR_BAD_MODEL)
    }

    fn kimi_model(applied: &crate::profile_apply::Applied) -> Option<&str> {
        let at = applied.argv.iter().position(|arg| arg == "--model")?;
        applied.argv.get(at + 1).map(String::as_str)
    }

    /// Builds the per-job home of a Codex or Kimi job before its spec is made.
    pub(crate) fn agent_home(&self, job: &Job, cwd: &Path) -> io::Result<()> {
        if Self::is_codex(job) {
            self.codex_home(&job.job_id, cwd)?;
        } else if Self::is_kimi(job) {
            self.kimi_home(&job.job_id, cwd)?;
        }
        Ok(())
    }

    /// The per-job `KIMI_CODE_HOME` of `job_id`, built under the jobs root on the first call and
    /// kept until [`AgentRunner::end_job`].
    pub(crate) fn kimi_home(&self, job_id: &str, cwd: &Path) -> io::Result<PathBuf> {
        let mut homes = self
            .kimi_homes
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(home) = homes.get(job_id) {
            return Ok(home.path().to_path_buf());
        }
        let home = KimiHome::create(self.jobs_root(cwd), job_id)?;
        let path = home.path().to_path_buf();
        homes.insert(job_id.to_owned(), home);
        drop(homes);
        Ok(path)
    }

    pub(crate) fn forget_kimi_home(&self, job_id: &str) {
        self.kimi_homes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }

    fn kimi_api_key(&self, job_id: &str) -> Option<String> {
        let held = self.credentials.as_ref()?.get(job_id)?;
        let secret = held
            .get(CredentialKind::KimiMembershipKey)
            .or_else(|| held.get(CredentialKind::KimiPlatformKey))?;
        std::str::from_utf8(secret.expose()).ok().map(str::to_owned)
    }

    /// The command line and environment of a Kimi job.
    ///
    /// The environment is [`kimi::env`] over the base environment: no box secret passes, and
    /// `KIMI_MODEL_API_KEY` is set from the held Kimi key only. A job with none held, or a runner
    /// with no credential book, gets no key.
    pub(crate) fn kimi_spec(&self, job: &Job, cwd: &Path, home: &Path) -> AgentSpec {
        let applied = self.profile_for(job);
        let prompt = applied
            .as_deref()
            .map_or(job.prompt.as_str(), |applied| applied.prompt.as_str());
        let model = applied.as_deref().and_then(Self::kimi_model);
        let name = kimi::resolve_model(model).unwrap_or(kimi::DEFAULT_MODEL);
        let argv = kimi::argv(
            &self.config.kimi_bin,
            &KimiJob {
                prompt,
                model: model.filter(|model| kimi::resolve_model(Some(model)).is_some()),
            },
        );
        let kimi_home = self
            .kimi_home(&job.job_id, cwd)
            .unwrap_or_else(|_| self.jobs_root(cwd).join(".kimi").join(&job.job_id));
        let key = self.kimi_api_key(&job.job_id);
        let mut env = kimi::env(
            &self.config.base_env,
            key.as_deref().unwrap_or_default(),
            name,
            &job.job_id,
            home,
            &kimi_home,
        );
        if key.is_none() {
            env.remove(&OsString::from(kimi::API_KEY_ENV));
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
