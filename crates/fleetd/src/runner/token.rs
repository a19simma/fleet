//! The per-job GitHub token and redactor of the runner.
//!
//! With a [`crate::cred::CredentialBook`] attached, the push and `gh` children take the token the job's
//! owner stored and never a value from the box environment: a job with no held credential gets
//! no token. Without a book the children keep the base environment token, which is the library
//! default for callers that have no credential channel. The agent shares fleetd's uid under the
//! direct launcher, so the token is hidden from other uids only (ADR-0024 Known limit).

use std::sync::{Arc, PoisonError};

use fleet_core::Redactor;
use tokio::process::Command;

use crate::cred::JobCredentials;
use crate::runner::{AgentRunner, Reporter};

impl<R: Reporter> AgentRunner<R> {
    /// The credential book the runner reads the GitHub token from. Call it before the runner
    /// is shared. A runner with a book never reads a token from its base environment.
    #[must_use]
    pub fn with_credentials(mut self, book: Arc<crate::cred::CredentialBook>) -> Self {
        self.credentials = Some(book);
        self
    }

    /// The GitHub token for `job_id`: the held credential when a book is attached, else the
    /// `GH_TOKEN` of the base environment. `None` when a book holds nothing for the job.
    pub(crate) fn github_token(&self, job_id: &str) -> Option<String> {
        match &self.credentials {
            Some(book) => {
                let held = book.get(job_id)?;
                let secret = held.github()?;
                std::str::from_utf8(secret.expose()).ok().map(str::to_owned)
            }
            None => self
                .config
                .base_env
                .iter()
                .find(|(name, _)| name == "GH_TOKEN")
                .and_then(|(_, value)| value.to_str().map(str::to_owned)),
        }
    }

    pub(crate) fn apply_github_token(&self, command: &mut Command, job_id: &str, gh: bool) {
        if self.credentials.is_none() {
            return;
        }
        let Some(host) = self.config.repo_policy.token_host() else {
            return;
        };
        let Some(token) = self.github_token(job_id) else {
            return;
        };
        command.env("GH_TOKEN", &token);
        if gh && !host.eq_ignore_ascii_case("github.com") {
            command.env("GH_ENTERPRISE_TOKEN", &token);
        }
    }

    /// Puts the holder's model credential into `env` and drops every model secret the box
    /// environment passed.
    ///
    /// With a book attached, a job gets `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` from
    /// its held credentials only. A job with none held gets neither, and the box values never
    /// stand in. Judge jobs fetch no credentials and keep the base environment. Without a book
    /// `env` is left as it is.
    pub(crate) fn apply_model_env(
        &self,
        env: &mut std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString>,
        job: &fleet_proto::v1::Job,
    ) {
        let Some(book) = &self.credentials else {
            return;
        };
        if job.kind() == fleet_proto::v1::JobKind::Judge {
            return;
        }
        for name in [crate::agent::API_KEY_ENV, crate::agent::OAUTH_TOKEN_ENV] {
            env.remove(std::ffi::OsStr::new(name));
        }
        let Some(held) = book.get(&job.job_id) else {
            return;
        };
        if let Some((name, secret)) = crate::agent::model_env(&held)
            && let Ok(value) = std::str::from_utf8(secret.expose())
        {
            env.insert(name.into(), value.into());
        }
    }

    /// Merges the redactor of `held` into the job's redactor until [`AgentRunner::end_job`].
    pub(crate) fn adopt_credentials(&self, job_id: &str, held: &JobCredentials) {
        let merged = Arc::new(self.redactor.merged(&held.redactor()));
        self.job_redactors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(job_id.to_owned(), merged);
    }

    /// The redactor for output of `job_id`: the runner's merged with the job's credentials.
    pub(crate) fn job_redactor(&self, job_id: &str) -> Arc<Redactor> {
        let held = self
            .job_redactors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(job_id)
            .cloned();
        held.unwrap_or_else(|| Arc::new(self.redactor.clone()))
    }

    pub(crate) fn forget_job_redactor(&self, job_id: &str) {
        self.job_redactors
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;
    use std::sync::Arc;

    use fleet_core::Redactor;
    use fleet_proto::v1::fleet_worker_server::{FleetWorker, FleetWorkerServer};
    use fleet_proto::v1::{
        ClaimJobReply, ClaimJobRequest, GetJobCredentialsReply, GetJobCredentialsRequest,
        GetJobTranscriptReply, GetJobTranscriptRequest, GetProfileBlobReply, GetProfileBlobRequest,
        Job, JobCredential, JobKind, ReportJobReply, ReportJobRequest,
    };
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::{Request, Response, Status};

    use crate::cred::{CredentialBook, CredentialClient};
    use crate::poller::channel;
    use crate::runner::{AgentRunner, Reporter, RunConfig, Scope};

    const HOLDER: &str = "holder-pat-0123456789abcdef";
    const AGENT: &str = "agent-key-0123456789abcdef";
    const BOX_PAT: &str = "box-pat-0123456789abcdef";
    const BOX_ENT: &str = "box-ent-0123456789abcdef";
    const BOX_OAUTH: &str = "box-oauth-0123456789abcdef";
    const BOX_KEY: &str = "box-key-0123456789abcdef";

    struct Quiet;

    impl Reporter for Quiet {
        fn report(
            &self,
            _: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            std::future::ready(Ok(ReportJobReply::default()))
        }
    }

    struct Stub(&'static str);

    #[tonic::async_trait]
    impl FleetWorker for Stub {
        async fn claim_job(
            &self,
            _: Request<ClaimJobRequest>,
        ) -> Result<Response<ClaimJobReply>, Status> {
            Err(Status::unimplemented("unused"))
        }

        async fn get_profile_blob(
            &self,
            _: Request<GetProfileBlobRequest>,
        ) -> Result<Response<GetProfileBlobReply>, Status> {
            Err(Status::unimplemented("unused"))
        }

        async fn get_job_transcript(
            &self,
            _: Request<GetJobTranscriptRequest>,
        ) -> Result<Response<GetJobTranscriptReply>, Status> {
            Err(Status::unimplemented("unused"))
        }

        async fn get_job_credentials(
            &self,
            _: Request<GetJobCredentialsRequest>,
        ) -> Result<Response<GetJobCredentialsReply>, Status> {
            let wire = |kind: &str, value: &str| JobCredential {
                kind: kind.into(),
                shape: "static_secret".into(),
                value: value.into(),
            };
            Ok(Response::new(GetJobCredentialsReply {
                credentials: vec![wire("github_pat", HOLDER), wire(self.0, AGENT)],
            }))
        }

        async fn report_job(
            &self,
            _: Request<ReportJobRequest>,
        ) -> Result<Response<ReportJobReply>, Status> {
            Err(Status::unimplemented("unused"))
        }
    }

    type Fixture = (AgentRunner<Quiet>, Arc<CredentialBook>, tempfile::TempDir);

    async fn fixture(attach: bool) -> Result<Fixture, Box<dyn std::error::Error>> {
        fixture_kind(attach, "anthropic_api_key").await
    }

    async fn fixture_kind(
        attach: bool,
        kind: &'static str,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}", listener.local_addr()?);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FleetWorkerServer::new(Stub(kind)))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let book = Arc::new(CredentialBook::new(CredentialClient::new(
            channel(&url)?,
            "tok-0123456789",
        )?));
        book.fetch("job1", 1, "box").await?;
        let dir = tempfile::tempdir()?;
        let mut config = RunConfig::new("claude-fake", false);
        config.base_env = vec![
            ("PATH".into(), std::env::var_os("PATH").unwrap_or_default()),
            ("GH_TOKEN".into(), BOX_PAT.into()),
            ("GH_ENTERPRISE_TOKEN".into(), BOX_ENT.into()),
            ("CLAUDE_CODE_OAUTH_TOKEN".into(), BOX_OAUTH.into()),
            ("ANTHROPIC_API_KEY".into(), BOX_KEY.into()),
        ];
        config.env_passthrough = vec!["ANTHROPIC_API_KEY".into()];
        let mut runner = AgentRunner::new(config, Quiet, Redactor::new([BOX_PAT]));
        if attach {
            runner = runner.with_credentials(Arc::clone(&book));
        }
        Ok((runner, book, dir))
    }

    async fn env_of(
        runner: &AgentRunner<Quiet>,
        dir: &Path,
        scope: Scope<'_>,
    ) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
        let out = runner
            .helper(Path::new("/usr/bin/env"), dir, &[], scope)
            .await
            .map_err(|_| "capture")?;
        Ok(out
            .stdout
            .lines()
            .filter_map(|line| line.split_once('='))
            .filter(|(key, _)| *key != "__CF_USER_TEXT_ENCODING")
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect())
    }

    fn keys(env: &[(String, String)]) -> BTreeSet<&str> {
        env.iter().map(|(key, _)| key.as_str()).collect()
    }

    fn value<'a>(env: &'a [(String, String)], key: &str) -> Option<&'a str> {
        env.iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    #[tokio::test]
    async fn the_gh_child_env_is_the_fixed_set_plus_the_holder_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, dir) = fixture(true).await?;
        let env = env_of(&runner, dir.path(), Scope::Gh("job1")).await?;
        let expected: BTreeSet<&str> = [
            "PATH",
            "HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "GIT_DIR",
            "GIT_CONFIG_GLOBAL",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_TERMINAL_PROMPT",
            "GH_PROMPT_DISABLED",
            "GH_HOST",
            "GH_CONFIG_DIR",
            "GH_NO_UPDATE_NOTIFIER",
            "GH_BROWSER",
            "GH_EDITOR",
            "GH_PAGER",
            "PAGER",
            "GH_TOKEN",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys(&env), expected);
        assert_eq!(value(&env, "GH_TOKEN"), Some(HOLDER));
        assert!(env.iter().all(|(_, v)| v != BOX_PAT && v != BOX_ENT));
        Ok(())
    }

    #[tokio::test]
    async fn the_push_child_takes_the_holder_token_and_never_the_box_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, dir) = fixture(true).await?;
        let env = env_of(&runner, dir.path(), Scope::Push("job1")).await?;
        assert_eq!(value(&env, "GH_TOKEN"), Some(HOLDER));
        assert!(value(&env, "GIT_ASKPASS").is_some());
        assert!(env.iter().all(|(_, v)| v != BOX_PAT && v != BOX_ENT));
        Ok(())
    }

    #[tokio::test]
    async fn a_job_without_a_held_credential_gets_no_token_and_no_box_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, dir) = fixture(true).await?;
        for scope in [Scope::Push("job2"), Scope::Gh("job2")] {
            let env = env_of(&runner, dir.path(), scope).await?;
            assert!(value(&env, "GH_TOKEN").is_none());
            assert!(value(&env, "GH_ENTERPRISE_TOKEN").is_none());
            assert!(env.iter().all(|(_, v)| v != BOX_PAT && v != BOX_ENT));
        }
        assert!(runner.github_token("job2").is_none());
        assert_eq!(runner.github_token("job1").as_deref(), Some(HOLDER));
        Ok(())
    }

    fn spec_env(runner: &AgentRunner<Quiet>, job_id: &str, kind: JobKind) -> Vec<(String, String)> {
        let job = Job {
            job_id: job_id.into(),
            kind: kind as i32,
            ..Job::default()
        };
        let dir = Path::new("/tmp");
        runner
            .agent_spec(&job, dir, dir)
            .env
            .iter()
            .filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v.to_str()?.to_owned())))
            .collect()
    }

    fn no_box_model_secret(env: &[(String, String)]) {
        assert!(env.iter().all(|(_, v)| v != BOX_OAUTH && v != BOX_KEY));
    }

    #[tokio::test]
    async fn the_agent_env_takes_the_holder_api_key_and_never_the_box_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, _dir) = fixture_kind(true, "anthropic_api_key").await?;
        let env = spec_env(&runner, "job1", JobKind::Agent);
        assert_eq!(value(&env, "ANTHROPIC_API_KEY"), Some(AGENT));
        assert!(value(&env, "CLAUDE_CODE_OAUTH_TOKEN").is_none());
        assert!(value(&env, "GH_TOKEN").is_none());
        no_box_model_secret(&env);
        Ok(())
    }

    #[tokio::test]
    async fn the_agent_env_takes_the_holder_oauth_token_and_never_the_box_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, _dir) = fixture_kind(true, "claude_subscription_token").await?;
        let env = spec_env(&runner, "job1", JobKind::Agent);
        assert_eq!(value(&env, "CLAUDE_CODE_OAUTH_TOKEN"), Some(AGENT));
        assert!(value(&env, "ANTHROPIC_API_KEY").is_none());
        no_box_model_secret(&env);
        Ok(())
    }

    #[tokio::test]
    async fn a_job_with_no_held_credential_gets_no_model_secret_and_no_box_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, _dir) = fixture(true).await?;
        let env = spec_env(&runner, "job2", JobKind::Agent);
        assert!(value(&env, "ANTHROPIC_API_KEY").is_none());
        assert!(value(&env, "CLAUDE_CODE_OAUTH_TOKEN").is_none());
        no_box_model_secret(&env);
        Ok(())
    }

    #[tokio::test]
    async fn a_runner_with_no_book_keeps_the_box_oauth_token_in_the_agent_env()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, _dir) = fixture(false).await?;
        let env = spec_env(&runner, "job1", JobKind::Agent);
        assert_eq!(value(&env, "CLAUDE_CODE_OAUTH_TOKEN"), Some(BOX_OAUTH));
        assert_eq!(value(&env, "ANTHROPIC_API_KEY"), Some(BOX_KEY));
        Ok(())
    }

    fn codex_job(job_id: &str) -> Job {
        Job {
            job_id: job_id.into(),
            agent: "codex".into(),
            prompt: "do it".into(),
            ..Job::default()
        }
    }

    fn codex_spec(
        runner: &AgentRunner<Quiet>,
        dir: &Path,
        job_id: &str,
    ) -> crate::runner::AgentSpec {
        runner.agent_spec(&codex_job(job_id), &dir.join("work"), &dir.join("home"))
    }

    fn spec_pairs(spec: &crate::runner::AgentSpec) -> Vec<(String, String)> {
        spec.env
            .iter()
            .filter_map(|(k, v)| Some((k.to_str()?.to_owned(), v.to_str()?.to_owned())))
            .collect()
    }

    #[tokio::test]
    async fn the_codex_env_holds_the_holder_key_and_no_other_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut runner, _book, dir) = fixture_kind(true, "codex_api_key").await?;
        runner.config.codex_bin = "codex-fake".into();
        runner
            .config
            .base_env
            .push(("CODEX_API_KEY".into(), BOX_KEY.into()));
        let spec = codex_spec(&runner, dir.path(), "job1");
        let env = spec_pairs(&spec);
        let expected: BTreeSet<&str> = [
            "PATH",
            "FLEET_JOB_ID",
            "SWARM_BOX",
            "HOME",
            "CODEX_HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "GIT_TERMINAL_PROMPT",
            "CODEX_API_KEY",
        ]
        .into_iter()
        .collect();
        assert_eq!(keys(&env), expected);
        assert_eq!(value(&env, "CODEX_API_KEY"), Some(AGENT));
        assert!(env.iter().all(|(_, v)| v != BOX_PAT
            && v != BOX_ENT
            && v != BOX_OAUTH
            && v != BOX_KEY
            && v != HOLDER));
        assert_eq!(spec.argv.first(), Some(&"codex-fake".into()));
        assert_eq!(spec.argv.get(1), Some(&"exec".into()));
        assert_eq!(spec.argv.last(), Some(&"do it".into()));
        Ok(())
    }

    #[tokio::test]
    async fn the_codex_home_exists_for_the_job_and_end_job_removes_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, dir) = fixture_kind(true, "codex_api_key").await?;
        let spec = codex_spec(&runner, dir.path(), "job1");
        let home = std::path::PathBuf::from(
            spec.env
                .get(std::ffi::OsStr::new("CODEX_HOME"))
                .ok_or("CODEX_HOME")?,
        );
        assert_eq!(home, dir.path().join(".codex").join("job1"));
        assert!(home.join("config.toml").is_file());
        assert_eq!(codex_spec(&runner, dir.path(), "job1"), spec);
        runner.end_job(&codex_job("job1"));
        assert!(!home.exists());
        Ok(())
    }

    #[tokio::test]
    async fn a_codex_job_with_no_held_key_gets_no_key_and_no_box_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut runner, _book, dir) = fixture_kind(true, "codex_api_key").await?;
        runner
            .config
            .base_env
            .push(("CODEX_API_KEY".into(), BOX_KEY.into()));
        let env = spec_pairs(&codex_spec(&runner, dir.path(), "job2"));
        assert!(value(&env, "CODEX_API_KEY").is_none());
        assert!(env.iter().all(|(_, v)| v != BOX_KEY && v != AGENT));
        Ok(())
    }

    #[tokio::test]
    async fn a_codex_job_needs_a_held_codex_key() -> Result<(), Box<dyn std::error::Error>> {
        for (kind, agent, expected) in [
            ("codex_api_key", "codex", true),
            ("anthropic_api_key", "codex", false),
            ("codex_api_key", "claude", false),
            ("codex_api_key", "", false),
            ("anthropic_api_key", "claude", true),
        ] {
            let (_runner, book, _dir) = fixture_kind(true, kind).await?;
            let held = book.get("job1").ok_or("held")?;
            assert_eq!(
                crate::agent::holds_model_credential(agent, &held),
                expected,
                "{kind} for {agent}"
            );
        }
        Ok(())
    }

    fn kimi_spec(
        runner: &AgentRunner<Quiet>,
        dir: &Path,
        job_id: &str,
    ) -> crate::runner::AgentSpec {
        let job = Job {
            job_id: job_id.into(),
            agent: "kimi".into(),
            prompt: "do it".into(),
            ..Job::default()
        };
        runner.agent_spec(&job, &dir.join("work"), &dir.join("home"))
    }

    #[tokio::test]
    async fn the_kimi_env_holds_the_holder_key_and_no_other_secret()
    -> Result<(), Box<dyn std::error::Error>> {
        for kind in ["kimi_membership_key", "kimi_platform_key"] {
            let (mut runner, _book, dir) = fixture_kind(true, kind).await?;
            runner
                .config
                .base_env
                .push(("KIMI_API_KEY".into(), BOX_KEY.into()));
            runner
                .config
                .base_env
                .push(("CODEX_API_KEY".into(), BOX_KEY.into()));
            let spec = kimi_spec(&runner, dir.path(), "job1");
            let env = spec_pairs(&spec);
            let expected: BTreeSet<&str> = [
                "PATH",
                "FLEET_JOB_ID",
                "SWARM_BOX",
                "HOME",
                "KIMI_CODE_HOME",
                "XDG_CONFIG_HOME",
                "XDG_CACHE_HOME",
                "GIT_TERMINAL_PROMPT",
                "KIMI_API_KEY",
            ]
            .into_iter()
            .collect();
            assert_eq!(keys(&env), expected, "{kind}");
            assert_eq!(value(&env, "KIMI_API_KEY"), Some(AGENT), "{kind}");
            assert!(env.iter().all(|(_, v)| v != BOX_PAT
                && v != BOX_ENT
                && v != BOX_OAUTH
                && v != BOX_KEY
                && v != HOLDER));
            assert_eq!(spec.argv.first(), Some(&"kimi".into()));
            assert_eq!(spec.argv.last(), Some(&"--prompt=do it".into()));
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_kimi_home_exists_for_the_job_and_end_job_removes_it()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let (runner, _book, dir) = fixture_kind(true, "kimi_platform_key").await?;
        let spec = kimi_spec(&runner, dir.path(), "job1");
        let home = std::path::PathBuf::from(
            spec.env
                .get(std::ffi::OsStr::new("KIMI_CODE_HOME"))
                .ok_or("KIMI_CODE_HOME")?,
        );
        assert_eq!(home, dir.path().join(".kimi").join("job1"));
        assert!(home.join("config.toml").is_file());
        assert_eq!(
            std::fs::metadata(&home)?.permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(kimi_spec(&runner, dir.path(), "job1"), spec);
        let job = Job {
            job_id: "job1".into(),
            agent: "kimi".into(),
            ..Job::default()
        };
        runner.end_job(&job);
        assert!(!home.exists());
        Ok(())
    }

    #[tokio::test]
    async fn a_kimi_job_with_no_held_key_gets_no_key_and_no_box_fallback()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut runner, _book, dir) = fixture_kind(true, "kimi_platform_key").await?;
        runner
            .config
            .base_env
            .push(("KIMI_API_KEY".into(), BOX_KEY.into()));
        let env = spec_pairs(&kimi_spec(&runner, dir.path(), "job2"));
        assert!(value(&env, "KIMI_API_KEY").is_none());
        assert!(env.iter().all(|(_, v)| v != BOX_KEY && v != AGENT));
        Ok(())
    }

    #[tokio::test]
    async fn a_kimi_job_needs_a_held_kimi_key() -> Result<(), Box<dyn std::error::Error>> {
        for (kind, agent, expected) in [
            ("kimi_membership_key", "kimi", true),
            ("kimi_platform_key", "kimi", true),
            ("codex_api_key", "kimi", false),
            ("anthropic_api_key", "kimi", false),
            ("kimi_platform_key", "claude", false),
            ("kimi_platform_key", "codex", false),
        ] {
            let (_runner, book, _dir) = fixture_kind(true, kind).await?;
            let held = book.get("job1").ok_or("held")?;
            assert_eq!(
                crate::agent::holds_model_credential(agent, &held),
                expected,
                "{kind} for {agent}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_judge_job_keeps_its_base_env_model_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let (runner, _book, _dir) = fixture(true).await?;
        let env = spec_env(&runner, "job1", JobKind::Judge);
        assert_eq!(value(&env, "CLAUDE_CODE_OAUTH_TOKEN"), Some(BOX_OAUTH));
        Ok(())
    }

    #[tokio::test]
    async fn a_runner_with_no_book_keeps_the_base_env_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, dir) = fixture(false).await?;
        let env = env_of(&runner, dir.path(), Scope::Gh("job1")).await?;
        assert_eq!(value(&env, "GH_TOKEN"), Some(BOX_PAT));
        Ok(())
    }

    #[tokio::test]
    async fn the_credential_redactor_merges_into_the_job_redactor_until_the_job_ends()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, book, _dir) = fixture(true).await?;
        let held = book.get("job1").ok_or("held")?;
        let text = format!("a {BOX_PAT} b {HOLDER} c {AGENT}");
        assert!(
            runner
                .job_redactor("job1")
                .redact_str(&text)
                .contains(HOLDER)
        );
        runner.adopt_credentials("job1", &held);
        let merged = runner.job_redactor("job1");
        let clean = merged.redact_str(&text);
        for secret in [BOX_PAT, HOLDER, AGENT] {
            assert!(!clean.contains(secret), "{secret}");
        }
        let other = runner.job_redactor("job2");
        assert!(other.redact_str(&text).contains(HOLDER));
        assert!(!other.redact_str(&text).contains(BOX_PAT));
        runner.end_job(&Job {
            job_id: "job1".into(),
            ..Job::default()
        });
        assert!(
            runner
                .job_redactor("job1")
                .redact_str(&text)
                .contains(HOLDER)
        );
        Ok(())
    }
}
