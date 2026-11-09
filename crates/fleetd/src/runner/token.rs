//! The per-job GitHub token and redactor of the runner.
//!
//! With a [`crate::cred::CredentialBook`] attached, the push and `gh` children take the token
//! the job's owner stored and never a value from the box environment: a job with no held
//! credential gets no token. Without a book the children keep the base environment token, which
//! is the library default for callers that have no credential channel. Production always
//! attaches a book. The agent shares fleetd's uid under the direct launcher, so the token is
//! hidden from other uids only (ADR-0024 Known limit).

use std::ffi::OsString;
use std::sync::{Arc, PoisonError};

use fleet_core::Redactor;
use tokio::process::Command;

use crate::agent_config::{JOB_EMAIL, JOB_NAME};
use crate::cred::{CredentialFailure, JobCredentials, LeaseFuture, LeasedToken, TokenSource};
use crate::runner::{AgentRunner, Reporter};

/// The [`TokenSource`] of one job.
///
/// It refreshes the job's installation token through the runner, then leases the held one.
struct JobTokenSource<R: Reporter> {
    agent: Arc<AgentRunner<R>>,
    job_id: String,
}

impl<R: Reporter> std::fmt::Debug for JobTokenSource<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobTokenSource")
            .field("job_id", &self.job_id)
            .finish_non_exhaustive()
    }
}

impl<R: Reporter + Send + Sync + 'static> TokenSource for JobTokenSource<R> {
    fn lease(&self) -> LeaseFuture<'_> {
        Box::pin(async move {
            self.agent.refresh_token(&self.job_id).await?;
            Ok(self.agent.leased_github_token(&self.job_id))
        })
    }
}

impl<R: Reporter + Send + Sync + 'static> AgentRunner<R> {
    /// A [`TokenSource`] that resolves the GitHub token of `job_id` on every call.
    pub(crate) fn token_source(self: &Arc<Self>, job_id: &str) -> Arc<dyn TokenSource> {
        Arc::new(JobTokenSource {
            agent: Arc::clone(self),
            job_id: job_id.to_owned(),
        })
    }
}

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
                held.github_str().map(str::to_owned)
            }
            None => self
                .config
                .base_env
                .iter()
                .find(|(name, _)| name == "GH_TOKEN")
                .and_then(|(_, value)| value.to_str().map(str::to_owned)),
        }
    }

    /// The GitHub token for `job_id` with a lease on it when a book holds it. Empty when the
    /// job holds no GitHub credential. Call it right after [`AgentRunner::refresh_token`].
    pub(crate) fn leased_github_token(&self, job_id: &str) -> LeasedToken {
        let Some(book) = &self.credentials else {
            return LeasedToken::new(self.github_token(job_id).unwrap_or_default(), None);
        };
        let Some((held, lease)) = book.lease_held(job_id) else {
            return LeasedToken::new(String::new(), None);
        };
        let token = held.github_str().map(str::to_owned).unwrap_or_default();
        LeasedToken::new(token, Some(lease))
    }

    /// The git author and committer environment for `job_id`: the bot identity of a held
    /// GitHub App credential, else the fixed job identity of a PAT job or a runner with no
    /// book.
    pub(crate) fn git_env(&self, job_id: &str) -> [(OsString, OsString); 4] {
        let (name, email) = self
            .credentials
            .as_ref()
            .and_then(|book| book.get(job_id))
            .and_then(|held| {
                held.git_identity()
                    .map(|bot| (bot.name().to_owned(), bot.email().to_owned()))
            })
            .unwrap_or_else(|| (JOB_NAME.to_owned(), JOB_EMAIL.to_owned()));
        [
            ("GIT_AUTHOR_NAME".into(), name.clone().into()),
            ("GIT_AUTHOR_EMAIL".into(), email.clone().into()),
            ("GIT_COMMITTER_NAME".into(), name.into()),
            ("GIT_COMMITTER_EMAIL".into(), email.into()),
        ]
    }

    /// Puts the GitHub token of `held` into `command`. `held` is the credentials the caller
    /// leased in the same step, so the token is the one the lease covers.
    pub(crate) fn apply_github_token(
        &self,
        command: &mut Command,
        held: Option<&JobCredentials>,
        gh: bool,
    ) {
        if self.credentials.is_none() {
            return;
        }
        let Some(host) = self.config.repo_policy.token_host() else {
            return;
        };
        let Some(token) = held.and_then(JobCredentials::github_str).map(str::to_owned) else {
            return;
        };
        command.env("GH_TOKEN", &token);
        if gh && !host.eq_ignore_ascii_case("github.com") {
            command.env("GH_ENTERPRISE_TOKEN", &token);
        }
    }

    /// Puts the holder's model credential into `env` and drops `ANTHROPIC_API_KEY` and
    /// `CLAUDE_CODE_OAUTH_TOKEN` from the box environment. The Codex and Kimi runners clear
    /// their own key variables.
    ///
    /// With a book attached, a job gets `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN` from
    /// its held credentials only. A job with none held gets neither, and the box values never
    /// stand in. Judge jobs fetch no credentials and keep the base environment. Without a book
    /// `env` is left as it is.
    pub(crate) fn apply_model_env(
        &self,
        env: &mut std::collections::BTreeMap<OsString, OsString>,
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

    /// Adds the values of `fresh` to the redactor of `job_id` in one update of its entry. A job
    /// with no entry has ended, so nothing is inserted.
    fn mask_refreshed(&self, job_id: &str, fresh: &JobCredentials) {
        let mut redactors = self
            .job_redactors
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(entry) = redactors.get_mut(job_id) {
            *entry = Arc::new(entry.merged(&fresh.redactor()));
        }
    }

    /// Renews the installation token of `job_id` when fewer than
    /// [`REFRESH_WINDOW_MS`](crate::cred::REFRESH_WINDOW_MS) of it remain, and keeps both the old
    /// and the new value in the job redactor. The redactor is updated before the book hands out
    /// the new token. A runner with no book, a PAT job and a job with a fresh token do nothing.
    ///
    /// # Errors
    ///
    /// Returns the [`CredentialFailure`] of a refresh that failed for good. The caller fails the
    /// step with its reason.
    pub(crate) async fn refresh_token(&self, job_id: &str) -> Result<(), CredentialFailure> {
        let Some(book) = &self.credentials else {
            return Ok(());
        };
        book.refresh_if_due_with(job_id, |fresh| self.mask_refreshed(job_id, fresh))
            .await?;
        Ok(())
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
    use std::sync::{Arc, PoisonError};

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

    use crate::agent_config::{JOB_EMAIL, JOB_NAME};
    use crate::cred::{CredentialBook, CredentialClient, CredentialFailure};
    use crate::poller::channel;
    use crate::runner::Ctl;
    use crate::runner::ci::{PollStop, Watched};
    use crate::runner::{AgentRunner, Reporter, RunConfig, Scope};
    use fleet_proto::PRECONDITION_APP_MINT_CAP;

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

    const APP_TOKEN: &str = "ghs_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    const BOT_NAME: &str = "fleet-bot[bot]";
    const BOT_EMAIL: &str = "123456+fleet-bot[bot]@users.noreply.github.com";

    const NEW_APP_TOKEN: &str = "ghs_ZyXwVuTsRqPoNmLkJiHgFeDcBa9876543210";
    const EXPIRES_MS: u64 = 4_000_000_000_000;

    #[derive(Debug)]
    struct Clock(std::sync::atomic::AtomicU64);

    impl crate::cred::Clock for Clock {
        fn now_ms(&self) -> u64 {
            self.0.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    struct Stub(
        &'static str,
        bool,
        std::sync::atomic::AtomicUsize,
        Option<Status>,
    );

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
                expires_at_ms: None,
                git_identity: None,
            };
            let call = self.2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if call > 0
                && let Some(refusal) = &self.3
            {
                return Err(refusal.clone());
            }
            let github = if self.1 {
                JobCredential {
                    expires_at_ms: Some(EXPIRES_MS),
                    git_identity: Some(fleet_proto::v1::GitIdentity {
                        name: BOT_NAME.into(),
                        email: BOT_EMAIL.into(),
                    }),
                    ..wire(
                        "github_installation_token",
                        if call == 0 { APP_TOKEN } else { NEW_APP_TOKEN },
                    )
                }
            } else {
                wire("github_pat", HOLDER)
            };
            Ok(Response::new(GetJobCredentialsReply {
                credentials: vec![github, wire(self.0, AGENT)],
            }))
        }

        async fn report_job(
            &self,
            _: Request<ReportJobRequest>,
        ) -> Result<Response<ReportJobReply>, Status> {
            Err(Status::unimplemented("unused"))
        }

        async fn report_shell_log(
            &self,
            _: Request<fleet_proto::v1::ReportShellLogRequest>,
        ) -> Result<Response<fleet_proto::v1::ReportShellLogReply>, Status> {
            Err(Status::unimplemented("not used"))
        }

        async fn report_timing(
            &self,
            _: Request<fleet_proto::v1::ReportTimingRequest>,
        ) -> Result<Response<fleet_proto::v1::ReportTimingReply>, Status> {
            Err(Status::unimplemented("not used"))
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
        fixture_with(attach, kind, false).await
    }

    async fn fixture_app() -> Result<Fixture, Box<dyn std::error::Error>> {
        fixture_with(true, "anthropic_api_key", true).await
    }

    async fn fixture_with(
        attach: bool,
        kind: &'static str,
        app: bool,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        fixture_clocked(attach, kind, app, Arc::new(crate::cred::SystemClock)).await
    }

    async fn fixture_clocked(
        attach: bool,
        kind: &'static str,
        app: bool,
        clock: Arc<dyn crate::cred::Clock>,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        fixture_full(attach, kind, app, clock, None, None).await
    }

    async fn fixture_refusing(
        refusal: Status,
        clock: Arc<dyn crate::cred::Clock>,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        fixture_full(true, "anthropic_api_key", true, clock, Some(refusal), None).await
    }

    async fn fixture_full(
        attach: bool,
        kind: &'static str,
        app: bool,
        clock: Arc<dyn crate::cred::Clock>,
        refusal: Option<Status>,
        revoker: Option<Arc<crate::revoke::Revoker>>,
    ) -> Result<Fixture, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let url = format!("http://{}", listener.local_addr()?);
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(FleetWorkerServer::new(Stub(kind, app, 0.into(), refusal)))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let mut book =
            CredentialBook::new(CredentialClient::new(channel(&url)?, "tok-0123456789")?)
                .with_clock(clock);
        if let Some(revoker) = revoker {
            book = book.with_revoker(revoker);
        }
        let book = Arc::new(book);
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
    async fn a_push_or_gh_child_refreshes_a_due_token_and_masks_both_values()
    -> Result<(), Box<dyn std::error::Error>> {
        for gh in [false, true] {
            let now = EXPIRES_MS - 10 * 60 * 1000 + 1000;
            let clock = Arc::new(Clock(now.into()));
            let (runner, book, dir) =
                fixture_clocked(true, "anthropic_api_key", true, clock).await?;
            let held = book.get("job1").ok_or("held")?;
            runner.adopt_credentials("job1", &held);
            let scope = if gh {
                Scope::Gh("job1")
            } else {
                Scope::Push("job1")
            };
            let env = env_of(&runner, dir.path(), scope).await?;
            assert_eq!(value(&env, "GH_TOKEN"), Some(NEW_APP_TOKEN));
            assert_eq!(runner.github_token("job1").as_deref(), Some(NEW_APP_TOKEN));
            let text = format!("{APP_TOKEN} {NEW_APP_TOKEN}");
            assert_eq!(
                runner.job_redactor("job1").redact_str(&text),
                "[REDACTED] [REDACTED]"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_refresh_for_a_job_that_ended_adds_no_redactor_entry()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = EXPIRES_MS - 10 * 60 * 1000 + 1000;
        let clock = Arc::new(Clock(now.into()));
        let (runner, book, _dir) = fixture_clocked(true, "anthropic_api_key", true, clock).await?;
        let held = book.get("job1").ok_or("held")?;
        runner.adopt_credentials("job1", &held);
        runner.forget_job_redactor("job1");
        runner.refresh_token("job1").await?;
        assert!(
            runner
                .job_redactors
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_redactor_masks_the_new_token_before_the_book_hands_it_out()
    -> Result<(), Box<dyn std::error::Error>> {
        let now = EXPIRES_MS - 10 * 60 * 1000 + 1000;
        let clock = Arc::new(Clock(now.into()));
        let (runner, book, _dir) = fixture_clocked(true, "anthropic_api_key", true, clock).await?;
        let held = book.get("job1").ok_or("held")?;
        runner.adopt_credentials("job1", &held);
        let masked_when_readable = std::sync::Mutex::new(None);
        book.refresh_if_due_with("job1", |fresh| {
            runner.mask_refreshed("job1", fresh);
            *masked_when_readable
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(
                runner.job_redactor("job1").redact_str(NEW_APP_TOKEN) == "[REDACTED]"
                    && book
                        .get("job1")
                        .and_then(|c| c.github().map(|s| s.expose().to_vec()))
                        .as_deref()
                        == Some(APP_TOKEN.as_bytes()),
            );
        })
        .await?;
        assert_eq!(
            masked_when_readable
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner),
            Some(true)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_token_with_time_left_is_not_refreshed_by_a_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let clock = Arc::new(Clock((EXPIRES_MS - 10 * 60 * 1000).into()));
        let (runner, _book, dir) = fixture_clocked(true, "anthropic_api_key", true, clock).await?;
        let env = env_of(&runner, dir.path(), Scope::Push("job1")).await?;
        assert_eq!(value(&env, "GH_TOKEN"), Some(APP_TOKEN));
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_refresh_fails_the_step_and_spawns_nothing()
    -> Result<(), Box<dyn std::error::Error>> {
        let clock = Arc::new(Clock((EXPIRES_MS - 5 * 60 * 1000).into()));
        let refusal = Status::failed_precondition(PRECONDITION_APP_MINT_CAP);
        let (runner, _book, dir) = fixture_refusing(refusal, clock).await?;
        let got = runner
            .helper(
                Path::new("/usr/bin/env"),
                dir.path(),
                &[],
                Scope::Push("job1"),
            )
            .await;
        assert_eq!(
            got.err(),
            Some(crate::proc::CaptureError::Credentials(
                CredentialFailure::MintCap
            ))
        );
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

    #[tokio::test]
    async fn only_a_claude_agent_job_asks_for_the_otel_env()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, _dir) = fixture(true).await?;
        let dir = Path::new("/tmp");
        let job = |agent: &str, kind: JobKind| Job {
            job_id: "job1".into(),
            agent: agent.into(),
            kind: kind as i32,
            ..Job::default()
        };
        for (agent, kind, want) in [
            ("claude", JobKind::Agent, true),
            ("", JobKind::Agent, true),
            ("codex", JobKind::Agent, false),
            ("kimi", JobKind::Agent, false),
            ("claude", JobKind::Judge, false),
            ("", JobKind::Judge, false),
        ] {
            let spec = runner.agent_spec(&job(agent, kind), dir, dir);
            assert_eq!(spec.otel, want, "{agent:?} {kind:?}");
        }
        Ok(())
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
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
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
    async fn the_kimi_home_is_shared_with_the_job_group_like_the_claude_home()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let (mut runner, _book, dir) = fixture_kind(true, "kimi_membership_key").await?;
        let gid = std::fs::metadata(dir.path())?.gid();
        runner.config.job_gid = Some(gid);
        let home = runner.kimi_home("job1", &dir.path().join("work"))?;
        for path in [home.parent().ok_or("parent")?, home.as_path()] {
            let meta = std::fs::metadata(path)?;
            assert_eq!(
                (meta.mode() & 0o7777, meta.gid()),
                (0o2770, gid),
                "{}",
                path.display()
            );
        }
        std::fs::write(home.join("config.toml"), b"")?;
        assert_eq!(
            std::fs::metadata(&home)?.permissions().mode() & 0o070,
            0o070
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_kimi_home_stays_private_without_a_job_group()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::PermissionsExt;
        let (runner, _book, dir) = fixture_kind(true, "kimi_membership_key").await?;
        let home = runner.kimi_home("job1", &dir.path().join("work"))?;
        assert_eq!(
            std::fs::metadata(&home)?.permissions().mode() & 0o777,
            0o700
        );
        Ok(())
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
                "GIT_AUTHOR_NAME",
                "GIT_AUTHOR_EMAIL",
                "GIT_COMMITTER_NAME",
                "GIT_COMMITTER_EMAIL",
                "KIMI_MODEL_API_KEY",
                "KIMI_MODEL_NAME",
                "KIMI_MODEL_PROVIDER_TYPE",
                "KIMI_MODEL_BASE_URL",
                "KIMI_DISABLE_TELEMETRY",
                "KIMI_CODE_NO_AUTO_UPDATE",
            ]
            .into_iter()
            .collect();
            assert_eq!(keys(&env), expected, "{kind}");
            assert_eq!(value(&env, "KIMI_MODEL_API_KEY"), Some(AGENT), "{kind}");
            assert_eq!(value(&env, "KIMI_MODEL_NAME"), Some("kimi-for-coding"));
            let argv = spec
                .argv
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>();
            assert!(argv.iter().all(|a| !a.contains(AGENT)), "{kind}");
            assert!(env.iter().all(|(_, v)| v != BOX_PAT
                && v != BOX_ENT
                && v != BOX_OAUTH
                && v != BOX_KEY
                && v != HOLDER));
            assert_eq!(spec.argv.first(), Some(&"kimi".into()));
            assert_eq!(
                argv,
                ["kimi", "-p", "do it", "--output-format", "stream-json"]
            );
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
        assert!(value(&env, "KIMI_MODEL_API_KEY").is_none());
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

    fn identity_of(env: &[(String, String)]) -> [Option<&str>; 4] {
        [
            "GIT_AUTHOR_NAME",
            "GIT_AUTHOR_EMAIL",
            "GIT_COMMITTER_NAME",
            "GIT_COMMITTER_EMAIL",
        ]
        .map(|key| value(env, key))
    }

    const BOT: [Option<&str>; 4] = [
        Some(BOT_NAME),
        Some(BOT_EMAIL),
        Some(BOT_NAME),
        Some(BOT_EMAIL),
    ];
    const FIXED: [Option<&str>; 4] = [
        Some(JOB_NAME),
        Some(JOB_EMAIL),
        Some(JOB_NAME),
        Some(JOB_EMAIL),
    ];

    #[tokio::test]
    async fn an_app_job_pushes_and_runs_gh_with_the_installation_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, dir) = fixture_app().await?;
        assert_eq!(runner.github_token("job1").as_deref(), Some(APP_TOKEN));
        for scope in [Scope::Push("job1"), Scope::Gh("job1")] {
            let env = env_of(&runner, dir.path(), scope).await?;
            assert_eq!(value(&env, "GH_TOKEN"), Some(APP_TOKEN));
            assert!(env.iter().all(|(_, v)| v != BOX_PAT && v != BOX_ENT));
        }
        let env = env_of(&runner, dir.path(), Scope::Gh("job1")).await?;
        assert_eq!(value(&env, "GH_ENTERPRISE_TOKEN"), None);
        Ok(())
    }

    #[tokio::test]
    async fn an_app_job_agent_env_carries_the_bot_and_never_the_token()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, _dir) = fixture_app().await?;
        let env = spec_env(&runner, "job1", JobKind::Agent);
        assert_eq!(identity_of(&env), BOT);
        assert!(value(&env, "GH_TOKEN").is_none());
        assert!(env.iter().all(|(_, v)| v != APP_TOKEN));
        Ok(())
    }

    #[tokio::test]
    async fn a_pat_job_and_a_runner_with_no_book_keep_the_fixed_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, _book, _dir) = fixture(true).await?;
        assert_eq!(
            identity_of(&spec_env(&runner, "job1", JobKind::Agent)),
            FIXED
        );
        assert_eq!(
            identity_of(&spec_env(&runner, "job2", JobKind::Agent)),
            FIXED
        );
        let (bare, _book, _dir) = fixture(false).await?;
        assert_eq!(identity_of(&spec_env(&bare, "job1", JobKind::Agent)), FIXED);
        let (app, _book, _dir) = fixture_app().await?;
        assert_eq!(identity_of(&spec_env(&app, "job2", JobKind::Agent)), FIXED);
        Ok(())
    }

    #[tokio::test]
    async fn the_fallback_commit_env_carries_the_bot_for_an_app_job_only()
    -> Result<(), Box<dyn std::error::Error>> {
        let (app, _book, dir) = fixture_app().await?;
        let env = env_of(&app, dir.path(), Scope::Tree("job1", dir.path())).await?;
        assert_eq!(identity_of(&env), BOT);
        assert!(env.iter().all(|(_, v)| v != APP_TOKEN));
        let env = env_of(&app, dir.path(), Scope::Tree("job2", dir.path())).await?;
        assert_eq!(identity_of(&env), FIXED);
        let (pat, _book, dir) = fixture(true).await?;
        let env = env_of(&pat, dir.path(), Scope::Tree("job1", dir.path())).await?;
        assert_eq!(identity_of(&env), FIXED);
        let (bare, _book, dir) = fixture(false).await?;
        let env = env_of(&bare, dir.path(), Scope::Tree("job1", dir.path())).await?;
        assert_eq!(identity_of(&env), FIXED);
        Ok(())
    }

    #[tokio::test]
    async fn a_codex_or_kimi_app_job_carries_the_bot_and_a_pat_job_the_fixed_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut app, _book, dir) = fixture_with(true, "codex_api_key", true).await?;
        app.config.codex_bin = "codex-fake".into();
        assert_eq!(
            identity_of(&spec_pairs(&codex_spec(&app, dir.path(), "job1"))),
            BOT
        );
        let (mut pat, _book, dir) = fixture_kind(true, "codex_api_key").await?;
        pat.config.codex_bin = "codex-fake".into();
        assert_eq!(
            identity_of(&spec_pairs(&codex_spec(&pat, dir.path(), "job1"))),
            FIXED
        );
        let (app, _book, dir) = fixture_with(true, "kimi_membership_key", true).await?;
        assert_eq!(
            identity_of(&spec_pairs(&kimi_spec(&app, dir.path(), "job1"))),
            BOT
        );
        let (pat, _book, dir) = fixture_kind(true, "kimi_membership_key").await?;
        assert_eq!(
            identity_of(&spec_pairs(&kimi_spec(&pat, dir.path(), "job1"))),
            FIXED
        );
        Ok(())
    }

    fn hostile_forms() -> Vec<(&'static str, String)> {
        vec![
            ("plain", format!("x {APP_TOKEN} y")),
            ("env echo", format!("GH_TOKEN={APP_TOKEN}")),
            ("export echo", format!("export GH_TOKEN='{APP_TOKEN}'")),
            (
                "url userinfo",
                format!("https://x-access-token:{APP_TOKEN}@github.com/o/r"),
            ),
            ("auth header", format!("Authorization: token {APP_TOKEN}")),
            ("twice", format!("{APP_TOKEN}{APP_TOKEN}")),
            ("crlf", format!("a\r\n{APP_TOKEN}\r\nb")),
            ("json quoted", format!("{{\"t\":\"{APP_TOKEN}\"}}")),
        ]
    }

    #[tokio::test]
    async fn the_installation_token_is_redacted_in_every_text_path()
    -> Result<(), Box<dyn std::error::Error>> {
        let (runner, book, _dir) = fixture_app().await?;
        let held = book.get("job1").ok_or("held")?;
        runner.adopt_credentials("job1", &held);
        let redactor = runner.job_redactor("job1");
        for (name, text) in hostile_forms() {
            let clean = redactor.redact_str(&text);
            assert!(!clean.contains(APP_TOKEN), "{name}: {clean}");
            assert!(!clean.contains("ghs_"), "{name}: {clean}");
            assert!(clean.contains("[REDACTED]"), "{name}");
            let mut value = serde_json::json!({ text.clone(): [text.clone()] });
            redactor.redact_value(&mut value);
            assert!(!value.to_string().contains("ghs_"), "{name}: {value}");
            let hidden = fleet_core::text::sanitise_lines(
                &redactor,
                &text,
                fleet_core::text::Cap::Bytes(usize::MAX),
            )
            .text;
            assert!(!hidden.contains("ghs_"), "{name}: {hidden}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_installation_token_straddling_a_shell_cap_is_redacted_before_the_cut()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::shell_timing::{ShellInput, ShellRecorder};
        use fleet_proto::{MAX_COMMAND_BYTES, MAX_SHELL_LOG_BYTES};
        let (runner, book, _dir) = fixture_app().await?;
        let held = book.get("job1").ok_or("held")?;
        runner.adopt_credentials("job1", &held);
        for back in [1, 4, 5, 9] {
            let command = format!("{}{APP_TOKEN} tail", "a".repeat(MAX_COMMAND_BYTES - back));
            let output = format!("{}{APP_TOKEN} tail", "b".repeat(MAX_SHELL_LOG_BYTES - back));
            let mut recorder = ShellRecorder::new(runner.job_redactor("job1").as_ref().clone());
            recorder
                .record(&ShellInput {
                    command,
                    output,
                    started: 1,
                    ended: Some(2),
                    exit_code: Some(0),
                    background: false,
                })
                .map_err(|_| "refused")?;
            let record = recorder.records().first().ok_or("no record")?;
            for text in [&record.command, &record.output] {
                for end in 4..=APP_TOKEN.len() {
                    assert!(
                        !text.contains(&APP_TOKEN[..end]),
                        "back {back}: {end} bytes leaked"
                    );
                }
            }
            assert!(record.truncated);
        }
        Ok(())
    }

    const PR: &str = "https://example.invalid/o/r/pull/1";
    const RUN_LINK: &str = "https://example.invalid/actions/runs/9/job/41";

    fn job1() -> Job {
        Job {
            job_id: "job1".into(),
            repo: "o/r".into(),
            ..Job::default()
        }
    }

    fn due_clock() -> Arc<Clock> {
        Arc::new(Clock((EXPIRES_MS - 5 * 60 * 1000).into()))
    }

    fn refusals() -> [(Status, CredentialFailure); 2] {
        [
            (
                Status::failed_precondition(PRECONDITION_APP_MINT_CAP),
                CredentialFailure::MintCap,
            ),
            (
                Status::permission_denied("lease"),
                CredentialFailure::LeaseMismatch,
            ),
        ]
    }

    #[tokio::test]
    async fn an_allowlist_refusal_stays_refused_on_every_later_lease()
    -> Result<(), Box<dyn std::error::Error>> {
        for (refusal, want) in [
            (
                Status::failed_precondition(fleet_proto::PRECONDITION_APP_REPO),
                CredentialFailure::RepoRefused,
            ),
            (
                Status::failed_precondition(fleet_proto::PRECONDITION_APP_INSTALLATION),
                CredentialFailure::InstallationRefused,
            ),
        ] {
            let (runner, _book, _dir) = fixture_refusing(refusal, due_clock()).await?;
            let source = Arc::new(runner).token_source("job1");
            for _ in 0..3 {
                assert_eq!(source.lease().await.err(), Some(want));
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_refresh_failure_is_returned_by_check_pr_and_never_read_as_waiting()
    -> Result<(), Box<dyn std::error::Error>> {
        for (refusal, want) in refusals() {
            let (runner, _book, dir) = fixture_refusing(refusal, due_clock()).await?;
            let got = runner.check_pr(&job1(), dir.path(), PR).await;
            assert_eq!(got, Err(want));
        }
        let (runner, _book, dir) =
            fixture_clocked(true, "anthropic_api_key", true, due_clock()).await?;
        assert!(runner.check_pr(&job1(), dir.path(), PR).await.is_ok());
        Ok(())
    }

    #[tokio::test]
    async fn a_refresh_failure_is_returned_by_failure_log_and_a_missing_url_is_none()
    -> Result<(), Box<dyn std::error::Error>> {
        for (refusal, want) in refusals() {
            let (runner, _book, dir) = fixture_refusing(refusal, due_clock()).await?;
            let got = runner
                .failure_log(&job1(), dir.path(), Some(RUN_LINK))
                .await;
            assert_eq!(got, Err(want));
            assert_eq!(
                runner.failure_log(&job1(), dir.path(), None).await,
                Ok(None)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_refresh_failure_stops_the_poll_with_its_reason()
    -> Result<(), Box<dyn std::error::Error>> {
        for (refusal, want) in refusals() {
            let (runner, _book, dir) = fixture_refusing(refusal, due_clock()).await?;
            let mut last = None;
            let got = runner.poll_ci(&job1(), dir.path(), PR, "", &mut last).await;
            assert!(
                matches!(got, Err(PollStop::Credentials(failure)) if failure == want),
                "{got:?}"
            );
        }
        Ok(())
    }

    fn ctl() -> (tokio::sync::watch::Sender<bool>, Ctl) {
        let (trigger, shutdown) = crate::poller::Shutdown::channel();
        (
            trigger,
            Ctl {
                deadline: Box::pin(tokio::time::sleep(std::time::Duration::from_secs(60))),
                shutdown,
            },
        )
    }

    #[tokio::test]
    async fn a_refresh_failure_ends_the_ci_watch_as_failed_with_its_reason()
    -> Result<(), Box<dyn std::error::Error>> {
        for (refusal, want) in refusals() {
            let (runner, _book, dir) = fixture_refusing(refusal, due_clock()).await?;
            let (_shutdown, mut ctl) = ctl();
            let got = runner.watch_ci(&job1(), dir.path(), PR, "", &mut ctl).await;
            assert!(
                matches!(got, Watched::Failed(reason) if reason == want.reason()),
                "{got:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_refresh_failure_while_fetching_the_log_ends_the_watch_as_failed()
    -> Result<(), Box<dyn std::error::Error>> {
        for (refusal, want) in refusals() {
            let (runner, _book, dir) = fixture_refusing(refusal, due_clock()).await?;
            let (_shutdown, mut ctl) = ctl();
            let done = fleet_proto::v1::JobCi {
                state: fleet_proto::v1::CiState::Failure.into(),
                url: Some(RUN_LINK.to_owned()),
                failure_log: None,
            };
            let got = runner
                .attach_log(&job1(), dir.path(), "", &mut ctl, done)
                .await;
            assert!(
                matches!(got, Watched::Failed(reason) if reason == want.reason()),
                "{got:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_refresh_failure_is_returned_by_existing_pr_and_never_read_as_no_pull_request()
    -> Result<(), Box<dyn std::error::Error>> {
        for (refusal, want) in refusals() {
            let (runner, _book, dir) = fixture_refusing(refusal, due_clock()).await?;
            let got = runner.existing_pr(&job1(), "swarm/job1", dir.path()).await;
            assert_eq!(got.err().map(|f| f.error), Some(want.reason()));
        }
        let (runner, _book, dir) =
            fixture_clocked(true, "anthropic_api_key", true, due_clock()).await?;
        let got = runner.existing_pr(&job1(), "swarm/job1", dir.path()).await;
        assert!(matches!(got, Ok(None)));
        Ok(())
    }

    #[tokio::test]
    async fn a_token_the_job_never_held_is_masked_in_a_redactor_cloned_before_the_refresh()
    -> Result<(), Box<dyn std::error::Error>> {
        let stranger = "ghs_QqWwEeRrTtYyUuIiOoPp1234567890";
        let (runner, book, _dir) = fixture_app().await?;
        let held = book.get("job1").ok_or("held")?;
        runner.adopt_credentials("job1", &held);
        let early = runner.job_redactor("job1").as_ref().clone();
        assert_eq!(early.redact_str(stranger), "[REDACTED]");
        let (pat_runner, pat_book, _pat_dir) = fixture(true).await?;
        let pat = pat_book.get("job1").ok_or("held")?;
        pat_runner.adopt_credentials("job1", &pat);
        assert_eq!(
            pat_runner.job_redactor("job1").redact_str(stranger),
            stranger
        );
        Ok(())
    }

    async fn counting_revoke_endpoint() -> Result<
        (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>),
        Box<dyn std::error::Error>,
    > {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let addr = listener.local_addr()?;
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = Arc::clone(&count);
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let seen = Arc::clone(&seen);
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    let _ = stream.read(&mut buf).await;
                    seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let _ = stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nconnection: close\r\n\r\n")
                        .await;
                });
            }
        });
        Ok((addr, count))
    }

    #[tokio::test]
    async fn a_gh_child_holds_its_token_until_it_exits_when_a_refresh_replaces_it()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::sync::atomic::Ordering;
        let (endpoint_addr, hits) = counting_revoke_endpoint().await?;
        let clock = Arc::new(Clock((EXPIRES_MS - 20 * 60 * 1000).into()));
        let revoker = Arc::new(crate::revoke::Revoker::plain(endpoint_addr));
        let (runner, book, dir) = fixture_full(
            true,
            "anthropic_api_key",
            true,
            clock.clone(),
            None,
            Some(revoker),
        )
        .await?;
        let child = runner.helper(
            Path::new("/bin/sleep"),
            dir.path(),
            &["1"],
            Scope::Gh("job1"),
        );
        let swap = async {
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            clock.0.store(EXPIRES_MS - 5 * 60 * 1000, Ordering::SeqCst);
            let swapped = book.refresh_if_due("job1").await;
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            (
                swapped.map(|got| got.is_some()),
                hits.load(Ordering::SeqCst),
            )
        };
        let (child, (swapped, during)) = tokio::join!(child, swap);
        assert!(child.is_ok());
        assert_eq!(swapped, Ok(true));
        assert_eq!(during, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while hits.load(Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "never revoked");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn script(dir: &Path, name: &str, body: &str) -> Result<std::path::PathBuf, std::io::Error> {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        Ok(path)
    }

    async fn leased_swap_fixture() -> Result<
        (
            Arc<AgentRunner<Quiet>>,
            Arc<CredentialBook>,
            Arc<Clock>,
            Arc<std::sync::atomic::AtomicUsize>,
            tempfile::TempDir,
        ),
        Box<dyn std::error::Error>,
    > {
        let (endpoint_addr, hits) = counting_revoke_endpoint().await?;
        let clock = Arc::new(Clock((EXPIRES_MS - 20 * 60 * 1000).into()));
        let revoker = Arc::new(crate::revoke::Revoker::plain(endpoint_addr));
        let (runner, book, dir) = fixture_full(
            true,
            "anthropic_api_key",
            true,
            clock.clone(),
            None,
            Some(revoker),
        )
        .await?;
        Ok((Arc::new(runner), book, clock, hits, dir))
    }

    async fn swap_midway(
        book: &CredentialBook,
        clock: &Clock,
        hits: &std::sync::atomic::AtomicUsize,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        use std::sync::atomic::Ordering;
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        clock.0.store(EXPIRES_MS - 5 * 60 * 1000, Ordering::SeqCst);
        assert!(book.refresh_if_due("job1").await?.is_some());
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        Ok(hits.load(Ordering::SeqCst))
    }

    async fn wait_revoked(hits: &std::sync::atomic::AtomicUsize) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while hits.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "never revoked");
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn a_broker_gh_call_after_a_refresh_uses_the_new_token_and_the_old_is_revoked_after_the_call()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::broker::{GhCli, GhExecutor, PushTarget};
        let (runner, book, clock, hits, dir) = leased_swap_fixture().await?;
        let scratch = crate::workspace::Workspace::new(dir.path().join("jobs"))
            .create_broker_scratch("job1")?;
        let bin = script(
            dir.path(),
            "gh",
            "#!/bin/sh\nprintf '%s\\n' \"$GH_TOKEN\" >> \"$HOME/tokens\"\nsleep 1\necho '[]'\n",
        )?;
        let gh = GhCli::new(bin, "github.com", String::new(), &scratch)?
            .with_token_source(runner.token_source("job1"));
        let target = PushTarget::Own("job1".to_owned());
        let url = "https://github.com/o/r/pull/1";
        let (first, during) = tokio::join!(
            gh.pr_checks(&target, url),
            swap_midway(&book, &clock, &hits)
        );
        assert!(first.is_ok());
        assert_eq!(during?, 0);
        wait_revoked(&hits).await;
        assert!(gh.pr_checks(&target, url).await.is_ok());
        let tokens = std::fs::read_to_string(scratch.join("tokens"))?;
        assert_eq!(
            tokens.lines().collect::<Vec<_>>(),
            [APP_TOKEN, NEW_APP_TOKEN]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_mirror_fetch_after_a_refresh_uses_the_new_token_and_the_old_is_revoked_after_the_fetch()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::workspace::{RepoPolicy, Workspace};
        let (runner, book, clock, hits, dir) = leased_swap_fixture().await?;
        let log = dir.path().join("tokens");
        let git = script(
            dir.path(),
            "git",
            &format!(
                "#!/bin/sh\ncase \" $* \" in *\" fetch \"*) printf '%s\\n' \"$GH_TOKEN\" >> \"{}\"; sleep 1; exit 0;; esac\nexec /usr/bin/git \"$@\"\n",
                log.display()
            ),
        )?;
        let ws = Workspace::new(dir.path().join("jobs"))
            .with_policy(RepoPolicy::new(["github.com"]))
            .with_git(&git, std::time::Duration::from_secs(30))
            .with_token_source("askpass-bin", runner.token_source("job1"));
        let repo = "https://github.com/o/r.git";
        let (first, during) =
            tokio::join!(ws.fetch_mirror(repo), swap_midway(&book, &clock, &hits));
        first?;
        assert_eq!(during?, 0);
        wait_revoked(&hits).await;
        ws.fetch_mirror(repo).await?;
        let tokens = std::fs::read_to_string(&log)?;
        assert_eq!(
            tokens.lines().collect::<Vec<_>>(),
            [APP_TOKEN, NEW_APP_TOKEN]
        );
        Ok(())
    }
}
