//! The daemon's job path: claim, prepare a worktree, run the agent, publish the result.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub forbids plain pub in a private module"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fleet_core::Redactor;
use fleet_proto::v1::{Job, JobKind};
use tokio::net::UnixStream;
use tonic::transport::Channel;

use crate::AgentLauncher;
use crate::Error;
use crate::agent_config::Bundle;
use crate::broker::{Broker, GhCli, MirrorGit};
use crate::config::Config;
use crate::connect_proxy::{ConnectProxy, ProxyLimits};
use crate::fetch::{Fetcher, SystemResolver, TcpDialer};
use crate::fetch_service::{FeedBook, FetchRecorder, FetchService, MAX_CONCURRENT_FETCHES};
use crate::jobenv::group_id;
use crate::jobsock::{JobContext, PerJob, ServeFuture, Service, ServiceName, Services};
use crate::poller::{
    GrpcReporter, JobRunner, PollRandom, Poller, RunError, SERVER_URL_ENV, Shutdown, TOKEN_ENV,
    Token, channel,
};
use crate::publish::{PublishGh, PublishGit};
use crate::runner::{AgentOutcome, AgentRunner, Interrupt, JobEnd, Reporter, RunConfig};
use crate::systemd::select_launcher;
use crate::telemetry::{FetchPhase, FetchRecordError};
use crate::toolhook::HookHub;
use crate::workspace::{RepoPolicy, Workspace, broker_scratch_path};

const ERR_WORKSPACE: &str = "workspace could not be prepared";
const ERR_PREPARE_TIMEOUT: &str = "workspace preparation timed out";
const ERR_SHUTDOWN: &str = "agent stopped by daemon shutdown";
const ERR_BROKER: &str = "job broker could not be set up";

/// The poller the daemon runs.
pub(crate) type JobPoller = Poller<DaemonRunner<GrpcReporter>>;

/// Runs one claimed job from checkout to terminal report.
pub(crate) struct DaemonRunner<R> {
    workspace: Workspace,
    agent: Arc<AgentRunner<R>>,
    box_name: String,
    broker: Option<BrokerWiring>,
}

/// A [`Broker`] with its executor types erased, so one [`PerJob`] registry holds them all.
pub(crate) struct DynBroker(Box<dyn Service>);

impl Service for DynBroker {
    fn serve(&self, ctx: JobContext, stream: UnixStream) -> ServeFuture<'_> {
        self.0.serve(ctx, stream)
    }
}

/// What the runner needs to build and register the broker of a claimed job.
pub(crate) struct BrokerWiring {
    registry: PerJob<DynBroker>,
    launcher: AgentLauncher,
    gh_bin: PathBuf,
    host: String,
    token: String,
    redactor: Redactor,
}

impl<R: Reporter> DaemonRunner<R> {
    fn new(workspace: Workspace, agent: AgentRunner<R>, box_name: &str) -> Self {
        Self {
            workspace,
            agent: Arc::new(agent),
            box_name: box_name.to_owned(),
            broker: None,
        }
    }

    fn with_broker(mut self, wiring: BrokerWiring) -> Self {
        self.broker = Some(wiring);
        self
    }

    async fn load_profile(&self, job: &Job, mut shutdown: Shutdown) -> Result<(), RunError> {
        let work = self.agent.load_profile(job, &self.box_name);
        let guarded = tokio::select! {
            guarded = self.agent.keep_alive(job, work) => guarded,
            () = shutdown.requested() => {
                self.agent.fail_job(job, ERR_SHUTDOWN).await;
                return Err(RunError);
            }
        };
        match guarded {
            Ok(Ok(())) => Ok(()),
            Ok(Err(err)) => {
                tracing::warn!(reason = err.reason(), "job profile refused");
                self.agent.fail_job(job, err.reason()).await;
                Err(RunError)
            }
            Err(Interrupt::Cancelled) => {
                self.agent.cancel_job(job).await;
                Err(RunError)
            }
            Err(_) => Err(RunError),
        }
    }

    async fn load_judge(&self, job: &Job, mut shutdown: Shutdown) -> Result<PathBuf, RunError> {
        let work = self.agent.load_judge(job, &self.box_name);
        let guarded = tokio::select! {
            guarded = self.agent.keep_alive(job, work) => guarded,
            () = shutdown.requested() => {
                self.agent.fail_job(job, ERR_SHUTDOWN).await;
                return Err(RunError);
            }
        };
        match guarded {
            Ok(Ok(dir)) => Ok(dir),
            Ok(Err(err)) => {
                tracing::warn!(reason = err.reason(), "judge transcript refused");
                self.agent.fail_job(job, err.reason()).await;
                Err(RunError)
            }
            Err(Interrupt::Cancelled) => {
                self.agent.cancel_job(job).await;
                Err(RunError)
            }
            Err(_) => Err(RunError),
        }
    }

    async fn run_judge(&self, job: &Job, shutdown: Shutdown) -> Result<(), RunError> {
        let dir = match self.load_judge(job, shutdown.clone()).await {
            Ok(dir) => dir,
            Err(stop) => {
                self.agent.clear_judge(job);
                return Err(stop);
            }
        };
        let outcome = self.agent.run(job, &dir, shutdown).await;
        let result = match outcome {
            Ok(AgentOutcome::Succeeded) => {
                self.agent.finish_judge(job).await;
                Ok(())
            }
            Ok(other) => {
                tracing::info!(outcome = ?other, "judge ended without a verdict");
                Ok(())
            }
            Err(stop) => Err(stop),
        };
        self.agent.clear_judge(job);
        result
    }

    async fn prepare(&self, job: &Job, mut shutdown: Shutdown) -> Result<PathBuf, RunError> {
        let work = self.agent.timed_clone(
            job,
            tokio::time::timeout(
                self.agent.prepare_timeout(),
                self.workspace
                    .prepare(&job.job_id, &job.repo, &job.base_ref),
            ),
        );
        let guarded = tokio::select! {
            guarded = self.agent.keep_alive(job, work) => guarded,
            () = shutdown.requested() => {
                self.agent.fail_job(job, ERR_SHUTDOWN).await;
                return Err(RunError);
            }
        };
        match guarded {
            Ok(Ok(Ok(checkout))) => Ok(checkout.path),
            Ok(Ok(Err(err))) => {
                tracing::warn!(
                    error = %err,
                    detail = err.detail().unwrap_or_default(),
                    "job workspace could not be prepared"
                );
                self.agent.fail_job(job, ERR_WORKSPACE).await;
                Err(RunError)
            }
            Ok(Err(_)) => {
                tracing::warn!("job workspace preparation timed out");
                self.agent.fail_job(job, ERR_PREPARE_TIMEOUT).await;
                Err(RunError)
            }
            Err(Interrupt::Cancelled) => {
                self.agent.cancel_job(job).await;
                Err(RunError)
            }
            Err(_) => Err(RunError),
        }
    }

    async fn execute(&self, job: &Job, path: &Path, shutdown: Shutdown) -> Result<(), RunError> {
        let outcome = self.agent.run(job, path, shutdown.clone()).await?;
        if matches!(outcome, AgentOutcome::Succeeded) {
            self.agent.finish(job, path, shutdown).await?;
        } else {
            tracing::info!(outcome = ?outcome, "job ended without a publish step");
        }
        Ok(())
    }
}

impl<R: Reporter + Send + Sync + 'static> DaemonRunner<R> {
    /// Builds the broker of `job` and registers it before the agent launches.
    ///
    /// Only the systemd launcher gets one: the direct launcher refuses the job socket, so
    /// nothing is built, no scratch dir is made, and the decision is logged. A failure fails the
    /// job with a fixed message; the detail only goes to the log.
    async fn register_broker(&self, job: &Job, cwd: &Path) -> Result<(), RunError> {
        let Some(wiring) = &self.broker else {
            return Ok(());
        };
        if wiring.launcher != AgentLauncher::Systemd {
            tracing::info!("no job broker: the direct launcher serves no job socket");
            return Ok(());
        }
        match self.build_broker(wiring, job, cwd) {
            Ok(()) => Ok(()),
            Err(detail) => {
                tracing::warn!(detail, "job broker could not be set up");
                self.agent.fail_job(job, ERR_BROKER).await;
                Err(RunError)
            }
        }
    }

    fn build_broker(&self, wiring: &BrokerWiring, job: &Job, cwd: &Path) -> Result<(), String> {
        let scratch = self
            .workspace
            .create_broker_scratch(&job.job_id)
            .map_err(|err| err.to_string())?;
        let git = PublishGit::new(
            Arc::clone(&self.agent),
            job.clone(),
            cwd.to_path_buf(),
            MirrorGit::new(self.workspace.clone(), job),
        );
        let checks = GhCli::new(
            wiring.gh_bin.clone(),
            wiring.host.clone(),
            wiring.token.clone(),
            scratch,
        )
        .map_err(|err| err.to_string())?;
        let gh = PublishGh::new(
            Arc::clone(&self.agent),
            job.clone(),
            cwd.to_path_buf(),
            checks,
        );
        let broker = Broker::new(wiring.launcher, job, git, gh, wiring.redactor.clone())
            .map_err(|err| err.to_string())?;
        wiring
            .registry
            .register(&job.job_id, Arc::new(DynBroker(Box::new(broker))))
            .map_err(|err| format!("{err:?}"))
    }
}

impl<R: Reporter + Send + Sync + 'static> JobRunner for DaemonRunner<R> {
    async fn run(&self, job: Job, shutdown: Shutdown) -> Result<(), RunError> {
        let _ended = self.agent.end_guard(&job);
        if job.kind() == JobKind::Judge {
            return self.run_judge(&job, shutdown).await;
        }
        if let Err(stop) = self.load_profile(&job, shutdown.clone()).await {
            self.agent.clear_profile(&job);
            return Err(stop);
        }
        let result = match self.prepare(&job, shutdown.clone()).await {
            Ok(path) => match self.register_broker(&job, &path).await {
                Ok(()) => self.execute(&job, &path, shutdown).await,
                Err(stop) => Err(stop),
            },
            Err(stop) => Err(stop),
        };
        self.agent.clear_profile(&job);
        if self.workspace.remove(&job.job_id, &job.repo).await.is_err() {
            tracing::warn!("job workspace could not be removed");
        }
        result
    }
}

fn job_gid(config: &Config) -> Result<Option<u32>, Error> {
    let Some(spec) = config.job_group.as_deref() else {
        return Ok(None);
    };
    let groups = std::fs::read_to_string("/etc/group").unwrap_or_default();
    group_id(spec, &groups)
        .map(Some)
        .ok_or(Error::InvalidValue {
            name: "job_group",
            value: spec.to_owned(),
        })
}

fn apply_limits(run: &mut RunConfig, config: &Config) {
    run.max_turns = config.max_turns;
    run.max_budget_usd = config.max_budget_usd;
    run.timeout = config.agent_timeout;
    run.ci_deadline = config.ci_deadline;
}

fn job_workspace(
    config: &Config,
    run: &mut RunConfig,
    env: &dyn Fn(&str) -> Option<String>,
) -> Workspace {
    let mut policy = RepoPolicy::new(config.repo_hosts.iter().cloned())
        .with_token_host(config.token_host.clone());
    if config.allow_file_repos {
        policy = policy.with_file_repos();
    }
    run.repo_policy = policy.clone();
    let mut workspace = Workspace::new(PathBuf::from(&config.jobs_dir))
        .with_policy(policy)
        .with_job_group(run.job_gid);
    if let Some(token) = env("GH_TOKEN") {
        workspace = workspace.with_credential(run.askpass_bin.clone(), token);
    }
    workspace
}

struct BookRecorder(Arc<FeedBook>);

impl FetchRecorder for BookRecorder {
    fn record(&self, job_id: &str, url: &str, phase: FetchPhase) -> Result<(), FetchRecordError> {
        self.0.record(job_id, url, phase)
    }
}

/// What [`job_services`] builds: the services and the hook that clears their per-job state.
pub(crate) struct JobServices {
    pub(crate) services: Services,
    pub(crate) end: JobEnd,
    pub(crate) broker: PerJob<DynBroker>,
    #[cfg(test)]
    pub(crate) proxy: Arc<ConnectProxy<SystemResolver, TcpDialer>>,
}

/// The services every Job socket of this daemon offers, built once and shared by all sockets.
///
/// `Fetch` is a [`FetchService`] over the config's policy and caps, system DNS and plain TCP,
/// recording through `feeds`. `EgressProxy` is a [`ConnectProxy`] over the config's
/// `egress_allow` list (the model API host is always allowed) with the system resolver and
/// dialer, so every dial is pinned to an address that passed `netguard::is_public_address`.
/// Both key their per-job state by the job id of the socket, never by the client. The `end`
/// hook of the result calls [`FetchService::forget`] and [`ConnectProxy::forget`], so the
/// runner passes it to [`AgentRunner::with_job_end`] and a job id reused later starts at zero.
/// `Broker` is a [`PerJob`] registry the runner fills at claim time ([`DaemonRunner`]); the
/// `end` hook unregisters the job id from it and removes the job's broker scratch dir, so a
/// connection after the job ended finds no broker. The direct launcher refuses a socket and
/// drops these in [`select_launcher`].
#[must_use]
pub(crate) fn job_services(config: &Config, feeds: &Arc<FeedBook>) -> JobServices {
    let fetcher = Fetcher::system(config.fetch_policy.clone(), config.fetch_caps);
    let fetch = Arc::new(FetchService::new(
        config.fetch_policy.clone(),
        config.fetch_caps,
        MAX_CONCURRENT_FETCHES,
        fetcher,
        BookRecorder(Arc::clone(feeds)),
    ));
    let proxy = Arc::new(ConnectProxy::new(
        config.egress_allow.clone(),
        ProxyLimits::default(),
        SystemResolver,
        TcpDialer,
    ));
    let mut services = Services::new();
    let end = JobEnd::new()
        .on_end({
            let fetch = Arc::clone(&fetch);
            move |job_id| fetch.forget(job_id)
        })
        .on_end({
            let proxy = Arc::clone(&proxy);
            move |job_id| proxy.forget(job_id)
        });
    let broker = PerJob::new();
    let jobs_dir = PathBuf::from(&config.jobs_dir);
    let end = end.unregistering(broker.clone()).on_end(move |job_id| {
        if let Some(scratch) = broker_scratch_path(&jobs_dir, job_id) {
            let _ = std::fs::remove_dir_all(scratch);
        }
    });
    services.insert(ServiceName::Broker, Arc::new(broker.clone()));
    services.insert(ServiceName::Fetch, fetch);
    services.insert(ServiceName::EgressProxy, Arc::new(Arc::clone(&proxy)));
    JobServices {
        services,
        end,
        broker,
        #[cfg(test)]
        proxy,
    }
}

/// Builds the poller when `FLEET_SERVER_URL` is set and non-empty, else `None`.
///
/// # Errors
///
/// Fails when the URL or `FLEET_TOKEN` is unusable. The error never holds either value.
pub(crate) fn build(
    config: &Config,
    env: &dyn Fn(&str) -> Option<String>,
    box_name: &str,
    redactor: Redactor,
    hub: Arc<HookHub>,
) -> Result<Option<JobPoller>, Error> {
    let Some(url) = env(SERVER_URL_ENV).filter(|url| !url.is_empty()) else {
        return Ok(None);
    };
    let token = env(TOKEN_ENV)
        .filter(|token| !token.is_empty())
        .map(Token::new)
        .ok_or(Error::InvalidValue {
            name: TOKEN_ENV,
            value: String::from("<redacted>"),
        })?;
    let channel: Channel = channel(&url)?;
    let reporter = GrpcReporter::new(channel.clone(), &token)?;
    let mut run = RunConfig::new(&config.claude_bin, config.disposable);
    run.gh_bin.clone_from(&config.gh_bin);
    run.jobs_dir = Some(config.jobs_dir.clone());
    run.job_gid = job_gid(config)?;
    apply_limits(&mut run, config);
    run.env_passthrough
        .clone_from(&config.agent_env_passthrough);
    if let Some(dir) = &config.agent_config_dir {
        run.bundle = Bundle::from_dir(dir).map_err(|err| Error::InvalidValue {
            name: "agent_config_dir",
            value: err.to_string(),
        })?;
    }
    let workspace = job_workspace(config, &mut run, env).with_redactor(redactor.clone());
    let feeds = Arc::new(FeedBook::default());
    let wired = job_services(config, &feeds);
    let launcher = select_launcher(config, run.job_gid, wired.services);
    let wiring = BrokerWiring {
        registry: wired.broker,
        launcher: config.agent_launcher,
        gh_bin: config.gh_bin.clone(),
        host: run
            .repo_policy
            .token_host()
            .unwrap_or("github.com")
            .to_owned(),
        token: env("GH_TOKEN").unwrap_or_default(),
        redactor: redactor.clone(),
    };
    let runner = DaemonRunner::new(
        workspace,
        AgentRunner::new(run, reporter, redactor)
            .with_hook_hub(hub)
            .with_launcher(launcher)
            .with_feed_book(feeds)
            .with_job_end(wired.end),
        box_name,
    )
    .with_broker(wiring);
    Poller::with_channel(
        channel,
        &token,
        box_name.to_owned(),
        runner,
        PollRandom::system(),
    )
    .map(Some)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use std::sync::{Arc, Mutex, PoisonError};

    use fleet_core::Profile;
    use fleet_proto::v1::{
        GetProfileBlobReply, GetProfileBlobRequest, ProfileRef, ReportJobReply, ReportJobRequest,
    };
    use tokio::sync::mpsc;
    use tonic::Status;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct Recorder(mpsc::UnboundedSender<ReportJobRequest>);

    impl Reporter for Recorder {
        fn report(
            &self,
            request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            let _ = self.0.send(request);
            std::future::ready(Ok(ReportJobReply::default()))
        }
    }

    #[test]
    fn the_agent_timeout_reaches_the_run_config() -> TestResult {
        let config = Config::resolve(Some("agent_timeout_secs = 77\n"), &|_| None)?;
        let mut run = RunConfig::new("claude", false);
        apply_limits(&mut run, &config);
        assert_eq!(run.timeout, Duration::from_secs(77));
        Ok(())
    }

    #[test]
    fn the_ci_deadline_reaches_the_run_config() -> TestResult {
        let config = Config::resolve(Some("ci_deadline_secs = 77\n"), &|_| None)?;
        let mut run = RunConfig::new("claude", false);
        apply_limits(&mut run, &config);
        assert_eq!(run.ci_deadline, Duration::from_secs(77));
        Ok(())
    }

    #[tokio::test]
    async fn the_gh_token_env_value_reaches_the_mirror_fetch() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = dir.path().join("rec-git");
        std::fs::write(
            &git,
            "#!/bin/sh\ncase \"$*\" in\n*\" fetch \"*) [ -n \"$GH_TOKEN\" ] && printf %s \"$GH_TOKEN\" > \"$(dirname \"$HOME\")/tok\" ;;\nesac\nexit 0\n",
        )?;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))?;
        let jobs = dir.path().join("jobs");
        let mut config = Config::resolve(None, &|_| None)?;
        config.jobs_dir.clone_from(&jobs);
        let mut run = RunConfig::new("claude", false);
        let env = |name: &str| (name == "GH_TOKEN").then(|| String::from("tok-wired"));
        let workspace =
            job_workspace(&config, &mut run, &env).with_git(&git, Duration::from_secs(10));
        workspace
            .prepare("job1", "https://github.com/o/r.git", "main")
            .await?;
        assert_eq!(std::fs::read_to_string(jobs.join("tok"))?, "tok-wired");
        Ok(())
    }

    #[tokio::test]
    async fn a_slow_prepare_renews_the_lease_before_it_returns() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = dir.path().join("slow-git");
        std::fs::write(&git, "#!/bin/sh\nsleep 1\nexit 1\n")?;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))?;
        let mut cfg = RunConfig::new("claude", false);
        cfg.report_interval = Duration::from_millis(100);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            Workspace::new(dir.path().join("jobs"))
                .with_policy(RepoPolicy::new(Vec::<String>::new()).with_file_repos())
                .with_git(&git, Duration::from_secs(10)),
            AgentRunner::new(cfg, Recorder(tx), Redactor::default()),
            "",
        );
        let job = Job {
            job_id: "job1".into(),
            repo: "file:///nonexistent.git".into(),
            base_ref: "main".into(),
            attempt: 1,
            ..Job::default()
        };
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(runner.run(job, shutdown).await.is_err());
        let mut renewals = 0;
        let mut terminal = false;
        while let Ok(report) = rx.try_recv() {
            if report.terminal_state.is_some() {
                terminal = true;
            } else if report.chunks.is_empty() {
                assert!(!terminal);
                renewals += 1;
            }
        }
        assert!(terminal);
        assert!(renewals >= 2, "renewals: {renewals}");
        Ok(())
    }

    struct Stale(mpsc::UnboundedSender<ReportJobRequest>);

    impl Reporter for Stale {
        fn report(
            &self,
            request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            let _ = self.0.send(request);
            std::future::ready(Err(Status::failed_precondition("stale")))
        }
    }

    fn script(dir: &Path, body: &str) -> Result<PathBuf, std::io::Error> {
        let git = dir.join("fake-git");
        std::fs::write(&git, format!("#!/bin/sh\n{body}\n"))?;
        std::fs::set_permissions(&git, std::fs::Permissions::from_mode(0o755))?;
        Ok(git)
    }

    fn workspace(dir: &Path, git: &Path) -> Workspace {
        Workspace::new(dir.join("jobs"))
            .with_policy(RepoPolicy::new(Vec::<String>::new()).with_file_repos())
            .with_git(git, Duration::from_secs(60))
    }

    fn sample_job() -> Job {
        Job {
            job_id: "job1".into(),
            repo: "file:///nonexistent.git".into(),
            base_ref: "main".into(),
            attempt: 1,
            ..Job::default()
        }
    }

    #[tokio::test]
    async fn a_lost_lease_during_prepare_ends_the_job_without_a_terminal_report() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = script(dir.path(), "sleep 30")?;
        let mut cfg = RunConfig::new("claude", false);
        cfg.report_interval = Duration::from_millis(100);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            workspace(dir.path(), &git),
            AgentRunner::new(cfg, Stale(tx), Redactor::default()),
            "",
        );
        let (_trigger, shutdown) = Shutdown::channel();
        let ended =
            tokio::time::timeout(Duration::from_secs(20), runner.run(sample_job(), shutdown))
                .await?;
        assert!(ended.is_err());
        while let Ok(report) = rx.try_recv() {
            assert!(report.terminal_state.is_none());
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_prepare_past_its_deadline_reports_failed() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = script(dir.path(), "sleep 30")?;
        let mut cfg = RunConfig::new("claude", false);
        cfg.prepare_timeout = Duration::from_millis(200);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            workspace(dir.path(), &git),
            AgentRunner::new(cfg, Recorder(tx), Redactor::default()),
            "",
        );
        let (_trigger, shutdown) = Shutdown::channel();
        let ended =
            tokio::time::timeout(Duration::from_secs(20), runner.run(sample_job(), shutdown))
                .await?;
        assert!(ended.is_err());
        let mut errors = Vec::new();
        while let Ok(report) = rx.try_recv() {
            errors.extend(report.error);
        }
        assert_eq!(errors, vec![ERR_PREPARE_TIMEOUT.to_owned()]);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_prepare_removes_what_it_left_behind() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let git = script(dir.path(), "exit 1")?;
        let leftover = dir.path().join("jobs").join("job1");
        std::fs::create_dir_all(&leftover)?;
        let (tx, _rx) = mpsc::unbounded_channel();
        let runner = DaemonRunner::new(
            workspace(dir.path(), &git),
            AgentRunner::new(
                RunConfig::new("claude", false),
                Recorder(tx),
                Redactor::default(),
            ),
            "",
        );
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(runner.run(sample_job(), shutdown).await.is_err());
        assert!(!leftover.exists());
        Ok(())
    }

    struct Blob {
        reports: mpsc::UnboundedSender<ReportJobRequest>,
        reply: Result<GetProfileBlobReply, Status>,
        asked: Arc<Mutex<Vec<GetProfileBlobRequest>>>,
    }

    impl Reporter for Blob {
        fn report(
            &self,
            request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
            let _ = self.reports.send(request);
            std::future::ready(Ok(ReportJobReply::default()))
        }

        fn profile_blob(
            &self,
            request: GetProfileBlobRequest,
        ) -> impl Future<Output = Result<GetProfileBlobReply, Status>> + Send {
            self.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request);
            std::future::ready(self.reply.clone())
        }
    }

    struct Fixture {
        runner: DaemonRunner<Blob>,
        reports: mpsc::UnboundedReceiver<ReportJobRequest>,
        asked: Arc<Mutex<Vec<GetProfileBlobRequest>>>,
        marker: PathBuf,
        dir: tempfile::TempDir,
    }

    fn fixture(reply: Result<GetProfileBlobReply, Status>) -> Result<Fixture, std::io::Error> {
        fixture_with(reply, false)
    }

    fn fixture_with(
        reply: Result<GetProfileBlobReply, Status>,
        jobs_dir: bool,
    ) -> Result<Fixture, std::io::Error> {
        let dir = tempfile::TempDir::new()?;
        let marker = dir.path().join("git-ran");
        let git = script(dir.path(), &format!("touch {}\nexit 1", marker.display()))?;
        let (tx, reports) = mpsc::unbounded_channel();
        let asked = Arc::new(Mutex::new(Vec::new()));
        let blob = Blob {
            reports: tx,
            reply,
            asked: Arc::clone(&asked),
        };
        let mut config = RunConfig::new("claude", false);
        if jobs_dir {
            config.jobs_dir = Some(dir.path().join("agent-jobs"));
        }
        let runner = DaemonRunner::new(
            workspace(dir.path(), &git),
            AgentRunner::new(config, blob, Redactor::default()),
            "the-box",
        );
        Ok(Fixture {
            runner,
            reports,
            asked,
            marker,
            dir,
        })
    }

    fn profile_job(profile: &Profile) -> Job {
        Job {
            profile: Some(ProfileRef {
                name: "p".into(),
                version: 3,
                hash: profile.hash().to_string(),
            }),
            ..sample_job()
        }
    }

    fn reply_for(job: &Job, content: Vec<u8>) -> GetProfileBlobReply {
        GetProfileBlobReply {
            profile: job.profile.clone(),
            content,
        }
    }

    fn errors(reports: &mut mpsc::UnboundedReceiver<ReportJobRequest>) -> Vec<String> {
        let mut out = Vec::new();
        while let Ok(report) = reports.try_recv() {
            out.extend(report.error);
        }
        out
    }

    #[tokio::test]
    async fn a_judge_job_never_clones_and_fails_with_a_fixed_reason() -> TestResult {
        let mut fx = fixture(Err(Status::unavailable("down")))?;
        let job = Job {
            kind: JobKind::Judge.into(),
            target_job_id: Some("target1".into()),
            ..sample_job()
        };
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(fx.runner.run(job, shutdown).await.is_err());
        assert_eq!(
            errors(&mut fx.reports),
            vec!["judge workspace could not be prepared".to_owned()]
        );
        assert!(!fx.marker.exists());
        assert!(fx.asked.lock().is_ok_and(|asked| asked.is_empty()));
        Ok(())
    }

    #[tokio::test]
    async fn a_refused_judge_job_leaves_no_transcript_on_disk() -> TestResult {
        let mut fx = fixture_with(Err(Status::unavailable("down")), true)?;
        let stale = fx.dir.path().join("agent-jobs").join("job1");
        std::fs::create_dir_all(&stale)?;
        std::fs::write(stale.join("transcript.jsonl"), "secret")?;
        let job = Job {
            kind: JobKind::Judge.into(),
            target_job_id: Some("target1".into()),
            ..sample_job()
        };
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(fx.runner.run(job, shutdown).await.is_err());
        assert_eq!(
            errors(&mut fx.reports),
            vec!["judge transcript could not be fetched".to_owned()]
        );
        assert!(!stale.exists());
        Ok(())
    }

    #[tokio::test]
    async fn a_tampered_profile_fails_the_job_before_the_clone() -> TestResult {
        let profile = Profile {
            model: Some("opus".into()),
            ..Profile::default()
        };
        let job = profile_job(&profile);
        let tampered = Profile {
            model: Some("haiku".into()),
            ..Profile::default()
        };
        let mut fx = fixture(Ok(reply_for(&job, tampered.canonical_json())))?;
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(fx.runner.run(job, shutdown).await.is_err());
        assert_eq!(
            errors(&mut fx.reports),
            vec!["profile invalid: profile hash does not match the job".to_owned()]
        );
        assert!(!fx.marker.exists());
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_blob_fetch_fails_the_job_before_the_clone() -> TestResult {
        let profile = Profile::default();
        let mut fx = fixture(Err(Status::permission_denied("no")))?;
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(
            fx.runner
                .run(profile_job(&profile), shutdown)
                .await
                .is_err()
        );
        assert_eq!(
            errors(&mut fx.reports),
            vec!["profile invalid: profile could not be fetched".to_owned()]
        );
        assert!(!fx.marker.exists());
        Ok(())
    }

    #[tokio::test]
    async fn an_invalid_profile_fails_the_job_before_the_clone() -> TestResult {
        let profile = Profile {
            model: Some(String::new()),
            ..Profile::default()
        };
        let job = profile_job(&profile);
        let mut fx = fixture(Ok(reply_for(&job, profile.canonical_json())))?;
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(fx.runner.run(job, shutdown).await.is_err());
        assert_eq!(
            errors(&mut fx.reports),
            vec!["profile invalid: profile model name is not allowed".to_owned()]
        );
        assert!(!fx.marker.exists());
        Ok(())
    }

    #[tokio::test]
    async fn a_verified_profile_is_fetched_with_the_lease_and_reaches_the_clone() -> TestResult {
        let profile = Profile::default();
        let job = profile_job(&profile);
        let mut fx = fixture(Ok(reply_for(&job, profile.canonical_json())))?;
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(fx.runner.run(job, shutdown).await.is_err());
        assert!(fx.marker.exists());
        assert_eq!(errors(&mut fx.reports), vec![ERR_WORKSPACE.to_owned()]);
        let asked = fx.asked.lock().unwrap_or_else(PoisonError::into_inner);
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].job_id, "job1");
        assert_eq!(asked[0].attempt, 1);
        assert_eq!(asked[0].r#box, "the-box");
        Ok(())
    }

    #[tokio::test]
    async fn a_job_without_a_profile_fetches_nothing() -> TestResult {
        let fx = fixture(Err(Status::internal("must not be called")))?;
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(fx.runner.run(sample_job(), shutdown).await.is_err());
        assert!(fx.marker.exists());
        assert_eq!(
            fx.asked
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
            0
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_kept_profile_is_cleared_when_the_job_ends() -> TestResult {
        let profile = Profile::default();
        let job = profile_job(&profile);
        let fx = fixture(Ok(reply_for(&job, profile.canonical_json())))?;
        let (_trigger, shutdown) = Shutdown::channel();
        assert!(fx.runner.run(job.clone(), shutdown).await.is_err());
        assert!(!fx.runner.agent.has_profile(&job));
        Ok(())
    }

    mod wired {
        use std::io;
        use std::sync::{Arc, Mutex, PoisonError};
        use std::time::Duration;

        use fleet_core::Redactor;
        use tempfile::TempDir;
        use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::UnixStream;
        use tokio::time::{Instant, timeout};

        use crate::config::Config;
        use crate::connect_proxy::FORBIDDEN;
        use crate::feed::Feed;
        use crate::fetch_service::{FeedBook, Refusal};
        use crate::jobsock::{
            AGENT_SLICE, JobSocket, Limits, Peer, PeerId, ServiceName, Services, read_frame,
            write_frame,
        };
        use crate::systemd::select_launcher;

        use super::super::job_services;

        type TestResult = Result<(), Box<dyn std::error::Error>>;

        const OUTER: Duration = Duration::from_secs(10);

        struct Cgroup;

        impl Peer for Cgroup {
            fn identity(&self, _: &UnixStream) -> io::Result<PeerId> {
                Ok(PeerId {
                    pid: 7,
                    cgroup: format!("0::/{AGENT_SLICE}/fleet-agent@job1.service\n"),
                })
            }
        }

        fn config_of(file: &str) -> Result<Config, Box<dyn std::error::Error>> {
            Ok(Config::resolve(Some(file), &|_| None)?)
        }

        fn names(services: &Services) -> Vec<&'static str> {
            let mut names: Vec<_> = services.keys().map(|name| name.as_str()).collect();
            names.sort_unstable();
            names
        }

        fn served(config: &Config, feeds: &Arc<FeedBook>) -> Vec<&'static str> {
            let launcher = select_launcher(config, None, job_services(config, feeds).services);
            let mut names: Vec<_> = launcher
                .job_services()
                .into_iter()
                .map(ServiceName::as_str)
                .collect();
            names.sort_unstable();
            names
        }

        struct Rig {
            _dir: TempDir,
            socket: JobSocket,
        }

        fn rig(config: &Config, feeds: &Arc<FeedBook>) -> Result<Rig, Box<dyn std::error::Error>> {
            rig_with(job_services(config, feeds).services)
        }

        fn rig_with(services: Services) -> Result<Rig, Box<dyn std::error::Error>> {
            let dir = TempDir::new()?;
            let socket = JobSocket::bind(
                &dir.path().join("job.sock"),
                "job1",
                services,
                Arc::new(Cgroup),
                Limits::default(),
            )?;
            Ok(Rig { _dir: dir, socket })
        }

        impl Rig {
            async fn open(&self, handshake: &[u8]) -> io::Result<UnixStream> {
                let mut stream = UnixStream::connect(self.socket.path()).await?;
                write_frame(&mut stream, handshake).await?;
                Ok(stream)
            }

            async fn fetch(&self, request: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
                let stream = self.open(ServiceName::Fetch.as_str().as_bytes()).await?;
                let (read, mut write) = stream.into_split();
                write_frame(&mut write, request).await?;
                let mut read = BufReader::new(read);
                let frame = timeout(OUTER, read_frame(&mut read)).await??;
                Ok(String::from_utf8(frame)?)
            }

            async fn connect(&self, head: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                let mut stream = self
                    .open(ServiceName::EgressProxy.as_str().as_bytes())
                    .await?;
                stream.write_all(head).await?;
                let mut got = Vec::new();
                timeout(OUTER, stream.read_to_end(&mut got)).await??;
                Ok(got)
            }
        }

        fn register(feeds: &FeedBook, job: &str) -> Arc<Mutex<Feed>> {
            let feed = Arc::new(Mutex::new(Feed::new(Instant::now())));
            feeds.register(job, Arc::clone(&feed), Redactor::default());
            feed
        }

        #[test]
        fn a_default_config_serves_exactly_broker_fetch_and_egress_proxy_under_systemd()
        -> TestResult {
            let feeds = Arc::new(FeedBook::default());
            let config = config_of("agent_launcher = \"systemd\"\n")?;
            assert_eq!(served(&config, &feeds), ["broker", "egress proxy", "fetch"]);
            assert_eq!(
                names(&job_services(&config, &feeds).services),
                ["broker", "egress proxy", "fetch"]
            );
            Ok(())
        }

        #[test]
        fn the_direct_launcher_serves_nothing_even_with_a_full_service_set() -> TestResult {
            let feeds = Arc::new(FeedBook::default());
            let config = config_of("agent_launcher = \"direct\"\n")?;
            assert_eq!(names(&job_services(&config, &feeds).services).len(), 3);
            assert_eq!(served(&config, &feeds), Vec::<&str>::new());
            let default = config_of("")?;
            assert_eq!(served(&default, &feeds), Vec::<&str>::new());
            Ok(())
        }

        #[tokio::test]
        async fn an_unknown_or_unregistered_service_name_closes_with_no_reply() -> TestResult {
            let feeds = Arc::new(FeedBook::default());
            let rig = rig(&config_of("agent_launcher = \"systemd\"\n")?, &feeds)?;
            let names: [&[u8]; 8] = [
                b"broker", b"bogus", b"Fetch", b"FETCH", b"fetch ", b"egress", b"fetch\0", b"",
            ];
            for name in names {
                let mut stream = rig.open(name).await?;
                let mut seen = Vec::new();
                timeout(OUTER, stream.read_to_end(&mut seen)).await??;
                assert_eq!(seen, Vec::<u8>::new(), "{name:?}");
            }
            Ok(())
        }

        #[tokio::test]
        async fn fetch_refuses_hostile_requests_with_fixed_text_and_never_echoes_them() -> TestResult
        {
            let feeds = Arc::new(FeedBook::default());
            let rig = rig(&config_of("agent_launcher = \"systemd\"\n")?, &feeds)?;
            let invalid = format!(
                r#"{{"status":"error","error":"{}"}}"#,
                Refusal::InvalidRequest.message()
            );
            let table: [(&str, &[u8], Option<&str>); 9] = [
                ("empty object", b"{}", None),
                ("not json", b"GET / HTTP/1.1", None),
                ("url not a string", br#"{"url":1}"#, None),
                (
                    "unknown key",
                    br#"{"url":"https://a.example/","x":1}"#,
                    None,
                ),
                (
                    "duplicate url",
                    br#"{"url":"https://a.example/","url":"https://b.example/"}"#,
                    None,
                ),
                (
                    "file scheme",
                    br#"{"url":"file:///etc/passwd"}"#,
                    Some("passwd"),
                ),
                (
                    "loopback literal",
                    br#"{"url":"http://127.0.0.1:9/secret"}"#,
                    Some("secret"),
                ),
                (
                    "userinfo",
                    br#"{"url":"https://user:hunter2@a.example/"}"#,
                    Some("hunter2"),
                ),
                (
                    "ipv6 literal",
                    br#"{"url":"http://[::1]/leak"}"#,
                    Some("leak"),
                ),
            ];
            for (label, request, leak) in table {
                let reply = rig.fetch(request).await?;
                assert!(
                    reply.starts_with(r#"{"status":"error","error":""#),
                    "{label}: {reply}"
                );
                if let Some(leak) = leak {
                    assert!(!reply.contains(leak), "{label}: {reply}");
                } else {
                    assert_eq!(reply, invalid, "{label}");
                }
            }
            Ok(())
        }

        #[tokio::test]
        async fn fetch_for_a_job_with_no_registered_feed_is_refused_before_any_lookup() -> TestResult
        {
            let feeds = Arc::new(FeedBook::default());
            let rig = rig(&config_of("agent_launcher = \"systemd\"\n")?, &feeds)?;
            let reply = rig.fetch(br#"{"url":"https://docs.example/page"}"#).await?;
            assert_eq!(
                reply,
                format!(
                    r#"{{"status":"error","error":"{}"}}"#,
                    Refusal::NotRecorded.message()
                )
            );
            Ok(())
        }

        #[tokio::test]
        async fn fetch_for_a_registered_job_records_its_intent_in_that_jobs_feed() -> TestResult {
            let feeds = Arc::new(FeedBook::default());
            let feed = register(&feeds, "job1");
            let other = register(&feeds, "job2");
            let config =
                config_of("agent_launcher = \"systemd\"\nfetch_connect_timeout_secs = 2\n")?;
            let rig = rig(&config, &feeds)?;
            let reply = rig
                .fetch(br#"{"url":"https://nohost.invalid/page"}"#)
                .await?;
            assert!(reply.starts_with(r#"{"status":"error""#), "{reply}");
            assert!(!reply.contains(Refusal::NotRecorded.message()), "{reply}");
            let events = feed.lock().unwrap_or_else(PoisonError::into_inner).batch();
            assert!(!events.is_empty(), "the intent reached the feed of job1");
            let others = other.lock().unwrap_or_else(PoisonError::into_inner).batch();
            assert!(others.is_empty(), "job2 saw nothing");
            Ok(())
        }

        #[tokio::test]
        async fn fetch_after_the_feed_is_forgotten_is_refused_again() -> TestResult {
            let feeds = Arc::new(FeedBook::default());
            let _feed = register(&feeds, "job1");
            feeds.forget("job1");
            let rig = rig(&config_of("agent_launcher = \"systemd\"\n")?, &feeds)?;
            let reply = rig.fetch(br#"{"url":"https://docs.example/page"}"#).await?;
            assert!(reply.contains(Refusal::NotRecorded.message()), "{reply}");
            Ok(())
        }

        #[tokio::test]
        async fn the_egress_proxy_refuses_every_hostile_connect_with_the_one_403() -> TestResult {
            let feeds = Arc::new(FeedBook::default());
            let rig = rig(&config_of("agent_launcher = \"systemd\"\n")?, &feeds)?;
            let table: [(&str, &[u8]); 9] = [
                (
                    "host off the allow list",
                    b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n",
                ),
                (
                    "allowed host, wrong port",
                    b"CONNECT api.anthropic.com:80 HTTP/1.1\r\n\r\n",
                ),
                ("ip literal", b"CONNECT 8.8.8.8:443 HTTP/1.1\r\n\r\n"),
                (
                    "userinfo trick",
                    b"CONNECT evil.example@api.anthropic.com:443 HTTP/1.1\r\n\r\n",
                ),
                (
                    "plain GET",
                    b"GET http://api.anthropic.com/ HTTP/1.1\r\n\r\n",
                ),
                (
                    "sibling domain",
                    b"CONNECT x.api.anthropic.com:443 HTTP/1.1\r\n\r\n",
                ),
                (
                    "loopback name off the list",
                    b"CONNECT localhost:443 HTTP/1.1\r\n\r\n",
                ),
                (
                    "metadata address",
                    b"CONNECT 169.254.169.254:443 HTTP/1.1\r\n\r\n",
                ),
                ("garbage", b"\x00\x01\x02\r\n\r\n"),
            ];
            for (label, head) in table {
                assert_eq!(rig.connect(head).await?, FORBIDDEN, "{label}");
            }
            Ok(())
        }

        #[tokio::test]
        async fn an_allowed_name_that_resolves_to_loopback_is_refused_by_the_pinned_dial()
        -> TestResult {
            let feeds = Arc::new(FeedBook::default());
            let config =
                config_of("agent_launcher = \"systemd\"\negress_allow = [\"localhost\"]\n")?;
            let rig = rig(&config, &feeds)?;
            let got = rig
                .connect(b"CONNECT localhost:443 HTTP/1.1\r\n\r\n")
                .await?;
            assert_eq!(got, FORBIDDEN);
            Ok(())
        }

        mod broker_wired {
            use std::os::unix::fs::{PermissionsExt, symlink};
            use std::path::{Path, PathBuf};
            use std::process::Command;

            use fleet_proto::v1::{Job, JobState, ReportJobRequest};
            use tokio::sync::mpsc;

            use super::*;
            use crate::AgentLauncher;
            use crate::broker::{Broker, ExecError, GhExecutor, GitExecutor, PushTarget};
            use crate::jobsock::{JobContext, ServeFuture, Service};
            use crate::poller::{JobRunner, RunError, Shutdown};
            use crate::runner::{
                AgentRunner, AgentSpec, DirectLauncher, Launched, Launcher, RunConfig,
            };
            use crate::workspace::{RepoPolicy, Workspace, scratch_is_private};

            use super::super::super::{
                BrokerWiring, DaemonRunner, DynBroker, ERR_BROKER, JobServices, job_workspace,
            };
            use super::super::Recorder;

            const SYSTEMD: &str = "agent_launcher = \"systemd\"\n";
            const LAUNCHES: Duration = Duration::from_secs(60);

            struct Fixture {
                dir: TempDir,
                origin: PathBuf,
                claude: PathBuf,
            }

            fn run_git(dir: &Path, args: &[&str]) -> TestResult {
                let status = Command::new("git")
                    .arg("-C")
                    .arg(dir)
                    .args(["-c", "user.name=t", "-c", "user.email=t@t.invalid"])
                    .args(args)
                    .status()?;
                assert!(status.success(), "git {args:?}");
                Ok(())
            }

            fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
                let dir = TempDir::new()?;
                let origin = dir.path().join("origin.git");
                let seed = dir.path().join("seed");
                std::fs::create_dir_all(&origin)?;
                run_git(&origin, &["init", "--bare", "-b", "main"])?;
                run_git(
                    dir.path(),
                    &["clone", origin.to_str().unwrap_or(""), "seed"],
                )?;
                run_git(&seed, &["commit", "--allow-empty", "-m", "init"])?;
                run_git(&seed, &["push", "origin", "HEAD:main"])?;
                let claude = dir.path().join("claude");
                std::fs::write(
                    &claude,
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '2.1.289 (Claude Code)'; fi\nexit 0\n",
                )?;
                std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755))?;
                Ok(Fixture {
                    dir,
                    origin,
                    claude,
                })
            }

            impl Fixture {
                fn jobs(&self) -> PathBuf {
                    self.dir.path().join("jobs")
                }

                fn job(&self, id: &str) -> Job {
                    Job {
                        job_id: id.into(),
                        repo: format!("file://{}", self.origin.display()),
                        base_ref: "main".into(),
                        attempt: 1,
                        ..Job::default()
                    }
                }

                fn services(&self) -> Result<JobServices, Box<dyn std::error::Error>> {
                    let mut config = config_of(SYSTEMD)?;
                    config.jobs_dir = self.jobs();
                    Ok(job_services(&config, &Arc::new(FeedBook::default())))
                }

                fn runner(
                    &self,
                    wired: &JobServices,
                    launcher: AgentLauncher,
                    spy: Spy,
                ) -> (
                    DaemonRunner<Recorder>,
                    mpsc::UnboundedReceiver<ReportJobRequest>,
                ) {
                    let (tx, rx) = mpsc::unbounded_channel();
                    let policy = RepoPolicy::new(Vec::<String>::new()).with_file_repos();
                    let workspace = Workspace::new(self.jobs()).with_policy(policy.clone());
                    let mut cfg = RunConfig::new(&self.claude, false);
                    cfg.repo_policy = policy;
                    let agent = AgentRunner::new(cfg, Recorder(tx), Redactor::default())
                        .with_launcher(Arc::new(spy))
                        .with_job_end(wired.end.clone());
                    let wiring = BrokerWiring {
                        registry: wired.broker.clone(),
                        launcher,
                        gh_bin: PathBuf::from("/usr/bin/gh"),
                        host: "github.com".to_owned(),
                        token: "tok".to_owned(),
                        redactor: Redactor::default(),
                    };
                    (
                        DaemonRunner::new(workspace, agent, "").with_broker(wiring),
                        rx,
                    )
                }
            }

            type OnLaunch = Arc<dyn Fn(&AgentSpec) + Send + Sync>;

            struct Spy {
                on_launch: OnLaunch,
                fail: bool,
            }

            impl Spy {
                fn new(on_launch: impl Fn(&AgentSpec) + Send + Sync + 'static) -> Self {
                    Self {
                        on_launch: Arc::new(on_launch),
                        fail: false,
                    }
                }

                const fn failing(mut self) -> Self {
                    self.fail = true;
                    self
                }
            }

            impl std::fmt::Debug for Spy {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct("Spy").finish_non_exhaustive()
                }
            }

            impl Launcher for Spy {
                fn launch(&self, spec: AgentSpec) -> io::Result<Launched> {
                    (self.on_launch)(&spec);
                    if self.fail {
                        return Err(io::Error::other("spy"));
                    }
                    DirectLauncher.launch(spec)
                }
            }

            fn push_to<T>(log: &Arc<Mutex<Vec<T>>>, entry: T) {
                log.lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(entry);
            }

            fn taken<T: Clone>(log: &Arc<Mutex<Vec<T>>>) -> Vec<T> {
                log.lock().unwrap_or_else(PoisonError::into_inner).clone()
            }

            async fn finished(
                runner: &DaemonRunner<Recorder>,
                job: Job,
            ) -> Result<Result<(), RunError>, Box<dyn std::error::Error>> {
                let (_trigger, shutdown) = Shutdown::channel();
                Ok(timeout(LAUNCHES, runner.run(job, shutdown)).await?)
            }

            fn succeeded(rx: &mut mpsc::UnboundedReceiver<ReportJobRequest>) -> bool {
                let mut done = false;
                while let Ok(report) = rx.try_recv() {
                    done |= report.terminal_state == Some(JobState::Succeeded as i32);
                }
                done
            }

            #[tokio::test]
            async fn the_broker_is_registered_with_a_private_scratch_before_the_agent_launches()
            -> TestResult {
                let fx = fixture()?;
                let wired = fx.services()?;
                let seen = Arc::new(Mutex::new(Vec::new()));
                let scratch = fx.jobs().join(".broker").join("job1");
                let spy = Spy::new({
                    let seen = Arc::clone(&seen);
                    let registry = wired.broker.clone();
                    let scratch = scratch.clone();
                    move |_| {
                        push_to(
                            &seen,
                            (registry.contains("job1"), scratch_is_private(&scratch)),
                        );
                    }
                });
                let (runner, mut rx) = fx.runner(&wired, AgentLauncher::Systemd, spy);
                let ended = finished(&runner, fx.job("job1")).await?;
                assert!(ended.is_ok(), "{ended:?}");
                assert_eq!(taken(&seen), [(true, true)]);
                assert!(succeeded(&mut rx));
                assert!(!wired.broker.contains("job1"), "unregistered at the end");
                assert!(!scratch.exists(), "scratch removed at the end");
                Ok(())
            }

            #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
            async fn two_concurrent_jobs_get_their_own_broker_and_distinct_scratch_dirs()
            -> TestResult {
                let fx = fixture()?;
                let wired = fx.services()?;
                let seen = Arc::new(Mutex::new(Vec::new()));
                let spy = Spy::new({
                    let seen = Arc::clone(&seen);
                    let registry = wired.broker.clone();
                    let jobs = fx.jobs();
                    move |spec| {
                        let id = spec
                            .cwd
                            .file_name()
                            .map(|name| name.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        let scratch = jobs.join(".broker").join(&id);
                        push_to(&seen, (id, scratch.clone(), scratch_is_private(&scratch)));
                        let deadline = std::time::Instant::now() + Duration::from_secs(20);
                        while taken(&seen).len() < 2 && std::time::Instant::now() < deadline {
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        assert_eq!(registry.len(), 2, "both brokers live while both launch");
                    }
                });
                let (runner, _rx) = fx.runner(&wired, AgentLauncher::Systemd, spy);
                let runner = Arc::new(runner);
                let tasks: Vec<_> = ["job1", "job2"]
                    .into_iter()
                    .map(|id| {
                        let runner = Arc::clone(&runner);
                        let job = fx.job(id);
                        tokio::spawn(async move {
                            let (_trigger, shutdown) = Shutdown::channel();
                            runner.run(job, shutdown).await
                        })
                    })
                    .collect();
                for task in tasks {
                    let ended = timeout(LAUNCHES, task).await??;
                    assert!(ended.is_ok(), "{ended:?}");
                }
                let mut got = taken(&seen);
                got.sort();
                assert_eq!(got.len(), 2);
                assert_ne!(got[0].1, got[1].1, "distinct scratch dirs");
                assert!(got.iter().all(|entry| entry.2), "both private");
                assert!(wired.broker.is_empty());
                Ok(())
            }

            #[tokio::test]
            async fn a_reused_job_id_gets_a_fresh_scratch_dir() -> TestResult {
                let fx = fixture()?;
                let wired = fx.services()?;
                let stale = Workspace::new(fx.jobs()).create_broker_scratch("job1")?;
                std::fs::write(stale.join("leftover"), "old")?;
                let seen = Arc::new(Mutex::new(Vec::new()));
                let spy = Spy::new({
                    let seen = Arc::clone(&seen);
                    let stale = stale.clone();
                    move |_| {
                        push_to(
                            &seen,
                            (stale.join("leftover").exists(), scratch_is_private(&stale)),
                        );
                    }
                });
                let (runner, _rx) = fx.runner(&wired, AgentLauncher::Systemd, spy);
                let ended = finished(&runner, fx.job("job1")).await?;
                assert!(ended.is_ok(), "{ended:?}");
                assert_eq!(taken(&seen), [(false, true)]);
                Ok(())
            }

            #[tokio::test]
            async fn the_direct_launcher_registers_no_broker_and_makes_no_scratch() -> TestResult {
                let fx = fixture()?;
                let wired = fx.services()?;
                let seen = Arc::new(Mutex::new(Vec::new()));
                let spy = Spy::new({
                    let seen = Arc::clone(&seen);
                    let registry = wired.broker.clone();
                    let broker_dir = fx.jobs().join(".broker");
                    move |_| push_to(&seen, (registry.len(), broker_dir.exists()))
                });
                let (runner, mut rx) = fx.runner(&wired, AgentLauncher::Direct, spy);
                let ended = finished(&runner, fx.job("job1")).await?;
                assert!(ended.is_ok(), "{ended:?}");
                assert_eq!(taken(&seen), [(0, false)]);
                assert!(succeeded(&mut rx));
                Ok(())
            }

            #[tokio::test]
            async fn a_symlink_at_the_scratch_path_fails_the_job_and_the_agent_never_launches()
            -> TestResult {
                let fx = fixture()?;
                let wired = fx.services()?;
                let scratch = Workspace::new(fx.jobs()).create_broker_scratch("job1")?;
                std::fs::remove_dir_all(&scratch)?;
                let victim = fx.dir.path().join("victim");
                std::fs::create_dir(&victim)?;
                std::fs::write(victim.join("keep"), "x")?;
                symlink(&victim, &scratch)?;
                let launches = Arc::new(Mutex::new(Vec::new()));
                let spy = Spy::new({
                    let launches = Arc::clone(&launches);
                    move |_| push_to(&launches, ())
                });
                let (runner, mut rx) = fx.runner(&wired, AgentLauncher::Systemd, spy);
                let ended = finished(&runner, fx.job("job1")).await?;
                assert!(ended.is_err());
                assert!(taken(&launches).is_empty(), "never launched");
                assert_eq!(super::super::errors(&mut rx), vec![ERR_BROKER.to_owned()]);
                assert!(victim.join("keep").exists(), "target untouched");
                assert!(wired.broker.is_empty());
                Ok(())
            }

            #[tokio::test]
            async fn a_launch_error_leaves_no_publish_state_and_no_broker() -> TestResult {
                let fx = fixture()?;
                let wired = fx.services()?;
                let launches = Arc::new(Mutex::new(Vec::new()));
                let spy = Spy::new({
                    let launches = Arc::clone(&launches);
                    move |_| push_to(&launches, ())
                })
                .failing();
                let (runner, _rx) = fx.runner(&wired, AgentLauncher::Systemd, spy);
                let ended = finished(&runner, fx.job("job1")).await?;
                let _ = ended;
                assert_eq!(taken(&launches).len(), 1);
                assert!(
                    runner
                        .agent
                        .publishing
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .is_empty(),
                    "publish state leaked"
                );
                assert!(wired.broker.is_empty());
                assert!(!fx.jobs().join(".broker").join("job1").exists());
                Ok(())
            }

            struct Live;

            impl Service for Live {
                fn serve(&self, _: JobContext, mut stream: UnixStream) -> ServeFuture<'_> {
                    Box::pin(async move {
                        let _ = stream.write_all(b"live").await;
                    })
                }
            }

            async fn broker_bytes(rig: &Rig) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
                let mut stream = rig.open(ServiceName::Broker.as_str().as_bytes()).await?;
                let mut got = Vec::new();
                timeout(OUTER, stream.read_to_end(&mut got)).await??;
                Ok(got)
            }

            #[tokio::test]
            async fn a_connection_after_the_job_ended_reaches_no_broker() -> TestResult {
                let fx = fixture()?;
                let mut wired = fx.services()?;
                wired
                    .broker
                    .register("job1", Arc::new(DynBroker(Box::new(Live))))?;
                let rig = rig_with(std::mem::take(&mut wired.services))?;
                assert_eq!(broker_bytes(&rig).await?, b"live");
                let (tx, _rx) = mpsc::unbounded_channel();
                let agent = AgentRunner::new(
                    RunConfig::new("claude", false),
                    Recorder(tx),
                    Redactor::default(),
                )
                .with_job_end(wired.end.clone());
                agent.end_job(&fx.job("job1"));
                assert_eq!(broker_bytes(&rig).await?, Vec::<u8>::new());
                Ok(())
            }

            struct FakeGit;

            impl GitExecutor for FakeGit {
                fn push(
                    &self,
                    _: &PushTarget,
                ) -> impl Future<Output = Result<String, ExecError>> + Send {
                    std::future::ready(Ok("pushed".to_owned()))
                }

                fn fetch(&self) -> impl Future<Output = Result<String, ExecError>> + Send {
                    std::future::ready(Ok("fetched".to_owned()))
                }
            }

            struct FakeGh;

            impl GhExecutor for FakeGh {
                fn pr_create(
                    &self,
                    _: &PushTarget,
                    _: &str,
                    _: &str,
                ) -> impl Future<Output = Result<String, ExecError>> + Send {
                    std::future::ready(Err(ExecError))
                }

                fn pr_checks(
                    &self,
                    _: &PushTarget,
                    _: &str,
                ) -> impl Future<Output = Result<String, ExecError>> + Send {
                    std::future::ready(Err(ExecError))
                }
            }

            async fn ask(rig: &Rig, request: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
                let stream = rig.open(ServiceName::Broker.as_str().as_bytes()).await?;
                let (read, mut write) = stream.into_split();
                write_frame(&mut write, request).await?;
                let mut read = BufReader::new(read);
                let frame = timeout(OUTER, read_frame(&mut read)).await??;
                Ok(String::from_utf8(frame)?)
            }

            #[tokio::test]
            async fn a_registered_broker_answers_requests_over_the_job_socket() -> TestResult {
                let fx = fixture()?;
                let mut wired = fx.services()?;
                let broker = Broker::new(
                    AgentLauncher::Systemd,
                    &fx.job("job1"),
                    FakeGit,
                    FakeGh,
                    Redactor::default(),
                )?;
                wired
                    .broker
                    .register("job1", Arc::new(DynBroker(Box::new(broker))))?;
                let rig = rig_with(std::mem::take(&mut wired.services))?;
                assert_eq!(
                    ask(&rig, br#"{"op":"fetch"}"#).await?,
                    r#"{"status":"done","output":"fetched"}"#
                );
                let hostile =
                    ask(&rig, br#"{"op":"fetch","repo":"https://evil.example/x"}"#).await?;
                assert!(hostile.contains("invalid_request"), "{hostile}");
                assert!(!hostile.contains("evil"), "{hostile}");
                Ok(())
            }

            #[test]
            fn the_job_group_reaches_the_workspace_the_broker_clones_for_its_mirror() -> TestResult
            {
                let config = config_of("")?;
                let mut run = RunConfig::new("claude", false);
                run.job_gid = Some(4242);
                let workspace = job_workspace(&config, &mut run, &|_| None);
                assert_eq!(workspace.job_group(), Some(4242));
                Ok(())
            }
        }

        mod ended {
            use std::os::unix::fs::PermissionsExt;
            use std::path::Path;
            use std::process::Command;

            use fleet_proto::v1::{Job, JobState, ReportJobReply, ReportJobRequest};
            use tokio::sync::mpsc;
            use tonic::Status;

            use super::*;
            use crate::connect_proxy::ProxyStats;
            use crate::fetch_service::FetchRecorder;
            use crate::jobsock::{JobContext, PerJob, ServeFuture, Service};
            use crate::poller::JobRunner;
            use crate::runner::{AgentRunner, Reporter, RunConfig};
            use crate::telemetry::{FetchPhase, FetchRecordError};
            use crate::workspace::{RepoPolicy, Workspace};

            use super::super::super::{DaemonRunner, DynBroker, JobServices};

            const URL: &str = "https://nohost.invalid/page";
            const FETCH: &[u8] = br#"{"url":"https://nohost.invalid/page"}"#;
            const HOSTILE: &[u8] = b"CONNECT localhost:443 HTTP/1.1\r\n\r\n";
            const CONFIG: &str = "agent_launcher = \"systemd\"\nfetch_max_per_job = 1\nfetch_connect_timeout_secs = 2\n";

            struct Probe;

            impl Service for Probe {
                fn serve(&self, _: JobContext, stream: UnixStream) -> ServeFuture<'_> {
                    Box::pin(async move { drop(stream) })
                }
            }

            struct Wiring {
                feeds: Arc<FeedBook>,
                registry: PerJob<Probe>,
                rig: Rig,
                services: JobServices,
                end: crate::runner::JobEnd,
            }

            fn wiring() -> Result<Wiring, Box<dyn std::error::Error>> {
                let feeds = Arc::new(FeedBook::default());
                let mut services = job_services(&config_of(CONFIG)?, &feeds);
                let registry = PerJob::new();
                registry.register("job1", Arc::new(Probe))?;
                services
                    .broker
                    .register("job1", Arc::new(DynBroker(Box::new(Probe))))?;
                let end = services.end.clone().unregistering(registry.clone());
                let rig = rig_with(std::mem::take(&mut services.services))?;
                Ok(Wiring {
                    feeds,
                    registry,
                    rig,
                    services,
                    end,
                })
            }

            fn job(id: &str) -> Job {
                Job {
                    job_id: id.into(),
                    repo: "file:///nonexistent.git".into(),
                    base_ref: "main".into(),
                    attempt: 1,
                    ..Job::default()
                }
            }

            impl Wiring {
                fn agent<R: Reporter>(&self, cfg: RunConfig, reporter: R) -> AgentRunner<R> {
                    AgentRunner::new(cfg, reporter, Redactor::default())
                        .with_feed_book(Arc::clone(&self.feeds))
                        .with_job_end(self.end.clone())
                }

                async fn spend(&self) -> TestResult {
                    register(&self.feeds, "job1");
                    let first = self.rig.fetch(FETCH).await?;
                    assert!(!first.contains(Refusal::CapReached.message()), "{first}");
                    let second = self.rig.fetch(FETCH).await?;
                    assert!(second.contains(Refusal::CapReached.message()), "{second}");
                    assert_eq!(self.rig.connect(HOSTILE).await?, FORBIDDEN);
                    assert_eq!(self.services.proxy.stats("job1").refusals, 1);
                    assert!(self.registry.contains("job1"));
                    assert!(self.services.broker.contains("job1"));
                    Ok(())
                }

                async fn assert_cleared(&self) -> TestResult {
                    assert!(!self.registry.contains("job1"), "registry entry");
                    assert!(!self.services.broker.contains("job1"), "broker entry");
                    assert_eq!(
                        self.feeds.record("job1", URL, FetchPhase::Intent),
                        Err(FetchRecordError::Closed),
                        "feed"
                    );
                    assert_eq!(self.services.proxy.stats("job1"), ProxyStats::default());
                    register(&self.feeds, "job1");
                    let first = self.rig.fetch(FETCH).await?;
                    assert!(!first.contains(Refusal::CapReached.message()), "{first}");
                    let second = self.rig.fetch(FETCH).await?;
                    assert!(second.contains(Refusal::CapReached.message()), "{second}");
                    Ok(())
                }
            }

            struct Cancelling;

            impl Reporter for Cancelling {
                fn report(
                    &self,
                    _: ReportJobRequest,
                ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
                    std::future::ready(Ok(ReportJobReply {
                        cancel_requested: true,
                        ..ReportJobReply::default()
                    }))
                }
            }

            struct Panicking;

            impl Reporter for Panicking {
                fn report(
                    &self,
                    _: ReportJobRequest,
                ) -> impl Future<Output = Result<ReportJobReply, Status>> + Send {
                    assert!(std::hint::black_box(false), "boom");
                    std::future::ready(Ok(ReportJobReply::default()))
                }
            }

            fn slow_prepare(dir: &Path) -> Result<Workspace, io::Error> {
                let git = super::super::script(dir, "sleep 30")?;
                Ok(super::super::workspace(dir, &git))
            }

            fn fast() -> RunConfig {
                let mut cfg = RunConfig::new("claude", false);
                cfg.report_interval = Duration::from_millis(100);
                cfg
            }

            #[tokio::test]
            async fn a_lost_lease_clears_every_service_and_the_next_job_starts_at_zero()
            -> TestResult {
                let wiring = wiring()?;
                wiring.spend().await?;
                let dir = TempDir::new()?;
                let (tx, _rx) = mpsc::unbounded_channel();
                let runner = DaemonRunner::new(
                    slow_prepare(dir.path())?,
                    wiring.agent(fast(), super::super::Stale(tx)),
                    "",
                );
                let (_trigger, shutdown) = crate::poller::Shutdown::channel();
                let ended =
                    timeout(Duration::from_secs(20), runner.run(job("job1"), shutdown)).await?;
                assert!(ended.is_err());
                wiring.assert_cleared().await
            }

            #[tokio::test]
            async fn a_cancelled_job_clears_every_service_and_the_next_job_starts_at_zero()
            -> TestResult {
                let wiring = wiring()?;
                wiring.spend().await?;
                let dir = TempDir::new()?;
                let runner = DaemonRunner::new(
                    slow_prepare(dir.path())?,
                    wiring.agent(fast(), Cancelling),
                    "",
                );
                let (_trigger, shutdown) = crate::poller::Shutdown::channel();
                let ended =
                    timeout(Duration::from_secs(20), runner.run(job("job1"), shutdown)).await?;
                assert!(ended.is_err());
                wiring.assert_cleared().await
            }

            #[tokio::test]
            async fn a_panicking_job_clears_every_service_and_the_next_job_starts_at_zero()
            -> TestResult {
                let wiring = wiring()?;
                wiring.spend().await?;
                let dir = TempDir::new()?;
                let runner = Arc::new(DaemonRunner::new(
                    slow_prepare(dir.path())?,
                    wiring.agent(fast(), Panicking),
                    "",
                ));
                let (_trigger, shutdown) = crate::poller::Shutdown::channel();
                let task = tokio::spawn(async move { runner.run(job("job1"), shutdown).await });
                let joined = timeout(Duration::from_secs(20), task).await?;
                assert!(joined.is_err_and(|err| err.is_panic()));
                wiring.assert_cleared().await
            }

            fn git(dir: &Path, args: &[&str]) -> TestResult {
                let status = Command::new("git")
                    .arg("-C")
                    .arg(dir)
                    .args(["-c", "user.name=t", "-c", "user.email=t@t.invalid"])
                    .args(args)
                    .status()?;
                assert!(status.success(), "git {args:?}");
                Ok(())
            }

            #[tokio::test]
            async fn a_job_that_succeeds_clears_every_service_and_the_next_job_starts_at_zero()
            -> TestResult {
                let wiring = wiring()?;
                wiring.spend().await?;
                let dir = TempDir::new()?;
                let origin = dir.path().join("origin.git");
                let seed = dir.path().join("seed");
                std::fs::create_dir_all(&origin)?;
                git(&origin, &["init", "--bare", "-b", "main"])?;
                git(
                    dir.path(),
                    &["clone", origin.to_str().unwrap_or(""), "seed"],
                )?;
                git(&seed, &["commit", "--allow-empty", "-m", "init"])?;
                git(&seed, &["push", "origin", "HEAD:main"])?;
                let claude = dir.path().join("claude");
                std::fs::write(
                    &claude,
                    "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo '2.1.289 (Claude Code)'; fi\nexit 0\n",
                )?;
                std::fs::set_permissions(&claude, std::fs::Permissions::from_mode(0o755))?;
                let (tx, mut rx) = mpsc::unbounded_channel();
                let policy = RepoPolicy::new(Vec::<String>::new()).with_file_repos();
                let workspace = Workspace::new(dir.path().join("jobs")).with_policy(policy.clone());
                let mut cfg = RunConfig::new(&claude, false);
                cfg.repo_policy = policy;
                let runner =
                    DaemonRunner::new(workspace, wiring.agent(cfg, super::super::Recorder(tx)), "");
                let mut job = job("job1");
                job.repo = format!("file://{}", origin.display());
                let (_trigger, shutdown) = crate::poller::Shutdown::channel();
                let ended = timeout(Duration::from_secs(60), runner.run(job, shutdown)).await?;
                assert!(ended.is_ok(), "{ended:?}");
                let mut succeeded = false;
                while let Ok(report) = rx.try_recv() {
                    succeeded |= report.terminal_state == Some(JobState::Succeeded as i32);
                }
                assert!(succeeded, "the job reached its SUCCEEDED report");
                wiring.assert_cleared().await
            }

            #[tokio::test]
            async fn ending_a_job_twice_and_ending_an_unknown_job_are_harmless() -> TestResult {
                let wiring = wiring()?;
                wiring.spend().await?;
                let (tx, _rx) = mpsc::unbounded_channel();
                let agent = wiring.agent(fast(), super::super::Recorder(tx));
                agent.end_job(&job("job2"));
                agent.end_job(&job("never"));
                assert!(wiring.registry.contains("job1"), "other ids leave job1");
                assert_eq!(wiring.services.proxy.stats("job1").refusals, 1);
                let capped = wiring.rig.fetch(FETCH).await?;
                assert!(capped.contains(Refusal::CapReached.message()), "{capped}");
                agent.end_job(&job("job1"));
                agent.end_job(&job("job1"));
                wiring.assert_cleared().await
            }

            #[tokio::test]
            async fn ending_a_job_while_its_fetch_is_in_flight_does_not_hang_or_revive_it()
            -> TestResult {
                let wiring = wiring()?;
                register(&wiring.feeds, "job1");
                let (tx, _rx) = mpsc::unbounded_channel();
                let agent = wiring.agent(fast(), super::super::Recorder(tx));
                let ender = async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    agent.end_job(&job("job1"));
                };
                let (reply, ()) = tokio::join!(wiring.rig.fetch(FETCH), ender);
                let reply = reply?;
                assert!(reply.starts_with(r#"{"status":"error""#), "{reply}");
                wiring.assert_cleared().await
            }
        }
    }
}
