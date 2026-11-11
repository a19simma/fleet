//! Publishes a finished job: commits leftovers, pushes its branch and opens the pull request.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError};

use fleet_core::host::HostKind;
use fleet_forge::{Git, GitCommand, GitError, GitOp, GitOutput, Http};
use fleet_proto::is_ci_url;
use fleet_proto::is_swarm_branch;
use fleet_proto::v1::Job;
use tokio::sync::{Mutex, MutexGuard};

use crate::broker::{ExecError, GhExecutor, GitExecutor, MirrorGit};
use crate::forge::JobForge;
use crate::phase::{Phases, elapsed_ms};
use crate::proc::{CAPTURE_BYTES, CaptureError, Captured};
use crate::runner::{AgentRunner, Failure, IntoFailure, Reporter, Scope};
use crate::workspace::{
    RepoPolicy, Workspace, is_commit_sha, job_owner, validate_job_id, validate_ref, validate_repo,
};

const MAX_TITLE_CHARS: usize = 256;
const MAX_PR_URL_BYTES: usize = 2048;
const ERR_COMMITS: &str = "job commits could not be inspected";
const ERR_PUSH: &str = "git push failed";
const ERR_PR: &str = "pull request could not be opened";
const ERR_PR_URL: &str = "pull request url was not returned";
const ERR_SECRET: &str = "uncommitted changes held a secret value";
const MAX_DIFF_BYTES: u64 = 32 * 1024 * 1024;
const FALLBACK_GUARDS: [&str; 16] = [
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.fsmonitor=",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "core.sshCommand=",
    "-c",
    "credential.helper=",
    "-c",
    "gc.auto=0",
    "-c",
    "maintenance.auto=false",
    "-c",
    "core.pager=cat",
];

/// The argv of every credentialed `git push` of a Job, shared by the finish step and the broker
/// so the hooks, fsmonitor, redirect and credential-helper guards cannot drift apart.
fn push_argv<'a>(repo: &'a str, refspec: &'a str) -> [&'a str; 14] {
    [
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=",
        "-c",
        "http.followRedirects=false",
        "-c",
        "credential.helper=",
        "push",
        "--quiet",
        "--no-verify",
        "--",
        repo,
        refspec,
    ]
}

impl<R: Reporter> AgentRunner<R> {
    /// The repository policy for `job`: the static policy, plus the Forgejo host the held
    /// credentials were issued for. A Forgejo Job accepts only its own host, so a repository on
    /// another host stays refused. A Job with no Forgejo entry gets the static policy.
    pub(crate) fn job_policy(&self, job: &Job) -> RepoPolicy {
        let held = self
            .credentials
            .as_ref()
            .and_then(|book| book.get(&job.job_id));
        match self.job_token_host(held.as_deref()) {
            Some((host, HostKind::Forgejo)) => {
                let mut forgejo = self.config.repo_policy.clone().with_job_host(host);
                forgejo.restrict_to(host);
                forgejo
            }
            _ => self.config.repo_policy.clone(),
        }
    }

    pub(crate) async fn publish(
        &self,
        job: &Job,
        cwd: &Path,
        phases: &mut Phases,
    ) -> Result<Published, Failure> {
        validate_job_id(&job.job_id).map_err(|_| Failure::bare(ERR_COMMITS))?;
        validate_repo(&job.repo, &self.job_policy(job)).map_err(|_| Failure::bare(ERR_PUSH))?;
        validate_ref(&job.base_ref).map_err(|_| Failure::bare(ERR_COMMITS))?;
        let local = format!("swarm/{}", job.job_id);
        let target = PushTarget::from_job(job)?;
        let branch = target.remote_branch();
        let shared = self.publish_state(&job.job_id);
        let mut book = shared.held.lock().await;
        let scratch = Scratch::create(cwd, &job.job_id).map_err(|()| Failure::bare(ERR_COMMITS))?;
        let dir = scratch.path();
        self.commit_leftovers(job, cwd, dir).await?;
        if !self.ahead(job, &local, cwd, dir).await? {
            return Ok(Published {
                branch: None,
                pr_url: None,
            });
        }
        let head = self.local_head(&local, dir).await?;
        if book.pushed.as_deref() != Some(head.as_str()) {
            let push_start = self.clock.now();
            let pushed = self.push_branch(job, dir, &local, &branch).await;
            phases.push = Some(elapsed_ms(&*self.clock, push_start));
            pushed?;
            book.pushed = Some(head);
        }
        let pr_url = match target {
            PushTarget::Chain(_) => job.pr_url.clone().filter(|url| is_ci_url(url)),
            PushTarget::Own(_) if !job.open_pr => None,
            PushTarget::Own(_) => Some(self.own_pr(job, &branch, dir, &mut book, phases).await?),
        };
        drop(book);
        Ok(Published {
            branch: Some(branch),
            pr_url,
        })
    }

    async fn own_pr(
        &self,
        job: &Job,
        branch: &str,
        dir: &Path,
        book: &mut Held,
        phases: &mut Phases,
    ) -> Result<String, Failure> {
        if let Some(url) = book.pr_url.clone() {
            return Ok(url);
        }
        let pr_start = self.clock.now();
        let opened = if book.pr_attempted {
            self.open_or_find_pr(job, branch, dir).await
        } else {
            self.open_pr(job, branch, dir).await
        };
        phases.pr = Some(elapsed_ms(&*self.clock, pr_start));
        let url = opened?;
        book.pr_url = Some(url.clone());
        Ok(url)
    }

    pub(crate) fn publish_state(&self, job_id: &str) -> Arc<JobPublish> {
        self.publishing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(job_id.to_owned())
            .or_default()
            .clone()
    }

    pub(crate) fn forget_publish(&self, job_id: &str) {
        self.publishing
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(job_id);
    }

    async fn push_branch(
        &self,
        job: &Job,
        dir: &Path,
        local: &str,
        branch: &str,
    ) -> Result<(), Failure> {
        let refspec = format!("refs/heads/{local}:refs/heads/{branch}");
        let pushed = self
            .helper(
                &self.config.git_bin,
                dir,
                &push_argv(&job.repo, &refspec),
                Scope::Push(&job.job_id),
            )
            .await
            .map_err(|e| e.failure(ERR_PUSH))?;
        if pushed.success {
            Ok(())
        } else {
            Err(Failure::tail(ERR_PUSH, &pushed.stderr))
        }
    }

    async fn local_head(&self, local: &str, dir: &Path) -> Result<String, Failure> {
        let parsed = self
            .helper(
                &self.config.git_bin,
                dir,
                &["rev-parse", "--verify", &format!("refs/heads/{local}")],
                Scope::Clean,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        let head = parsed.stdout.trim();
        if parsed.success && is_commit_sha(head) {
            Ok(head.to_owned())
        } else {
            Err(Failure::bare(ERR_COMMITS))
        }
    }

    /// Starts the broker `push`: validates the Job, takes the publish lock and finds out whether
    /// the Job's committed work needs pushing. It reads the finish step's state and never a
    /// refspec of the agent, and adds no leftover commit. A head the shared [`JobPublish`] state
    /// already holds is [`Pushed::Already`].
    pub(crate) async fn broker_push_begin<'a>(
        &self,
        shared: &'a JobPublish,
        job: &Job,
        cwd: &Path,
    ) -> Result<PushBegin<'a>, Failure> {
        validate_job_id(&job.job_id).map_err(|_| Failure::bare(ERR_COMMITS))?;
        validate_repo(&job.repo, &self.job_policy(job)).map_err(|_| Failure::bare(ERR_PUSH))?;
        validate_ref(&job.base_ref).map_err(|_| Failure::bare(ERR_COMMITS))?;
        let local = format!("swarm/{}", job.job_id);
        let branch = PushTarget::from_job(job)?.remote_branch();
        let book = shared.held.lock().await;
        let scratch = Scratch::create(cwd, &job.job_id).map_err(|()| Failure::bare(ERR_COMMITS))?;
        if !self.ahead(job, &local, cwd, scratch.path()).await? {
            return Ok(PushBegin::Settled(Pushed::Nothing));
        }
        let head = self.local_head(&local, scratch.path()).await?;
        if book.pushed.as_deref() == Some(head.as_str()) {
            return Ok(PushBegin::Settled(Pushed::Already));
        }
        Ok(PushBegin::Run(PushRun {
            book,
            scratch,
            head,
            local,
            branch,
        }))
    }

    /// Starts the broker `pr_create`: validates the Job and takes the publish lock. It returns the
    /// URL the shared state holds, or the `pr_url` a fix Job carries, without opening anything. A
    /// Job with `open_pr` off, or a branch not yet pushed, fails. Otherwise it marks the attempt,
    /// so the finish step looks for the pull request before it creates one, and returns the
    /// branch to open it for.
    pub(crate) async fn broker_pr_begin<'a>(
        &self,
        shared: &'a JobPublish,
        job: &Job,
    ) -> Result<PrBegin<'a>, Failure> {
        validate_job_id(&job.job_id).map_err(|_| Failure::bare(ERR_COMMITS))?;
        validate_repo(&job.repo, &self.job_policy(job)).map_err(|_| Failure::bare(ERR_PR))?;
        validate_ref(&job.base_ref).map_err(|_| Failure::bare(ERR_PR))?;
        let target = PushTarget::from_job(job)?;
        let branch = target.remote_branch();
        let mut book = shared.held.lock().await;
        if let Some(url) = book.pr_url.clone() {
            return Ok(PrBegin::Known(url));
        }
        match target {
            PushTarget::Chain(_) => {
                return job
                    .pr_url
                    .clone()
                    .filter(|url| is_ci_url(url))
                    .map(PrBegin::Known)
                    .ok_or_else(|| Failure::bare(ERR_PR));
            }
            PushTarget::Own(_) if !job.open_pr => return Err(Failure::bare(ERR_PR)),
            PushTarget::Own(_) => {}
        }
        if book.pushed.is_none() {
            return Err(Failure::bare(ERR_PR));
        }
        book.pr_attempted = true;
        Ok(PrBegin::Open(PrRun { book, branch }))
    }

    async fn open_or_find_pr(
        &self,
        job: &Job,
        branch: &str,
        dir: &Path,
    ) -> Result<String, Failure> {
        match self.existing_pr(job, branch, dir).await? {
            Some(url) => Ok(url),
            None => self.open_pr(job, branch, dir).await,
        }
    }

    /// Looks up the open pull request of `branch`. `None` when there is none, or when the
    /// listing failed to start, timed out or exited nonzero: the caller then opens one.
    ///
    /// # Errors
    ///
    /// A credential failure of the token refresh before the call, such as the mint cap or a
    /// lost lease, is terminal: it fails the step with the failure's reason and never reads
    /// as "no pull request".
    pub(crate) async fn existing_pr(
        &self,
        job: &Job,
        branch: &str,
        dir: &Path,
    ) -> Result<Option<String>, Failure> {
        let listed = self
            .helper(
                &self.config.gh_bin,
                dir,
                &[
                    "pr", "list", "--repo", &job.repo, "--head", branch, "--state", "open",
                    "--limit", "1", "--json", "url", "--jq", ".[].url",
                ],
                Scope::Gh(&job.job_id),
            )
            .await;
        match listed {
            Err(CaptureError::Credentials(failure)) => Err(Failure::bare(failure.reason())),
            Ok(listed) if listed.success => Ok(pr_url(&listed.stdout)),
            Ok(_) | Err(_) => Ok(None),
        }
    }

    fn holds_secret(&self, job_id: &str, text: &str) -> bool {
        matches!(self.job_redactor(job_id).redact_str(text), Cow::Owned(_))
    }

    async fn commit_leftovers(&self, job: &Job, cwd: &Path, dir: &Path) -> Result<(), Failure> {
        let tree = Scope::Tree(&job.job_id, cwd);
        let listed = self
            .helper(
                &self.config.git_bin,
                dir,
                &["config", "--list", "--name-only"],
                tree,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !listed.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        let mut guards: Vec<String> = FALLBACK_GUARDS.map(str::to_owned).to_vec();
        for name in filter_drivers(&listed.stdout).ok_or_else(|| Failure::bare(ERR_COMMITS))? {
            for (key, value) in [
                ("clean", ""),
                ("smudge", ""),
                ("process", ""),
                ("required", "false"),
            ] {
                guards.push("-c".to_owned());
                guards.push(format!("filter.{name}.{key}={value}"));
            }
        }
        let status = self
            .guarded(
                dir,
                &guards,
                tree,
                &["status", "--porcelain"],
                CAPTURE_BYTES,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !status.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        if status.stdout.trim().is_empty() {
            return Ok(());
        }
        let added = self
            .guarded(dir, &guards, tree, &["add", "-A"], CAPTURE_BYTES)
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !added.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        let staged = self
            .guarded(
                dir,
                &guards,
                tree,
                &[
                    "diff",
                    "--cached",
                    "--text",
                    "--no-ext-diff",
                    "--no-textconv",
                    "--no-color",
                ],
                MAX_DIFF_BYTES,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !staged.success || staged.truncated {
            return Err(Failure::bare(ERR_COMMITS));
        }
        if self.holds_secret(&job.job_id, &staged.stdout) {
            return Err(Failure::bare(ERR_SECRET));
        }
        if staged.stdout.is_empty() {
            return Ok(());
        }
        let message = format!("chore: uncommitted job changes (fleet job {})", job.job_id);
        let committed = self
            .guarded(
                dir,
                &guards,
                tree,
                &[
                    "commit",
                    "--quiet",
                    "--no-verify",
                    "--no-gpg-sign",
                    "-m",
                    &message,
                ],
                CAPTURE_BYTES,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if committed.success {
            Ok(())
        } else {
            Err(Failure::bare(ERR_COMMITS))
        }
    }

    async fn guarded(
        &self,
        dir: &Path,
        guards: &[String],
        tree: Scope<'_>,
        rest: &[&str],
        limit: u64,
    ) -> Result<Captured, CaptureError> {
        let mut args: Vec<&str> = guards.iter().map(String::as_str).collect();
        args.extend_from_slice(rest);
        self.helper_limited(&self.config.git_bin, dir, &args, tree, limit)
            .await
    }

    async fn ahead(
        &self,
        job: &Job,
        branch: &str,
        cwd: &Path,
        dir: &Path,
    ) -> Result<bool, Failure> {
        self.helper(
            &self.config.git_bin,
            dir,
            &["init", "--bare", "--quiet"],
            Scope::Clean,
        )
        .await
        .map_err(|e| e.failure(ERR_COMMITS))?;
        let root = cwd.parent().ok_or_else(|| Failure::bare(ERR_COMMITS))?;
        link_mirror(
            dir,
            &Workspace::mirror_dir_for(root, &job_owner(job), &job.repo),
        )
        .map_err(|_| Failure::bare(ERR_COMMITS))?;
        let worktree = cwd.to_str().ok_or_else(|| Failure::bare(ERR_COMMITS))?;
        let head = format!("+refs/heads/{branch}:refs/heads/{branch}");
        let pinned = is_commit_sha(&job.base_ref);
        let base = format!(
            "+refs/remotes/origin/{base}:refs/remotes/origin/{base}",
            base = job.base_ref
        );
        let mut specs = vec![head.as_str()];
        if !pinned {
            specs.push(base.as_str());
        }
        let mut fetch_args = vec![
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=",
            "-c",
            "core.sshCommand=",
            "-c",
            "credential.helper=",
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            "--",
            worktree,
        ];
        fetch_args.extend(specs);
        let fetched = self
            .helper(&self.config.git_bin, dir, &fetch_args, Scope::Clean)
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        if !fetched.success {
            return Err(Failure::bare(ERR_COMMITS));
        }
        let floor = if pinned {
            job.base_ref.clone()
        } else {
            format!("refs/remotes/origin/{}", job.base_ref)
        };
        let range = format!("{floor}..refs/heads/{branch}");
        let counted = self
            .helper(
                &self.config.git_bin,
                dir,
                &["rev-list", "--count", &range],
                Scope::Clean,
            )
            .await
            .map_err(|e| e.failure(ERR_COMMITS))?;
        let count = counted.stdout.trim();
        if !counted.success || count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
            return Err(Failure::bare(ERR_COMMITS));
        }
        Ok(!count.bytes().all(|b| b == b'0'))
    }

    async fn open_pr(&self, job: &Job, branch: &str, dir: &Path) -> Result<String, Failure> {
        let subject = self
            .helper(
                &self.config.git_bin,
                dir,
                &["log", "-1", "--format=%s", &format!("refs/heads/{branch}")],
                Scope::Clean,
            )
            .await
            .map_err(|e| e.failure(ERR_PR))?;
        let title: String = match subject.stdout.trim() {
            "" => branch,
            line => line,
        }
        .chars()
        .take(MAX_TITLE_CHARS)
        .collect();
        self.create_pr(
            job,
            branch,
            dir,
            &title,
            &format!("Fleet job {}", job.job_id),
        )
        .await
    }

    async fn create_pr(
        &self,
        job: &Job,
        branch: &str,
        dir: &Path,
        title: &str,
        body: &str,
    ) -> Result<String, Failure> {
        let created = self
            .helper(
                &self.config.gh_bin,
                dir,
                &[
                    "pr",
                    "create",
                    "--repo",
                    &job.repo,
                    "--head",
                    branch,
                    "--base",
                    &job.base_ref,
                    "--title",
                    title,
                    "--body",
                    body,
                ],
                Scope::Gh(&job.job_id),
            )
            .await
            .map_err(|e| e.failure(ERR_PR))?;
        if !created.success {
            return Err(Failure::tail(ERR_PR, &created.stderr));
        }
        pr_url(&created.stdout).ok_or_else(|| Failure::bare(ERR_PR_URL))
    }
}

/// The remote branch a job pushes to, built once from the claimed Job.
///
/// A normal job pushes to its own `swarm/<job_id>` branch. A fix Job (`parent_job_id` set,
/// ADR-0028) pushes to the existing chain-root branch named by its `base_ref`, which passed
/// [`is_swarm_branch`] when the target was built. `git push` receives no branch name except
/// through [`PushTarget::remote_branch`].
enum PushTarget {
    Own(String),
    Chain(String),
}

impl PushTarget {
    fn from_job(job: &Job) -> Result<Self, Failure> {
        if job.parent_job_id.is_none() {
            Ok(Self::Own(job.job_id.clone()))
        } else if is_swarm_branch(&job.base_ref) {
            Ok(Self::Chain(job.base_ref.clone()))
        } else {
            Err(Failure::bare(ERR_PUSH))
        }
    }

    fn remote_branch(&self) -> String {
        match self {
            Self::Own(job_id) => format!("swarm/{job_id}"),
            Self::Chain(branch) => branch.clone(),
        }
    }
}

/// What a broker `push` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pushed {
    /// The Job's branch has no commit beyond its base.
    Nothing,
    /// The head was already published, by an earlier push or by the finish step.
    Already,
    /// The head was pushed now.
    Done,
}

impl Pushed {
    const fn status(self) -> &'static str {
        match self {
            Self::Nothing => "nothing to push",
            Self::Already => "already published",
            Self::Done => "pushed",
        }
    }
}

/// The publish state of one Job, shared by the broker and the finish step.
///
/// Its lock is held across every publish operation of the Job, so a broker `push` and the
/// finish step never run git in the Job's scratch repo at once. It remembers the head commit
/// already pushed and the pull request URL already known. The finish step skips a push of a
/// head recorded here and still pushes any commit made after it. After a broker `pr_create`
/// that did not return a URL, the finish step looks for an open pull request of the branch
/// before it creates one, because the failed call may have created it.
#[derive(Debug, Default)]
pub struct JobPublish {
    held: Mutex<Held>,
}

#[derive(Debug, Default)]
struct Held {
    pushed: Option<String>,
    pr_url: Option<String>,
    pr_attempted: bool,
}

/// What [`AgentRunner::broker_push_begin`] found.
pub(crate) enum PushBegin<'a> {
    /// Nothing to push, or the head is already published.
    Settled(Pushed),
    /// The head must be pushed.
    Run(PushRun<'a>),
}

/// A broker push in progress. It holds the publish lock and the scratch repo until
/// [`PushRun::done`] or its drop.
pub(crate) struct PushRun<'a> {
    book: MutexGuard<'a, Held>,
    scratch: Scratch,
    head: String,
    local: String,
    branch: String,
}

impl PushRun<'_> {
    pub(crate) fn branch(&self) -> &str {
        &self.branch
    }

    /// Records the head as published and releases the lock.
    pub(crate) fn done(mut self) -> Pushed {
        self.book.pushed = Some(self.head);
        Pushed::Done
    }
}

/// What [`AgentRunner::broker_pr_begin`] found.
pub(crate) enum PrBegin<'a> {
    /// The URL is already known.
    Known(String),
    /// The pull request must be opened.
    Open(PrRun<'a>),
}

/// A broker `pr_create` in progress. It holds the publish lock until [`PrRun::done`] or its drop.
pub(crate) struct PrRun<'a> {
    book: MutexGuard<'a, Held>,
    branch: String,
}

impl PrRun<'_> {
    pub(crate) fn branch(&self) -> &str {
        &self.branch
    }

    /// Records the URL and releases the lock.
    pub(crate) fn done(mut self, url: &str) {
        self.book.pr_url = Some(url.to_owned());
    }
}

/// The git seam of one broker push: the finish step's `git push` into the Job's repo, run in
/// the scratch repo.
///
/// The adapter calls it with the branch it validated. It pushes `refs/heads/{local}` to that
/// branch of the Job's repo with hooks, redirects and credential helpers off, and takes the
/// token from the runner's own refresh, lease and askpass path, so it ignores the credential of
/// the command. A start failure, a timeout and a credential failure are all
/// [`GitError::Spawn`] or [`GitError::Timeout`] with no text. It refuses any other operation.
struct PushGit<'a, R> {
    runner: &'a AgentRunner<R>,
    job: &'a Job,
    dir: &'a Path,
    local: &'a str,
}

impl<R: Reporter + Send + Sync + 'static> Git for PushGit<'_, R> {
    async fn run(&self, command: GitCommand) -> Result<GitOutput, GitError> {
        let branch = command
            .branch
            .filter(|_| command.op == GitOp::Push)
            .ok_or(GitError::Spawn)?;
        let refspec = format!("refs/heads/{}:refs/heads/{branch}", self.local);
        let pushed = self
            .runner
            .helper(
                &self.runner.config.git_bin,
                self.dir,
                &push_argv(&self.job.repo, &refspec),
                Scope::Push(&self.job.job_id),
            )
            .await
            .map_err(|error| match error {
                CaptureError::Timeout => GitError::Timeout,
                CaptureError::Start | CaptureError::Credentials(_) => {
                    tracing::warn!(error = error.failure(ERR_PUSH).error, "broker push failed");
                    GitError::Spawn
                }
            })?;
        Ok(GitOutput {
            code: i32::from(!pushed.success),
            stderr: pushed.stderr,
        })
    }
}

/// The real `push` of the broker: the finish step's publish path for one Job, through
/// [`JobForge::push`].
///
/// Branch and repo come from the claimed Job, never from a request. The push is fast-forward
/// only, as in the finish step. A failure logs a fixed line and replies with the broker's fixed
/// error: no git stderr leaves this executor. `fetch` goes through [`JobForge::fetch`] with
/// [`MirrorGit`] as its git seam. A Job with no [`JobForge`] gets the fixed error from both.
/// `DaemonRunner` builds it per claimed Job under the systemd launcher.
pub struct PublishGit<R, H> {
    runner: Arc<AgentRunner<R>>,
    shared: Arc<JobPublish>,
    job: Job,
    cwd: PathBuf,
    mirror: MirrorGit,
    forge: Option<JobForge<H>>,
}

impl<R: Reporter, H> PublishGit<R, H> {
    /// An executor that publishes the worktree `cwd` of `job`, on the publish state the
    /// runner keeps for the Job.
    #[must_use]
    pub fn new(
        runner: Arc<AgentRunner<R>>,
        job: Job,
        cwd: PathBuf,
        mirror: MirrorGit,
        forge: Option<JobForge<H>>,
    ) -> Self {
        Self {
            shared: runner.publish_state(&job.job_id),
            runner,
            job,
            cwd,
            mirror,
            forge,
        }
    }
}

/// The git seam of one broker fetch: it refreshes the Job's mirror and refuses any other
/// operation. A failure is exit code 1 with no text, since [`MirrorGit`] logs the cause.
struct MirrorFetch(MirrorGit);

impl Git for MirrorFetch {
    async fn run(&self, command: GitCommand) -> Result<GitOutput, GitError> {
        if command.op != GitOp::Fetch {
            return Err(GitError::Spawn);
        }
        Ok(GitOutput {
            code: i32::from(!self.0.refresh().await),
            stderr: String::new(),
        })
    }
}

impl<R: Reporter + Send + Sync + 'static, H: Http> GitExecutor for PublishGit<R, H> {
    async fn push(&self, _target: &crate::broker::PushTarget) -> Result<String, ExecError> {
        let forge = self.forge.as_ref().ok_or(ExecError)?;
        let run = match self
            .runner
            .broker_push_begin(&self.shared, &self.job, &self.cwd)
            .await
            .map_err(|failure| {
                tracing::warn!(error = failure.error, "broker push failed");
                ExecError
            })? {
            PushBegin::Settled(pushed) => return Ok(pushed.status().to_owned()),
            PushBegin::Run(run) => run,
        };
        let git = PushGit {
            runner: &self.runner,
            job: &self.job,
            dir: run.scratch.path(),
            local: &run.local,
        };
        forge.push(git, run.branch()).await?;
        Ok(run.done().status().to_owned())
    }

    async fn fetch(&self) -> Result<String, ExecError> {
        let forge = self.forge.as_ref().ok_or(ExecError)?;
        forge.fetch(MirrorFetch(self.mirror.clone())).await
    }
}

/// The real `pr_create` of the broker, through [`JobForge::create_pr`], with `pr_checks`
/// delegated to the executor `C`.
///
/// It returns the URL the shared [`JobPublish`] state holds, else the URL the adapter returns:
/// the open pull request of the Job's branch, or a new one with the title and body the broker
/// validated and redacted. A Job with `open_pr` off, or a branch not yet pushed, fails. A fix Job
/// returns the `pr_url` its Job carries. A Job with no [`JobForge`] gets the fixed error.
pub struct PublishGh<R, C, H> {
    runner: Arc<AgentRunner<R>>,
    shared: Arc<JobPublish>,
    job: Job,
    checks: C,
    forge: Option<JobForge<H>>,
}

impl<R: Reporter, C, H> PublishGh<R, C, H> {
    /// An executor that opens the pull request of `job`, on the publish state the runner
    /// keeps for the Job.
    #[must_use]
    pub fn new(
        runner: Arc<AgentRunner<R>>,
        job: Job,
        checks: C,
        forge: Option<JobForge<H>>,
    ) -> Self {
        Self {
            shared: runner.publish_state(&job.job_id),
            runner,
            job,
            checks,
            forge,
        }
    }
}

impl<R: Reporter + Send + Sync + 'static, C: GhExecutor, H: Http> GhExecutor
    for PublishGh<R, C, H>
{
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the publish lock must span the forge call, and done consumes the guard"
    )]
    async fn pr_create(
        &self,
        _target: &crate::broker::PushTarget,
        title: &str,
        body: &str,
    ) -> Result<String, ExecError> {
        let run = match self
            .runner
            .broker_pr_begin(&self.shared, &self.job)
            .await
            .map_err(|failure| {
                tracing::warn!(error = failure.error, "broker pr_create failed");
                ExecError
            })? {
            PrBegin::Known(url) => return Ok(url),
            PrBegin::Open(run) => run,
        };
        let forge = self.forge.as_ref().ok_or(ExecError)?;
        let url = forge.create_pr(run.branch(), title, body).await?;
        run.done(&url);
        Ok(url)
    }

    fn pr_checks(
        &self,
        target: &crate::broker::PushTarget,
        pr_url: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send {
        self.checks.pr_checks(target, pr_url)
    }
}

pub(crate) struct Published {
    pub(crate) branch: Option<String>,
    pub(crate) pr_url: Option<String>,
}

pub(crate) const HOME_DIR: &str = "home";
pub(crate) const GH_CONFIG_DIR: &str = "gh";

pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn create(cwd: &Path, job_id: &str) -> Result<Self, ()> {
        let parent = cwd.parent().ok_or(())?;
        let path = parent.join(format!(".finish-{job_id}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).map_err(|_| ())?;
        for sub in [HOME_DIR, GH_CONFIG_DIR] {
            std::fs::create_dir(path.join(sub)).map_err(|_| ())?;
        }
        Ok(Self(path))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Points the scratch repo's object store at the mirror's, so the fetch from the job dir
/// moves only the objects the job added. Does nothing when the mirror has no object store.
///
/// The mirror is fleetd's own and the job group cannot write it, so the alternate is
/// trusted. The path is made absolute because git resolves a relative alternate against the
/// objects directory, not the caller's cwd.
fn link_mirror(scratch: &Path, mirror: &Path) -> std::io::Result<()> {
    let objects = std::path::absolute(mirror)?.join("objects");
    if !objects.is_dir() {
        return Ok(());
    }
    let info = scratch.join("objects").join("info");
    std::fs::create_dir_all(&info)?;
    let mut line = objects.into_os_string();
    line.push("\n");
    std::fs::write(info.join("alternates"), line.as_encoded_bytes())
}

fn filter_drivers(listing: &str) -> Option<BTreeSet<String>> {
    let mut names = BTreeSet::new();
    for line in listing.lines() {
        let Some(rest) = line.strip_prefix("filter.") else {
            continue;
        };
        let Some((name, _)) = rest.rsplit_once('.') else {
            continue;
        };
        if name.contains('=') {
            return None;
        }
        names.insert(name.to_owned());
    }
    Some(names)
}

fn pr_url(stdout: &str) -> Option<String> {
    let line = stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())?;
    let plain = line.len() <= MAX_PR_URL_BYTES
        && line.starts_with("https://")
        && !line.chars().any(|c| c.is_control() || c.is_whitespace());
    plain.then(|| line.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{ERR_PUSH, PushTarget, Scratch, link_mirror};
    use crate::runner::{AgentRunner, Reporter, RunConfig};
    use crate::workspace::{RepoPolicy, Workspace};
    use fleet_core::Redactor;
    use fleet_proto::v1::Job;
    use fleet_proto::v1::{ReportJobReply, ReportJobRequest};
    use std::future::Future;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn git(dir: &Path, args: &[&str]) -> Result<String, Box<dyn std::error::Error>> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid"])
            .args(args)
            .output()?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!("git {args:?} failed: {stderr}").into());
        }
        Ok(String::from_utf8(out.stdout)?.trim().to_owned())
    }

    fn relative_to_cwd(path: &Path) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let mut relative = PathBuf::new();
        for _ in std::env::current_dir()?.components().skip(1) {
            relative.push("..");
        }
        relative.push(path.strip_prefix("/")?);
        assert!(relative.is_relative());
        Ok(relative)
    }

    fn mirror_with_commit(dir: &Path) -> Result<(PathBuf, String), Box<dyn std::error::Error>> {
        let mirror = dir.join("mirror.git");
        let seed = dir.join("seed");
        std::fs::create_dir_all(&seed)?;
        git(
            dir,
            &["init", "--bare", "--quiet", "-b", "main", "mirror.git"],
        )?;
        git(&seed, &["init", "--quiet", "-b", "main"])?;
        std::fs::write(seed.join("a.txt"), "one")?;
        git(&seed, &["add", "."])?;
        git(&seed, &["commit", "--quiet", "-m", "one"])?;
        let target = mirror.to_str().ok_or("path")?;
        git(&seed, &["push", "--quiet", target, "main"])?;
        Ok((mirror, git(&seed, &["rev-parse", "HEAD"])?))
    }

    #[test]
    fn the_scratch_repo_reads_the_mirror_objects_through_a_relative_path() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let (mirror, sha) = mirror_with_commit(dir.path())?;
        let scratch = dir.path().join("scratch");
        git(
            dir.path(),
            &["init", "--bare", "--quiet", "-b", "main", "scratch"],
        )?;
        assert!(git(&scratch, &["cat-file", "-e", &sha]).is_err());
        link_mirror(&scratch, &relative_to_cwd(&mirror)?)?;
        git(&scratch, &["cat-file", "-e", &sha])?;
        let alternates = std::fs::read_to_string(scratch.join("objects/info/alternates"))?;
        assert!(Path::new(alternates.trim()).is_absolute(), "{alternates}");
        Ok(())
    }

    #[test]
    fn a_fetch_into_the_linked_scratch_moves_only_the_new_objects() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let (mirror, _) = mirror_with_commit(dir.path())?;
        let job = dir.path().join("job");
        let source = mirror.to_str().ok_or("path")?;
        git(
            dir.path(),
            &["clone", "--quiet", "--no-local", source, "job"],
        )?;
        std::fs::write(job.join("b.txt"), "two")?;
        git(&job, &["add", "."])?;
        git(&job, &["commit", "--quiet", "-m", "two"])?;
        let scratch = dir.path().join("scratch");
        git(
            dir.path(),
            &["init", "--bare", "--quiet", "-b", "main", "scratch"],
        )?;
        link_mirror(&scratch, &mirror)?;
        let worktree = job.to_str().ok_or("path")?;
        git(
            &scratch,
            &[
                "fetch",
                "--quiet",
                "--",
                worktree,
                "+refs/heads/main:refs/heads/main",
            ],
        )?;
        let counts = git(&scratch, &["count-objects", "-v"])?;
        let loose = counts
            .lines()
            .find_map(|l| l.strip_prefix("count: "))
            .ok_or("count")?;
        assert!(loose.parse::<u32>()? <= 3, "{counts}");
        let packed = counts
            .lines()
            .find_map(|l| l.strip_prefix("in-pack: "))
            .ok_or("in-pack")?;
        assert!(packed.parse::<u32>()? <= 3, "{counts}");
        Ok(())
    }

    #[test]
    fn a_mirror_without_an_object_store_is_skipped() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let scratch = dir.path().join("scratch");
        git(
            dir.path(),
            &["init", "--bare", "--quiet", "-b", "main", "scratch"],
        )?;
        link_mirror(&scratch, &dir.path().join("absent.git"))?;
        assert!(!scratch.join("objects/info/alternates").exists());
        Ok(())
    }

    struct Quiet;

    impl Reporter for Quiet {
        fn report(
            &self,
            _request: ReportJobRequest,
        ) -> impl Future<Output = Result<ReportJobReply, tonic::Status>> + Send {
            std::future::ready(Ok(ReportJobReply::default()))
        }
    }

    #[tokio::test]
    async fn the_production_ahead_path_borrows_the_mirror_objects() -> TestResult {
        let dir = tempfile::TempDir::new()?;
        let origin = dir.path().join("origin.git");
        let seed = dir.path().join("seed");
        std::fs::create_dir_all(&seed)?;
        git(
            dir.path(),
            &["init", "--bare", "--quiet", "-b", "main", "origin.git"],
        )?;
        git(&seed, &["init", "--quiet", "-b", "main"])?;
        std::fs::write(seed.join("a.txt"), "one")?;
        git(&seed, &["add", "."])?;
        git(&seed, &["commit", "--quiet", "-m", "one"])?;
        let url = origin.to_str().ok_or("path")?.to_owned();
        git(&seed, &["push", "--quiet", &url, "main"])?;
        let root = dir.path().join("jobs");
        let checkout = Workspace::new(&root)
            .with_policy(RepoPolicy::new(Vec::<String>::new()).with_file_repos())
            .with_owner("7")
            .prepare("job1", &url, "main")
            .await?;
        std::fs::write(checkout.path.join("b.txt"), "two")?;
        git(&checkout.path, &["add", "."])?;
        git(&checkout.path, &["commit", "--quiet", "-m", "two"])?;
        let mut config = RunConfig::new("claude-fake", false);
        config.jobs_dir = Some(root.clone());
        let runner = AgentRunner::new(config, Quiet, Redactor::default());
        let job = Job {
            job_id: "job1".into(),
            repo: url.clone(),
            base_ref: "main".into(),
            user_id: 7,
            ..Job::default()
        };
        let scratch = Scratch::create(&checkout.path, "job1").map_err(|()| "scratch")?;
        let ahead = runner
            .ahead(&job, "swarm/job1", &checkout.path, scratch.path())
            .await
            .map_err(|_| "ahead")?;
        assert!(ahead);
        let alternates = std::fs::read_to_string(scratch.path().join("objects/info/alternates"))?;
        let mirror = Workspace::mirror_dir_for(&root, "7", &url);
        assert_eq!(
            Path::new(alternates.trim()),
            std::path::absolute(mirror)?.join("objects")
        );
        Ok(())
    }

    fn test_job() -> Job {
        Job {
            job_id: "job1".into(),
            prompt: "do it".into(),
            ..Job::default()
        }
    }

    fn fix_job(base_ref: &str) -> Job {
        Job {
            parent_job_id: Some("root1".into()),
            base_ref: base_ref.into(),
            ..test_job()
        }
    }

    #[test]
    fn a_normal_job_targets_its_own_swarm_branch() {
        let target = PushTarget::from_job(&test_job()).ok();
        assert!(matches!(target, Some(PushTarget::Own(_))));
        assert_eq!(
            target.map(|t| t.remote_branch()),
            Some("swarm/job1".to_owned())
        );
    }

    #[test]
    fn a_fix_job_targets_the_chain_branch_of_its_base_ref() {
        let target = PushTarget::from_job(&fix_job("swarm/root1")).ok();
        assert!(matches!(target, Some(PushTarget::Chain(_))));
        assert_eq!(
            target.map(|t| t.remote_branch()),
            Some("swarm/root1".to_owned())
        );
    }

    #[test]
    fn a_fix_job_with_a_base_ref_that_is_no_swarm_branch_is_refused() {
        for base_ref in ["main", "swarm/", "swarm/a/b", "swarm/a-b", ""] {
            let refused = PushTarget::from_job(&fix_job(base_ref)).err();
            assert_eq!(
                refused.map(|f| f.error),
                Some(ERR_PUSH),
                "{base_ref:?} accepted"
            );
        }
        let long = format!("swarm/{}", "a".repeat(65));
        assert!(PushTarget::from_job(&fix_job(&long)).is_err());
    }

    #[test]
    fn a_normal_job_ignores_a_base_ref_that_is_no_swarm_branch() {
        let job = Job {
            base_ref: "main".into(),
            ..test_job()
        };
        assert_eq!(
            PushTarget::from_job(&job).ok().map(|t| t.remote_branch()),
            Some("swarm/job1".to_owned())
        );
    }
}
