//! Publishes a finished job: commits leftovers, pushes its branch and opens the pull request.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use fleet_proto::is_ci_url;
use fleet_proto::is_swarm_branch;
use fleet_proto::v1::Job;

use crate::phase::{Phases, elapsed_ms};
use crate::proc::{CAPTURE_BYTES, CaptureError, Captured};
use crate::runner::{AgentRunner, Failure, IntoFailure, Reporter, Scope};
use crate::workspace::{is_commit_sha, validate_job_id, validate_ref, validate_repo};

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

impl<R: Reporter> AgentRunner<R> {
    pub(crate) async fn publish(
        &self,
        job: &Job,
        cwd: &Path,
        phases: &mut Phases,
    ) -> Result<Published, Failure> {
        validate_job_id(&job.job_id).map_err(|_| Failure::bare(ERR_COMMITS))?;
        validate_repo(&job.repo, &self.config.repo_policy).map_err(|_| Failure::bare(ERR_PUSH))?;
        validate_ref(&job.base_ref).map_err(|_| Failure::bare(ERR_COMMITS))?;
        let local = format!("swarm/{}", job.job_id);
        let target = PushTarget::from_job(job)?;
        let branch = target.remote_branch();
        let scratch = Scratch::create(cwd, &job.job_id).map_err(|()| Failure::bare(ERR_COMMITS))?;
        let dir = scratch.path();
        self.commit_leftovers(job, cwd, dir).await?;
        if !self.ahead(job, &local, cwd, dir).await? {
            return Ok(Published {
                branch: None,
                pr_url: None,
            });
        }
        let refspec = format!("refs/heads/{local}:refs/heads/{branch}");
        let push_start = self.clock.now();
        let pushed = self
            .helper(
                &self.config.git_bin,
                dir,
                &[
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
                    &job.repo,
                    &refspec,
                ],
                Scope::Push,
            )
            .await;
        phases.push = Some(elapsed_ms(&*self.clock, push_start));
        let pushed = pushed.map_err(|e| e.failure(ERR_PUSH))?;
        if !pushed.success {
            return Err(Failure::tail(ERR_PUSH, &pushed.stderr));
        }
        let pr_url = match target {
            PushTarget::Chain(_) => job.pr_url.clone().filter(|url| is_ci_url(url)),
            PushTarget::Own(_) if !job.open_pr => None,
            PushTarget::Own(_) => {
                let pr_start = self.clock.now();
                let opened = self.open_pr(job, &branch, dir).await;
                phases.pr = Some(elapsed_ms(&*self.clock, pr_start));
                Some(opened?)
            }
        };
        Ok(Published {
            branch: Some(branch),
            pr_url,
        })
    }

    async fn commit_leftovers(&self, job: &Job, cwd: &Path, dir: &Path) -> Result<(), Failure> {
        let tree = Scope::Tree(cwd);
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
        if matches!(self.redactor.redact_str(&staged.stdout), Cow::Owned(_)) {
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
                    &title,
                    "--body",
                    &format!("Fleet job {}", job.job_id),
                ],
                Scope::Gh,
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
    use super::{ERR_PUSH, PushTarget};
    use fleet_proto::v1::Job;

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
