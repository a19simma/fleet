//! Watches the checks of the pull request a job opened, until they settle or a deadline passes.

use std::future::{self, Future};
use std::path::Path;
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::{CiState, Job, JobCi};
use fleet_proto::{MAX_CI_LOG_BYTES, is_ci_log, is_ci_url};
use serde_json::{Value, json};
use tokio::time::Instant;
use tonic::Code;

use super::{AgentRunner, Ctl, Interrupt, Reporter, Scope, Stop, report_request};
use crate::broker::{ExecError, GhExecutor, GitExecutor, PushTarget};
use crate::forge::{CiResult, Forge, GitHubForge};
use crate::publish::Scratch;

/// What one `gh pr checks` call showed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Seen {
    Passed { url: Option<String> },
    Failed { url: Option<String> },
    Waiting { url: Option<String> },
}

/// How the watch ended.
pub(super) enum Watched {
    Done(JobCi),
    Lost,
    Cancelled,
    Shutdown,
}

/// Passing polls in a row that end the watch as a success. The first poll may list only the
/// checks that registered early, so one settled answer is not enough.
const SETTLED_POLLS: u32 = 2;

/// Reads the output of `gh pr checks --json bucket,link`.
///
/// Any `fail` or `cancel` bucket gives [`Seen::Failed`] at once. Every bucket `pass` or
/// `skipping` gives [`Seen::Passed`]. An empty list, an unknown bucket or output that is not
/// a JSON list gives [`Seen::Waiting`], so a pull request with no checks yet never passes.
pub(super) fn classify(stdout: &str) -> Seen {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(stdout) else {
        return Seen::Waiting { url: None };
    };
    let bucket = |item: &Value| {
        item.get("bucket")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let link = |item: &Value| {
        item.get("link")
            .and_then(Value::as_str)
            .filter(|link| is_ci_url(link))
            .map(str::to_owned)
    };
    if let Some(failed) = items
        .iter()
        .find(|item| matches!(bucket(item).as_deref(), Some("fail" | "cancel")))
    {
        return Seen::Failed { url: link(failed) };
    }
    let url = items.iter().find_map(link);
    let settled = !items.is_empty()
        && items
            .iter()
            .all(|item| matches!(bucket(item).as_deref(), Some("pass" | "skipping")));
    if settled {
        Seen::Passed { url }
    } else {
        Seen::Waiting { url }
    }
}

struct Replay(String);

impl GitExecutor for Replay {
    fn push(&self, _target: &PushTarget) -> impl Future<Output = Result<String, ExecError>> + Send {
        future::ready(Err(ExecError))
    }

    fn fetch(&self) -> impl Future<Output = Result<String, ExecError>> + Send {
        future::ready(Err(ExecError))
    }
}

impl GhExecutor for Replay {
    fn pr_create(
        &self,
        _target: &PushTarget,
        _title: &str,
        _body: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send {
        future::ready(Err(ExecError))
    }

    fn pr_checks(
        &self,
        _target: &PushTarget,
        _pr_url: &str,
    ) -> impl Future<Output = Result<String, ExecError>> + Send {
        future::ready(Ok(self.0.clone()))
    }
}

fn link_of(seen: Seen) -> Option<String> {
    match seen {
        Seen::Passed { url } | Seen::Failed { url } | Seen::Waiting { url } => url,
    }
}

/// Reads one `gh pr checks` answer through [`Forge::ci_result`], with the capture's
/// `truncated` flag carried into the forge input.
///
/// `Success` and `Neutral` give [`Seen::Passed`] only when `success` holds, `Failure` gives
/// [`Seen::Failed`], and everything else gives [`Seen::Waiting`]. A forge error, which
/// includes a list the capture cut without a visible failure, is [`Seen::Waiting`], so an
/// unknown or truncated result never counts as success.
pub(super) async fn read_checks(
    target: &PushTarget,
    pr_url: &str,
    stdout: &str,
    truncated: bool,
    success: bool,
) -> Seen {
    let Ok(Value::Array(items)) = serde_json::from_str::<Value>(stdout) else {
        return Seen::Waiting { url: None };
    };
    let url = link_of(classify(stdout));
    let body = json!({ "checks": items, "truncated": truncated }).to_string();
    let forge = GitHubForge::new(Replay(body.clone()), Replay(body));
    match forge.ci_result(target, pr_url).await {
        Ok(CiResult::Failure) => Seen::Failed { url },
        Ok(CiResult::Success | CiResult::Neutral) if success => Seen::Passed { url },
        Ok(CiResult::Success | CiResult::Neutral) => Seen::Waiting { url: None },
        _ => Seen::Waiting { url },
    }
}

fn next_pause(pause: Duration, cap: Duration) -> Duration {
    (pause * 2).min(cap)
}

fn actions_job_id(url: &str) -> Option<&str> {
    let (_, tail) = url.split_once("/job/")?;
    let digits = tail.split(['/', '?', '#']).next()?;
    (!digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())).then_some(digits)
}

/// Drops every character the server refuses, redacts the whole result and keeps the last
/// [`MAX_CI_LOG_BYTES`] bytes, since the end of a failed run holds the error. Filtering comes
/// first so a secret with a zero-width character inside still matches the redactor.
pub(super) fn clean_log(text: &str, redactor: &Redactor) -> Option<String> {
    let kept: String = text
        .chars()
        .filter(|c| matches!(c, '\n' | '\t') || is_ci_log(c.encode_utf8(&mut [0; 4])))
        .collect();
    let redacted = redactor.redact_str(&kept);
    let mut start = redacted.len().saturating_sub(MAX_CI_LOG_BYTES);
    while !redacted.is_char_boundary(start) {
        start += 1;
    }
    let tail = redacted.get(start..)?.trim();
    (is_ci_log(tail)).then(|| tail.to_owned())
}

fn ci(state: CiState, url: Option<String>, failure_log: Option<String>) -> JobCi {
    JobCi {
        state: state.into(),
        url,
        failure_log,
    }
}

impl<R: Reporter> AgentRunner<R> {
    pub(super) async fn watch_ci(
        &self,
        job: &Job,
        cwd: &Path,
        pr_url: &str,
        progress: &str,
        ctl: &mut Ctl,
    ) -> Watched {
        let Ok(scratch) = Scratch::create(cwd, &job.job_id) else {
            return Watched::Done(ci(CiState::Timeout, None, None));
        };
        ctl.deadline
            .as_mut()
            .reset(Instant::now() + self.config.ci_deadline);
        let mut last_url = None;
        let raced = ctl
            .race(self.alive(
                job,
                progress,
                self.poll_ci(job, scratch.path(), pr_url, progress, &mut last_url),
            ))
            .await;
        match raced {
            Ok(Ok(Ok(done))) if done.state == i32::from(CiState::Failure) => {
                self.attach_log(job, scratch.path(), progress, ctl, done)
                    .await
            }
            Ok(Ok(Ok(done))) => Watched::Done(done),
            Ok(Ok(Err(Interrupt::Lost)) | Err(Interrupt::Lost)) => Watched::Lost,
            Ok(Ok(Err(Interrupt::Cancelled)) | Err(Interrupt::Cancelled)) => Watched::Cancelled,
            Err(Stop::Timeout) => Watched::Done(ci(CiState::Timeout, last_url, None)),
            Err(Stop::Shutdown) => Watched::Shutdown,
        }
    }

    /// Fetches the log of an observed failure under its own budget. A slow or failing fetch
    /// leaves the failure without a log, and never turns it into a timeout.
    async fn attach_log(
        &self,
        job: &Job,
        dir: &Path,
        progress: &str,
        ctl: &mut Ctl,
        mut done: JobCi,
    ) -> Watched {
        ctl.deadline
            .as_mut()
            .reset(Instant::now() + self.config.ci_log_budget);
        let fetched = ctl
            .race(self.alive(
                job,
                progress,
                self.failure_log(job, dir, done.url.as_deref()),
            ))
            .await;
        match fetched {
            Ok(Ok(log)) => {
                done.failure_log = log;
                Watched::Done(done)
            }
            Ok(Err(Interrupt::Lost)) => Watched::Lost,
            Ok(Err(Interrupt::Cancelled)) => Watched::Cancelled,
            Err(Stop::Timeout) => Watched::Done(done),
            Err(Stop::Shutdown) => Watched::Shutdown,
        }
    }

    async fn poll_ci(
        &self,
        job: &Job,
        dir: &Path,
        pr_url: &str,
        progress: &str,
        last_url: &mut Option<String>,
    ) -> Result<JobCi, Interrupt> {
        let mut pause = self.config.ci_poll_initial;
        let mut passes = 0;
        loop {
            let (url, settled) = match self.check_pr(job, dir, pr_url).await {
                Seen::Passed { url } => {
                    passes += 1;
                    (url, passes >= SETTLED_POLLS)
                }
                Seen::Failed { url } => return Ok(ci(CiState::Failure, url, None)),
                Seen::Waiting { url } => {
                    passes = 0;
                    (url, false)
                }
            };
            if url.is_some() {
                *last_url = url;
            }
            if settled {
                return Ok(ci(CiState::Success, last_url.clone(), None));
            }
            let mut request = report_request(job, progress, Vec::new());
            request.ci = Some(ci(CiState::Pending, last_url.clone(), None));
            match self.reporter.report(request).await {
                Err(status) if status.code() == Code::FailedPrecondition => {
                    return Err(Interrupt::Lost);
                }
                Ok(reply) if reply.cancel_requested => return Err(Interrupt::Cancelled),
                _ => {}
            }
            tokio::time::sleep(pause).await;
            pause = next_pause(pause, self.config.ci_poll_cap);
        }
    }

    /// Runs `gh pr checks` and reads it with [`read_checks`]. An answer cut by the capture
    /// limit, a failed start and a nonzero exit with an all-pass list read as [`Seen::Waiting`],
    /// never as a pass.
    async fn check_pr(&self, job: &Job, dir: &Path, pr_url: &str) -> Seen {
        let Ok(target) = PushTarget::from_job(job) else {
            return Seen::Waiting { url: None };
        };
        let checked = self
            .helper(
                &self.config.gh_bin,
                dir,
                &["pr", "checks", pr_url, "--json", "bucket,link"],
                Scope::Gh,
            )
            .await;
        match checked {
            Ok(out) => read_checks(&target, pr_url, &out.stdout, out.truncated, out.success).await,
            Err(_) => Seen::Waiting { url: None },
        }
    }

    async fn failure_log(&self, job: &Job, dir: &Path, url: Option<&str>) -> Option<String> {
        let id = actions_job_id(url?)?;
        let out = self
            .helper_tail(
                &self.config.gh_bin,
                dir,
                &[
                    "run",
                    "view",
                    "--job",
                    id,
                    "--repo",
                    &job.repo,
                    "--log-failed",
                ],
                Scope::Gh,
            )
            .await
            .ok()?;
        out.success
            .then(|| clean_log(&out.stdout, &self.redactor))
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fleet_proto::MAX_CI_URL_BYTES;

    use crate::broker::PushTarget;

    const LINK: &str = "https://example.invalid/actions/runs/9/job/41";

    fn item(bucket: &str, link: &str) -> String {
        format!(r#"{{"bucket":"{bucket}","link":"{link}","name":"n"}}"#)
    }

    fn list(items: &[String]) -> String {
        format!("[{}]", items.join(","))
    }

    #[test]
    fn all_pass_or_skipping_is_passed() {
        let out = list(&[item("pass", LINK), item("skipping", "")]);
        assert_eq!(
            classify(&out),
            Seen::Passed {
                url: Some(LINK.to_owned())
            }
        );
    }

    #[test]
    fn a_fail_or_cancel_bucket_is_failed_with_its_own_link() {
        let other = "https://example.invalid/actions/runs/9/job/42";
        for bucket in ["fail", "cancel"] {
            let out = list(&[
                item("pass", LINK),
                item(bucket, other),
                item("pending", LINK),
            ]);
            assert_eq!(
                classify(&out),
                Seen::Failed {
                    url: Some(other.to_owned())
                }
            );
        }
    }

    #[test]
    fn a_pending_or_unknown_bucket_keeps_waiting() {
        for bucket in ["pending", "queued", ""] {
            let out = list(&[item("pass", LINK), item(bucket, LINK)]);
            assert_eq!(
                classify(&out),
                Seen::Waiting {
                    url: Some(LINK.to_owned())
                },
                "{bucket}"
            );
        }
    }

    #[test]
    fn no_checks_and_unreadable_output_wait_and_never_pass() {
        for out in ["[]", "", "not json", "{}", "null", r#"[{"name":"n"}]"#] {
            assert!(matches!(classify(out), Seen::Waiting { .. }), "{out}");
        }
    }

    #[test]
    fn a_link_the_server_would_refuse_is_dropped() {
        let long = format!("https://example.invalid/{}", "a".repeat(MAX_CI_URL_BYTES));
        for link in [
            "http://example.invalid/x",
            "https://user@example.invalid/x",
            "https://example.invalid/a b",
            "https://example.invalid/a\\\\b",
            "https://example.invalid/caf\u{e9}",
            "https://example.invalid/a\u{200b}b",
            "https://",
            "",
            long.as_str(),
        ] {
            let out = list(&[item("pass", link)]);
            assert_eq!(classify(&out), Seen::Passed { url: None }, "{link}");
        }
    }

    #[test]
    fn a_secret_split_by_a_zero_width_character_is_still_redacted() {
        let redactor = Redactor::new(["hunter2-hunter2"]);
        let cut = clean_log("token hunter2-\u{200b}hunter2 end", &redactor);
        assert_eq!(cut.as_deref(), Some("token [REDACTED] end"));
        let bidi = clean_log("hunter\u{202e}2-hunter2", &redactor);
        assert_eq!(bidi.as_deref(), Some("[REDACTED]"));
    }

    #[test]
    fn a_link_of_exactly_the_cap_is_kept() {
        let prefix = "https://example.invalid/";
        let link = format!("{prefix}{}", "a".repeat(MAX_CI_URL_BYTES - prefix.len()));
        assert_eq!(link.len(), MAX_CI_URL_BYTES);
        assert_eq!(
            classify(&list(&[item("pass", &link)])),
            Seen::Passed { url: Some(link) }
        );
    }

    fn own() -> PushTarget {
        PushTarget::Own("job1".to_owned())
    }

    #[tokio::test]
    async fn a_truncated_all_pass_list_waits_and_never_passes() {
        let items: Vec<String> = (0..50).map(|_| item("pass", LINK)).collect();
        let seen = read_checks(&own(), "u", &list(&items), true, true).await;
        assert!(matches!(seen, Seen::Waiting { .. }), "{seen:?}");
    }

    #[tokio::test]
    async fn a_truncated_list_with_a_visible_failure_fails() {
        let out = list(&[item("pass", LINK), item("fail", LINK)]);
        let seen = read_checks(&own(), "u", &out, true, false).await;
        assert!(matches!(seen, Seen::Failed { .. }), "{seen:?}");
    }

    #[tokio::test]
    async fn the_forge_result_maps_to_the_seen_state() {
        let cases = [
            (list(&[item("pass", LINK)]), true, true),
            (list(&[item("pass", LINK)]), false, false),
            (
                list(&[item("pass", LINK), item("skipping", "")]),
                true,
                true,
            ),
        ];
        for (out, success, passed) in cases {
            let seen = read_checks(&own(), "u", &out, false, success).await;
            assert_eq!(matches!(seen, Seen::Passed { .. }), passed, "{seen:?}");
        }
        let pending = list(&[item("pass", LINK), item("pending", LINK)]);
        let seen = read_checks(&own(), "u", &pending, false, false).await;
        assert!(matches!(seen, Seen::Waiting { .. }), "{seen:?}");
        let seen = read_checks(&own(), "u", "[]", false, true).await;
        assert!(matches!(seen, Seen::Waiting { .. }), "{seen:?}");
        let seen = read_checks(&own(), "u", "junk", false, true).await;
        assert!(matches!(seen, Seen::Waiting { .. }), "{seen:?}");
    }

    #[test]
    fn the_pause_doubles_up_to_the_cap() {
        let ms = Duration::from_millis;
        assert_eq!(next_pause(ms(20), ms(50)), ms(40));
        assert_eq!(next_pause(ms(40), ms(50)), ms(50));
        assert_eq!(next_pause(ms(50), ms(50)), ms(50));
        assert_eq!(next_pause(ms(5), ms(30)), ms(10));
    }

    #[test]
    fn the_job_id_is_the_digits_after_job() {
        assert_eq!(actions_job_id(LINK), Some("41"));
        assert_eq!(
            actions_job_id("https://x.invalid/runs/9/job/41?pr=1"),
            Some("41")
        );
        assert_eq!(actions_job_id("https://x.invalid/runs/9"), None);
        assert_eq!(actions_job_id("https://x.invalid/runs/9/job/"), None);
        assert_eq!(actions_job_id("https://x.invalid/runs/9/job/4a"), None);
        assert_eq!(actions_job_id("https://x.invalid/runs/9/job/--x"), None);
    }

    #[test]
    fn a_log_is_redacted_stripped_and_cut_to_its_tail() {
        let redactor = Redactor::new(["hunter2-hunter2"]);
        assert_eq!(
            clean_log("a\x1b[31mb hunter2-hunter2\r\n\tc\0\n", &redactor).as_deref(),
            Some("a[31mb [REDACTED]\n\tc")
        );
        assert_eq!(clean_log("", &redactor), None);
        assert_eq!(clean_log(" \n\x1b\0 ", &redactor), None);
        let big = format!("{}\nEND", "x".repeat(MAX_CI_LOG_BYTES * 2));
        let cut = clean_log(&big, &redactor).unwrap_or_default();
        assert!(cut.len() <= MAX_CI_LOG_BYTES);
        assert!(cut.ends_with("\nEND"));
        let wide = "é".repeat(MAX_CI_LOG_BYTES);
        let cut = clean_log(&wide, &redactor).unwrap_or_default();
        assert!(cut.len() <= MAX_CI_LOG_BYTES && cut.len() > MAX_CI_LOG_BYTES - 4);
    }
}
