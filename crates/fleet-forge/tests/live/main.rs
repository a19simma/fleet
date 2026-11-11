//! The live contract suite of ADR-0068 against a real Forgejo, driven by `mise run live:forgejo`.
//!
//! Every test that reaches the network is `#[ignore]`d, so the normal run needs no token and no
//! network. The live test fails, never passes, when `FORGEJO_TOKEN` or `FORGEJO_E2E_URL` is
//! absent. It creates throwaway repositories under a per-run name, drops them in a guard that
//! also runs on failure, and never prints the token or the host name.

#![expect(
    clippy::redundant_pub_crate,
    reason = "unreachable_pub rejects plain pub in a private module of a test crate"
)]

mod cases;
mod support;

use fleet_core::host::HostName;
use fleet_forge::contract::{Case, Outcome};
use fleet_forge::{
    CiResult, Credential, ForgeApi, ForgeError, ForgeGit, GiteaForge, GiteaGit, PushTarget,
    RepoAccess, RepoRef, Token,
};
use serde_json::{Value, json};

use cases::{ORDER, Plan, plan};
use support::{
    Api, Auth, BOGUS_TOKEN, Counter, Curl, LiveGit, NAME_PREFIX, RepoGuard, Scratch, Settings,
    Wire, header, header_names, leaked_names, local_git, random_hex, shape, sweep,
};

type Adapter = GiteaForge<Curl, GiteaGit<LiveGit>>;

struct Run {
    api: Api,
    host: HostName,
    token: Token,
    owner: String,
    repo: String,
    git: LiveGit,
    count: Counter,
    pr_url: Option<String>,
    sha: Option<String>,
}

impl Run {
    fn repo_ref(&self, name: &str) -> Result<RepoRef, String> {
        RepoRef::new(self.host.clone(), &self.owner, name).map_err(|e| e.to_string())
    }

    fn access(&self, name: &str, token: &Token) -> Result<RepoAccess, String> {
        Ok(RepoAccess::new(
            self.repo_ref(name)?,
            Credential::new(self.host.clone(), token.clone()),
        ))
    }

    fn adapter(&self, git: &LiveGit) -> Adapter {
        GiteaForge::new(self.api.curl.clone()).with_git(self.host.clone(), git.clone())
    }

    fn target(&self, token: &Token, branch: &str) -> Result<PushTarget, String> {
        PushTarget::new(self.access(&self.repo, token)?, branch, "main").map_err(|e| e.to_string())
    }

    fn bogus() -> Result<Token, String> {
        Token::new(BOGUS_TOKEN.to_owned()).map_err(|e| e.to_string())
    }

    fn pr_link(&self, number: u64) -> String {
        format!(
            "https://{}/{}/{}/pulls/{number}",
            self.host, self.owner, self.repo
        )
    }

    fn status(&self, state: &str, context: &str) -> Result<(), String> {
        let sha = self.sha.as_deref().ok_or("no head sha")?;
        let path = format!("/api/v1/repos/{}/{}/statuses/{sha}", self.owner, self.repo);
        let body = json!({ "state": state, "context": context, "description": "fleet e2e" });
        let reply = self.api.call("POST", &path, Auth::Token, Some(&body))?;
        if reply.status == 201 {
            Ok(())
        } else {
            Err(format!("post status {state}: {}", reply.status))
        }
    }
}

fn ci(result: Result<CiResult, ForgeError>) -> Outcome {
    result.map_or_else(Outcome::Failed, Outcome::Ci)
}

fn failed<T>(result: Result<T, ForgeError>, ok: impl FnOnce(T) -> Outcome) -> Outcome {
    result.map_or_else(Outcome::Failed, ok)
}

async fn drive(run: &mut Run, case: Case) -> Result<Outcome, String> {
    match case {
        Case::IdentifyOk
        | Case::VerifyReadPush
        | Case::Verify404
        | Case::Verify401
        | Case::VerifyRedirect
        | Case::CredentialOtherHost => drive_read(run, case).await,
        Case::FetchAuthFailure
        | Case::FetchOk
        | Case::PushRevoked
        | Case::PushOk
        | Case::PushNonFastForward => drive_git(run, case).await,
        _ => drive_pr(run, case).await,
    }
}

async fn drive_read(run: &Run, case: Case) -> Result<Outcome, String> {
    let token = run.token.clone();
    let git = run.git.clone();
    let adapter = run.adapter(&git);
    let missing = format!("{NAME_PREFIX}{}-missing", random_hex()?);
    let outcome = match case {
        Case::IdentifyOk => failed(adapter.identify(&run.host).await, Outcome::Identified),
        Case::VerifyReadPush => {
            let access = run.access(&run.repo.clone(), &token)?;
            failed(adapter.verify(&access).await, |v| Outcome::Verified(v.push))
        }
        Case::Verify404 => {
            let access = run.access(&missing, &token)?;
            failed(adapter.verify(&access).await, |v| Outcome::Verified(v.push))
        }
        Case::Verify401 => {
            let access = run.access(&run.repo.clone(), &Run::bogus()?)?;
            failed(adapter.verify(&access).await, |v| Outcome::Verified(v.push))
        }
        Case::VerifyRedirect => rename_redirect(run, &adapter).await?,
        Case::CredentialOtherHost => {
            let other = HostName::normalise("other.example.com").map_err(|e| e.to_string())?;
            let access = RepoAccess::new(
                run.repo_ref(&run.repo.clone())?,
                Credential::new(other, token),
            );
            failed(adapter.verify(&access).await, |v| Outcome::Verified(v.push))
        }
        other => return Err(format!("case {} is not a read case", other.name())),
    };
    Ok(outcome)
}

async fn drive_git(run: &Run, case: Case) -> Result<Outcome, String> {
    let token = run.token.clone();
    let git = run.git.clone();
    let adapter = run.adapter(&git);
    let outcome = match case {
        Case::FetchAuthFailure => {
            let bad = run.git.with_token(BOGUS_TOKEN);
            let access = run.access(&run.repo.clone(), &Run::bogus()?)?;
            failed(run.adapter(&bad).fetch(&access).await, |_| Outcome::Fetched)
        }
        Case::FetchOk => {
            let access = run.access(&run.repo.clone(), &token)?;
            failed(adapter.fetch(&access).await, |_| Outcome::Fetched)
        }
        Case::PushRevoked => {
            let branch = run.branch();
            local_git(
                &run.git.clone_dir(),
                &["checkout", "-q", "-b", &branch, "origin/main"],
            )?;
            std::fs::write(run.git.clone_dir().join("e2e.txt"), "one\n")
                .map_err(|e| e.to_string())?;
            local_git(&run.git.clone_dir(), &["add", "e2e.txt"])?;
            local_git(&run.git.clone_dir(), &["commit", "-q", "-m", "fleet e2e"])?;
            let bad = run.git.with_token(BOGUS_TOKEN);
            let target = run.target(&Run::bogus()?, &branch)?;
            failed(run.adapter(&bad).push(&target).await, |_| Outcome::Pushed)
        }
        Case::PushOk => {
            let target = run.target(&token, &run.branch())?;
            failed(adapter.push(&target).await, |_| Outcome::Pushed)
        }
        Case::PushNonFastForward => {
            let branch = run.branch();
            let dir = run.git.clone_dir();
            local_git(&dir, &["checkout", "-q", "-B", &branch, "origin/main"])?;
            std::fs::write(dir.join("other.txt"), "two\n").map_err(|e| e.to_string())?;
            local_git(&dir, &["add", "other.txt"])?;
            local_git(&dir, &["commit", "-q", "-m", "fleet e2e diverged"])?;
            let target = run.target(&token, &branch)?;
            failed(adapter.push(&target).await, |_| Outcome::Pushed)
        }
        other => return Err(format!("case {} is not a git case", other.name())),
    };
    Ok(outcome)
}

async fn drive_pr(run: &mut Run, case: Case) -> Result<Outcome, String> {
    let token = run.token.clone();
    let git = run.git.clone();
    let adapter = run.adapter(&git);
    let outcome = match case {
        Case::CreatePrRejected => {
            let target = run.target(&token, "main")?;
            failed(adapter.create_pr(&target, "e2e", "e2e").await, |_| {
                Outcome::PrUrl
            })
        }
        Case::CreatePrOk | Case::CreatePrExists => {
            let target = run.target(&token, &run.branch())?;
            match adapter.create_pr(&target, "fleet e2e", "throwaway").await {
                Err(error) => Outcome::Failed(error),
                Ok(url) => pr_outcome(run, case, &url),
            }
        }
        Case::CiNone => {
            record_ci_shape(run)?;
            ci(adapter
                .ci_result(&run.target(&token, &run.branch())?, &run.known_pr()?)
                .await)
        }
        Case::CiChecksNone => {
            let target = run.target(&token, &run.branch())?;
            failed(adapter.ci_checks(&target, &run.known_pr()?).await, |list| {
                if list.is_empty() {
                    Outcome::Checks(fleet_forge::contract::ChecksSeen::Empty)
                } else {
                    Outcome::Checks(fleet_forge::contract::ChecksSeen::Other)
                }
            })
        }
        Case::Ci404 => ci(adapter
            .ci_result(&run.target(&token, &run.branch())?, &run.pr_link(99_999))
            .await),
        Case::CiChecks404 => {
            let target = run.target(&token, &run.branch())?;
            failed(
                adapter.ci_checks(&target, &run.pr_link(99_999)).await,
                |_| Outcome::Checks(fleet_forge::contract::ChecksSeen::Other),
            )
        }
        Case::CiPending => ci_after(run, &adapter, &[("pending", "ci/e2e")]).await?,
        Case::CiSuccess => ci_after(run, &adapter, &[("success", "ci/e2e")]).await?,
        Case::CiFailure => ci_after(run, &adapter, &[("failure", "ci/e2e")]).await?,
        Case::CiMixed => {
            let posts = [
                ("failure", "ci/e2e"),
                ("success", "ci/b"),
                ("pending", "ci/c"),
            ];
            ci_after(run, &adapter, &posts).await?
        }
        other => return Err(format!("case {} is not a pull request case", other.name())),
    };
    Ok(outcome)
}

impl Run {
    fn branch(&self) -> String {
        self.repo.clone()
    }

    fn known_pr(&self) -> Result<String, String> {
        self.pr_url
            .clone()
            .ok_or_else(|| "no pull request yet".to_owned())
    }
}

fn pr_outcome(run: &mut Run, case: Case, url: &str) -> Outcome {
    let prefix = format!("https://{}/{}/{}/pulls/", run.host, run.owner, run.repo);
    let shaped = url
        .strip_prefix(&prefix)
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    if !shaped {
        return Outcome::BadUrl;
    }
    match (case, run.pr_url.as_deref()) {
        (Case::CreatePrExists, Some(first)) if first != url => return Outcome::BadUrl,
        (Case::CreatePrOk, _) => run.pr_url = Some(url.to_owned()),
        _ => {}
    }
    Outcome::PrUrl
}

async fn ci_after(
    run: &mut Run,
    adapter: &Adapter,
    posts: &[(&str, &str)],
) -> Result<Outcome, String> {
    if run.sha.is_none() {
        let number = run
            .known_pr()?
            .rsplit('/')
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or("pr number")?;
        let path = format!("/api/v1/repos/{}/{}/pulls/{number}", run.owner, run.repo);
        let reply = run.api.call("GET", &path, Auth::Token, None)?;
        let sha = run
            .api
            .json(&reply)?
            .pointer("/head/sha")
            .and_then(Value::as_str)
            .map(str::to_owned);
        run.sha = sha;
    }
    for (state, context) in posts {
        run.status(state, context)?;
    }
    let target = run.target(&run.token.clone(), &run.branch())?;
    Ok(ci(adapter.ci_result(&target, &run.known_pr()?).await))
}

fn record_ci_shape(run: &Run) -> Result<(), String> {
    let number = run
        .known_pr()?
        .rsplit('/')
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .ok_or("pr number")?;
    let base = format!("/api/v1/repos/{}/{}", run.owner, run.repo);
    let pull = run
        .api
        .call("GET", &format!("{base}/pulls/{number}"), Auth::Token, None)?;
    let sha = run
        .api
        .json(&pull)?
        .pointer("/head/sha")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or("pull head sha")?;
    for (label, path) in [
        (
            "no-status-reply",
            format!("{base}/commits/{sha}/status?page=1&limit=50"),
        ),
        (
            "no-runs-reply",
            format!("{base}/actions/runs?head_sha={sha}&page=1&limit=50"),
        ),
    ] {
        let reply = run.api.call("GET", &path, Auth::Token, None)?;
        let body = serde_json::from_slice::<Value>(&reply.body)
            .map_or_else(|_| "not-json".to_owned(), |value| shape(&value, 3));
        run.api
            .redactor
            .record(label, &format!("status={} shape={body}", reply.status));
    }
    Ok(())
}

async fn rename_redirect(run: &Run, adapter: &Adapter) -> Result<Outcome, String> {
    let id = random_hex()?;
    let old = format!("{NAME_PREFIX}{id}-old");
    let new = format!("{NAME_PREFIX}{id}-new");
    let (mut guard, owner) = RepoGuard::create(&run.api, &old)?;
    guard.renamed(&new);
    let patch = run.api.call(
        "PATCH",
        &format!("/api/v1/repos/{owner}/{old}"),
        Auth::Token,
        Some(&json!({ "name": new })),
    )?;
    run.api
        .redactor
        .record("rename-patch-status", &patch.status.to_string());
    let raw = run.api.call(
        "GET",
        &format!("/api/v1/repos/{owner}/{old}"),
        Auth::Token,
        None,
    )?;
    run.api.redactor.record(
        "rename-old-name",
        &format!(
            "status={} location={} headers={}",
            raw.status,
            header(&raw, "location").unwrap_or("none"),
            header_names(&raw)
        ),
    );
    let access = run.access(&old, &run.token)?;
    run.count.reset();
    let outcome = failed(adapter.verify(&access).await, |v| Outcome::Verified(v.push));
    drop(guard);
    Ok(outcome)
}

fn open_probes(api: &Api) -> Result<(), String> {
    let record = |label: &str, text: &str| api.redactor.record(label, text);
    let version = api.call("GET", "/api/v1/version", Auth::Anonymous, None)?;
    record(
        "version",
        &format!(
            "status={} body={}",
            version.status,
            String::from_utf8_lossy(&version.body)
        ),
    );
    record("version-headers", &header_names(&version));
    for (label, path, auth) in [
        ("invalid-token on user", "/api/v1/user", Auth::Bogus),
        (
            "invalid-token on search",
            "/api/v1/repos/search?limit=1",
            Auth::Bogus,
        ),
        ("token on user", "/api/v1/user", Auth::Token),
        (
            "token on search",
            "/api/v1/repos/search?limit=1",
            Auth::Token,
        ),
        (
            "anonymous on search",
            "/api/v1/repos/search?limit=1",
            Auth::Anonymous,
        ),
    ] {
        let reply = api.call("GET", path, auth, None)?;
        record(
            label,
            &format!("status={} message={}", reply.status, api.message(&reply)),
        );
    }
    Ok(())
}

fn probes(api: &Api, owner: &str, repo: &str) -> Result<(), String> {
    let record = |label: &str, text: &str| api.redactor.record(label, text);
    let repo_path = format!("/api/v1/repos/{owner}/{repo}");
    let missing = format!(
        "/api/v1/repos/{owner}/{NAME_PREFIX}never-created-{}",
        random_hex()?
    );
    for (label, path, auth) in [
        ("invalid-token on repo", repo_path.as_str(), Auth::Bogus),
        (
            "anonymous on private repo",
            repo_path.as_str(),
            Auth::Anonymous,
        ),
        (
            "anonymous on missing repo",
            missing.as_str(),
            Auth::Anonymous,
        ),
        ("token on missing repo", missing.as_str(), Auth::Token),
    ] {
        let reply = api.call("GET", path, auth, None)?;
        record(label, &format!("status={}", reply.status));
    }
    let own = api.call("GET", &repo_path, Auth::Token, None)?;
    let body = api.json(&own)?;
    record(
        "repo-reply",
        &format!(
            "status={} permissions={} private={} headers={}",
            own.status,
            body.get("permissions")
                .map_or_else(|| "absent".to_owned(), Value::to_string),
            body.get("private")
                .map_or_else(|| "absent".to_owned(), Value::to_string),
            header_names(&own)
        ),
    );
    let again = api.call(
        "POST",
        "/api/v1/user/repos",
        Auth::Token,
        Some(&json!({ "name": repo })),
    )?;
    record("duplicate-create", &format!("status={}", again.status));
    if again.status != 409 {
        return Err(format!("duplicate create answered {}", again.status));
    }
    Ok(())
}

fn scopes(api: &Api, owner: &str, repo: &str) -> Result<(), String> {
    let base = format!("/api/v1/repos/{owner}/{repo}");
    let probes: [(&str, &str, String, Option<Value>); 8] = [
        ("read:repository", "GET", base.clone(), None),
        (
            "write:repository",
            "PATCH",
            base.clone(),
            Some(json!({ "description": "fleet e2e probe" })),
        ),
        (
            "write:issue",
            "POST",
            format!("{base}/issues"),
            Some(json!({ "title": "fleet e2e probe" })),
        ),
        ("read:issue", "GET", format!("{base}/issues"), None),
        ("read:user", "GET", "/api/v1/user".to_owned(), None),
        (
            "read:organization",
            "GET",
            "/api/v1/user/orgs".to_owned(),
            None,
        ),
        (
            "read:notification",
            "GET",
            "/api/v1/notifications".to_owned(),
            None,
        ),
        (
            "read:package",
            "GET",
            format!("/api/v1/packages/{owner}"),
            None,
        ),
    ];
    let mut granted = Vec::new();
    let mut denied = Vec::new();
    for (scope, method, path, body) in &probes {
        let reply = api.call(method, path, Auth::Token, body.as_ref())?;
        let bucket = if (200..300).contains(&reply.status) {
            &mut granted
        } else {
            &mut denied
        };
        bucket.push(format!("{scope}={}", reply.status));
    }
    api.redactor.record("scopes granted", &granted.join(" "));
    api.redactor.record("scopes denied", &denied.join(" "));
    for required in ["read:repository", "write:repository", "write:issue"] {
        if !granted
            .iter()
            .any(|entry| entry.starts_with(&format!("{required}=")))
        {
            return Err(format!("the token lacks {required}"));
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "live: run through `mise run live:forgejo`"]
async fn the_shared_contract_holds_on_the_live_forgejo() -> Result<(), String> {
    let settings = Settings::from_env().map_err(|e| e.to_string())?;
    let count = Counter::default();
    let curl = Curl::new(settings.host.clone(), count.clone());
    let api = Api::new(curl, &settings.token, &settings.host);
    open_probes(&api)?;
    let id = random_hex()?;
    let repo = format!("{NAME_PREFIX}{id}");
    let (_guard, owner) = RepoGuard::create(&api, &repo)?;
    let scratch = Scratch::create(&id)?;
    let git = LiveGit::new(
        settings.host.clone(),
        settings.token.expose(),
        &owner,
        &scratch.path,
        count.clone(),
    )?;
    probes(&api, &owner, &repo)?;
    scopes(&api, &owner, &repo)?;
    let mut run = Run {
        api,
        host: settings.host,
        token: settings.token,
        owner,
        repo,
        git,
        count,
        pr_url: None,
        sha: None,
    };
    let mut failures = Vec::new();
    for &case in ORDER {
        run.count.reset();
        let outcome = drive(&mut run, case).await;
        let seen = run.count.get();
        let verdict = match outcome {
            Err(message) => Some(run.api.redactor.scrub(&message, 300)),
            Ok(actual) if actual != case.expected(fleet_forge::fake::Shape::Gitea) => {
                Some(format!(
                    "expected {:?}, got {actual:?}",
                    case.expected(fleet_forge::fake::Shape::Gitea)
                ))
            }
            Ok(_) if !case.calls().allows(seen) => {
                Some(format!("{seen} requests, owed {:?}", case.calls()))
            }
            Ok(_) => None,
        };
        run.api.redactor.record(
            &format!("case {}", case.name()),
            verdict.as_deref().unwrap_or("ok"),
        );
        if let Some(message) = verdict {
            failures.push(format!("{}: {message}", case.name()));
        }
    }
    for &case in Case::ALL {
        if let Plan::Skip(reason) = plan(case) {
            run.api.redactor.record(
                &format!("case {}", case.name()),
                &format!("skipped, {reason}"),
            );
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

#[tokio::test]
#[ignore = "live: run through `mise run live:forgejo:cleanup`"]
async fn cleanup_leaked_throwaway_repositories() -> Result<(), String> {
    let settings = Settings::from_env().map_err(|e| e.to_string())?;
    let curl = Curl::new(settings.host.clone(), Counter::default());
    let api = Api::new(curl, &settings.token, &settings.host);
    let user = api.call("GET", "/api/v1/user", Auth::Token, None)?;
    let login = api
        .json(&user)?
        .get("login")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or("user reply holds no login")?;
    let mut names = Vec::new();
    for page in 1..=40 {
        let path = format!("/api/v1/user/repos?page={page}&limit=50");
        let reply = api.call("GET", &path, Auth::Token, None)?;
        if reply.status != 200 {
            return Err(format!("list repositories: status {}", reply.status));
        }
        let body = api.json(&reply)?;
        let count = body.as_array().map_or(0, Vec::len);
        names.extend(leaked_names(&body, &login));
        if count < 50 {
            break;
        }
    }
    let leaked = sweep(&names, |name| {
        let path = format!("/api/v1/repos/{login}/{name}");
        api.call("DELETE", &path, Auth::Token, None)
            .ok()
            .map(|reply| reply.status)
    });
    api.redactor.record(
        "cleanup",
        &format!(
            "found={} removed={} failed={}",
            names.len(),
            names.len() - leaked.len(),
            leaked.len()
        ),
    );
    if leaked.is_empty() {
        Ok(())
    } else {
        Err(format!("could not delete {}", leaked.join(" ")))
    }
}

#[test]
fn a_cleanup_sweep_deletes_the_renamed_name_and_forgives_the_forwarding_old_name() {
    let names = vec!["fleet-e2e-a-old".to_owned(), "fleet-e2e-a-new".to_owned()];
    let mut asked = Vec::new();
    let leaked = sweep(&names, |name| {
        asked.push(name.to_owned());
        Some(if name.ends_with("-new") { 204 } else { 301 })
    });
    assert_eq!(leaked, Vec::<String>::new());
    assert_eq!(asked, vec!["fleet-e2e-a-new", "fleet-e2e-a-old"]);
}

#[test]
fn a_cleanup_sweep_reports_every_name_that_may_still_exist() {
    let names = vec!["fleet-e2e-a-old".to_owned(), "fleet-e2e-a-new".to_owned()];
    assert_eq!(
        sweep(&names, |_| Some(500)),
        vec!["fleet-e2e-a-new", "fleet-e2e-a-old"]
    );
    assert_eq!(
        sweep(&names, |name| {
            Some(if name.ends_with("-new") { 403 } else { 301 })
        }),
        vec!["fleet-e2e-a-new", "fleet-e2e-a-old"]
    );
    assert_eq!(
        sweep(&names, |_| None),
        vec!["fleet-e2e-a-new", "fleet-e2e-a-old"]
    );
    assert_eq!(sweep(&names, |_| Some(404)), Vec::<String>::new());
    let foreign = vec!["precious".to_owned()];
    assert_eq!(sweep(&foreign, |_| unreachable!()), Vec::<String>::new());
}

#[test]
fn a_cleanup_list_keeps_only_own_throwaway_repositories() {
    let page = json!([
        {"name": "fleet-e2e-1", "owner": {"login": "me"}},
        {"name": "fleet-e2e-2", "owner": {"login": "someone"}},
        {"name": "keep", "owner": {"login": "me"}},
        {"name": "fleet-e2e", "owner": {"login": "me"}},
        {"owner": {"login": "me"}}
    ]);
    assert_eq!(leaked_names(&page, "me"), vec!["fleet-e2e-1"]);
    assert_eq!(leaked_names(&json!({"x": 1}), "me"), Vec::<String>::new());
}

#[test]
fn a_reply_shape_holds_keys_and_types_and_never_values() {
    let body = json!({"state": "secret-state", "statuses": null, "n": 3,
        "list": [{"context": "ci", "ok": true}], "empty": [], "deep": {"a": {"b": {"c": 1}}}});
    let text = shape(&body, 3);
    assert_eq!(
        text,
        "{deep:{a:{b:object(1)}},empty:array(0),list:array(1)[{context:string,ok:bool}],n:number,state:string,statuses:null}"
    );
    assert!(!text.contains("secret"));
}

#[test]
fn the_cleanup_guard_requests_do_not_count_against_a_case() {
    let host = HostName::normalise("git.example.com").unwrap_or_else(|_| unreachable!());
    let counter = Counter::default();
    let curl = Curl::new(host, counter.clone());
    curl.uncounted().count.bump();
    assert_eq!(counter.get(), 0);
    curl.count.bump();
    assert_eq!(counter.get(), 1);
}

#[test]
fn every_contract_case_is_run_or_skipped_with_a_reason_exactly_once() {
    let ran: Vec<Case> = Case::ALL
        .iter()
        .copied()
        .filter(|&case| matches!(plan(case), Plan::Run))
        .collect();
    let mut ordered = ORDER.to_vec();
    ordered.sort_by_key(|case| case.name());
    let mut expected = ran;
    expected.sort_by_key(|case| case.name());
    assert_eq!(ordered, expected);
    let mut names: Vec<_> = ORDER.iter().map(|case| case.name()).collect();
    names.dedup();
    assert_eq!(names.len(), ORDER.len());
}

#[test]
fn an_unset_token_or_url_fails_closed_and_names_the_variable() {
    let none = Settings::from_lookup(|_| None).err();
    assert_eq!(
        none,
        Some(support::SetupError::Missing(vec![
            "FORGEJO_TOKEN",
            "FORGEJO_E2E_URL"
        ]))
    );
    let only_url = Settings::from_lookup(|name| {
        (name == "FORGEJO_E2E_URL").then(|| "https://git.example.com".to_owned())
    })
    .err();
    assert_eq!(
        only_url,
        Some(support::SetupError::Missing(vec!["FORGEJO_TOKEN"]))
    );
    let only_token =
        Settings::from_lookup(|name| (name == "FORGEJO_TOKEN").then(|| "abc".to_owned())).err();
    assert_eq!(
        only_token,
        Some(support::SetupError::Missing(vec!["FORGEJO_E2E_URL"]))
    );
    let blank = Settings::from_lookup(|_| Some("  \n".to_owned())).err();
    assert_eq!(
        blank,
        Some(support::SetupError::Missing(vec![
            "FORGEJO_TOKEN",
            "FORGEJO_E2E_URL"
        ]))
    );
    let both = Settings::from_lookup(|name| {
        Some(
            if name == "FORGEJO_TOKEN" {
                "abc\n"
            } else {
                "https://git.example.com/"
            }
            .to_owned(),
        )
    });
    assert_eq!(
        both.map(|s| s.host.to_string()).ok(),
        Some("git.example.com".to_owned())
    );
}

#[test]
fn a_hostile_url_is_refused() {
    let hostile = [
        "http://git.example.com",
        "HTTPS://git.example.com",
        "git.example.com",
        "https://",
        "https://user@git.example.com",
        "https://user:pw@git.example.com",
        "https://git.example.com:8443",
        "https://git.example.com/sub",
        "https://git.example.com/?x=1",
        "https://git.example.com#frag",
        "https://[::1]",
        "https://git.example.com\\@evil.example",
        "https://git.example.com\r\nHost: evil.example",
        "https://git.example.com\u{85}",
        "https://git.example.com\u{2028}",
        "https://git .example.com",
        "https://10.0.0.1",
        "https://localhost",
        "https://.example.com",
        "https://git..example.com",
    ];
    for url in hostile {
        assert_eq!(
            support::host_of(url),
            Err(support::SetupError::BadUrl),
            "{url:?}"
        );
    }
}

#[test]
fn the_redactor_removes_the_token_and_host_before_it_truncates() {
    let redactor = support::Redactor::new("SECRET123", "git.example.com");
    let text = format!("aaaa{}bbb git.example.com", "SECRET123");
    assert_eq!(redactor.scrub(&text, 1000), "aaaa<token>bbb <host>");
    let straddling = redactor.scrub(&text, 8);
    assert_eq!(straddling, "aaaa<tok");
    for cut in 0..text.len() {
        let out = redactor.scrub(&text, cut);
        assert!(!out.contains("SECR"), "cut {cut}: {out}");
    }
    let multibyte = redactor.scrub("ééé", 3);
    assert_eq!(multibyte, "é");
    assert_eq!(support::Redactor::new("", "").scrub("plain", 10), "plain");
}

#[test]
fn a_curl_config_carries_the_secret_and_refuses_injection() {
    let host = HostName::normalise("git.example.com").unwrap_or_else(|_| unreachable!());
    let auth = vec![("Authorization".to_owned(), "token SECRET".to_owned())];
    let config = support::curl_config(&host, "POST", "/api/v1/x", &auth, br#"{"a":"q\"\\n"}"#)
        .unwrap_or_default();
    assert!(config.contains("url = \"https://git.example.com/api/v1/x\"\n"));
    assert!(config.contains("header = \"Authorization: token SECRET\"\n"));
    assert!(config.contains("request = \"POST\"\n"));
    assert!(config.contains("data-binary = \"{\\\"a\\\":\\\"q\\\\\\\"\\\\\\\\n\\\"}\"\n"));
    let bad_headers: [Vec<(String, String)>; 4] = [
        vec![("A".to_owned(), "x\r\nB: y".to_owned())],
        vec![("A\nB".to_owned(), "x".to_owned())],
        vec![("A:B".to_owned(), "x".to_owned())],
        vec![(String::new(), "x".to_owned())],
    ];
    for headers in &bad_headers {
        assert!(support::curl_config(&host, "GET", "/x", headers, b"").is_err());
    }
    for path in ["x", "/a b", "/a\nb", "/a\r\nb"] {
        assert!(
            support::curl_config(&host, "GET", path, &[], b"").is_err(),
            "{path:?}"
        );
    }
    assert!(support::curl_config(&host, "POST", "/x", &[], b"@/etc/passwd").is_err());
    assert!(support::curl_config(&host, "POST", "/x", &[], &[0xff, 0xfe]).is_err());
    assert!(support::curl_config(&host, "get", "/x", &[], b"").is_err());
}

#[test]
fn a_curl_reply_parses_to_status_headers_and_body() {
    let ok = support::parse_reply(b"HTTP/2 200 \r\nContent-Type: a/b\r\nX-K: v:w\r\n\r\n{\"a\":1}");
    let reply = ok.unwrap_or_else(|| unreachable!());
    assert_eq!(reply.status, 200);
    assert_eq!(header(&reply, "x-k"), Some("v:w"));
    assert_eq!(reply.body, b"{\"a\":1}");
    let interim = support::parse_reply(
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 301 Moved\r\nLocation: /x\r\n\r\n",
    );
    assert_eq!(interim.map(|r| r.status), Some(301));
    for bad in [
        &b""[..],
        b"HTTP/1.1 200 OK\r\nA: b",
        b"HTTP/1.1 abc\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nnocolon\r\n\r\n",
        b"HTTP/1.1\r\n\r\n",
    ] {
        assert!(support::parse_reply(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn two_run_ids_differ_and_are_twelve_hex_digits() {
    let first = random_hex();
    let second = random_hex();
    assert_ne!(first, second);
    assert_eq!(first.map(|h| h.len()), Ok(12));
}

#[derive(Clone)]
struct Script {
    reply: fn(&str, &str) -> (u16, &'static str),
    log: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

impl Script {
    fn new(reply: fn(&str, &str) -> (u16, &'static str)) -> Self {
        Self {
            reply,
            log: std::sync::Arc::default(),
        }
    }

    fn deletes(&self) -> Vec<String> {
        self.log
            .lock()
            .map(|log| {
                log.iter()
                    .filter(|(method, _)| method == "DELETE")
                    .map(|(_, path)| path.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Wire for Script {
    fn call(
        &self,
        method: &str,
        path: &str,
        _headers: &[(String, String)],
        _body: &[u8],
    ) -> Result<fleet_forge::HttpResponse, fleet_forge::HttpError> {
        if let Ok(mut log) = self.log.lock() {
            log.push((method.to_owned(), path.to_owned()));
        }
        let (status, body) = (self.reply)(method, path);
        Ok(fleet_forge::HttpResponse {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        })
    }

    fn uncounted(&self) -> Self {
        self.clone()
    }
}

fn scripted_forge(method: &str, path: &str) -> (u16, &'static str) {
    match (method, path) {
        ("POST", _) => (201, r#"{"name":"fleet-e2e-x"}"#),
        ("GET", "/api/v1/user") => (200, r#"{"login":"me"}"#),
        ("DELETE", _) => (204, ""),
        _ => (500, ""),
    }
}

fn scripted_forge_with_owner(method: &str, path: &str) -> (u16, &'static str) {
    match method {
        "POST" => (201, r#"{"owner":{"login":"me"}}"#),
        _ => scripted_forge(method, path),
    }
}

fn scripted_api(script: &Script) -> Result<Api<Script>, String> {
    let token = Token::new("0123456789abcdef0123456789abcdef01234567".to_owned())
        .map_err(|_| "token".to_owned())?;
    let host = HostName::normalise("forge.example.org").map_err(|_| "host".to_owned())?;
    Ok(Api::new(script.clone(), &token, &host))
}

#[test]
fn a_create_reply_without_an_owner_still_deletes_the_repository() {
    let script = Script::new(scripted_forge);
    let api = scripted_api(&script).unwrap_or_else(|_| unreachable!());
    assert!(RepoGuard::create(&api, "fleet-e2e-x").is_err());
    assert_eq!(script.deletes(), vec!["/api/v1/repos/me/fleet-e2e-x"]);
}

#[test]
fn a_create_reply_with_an_owner_deletes_the_repository_when_the_guard_drops() {
    let script = Script::new(scripted_forge_with_owner);
    let api = scripted_api(&script).unwrap_or_else(|_| unreachable!());
    let made = RepoGuard::create(&api, "fleet-e2e-x");
    assert_eq!(made.as_ref().map(|(_, owner)| owner.as_str()), Ok("me"));
    assert_eq!(script.deletes(), Vec::<String>::new());
    drop(made);
    assert_eq!(script.deletes(), vec!["/api/v1/repos/me/fleet-e2e-x"]);
}
