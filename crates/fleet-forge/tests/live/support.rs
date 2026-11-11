//! Seams and guards of the live suite: the settings read from the environment, the redactor, an
//! `Http` seam over `curl`, a `Git` seam with askpass, and the drop guard that deletes a
//! throwaway repository.

use std::fmt::Write as _;
use std::fs::{self, File};
use std::future::{Future, ready};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fleet_core::host::HostName;
use fleet_forge::{
    Git, GitCommand, GitError, GitOp, GitOutput, Http, HttpError, HttpRequest, HttpResponse,
    MAX_BODY_BYTES, Method, REPO_CHECK_BUDGET, Token,
};
use serde_json::Value;

pub(crate) const TOKEN_VAR: &str = "FORGEJO_TOKEN";
pub(crate) const URL_VAR: &str = "FORGEJO_E2E_URL";
pub(crate) const BOGUS_TOKEN: &str = "0000000000000000000000000000000000000000";
pub(crate) const NAME_PREFIX: &str = "fleet-e2e-";
const HEADER_ALLOWANCE: usize = 16 * 1024;
const GIT_DEADLINE: Duration = Duration::from_secs(60);
const RECORD_CAP: usize = 600;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SetupError {
    Missing(Vec<&'static str>),
    BadToken,
    BadUrl,
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(names) => write!(
                f,
                "missing environment: {}; run `mise run live:forgejo`",
                names.join(", ")
            ),
            Self::BadToken => write!(f, "{TOKEN_VAR} is not a valid token"),
            Self::BadUrl => write!(f, "{URL_VAR} is not an https URL of a bare host name"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Settings {
    pub(crate) token: Token,
    pub(crate) host: HostName,
}

fn present(value: Option<String>) -> Option<String> {
    value
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty())
}

pub(crate) fn host_of(url: &str) -> Result<HostName, SetupError> {
    let rest = url.strip_prefix("https://").ok_or(SetupError::BadUrl)?;
    let host = rest.strip_suffix('/').unwrap_or(rest);
    if host.contains(['/', '@', ':', '?', '#', '[', ']', '\\']) {
        return Err(SetupError::BadUrl);
    }
    HostName::normalise(host).map_err(|_| SetupError::BadUrl)
}

impl Settings {
    pub(crate) fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Result<Self, SetupError> {
        let token = present(lookup(TOKEN_VAR));
        let url = present(lookup(URL_VAR));
        match (token, url) {
            (Some(token), Some(url)) => Ok(Self {
                token: Token::new(token).map_err(|_| SetupError::BadToken)?,
                host: host_of(&url)?,
            }),
            (token, url) => {
                let mut missing = Vec::new();
                if token.is_none() {
                    missing.push(TOKEN_VAR);
                }
                if url.is_none() {
                    missing.push(URL_VAR);
                }
                Err(SetupError::Missing(missing))
            }
        }
    }

    pub(crate) fn from_env() -> Result<Self, SetupError> {
        Self::from_lookup(|name| std::env::var(name).ok())
    }
}

pub(crate) struct Redactor {
    rules: Vec<(String, &'static str)>,
}

impl Redactor {
    pub(crate) fn new(token: &str, host: &str) -> Self {
        let rules = [(token, "<token>"), (host, "<host>")]
            .into_iter()
            .filter(|(secret, _)| !secret.is_empty())
            .map(|(secret, mark)| (secret.to_owned(), mark))
            .collect();
        Self { rules }
    }

    pub(crate) fn scrub(&self, text: &str, cap: usize) -> String {
        let mut out = text.to_owned();
        for (secret, mark) in &self.rules {
            out = out.replace(secret.as_str(), mark);
        }
        if out.len() > cap {
            let mut end = cap;
            while !out.is_char_boundary(end) {
                end -= 1;
            }
            out.truncate(end);
        }
        out
    }

    pub(crate) fn record(&self, label: &str, text: &str) {
        eprintln!("LIVE-RECORD {label}: {}", self.scrub(text, RECORD_CAP));
    }
}

#[derive(Clone, Default)]
pub(crate) struct Counter(Arc<AtomicUsize>);

impl Counter {
    pub(crate) fn bump(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    pub(crate) fn reset(&self) {
        self.0.store(0, Ordering::SeqCst);
    }

    pub(crate) fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

fn quote(text: &str) -> String {
    let mut out = String::from('"');
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn clean(text: &str) -> bool {
    !text.chars().any(|c| c.is_control() || c == '\u{2028}')
}

pub(crate) fn curl_config(
    host: &HostName,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<String, HttpError> {
    let body = std::str::from_utf8(body).map_err(|_| HttpError::HostRefused)?;
    let header_ok = headers.iter().all(|(name, value)| {
        clean(name) && clean(value) && !name.contains(':') && !name.is_empty()
    });
    let plain_body = !body.starts_with('@') && clean(body);
    let method_ok = !method.is_empty() && method.chars().all(|c| c.is_ascii_uppercase());
    if !path.starts_with('/')
        || !clean(path)
        || path.contains(' ')
        || !header_ok
        || !plain_body
        || !method_ok
    {
        return Err(HttpError::HostRefused);
    }
    let mut out = format!(
        "url = {}\nrequest = {}\n",
        quote(&format!("https://{host}{path}")),
        quote(method)
    );
    for (name, value) in headers {
        let _ = writeln!(out, "header = {}", quote(&format!("{name}: {value}")));
    }
    if !body.is_empty() {
        let _ = writeln!(out, "data-binary = {}", quote(body));
    }
    Ok(out)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub(crate) fn parse_reply(mut raw: &[u8]) -> Option<HttpResponse> {
    loop {
        let split = find(raw, b"\r\n\r\n")?;
        let head = std::str::from_utf8(raw.get(..split)?).ok()?;
        let rest = raw.get(split + 4..)?;
        let mut lines = head.split("\r\n");
        let mut status_line = lines.next()?.split(' ');
        status_line.next()?;
        let status: u16 = status_line.next()?.parse().ok()?;
        if (100..200).contains(&status) {
            raw = rest;
            continue;
        }
        let mut headers = Vec::new();
        for line in lines {
            let (name, value) = line.split_once(':')?;
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
        return Some(HttpResponse {
            status,
            headers,
            body: rest.to_vec(),
        });
    }
}

#[derive(Clone)]
pub(crate) struct Curl {
    host: HostName,
    pub(crate) count: Counter,
}

impl Curl {
    pub(crate) fn new(host: HostName, count: Counter) -> Self {
        Self { host, count }
    }

    /// A handle to the same host whose requests no counter sees, for the cleanup that follows a
    /// case and must not count against the case's request budget.
    pub(crate) fn uncounted(&self) -> Self {
        Self {
            host: self.host.clone(),
            count: Counter::default(),
        }
    }

    pub(crate) fn call(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError> {
        self.count.bump();
        let config = curl_config(&self.host, method, path, headers, body)?;
        let budget = REPO_CHECK_BUDGET.as_secs().to_string();
        let mut child = Command::new("curl")
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .args([
                "-q",
                "--silent",
                "--include",
                "--proto",
                "=https",
                "--tlsv1.2",
            ])
            .args(["--max-time", budget.as_str(), "--config", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| HttpError::Reset)?;
        let mut stdin = child.stdin.take().ok_or(HttpError::Reset)?;
        stdin
            .write_all(config.as_bytes())
            .map_err(|_| HttpError::Reset)?;
        drop(stdin);
        let output = child.wait_with_output().map_err(|_| HttpError::Reset)?;
        match output.status.code() {
            Some(0) => {}
            Some(28) => return Err(HttpError::Timeout),
            _ => return Err(HttpError::Reset),
        }
        if output.stdout.len() > MAX_BODY_BYTES + HEADER_ALLOWANCE {
            return Err(HttpError::BodyTooLarge);
        }
        let reply = parse_reply(&output.stdout).ok_or(HttpError::Reset)?;
        if reply.body.len() > MAX_BODY_BYTES {
            return Err(HttpError::BodyTooLarge);
        }
        Ok(reply)
    }
}

/// The request seam of the live suite: one call over a wire, and a handle whose requests no
/// counter sees. `Curl` is the real wire, a test passes a scripted one.
pub(crate) trait Wire: Clone {
    fn call(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError>;

    fn uncounted(&self) -> Self;
}

impl Wire for Curl {
    fn call(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, HttpError> {
        Self::call(self, method, path, headers, body)
    }

    fn uncounted(&self) -> Self {
        Self::uncounted(self)
    }
}

impl Http for Curl {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, HttpError>> + Send {
        let method = match request.method {
            Method::Get => "GET",
            Method::Post => "POST",
        };
        let reply = if request.host == self.host {
            self.call(method, &request.path, &request.headers, &request.body)
        } else {
            Err(HttpError::HostRefused)
        };
        ready(reply)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Auth {
    Token,
    Bogus,
    Anonymous,
}

pub(crate) struct Api<W = Curl> {
    pub(crate) curl: W,
    token: String,
    pub(crate) redactor: Redactor,
}

impl<W: Wire> Api<W> {
    pub(crate) fn new(curl: W, token: &Token, host: &HostName) -> Self {
        Self {
            curl,
            token: token.expose().to_owned(),
            redactor: Redactor::new(token.expose(), host.as_str()),
        }
    }

    pub(crate) fn call(
        &self,
        method: &str,
        path: &str,
        auth: Auth,
        body: Option<&Value>,
    ) -> Result<HttpResponse, String> {
        let mut headers = vec![("Accept".to_owned(), "application/json".to_owned())];
        match auth {
            Auth::Token => {
                headers.push(("Authorization".to_owned(), format!("token {}", self.token)));
            }
            Auth::Bogus => {
                headers.push(("Authorization".to_owned(), format!("token {BOGUS_TOKEN}")));
            }
            Auth::Anonymous => {}
        }
        let bytes = body.map_or_else(Vec::new, |value| {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
            value.to_string().into_bytes()
        });
        self.curl
            .call(method, path, &headers, &bytes)
            .map_err(|error| format!("{method} {path}: {error}"))
    }

    pub(crate) fn message(&self, response: &HttpResponse) -> String {
        let text = serde_json::from_slice::<Value>(&response.body)
            .ok()
            .and_then(|body| {
                body.get("message")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default();
        self.redactor.scrub(&text, 300)
    }

    pub(crate) fn json(&self, response: &HttpResponse) -> Result<Value, String> {
        serde_json::from_slice(&response.body).map_err(|_| {
            self.redactor.scrub(
                &format!("status {} with a body that is not JSON", response.status),
                RECORD_CAP,
            )
        })
    }
}

pub(crate) fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(crate) fn header_names(response: &HttpResponse) -> String {
    let mut names: Vec<String> = response
        .headers
        .iter()
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    names.sort();
    names.dedup();
    names.join(",")
}

pub(crate) fn random_hex() -> Result<String, String> {
    let mut bytes = [0_u8; 6];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|_| "no random bytes".to_owned())?;
    Ok(bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    }))
}

pub(crate) struct Scratch {
    pub(crate) path: PathBuf,
}

impl Scratch {
    pub(crate) fn create(id: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("{NAME_PREFIX}{id}"));
        fs::create_dir(&path)
            .map_err(|_| "scratch directory exists or is not creatable".to_owned())?;
        Ok(Self { path })
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Deletes the throwaway repositories it holds when dropped. It is armed as soon as the forge
/// answers 201, before the reply is read, so a reply that cannot be read still deletes the
/// repository. A guard that never learned the owner asks the forge for the token's own login.
pub(crate) struct RepoGuard<W: Wire = Curl> {
    curl: W,
    token: String,
    owner: Option<String>,
    names: Vec<String>,
}

impl<W: Wire> RepoGuard<W> {
    pub(crate) fn create(api: &Api<W>, name: &str) -> Result<(Self, String), String> {
        if !name.starts_with(NAME_PREFIX) {
            return Err("throwaway names carry the fleet-e2e prefix".to_owned());
        }
        let body = serde_json::json!({
            "name": name,
            "private": true,
            "auto_init": true,
            "default_branch": "main",
            "description": "fleet live e2e throwaway",
        });
        let response = api.call("POST", "/api/v1/user/repos", Auth::Token, Some(&body))?;
        if response.status != 201 {
            return Err(format!(
                "create {name}: status {}: {}",
                response.status,
                api.message(&response)
            ));
        }
        let mut guard = Self {
            curl: api.curl.uncounted(),
            token: api.token.clone(),
            owner: None,
            names: vec![name.to_owned()],
        };
        let owner = api
            .json(&response)?
            .pointer("/owner/login")
            .and_then(Value::as_str)
            .ok_or("create reply holds no owner")?
            .to_owned();
        guard.owner = Some(owner.clone());
        Ok((guard, owner))
    }

    pub(crate) fn renamed(&mut self, name: &str) {
        self.names.push(name.to_owned());
    }
}

impl<W: Wire> RepoGuard<W> {
    fn own_login(&self, headers: &[(String, String)]) -> Option<String> {
        let reply = self
            .curl
            .call("GET", "/api/v1/user", headers, &[])
            .ok()
            .filter(|reply| reply.status == 200)?;
        serde_json::from_slice::<Value>(&reply.body)
            .ok()?
            .get("login")
            .and_then(Value::as_str)
            .map(str::to_owned)
    }
}

impl<W: Wire> Drop for RepoGuard<W> {
    fn drop(&mut self) {
        let headers = vec![("Authorization".to_owned(), format!("token {}", self.token))];
        let owner = self.owner.clone().or_else(|| self.own_login(&headers));
        let leaked = sweep(&self.names, |name| {
            let owner = owner.as_deref()?;
            let path = format!("/api/v1/repos/{owner}/{name}");
            self.curl
                .call("DELETE", &path, &headers, &[])
                .ok()
                .map(|reply| reply.status)
        });
        for name in leaked {
            eprintln!("LEAKED throwaway repository {name}: delete it by hand");
        }
    }
}

/// Deletes a repository under each of its names, newest first, and returns the names that may
/// still exist. `delete` answers the status of one `DELETE`, or `None` when the call failed.
///
/// A 204 or 404 means the name is gone. A redirect on an older name means the repository was
/// renamed, and it counts as gone only when a newer name is gone, because the forge forwards the
/// old name to the new one.
pub(crate) fn sweep(names: &[String], mut delete: impl FnMut(&str) -> Option<u16>) -> Vec<String> {
    let mut leaked = Vec::new();
    let mut newer_gone = false;
    for name in names.iter().rev() {
        if !name.starts_with(NAME_PREFIX) {
            continue;
        }
        match delete(name) {
            Some(204 | 404) => newer_gone = true,
            Some(301 | 302 | 307 | 308) if newer_gone => {}
            _ => leaked.push(name.clone()),
        }
    }
    leaked
}

/// The key names and value types of a JSON document, never its values, so a reply shape can be
/// recorded without leaking content. Objects nest to `depth` levels, an array shows its length and
/// the shape of its first element.
pub(crate) fn shape(value: &Value, depth: usize) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(_) => "bool".to_owned(),
        Value::Number(_) => "number".to_owned(),
        Value::String(_) => "string".to_owned(),
        Value::Array(list) => match (list.first(), depth) {
            (Some(first), 1..) => format!("array({})[{}]", list.len(), shape(first, depth - 1)),
            _ => format!("array({})", list.len()),
        },
        Value::Object(map) if depth > 0 => {
            let fields: Vec<String> = map
                .iter()
                .map(|(key, inner)| format!("{key}:{}", shape(inner, depth - 1)))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Object(map) => format!("object({})", map.len()),
    }
}

/// The names of the repositories on one page of `GET /user/repos` that a cleanup may delete: the
/// authenticated user's own repositories whose name carries the throwaway prefix.
pub(crate) fn leaked_names(page: &Value, login: &str) -> Vec<String> {
    page.as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter(|repo| repo.pointer("/owner/login").and_then(Value::as_str) == Some(login))
        .filter_map(|repo| repo.get("name").and_then(Value::as_str))
        .filter(|name| name.starts_with(NAME_PREFIX))
        .map(str::to_owned)
        .collect()
}

#[derive(Clone)]
pub(crate) struct LiveGit {
    host: HostName,
    token: String,
    user: String,
    dir: PathBuf,
    pub(crate) count: Counter,
}

const ASKPASS: &str = "#!/bin/sh\ncase \"$1\" in\nUsername*) printf '%s\\n' \"$FLEET_E2E_USER\" ;;\n*) printf '%s\\n' \"$FLEET_E2E_TOKEN\" ;;\nesac\n";

impl LiveGit {
    pub(crate) fn new(
        host: HostName,
        token: &str,
        user: &str,
        dir: &Path,
        count: Counter,
    ) -> Result<Self, String> {
        let script = dir.join("askpass.sh");
        if !script.exists() {
            fs::write(&script, ASKPASS).map_err(|_| "askpass not writable".to_owned())?;
            fs::set_permissions(&script, fs::Permissions::from_mode(0o700))
                .map_err(|_| "askpass not executable".to_owned())?;
        }
        Ok(Self {
            host,
            token: token.to_owned(),
            user: user.to_owned(),
            dir: dir.to_path_buf(),
            count,
        })
    }

    pub(crate) fn with_token(&self, token: &str) -> Self {
        Self {
            token: token.to_owned(),
            ..self.clone()
        }
    }

    pub(crate) fn clone_dir(&self) -> PathBuf {
        self.dir.join("clone")
    }

    fn base(&self) -> Command {
        let mut command = Command::new("git");
        command
            .args(["-c", "credential.helper=", "-c", "core.askPass="])
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.dir)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", self.dir.join("askpass.sh"))
            .env("FLEET_E2E_USER", &self.user)
            .env("FLEET_E2E_TOKEN", &self.token);
        command
    }

    fn execute(&self, mut command: Command) -> Result<GitOutput, GitError> {
        let log = self.dir.join("git.stderr");
        let file = File::create(&log).map_err(|_| GitError::Spawn)?;
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(file))
            .spawn()
            .map_err(|_| GitError::Spawn)?;
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() > GIT_DEADLINE => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(GitError::Timeout);
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => return Err(GitError::Spawn),
            }
        };
        let raw = fs::read(&log).map_err(|_| GitError::Spawn)?;
        Ok(GitOutput {
            code: status.code().unwrap_or(-1),
            stderr: String::from_utf8_lossy(&raw).into_owned(),
        })
    }
}

impl Git for LiveGit {
    fn run(&self, command: GitCommand) -> impl Future<Output = Result<GitOutput, GitError>> + Send {
        ready(self.exec(command))
    }
}

impl LiveGit {
    fn exec(&self, command: GitCommand) -> Result<GitOutput, GitError> {
        self.count.bump();
        if *command.repo.host() != self.host {
            return Err(GitError::Spawn);
        }
        let url = format!(
            "https://{}/{}/{}.git",
            self.host,
            command.repo.owner(),
            command.repo.repo()
        );
        let clone = self.clone_dir();
        let mut git = self.base();
        match command.op {
            GitOp::Fetch if !clone.join(".git").exists() => {
                git.args(["clone", "--quiet", url.as_str()]).arg(&clone);
            }
            GitOp::Fetch => {
                git.arg("-C")
                    .arg(&clone)
                    .args(["fetch", "--quiet", "origin"]);
            }
            GitOp::Push => {
                let branch = command.branch.ok_or(GitError::Spawn)?;
                let refspec = format!("refs/heads/{branch}:refs/heads/{branch}");
                git.arg("-C")
                    .arg(&clone)
                    .args(["push", "--quiet", "origin", refspec.as_str()]);
            }
        }
        self.execute(git)
    }
}

pub(crate) fn local_git(dir: &Path, args: &[&str]) -> Result<(), String> {
    let status = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=fleet-e2e",
            "-c",
            "user.email=e2e@example.invalid",
        ])
        .args(["-c", "commit.gpgsign=false"])
        .args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "git did not start".to_owned())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("local git {} failed", args.first().unwrap_or(&"")))
    }
}
