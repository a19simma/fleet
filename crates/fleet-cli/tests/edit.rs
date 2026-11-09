//! `fleet edit` against an in-process `FleetEdit` stub: request fields, per-invocation keys,
//! bounded payload input, the user-token refusal of a decision, the scrubbing of every printed
//! field, and `edit apply` against real temporary git repositories.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::path::Path;
use std::process::Command;
use std::sync::{Arc, Mutex};

use clap::Parser;
use fleet_cli::{Cli, CliError, run};
use fleet_proto::MAX_EDIT_PAYLOAD_BYTES;
use fleet_proto::v1::fleet_edit_server::{FleetEdit, FleetEditServer};
use fleet_proto::v1::{
    DecideEditRequest, EditKind, EditState, FileEditRequest, GetEditRequest, ListEditsReply,
    ListEditsRequest, SuggestedEdit,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::{Code, Request, Response, Status};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: &str = "client-token-0123456789";
const USER_TOKEN_REQUIRED: &str = "a per-user API token is required to decide an edit";

#[derive(Clone, Default)]
struct Stub {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    edits: Vec<SuggestedEdit>,
    refuse_decide: bool,
}

impl Stub {
    fn record(&self, method: &str, request: &impl std::fmt::Debug) {
        self.calls
            .lock()
            .unwrap()
            .push((method.to_owned(), format!("{request:?}")));
    }

    fn first(&self) -> SuggestedEdit {
        self.edits.first().cloned().unwrap_or_else(|| edit(1))
    }
}

fn edit(id: u64) -> SuggestedEdit {
    SuggestedEdit {
        id,
        kind: EditKind::FilePatch as i32,
        state: EditState::Accepted as i32,
        target: "f.txt".into(),
        base_hash: "b2f931a".into(),
        payload: String::new(),
        filed_by: "ann".into(),
        decided_by: Some(9),
        decided_at_ms: Some(0),
        created_at_ms: 0,
    }
}

#[tonic::async_trait]
impl FleetEdit for Stub {
    async fn file_edit(
        &self,
        r: Request<FileEditRequest>,
    ) -> Result<Response<SuggestedEdit>, Status> {
        self.record("file_edit", r.get_ref());
        Ok(Response::new(self.first()))
    }

    async fn list_edits(
        &self,
        r: Request<ListEditsRequest>,
    ) -> Result<Response<ListEditsReply>, Status> {
        self.record("list_edits", r.get_ref());
        Ok(Response::new(ListEditsReply {
            edits: self.edits.clone(),
        }))
    }

    async fn get_edit(
        &self,
        r: Request<GetEditRequest>,
    ) -> Result<Response<SuggestedEdit>, Status> {
        self.record("get_edit", r.get_ref());
        let id = r.get_ref().id;
        self.edits
            .iter()
            .find(|e| e.id == id)
            .cloned()
            .map(Response::new)
            .ok_or_else(|| Status::not_found("no such edit"))
    }

    async fn decide_edit(
        &self,
        r: Request<DecideEditRequest>,
    ) -> Result<Response<SuggestedEdit>, Status> {
        self.record("decide_edit", r.get_ref());
        if self.refuse_decide {
            return Err(Status::permission_denied(USER_TOKEN_REQUIRED));
        }
        Ok(Response::new(self.first()))
    }
}

async fn serve(stub: Stub) -> Result<String, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let url = format!("http://{}", listener.local_addr()?);
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(FleetEditServer::new(stub))
            .serve_with_incoming(TcpListenerStream::new(listener)),
    );
    Ok(url)
}

async fn cli(url: &str, args: &[&str], stdin: &[u8]) -> (Result<(), CliError>, String) {
    let mut full = vec!["fleet", "--server", url, "edit"];
    full.extend_from_slice(args);
    let parsed = Cli::try_parse_from(full).unwrap();
    let mut out = Vec::new();
    let mut stdin = stdin;
    let result = run(
        parsed,
        |name| (name == "FLEET_CLIENT_TOKEN").then(|| TOKEN.to_owned()),
        &mut stdin,
        &mut out,
    )
    .await;
    (result, String::from_utf8_lossy(&out).into_owned())
}

fn calls(stub: &Stub) -> Vec<(String, String)> {
    stub.calls.lock().unwrap().clone()
}

fn methods(stub: &Stub) -> Vec<String> {
    calls(stub).into_iter().map(|(m, _)| m).collect()
}

fn key_of(debug: &str) -> String {
    let rest = debug.split("key: \"").nth(1).unwrap();
    rest.split('"').next().unwrap().to_owned()
}

fn clean(out: &str) -> bool {
    !out.contains(TOKEN)
        && !out.contains("client-tok")
        && !out.chars().any(|c| {
            (c.is_control() && c != '\n' && c != '\t') || "\u{202e}\u{2028}\u{85}".contains(c)
        })
}

fn hostile() -> String {
    format!("a\u{1b}[31m{TOKEN}\u{202e}\r\u{85}b\u{2028}c\0d")
}

#[tokio::test]
async fn file_sends_kind_target_base_hash_payload_and_a_fresh_key_per_invocation() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let args = [
        "-p",
        "proj",
        "file",
        "file-patch",
        "src/a.txt",
        "--base-hash",
        "abc1234",
        "--file",
        "-",
    ];
    cli(&url, &args, b"the diff\n").await.0?;
    cli(&url, &args, b"the diff\n").await.0?;
    let seen = calls(&stub);
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[0].0, "file_edit");
    for field in [
        "project: \"proj\"",
        "kind: FilePatch",
        "target: \"src/a.txt\"",
        "base_hash: \"abc1234\"",
        "payload: \"the diff\\n\"",
    ] {
        assert!(seen[0].1.contains(field), "{field} in {seen:?}");
    }
    assert_ne!(key_of(&seen[0].1), key_of(&seen[1].1));
    Ok(())
}

#[tokio::test]
async fn file_maps_each_kind_and_defaults_the_base_hash_to_empty() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    for (word, kind) in [
        ("slice-op", "SliceOp"),
        ("pitfall", "Pitfall"),
        ("file-patch", "FilePatch"),
    ] {
        cli(&url, &["-p", "p", "file", word, "t", "--file", "-"], b"x")
            .await
            .0?;
        let debug = calls(&stub).pop().unwrap().1;
        assert!(debug.contains(&format!("kind: {kind}")), "{debug}");
        assert!(debug.contains("base_hash: \"\""), "{debug}");
    }
    Ok(())
}

#[tokio::test]
async fn file_payload_at_the_cap_is_sent_and_one_byte_over_is_refused_before_connecting()
-> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    let at = vec![b'a'; MAX_EDIT_PAYLOAD_BYTES];
    cli(
        &url,
        &["-p", "p", "file", "pitfall", "t", "--file", "-"],
        &at,
    )
    .await
    .0?;
    assert_eq!(methods(&stub), ["file_edit"]);
    let over = vec![b'a'; MAX_EDIT_PAYLOAD_BYTES + 1];
    let (result, _) = cli(
        "http://127.0.0.1:1",
        &["-p", "p", "file", "pitfall", "t", "--file", "-"],
        &over,
    )
    .await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    let (result, _) = cli(
        "http://127.0.0.1:1",
        &["-p", "p", "file", "pitfall", "t", "--file", "-"],
        &[0xff, 0xfe],
    )
    .await;
    assert!(matches!(result, Err(CliError::Usage(_))), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn list_sends_the_state_filter_and_prints_one_row_per_edit() -> TestResult {
    let stub = Stub {
        edits: vec![edit(4), edit(5)],
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(&url, &["-p", "p", "list", "--state", "pending"], b"").await;
    result?;
    let debug = calls(&stub)[0].1.clone();
    assert!(debug.contains("project: \"p\""), "{debug}");
    assert!(debug.contains("state: Some(Pending)"), "{debug}");
    assert_eq!(out.lines().count(), 2, "{out:?}");
    assert!(
        out.starts_with("4\tfile-patch\taccepted\tf.txt\tann\t"),
        "{out:?}"
    );
    cli(&url, &["-p", "p", "list"], b"").await.0?;
    assert!(calls(&stub)[1].1.contains("state: None"));
    Ok(())
}

#[tokio::test]
async fn show_sends_the_id_and_prints_the_row_hash_and_indented_payload() -> TestResult {
    let mut one = edit(7);
    one.payload = "diff --git a/x b/x\n+++ b/x\n".into();
    let stub = Stub {
        edits: vec![one],
        ..Stub::default()
    };
    let url = serve(stub.clone()).await?;
    let (result, out) = cli(&url, &["-p", "p", "show", "7"], b"").await;
    result?;
    let debug = calls(&stub)[0].1.clone();
    assert!(
        debug.contains("id: 7") && debug.contains("project: \"p\""),
        "{debug}"
    );
    assert!(
        out.starts_with("7\tfile-patch\taccepted\tf.txt\tann\t"),
        "{out:?}"
    );
    assert!(out.contains("base_hash: b2f931a\n"), "{out:?}");
    assert!(
        out.contains("payload:\n  diff --git a/x b/x\n  +++ b/x\n"),
        "{out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn accept_and_reject_call_decide_edit_with_the_decision_and_a_key() -> TestResult {
    let stub = Stub::default();
    let url = serve(stub.clone()).await?;
    cli(&url, &["-p", "p", "accept", "3"], b"").await.0?;
    cli(&url, &["-p", "p", "reject", "3"], b"").await.0?;
    cli(
        &url,
        &["-p", "p", "--idempotency-key", "k1", "accept", "3"],
        b"",
    )
    .await
    .0?;
    let seen = calls(&stub);
    assert_eq!(methods(&stub), ["decide_edit"; 3]);
    assert!(seen[0].1.contains("decision: Accept") && seen[0].1.contains("id: 3"));
    assert!(seen[1].1.contains("decision: Reject"));
    assert_ne!(key_of(&seen[0].1), key_of(&seen[1].1));
    assert_eq!(key_of(&seen[2].1), "k1");
    Ok(())
}

#[tokio::test]
async fn a_refused_decision_names_the_per_user_token_and_never_prints_the_token() -> TestResult {
    let stub = Stub {
        refuse_decide: true,
        ..Stub::default()
    };
    let url = serve(stub).await?;
    for verb in ["accept", "reject"] {
        let (result, _) = cli(&url, &["-p", "p", verb, "3"], b"").await;
        let Err(CliError::Rpc(status)) = result else {
            panic!("{verb}: not an rpc refusal");
        };
        assert_eq!(status.code(), Code::PermissionDenied);
        let shown = CliError::Rpc(status).to_string();
        assert!(shown.contains(USER_TOKEN_REQUIRED), "{shown}");
        assert!(shown.contains("FLEET_CLIENT_TOKEN"), "{shown}");
        assert!(shown.contains("per-user API token"), "{shown}");
        assert!(!shown.contains(TOKEN), "{shown}");
    }
    Ok(())
}

#[tokio::test]
async fn a_command_without_a_project_and_an_empty_key_are_refused_before_connecting() -> TestResult
{
    for args in [
        &["list"][..],
        &["show", "1"],
        &["accept", "1"],
        &["apply", "1"],
        &["--idempotency-key", "", "-p", "p", "accept", "1"],
    ] {
        let (result, _) = cli("http://127.0.0.1:1", args, b"").await;
        assert!(
            matches!(result, Err(CliError::Usage(_))),
            "{args:?}: {result:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn every_printed_field_is_scrubbed_one_hostile_value_per_field() -> TestResult {
    let h = hostile();
    let fields: [&dyn Fn(&mut SuggestedEdit); 4] = [
        &|e| e.target = h.clone(),
        &|e| e.filed_by = h.clone(),
        &|e| e.base_hash = h.clone(),
        &|e| e.payload = h.clone(),
    ];
    for set in fields {
        let mut e = edit(1);
        set(&mut e);
        let url = serve(Stub {
            edits: vec![e],
            ..Stub::default()
        })
        .await?;
        for args in [
            &["-p", "p", "list"][..],
            &["-p", "p", "show", "1"],
            &["-p", "p", "accept", "1"],
        ] {
            let (result, out) = cli(&url, args, b"").await;
            result?;
            assert!(clean(&out), "{args:?}: {out:?}");
            assert_ne!(out, "");
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_multiline_payload_cannot_forge_a_row() -> TestResult {
    let mut e = edit(1);
    e.payload = "x\n99\tfile-patch\taccepted\tevil\tmallory\n".into();
    let url = serve(Stub {
        edits: vec![e],
        ..Stub::default()
    })
    .await?;
    let (result, out) = cli(&url, &["-p", "p", "show", "1"], b"").await;
    result?;
    assert!(out.lines().all(|l| !l.starts_with("99\t")), "{out:?}");
    Ok(())
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "t")
        .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
        .env("GIT_COMMITTER_NAME", "t")
        .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn write(dir: &Path, name: &str, text: &str) {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, text).unwrap();
}

fn read(dir: &Path, name: &str) -> String {
    std::fs::read_to_string(dir.join(name)).unwrap()
}

const BASE: &str = "one\ntwo\nthree\nfour\nfive\n";

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    write(dir.path(), "f.txt", BASE);
    write(dir.path(), "g.txt", "g\n");
    write(dir.path(), "sub/h.txt", "h\n");
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "init"]);
    dir
}

fn diff_of(dir: &Path, name: &str, new: Option<&str>) -> String {
    match new {
        Some(text) => write(dir, name, text),
        None => std::fs::remove_file(dir.join(name)).unwrap(),
    }
    git(dir, &["add", "-N", name]);
    let diff = git(dir, &["diff", "HEAD", "--", name]);
    git(dir, &["reset", "-q", "--", name]);
    if git(dir, &["ls-files", "--", name]).is_empty() {
        std::fs::remove_file(dir.join(name)).unwrap();
    } else {
        git(dir, &["checkout", "-q", "--", name]);
    }
    diff
}

const CHANGED: &str = "one\ntwo\nTHREE\nfour\nfive\n";

fn accepted(id: u64, target: &str, payload: &str) -> SuggestedEdit {
    SuggestedEdit {
        target: target.into(),
        payload: payload.into(),
        ..edit(id)
    }
}

async fn apply(edits: Vec<SuggestedEdit>, dir: &Path) -> (Result<(), CliError>, String, Stub) {
    let stub = Stub {
        edits,
        ..Stub::default()
    };
    let url = serve(stub.clone()).await.unwrap();
    let repo = dir.to_str().unwrap();
    let (result, out) = cli(&url, &["-p", "p", "apply", "1", "--repo", repo], b"").await;
    (result, out, stub)
}

fn refused(result: &Result<(), CliError>) -> String {
    match result {
        Err(CliError::Apply(text)) => text.clone(),
        other => format!("not an apply refusal: {other:?}"),
    }
}

#[tokio::test]
async fn apply_changes_the_working_tree_and_stages_and_commits_nothing() -> TestResult {
    let dir = repo();
    let head = git(dir.path(), &["rev-parse", "HEAD"]);
    let patch = diff_of(dir.path(), "f.txt", Some(CHANGED));
    let (result, out, stub) = apply(vec![accepted(1, "f.txt", &patch)], dir.path()).await;
    result?;
    assert_eq!(methods(&stub), ["get_edit"]);
    assert_eq!(read(dir.path(), "f.txt"), CHANGED);
    assert_eq!(git(dir.path(), &["status", "--porcelain"]), " M f.txt\n");
    assert_eq!(git(dir.path(), &["diff", "--cached", "--name-only"]), "");
    assert_eq!(git(dir.path(), &["rev-parse", "HEAD"]), head);
    assert!(
        out.contains("applied") && out.contains("f.txt") && out.contains("uncommitted"),
        "{out:?}"
    );
    Ok(())
}

#[tokio::test]
async fn apply_leaves_another_staged_file_staged_and_runs_beside_other_local_changes() -> TestResult
{
    let dir = repo();
    let patch = diff_of(dir.path(), "f.txt", Some(CHANGED));
    write(dir.path(), "g.txt", "g2\n");
    git(dir.path(), &["add", "g.txt"]);
    write(dir.path(), "sub/h.txt", "h2\n");
    write(dir.path(), "new.txt", "n\n");
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &patch)], dir.path()).await;
    result?;
    let status = git(dir.path(), &["status", "--porcelain"]);
    assert!(status.contains("M  g.txt\n"), "{status}");
    assert!(status.contains(" M f.txt\n"), "{status}");
    assert!(status.contains(" M sub/h.txt\n"), "{status}");
    assert!(status.contains("?? new.txt\n"), "{status}");
    Ok(())
}

#[tokio::test]
async fn apply_from_a_subdirectory_uses_the_repository_root() -> TestResult {
    let dir = repo();
    let patch = diff_of(dir.path(), "f.txt", Some(CHANGED));
    let sub = dir.path().join("sub");
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &patch)], &sub).await;
    result?;
    assert_eq!(read(dir.path(), "f.txt"), CHANGED);
    Ok(())
}

#[tokio::test]
async fn apply_creates_and_deletes_files() -> TestResult {
    let dir = repo();
    let create = diff_of(dir.path(), "made.txt", Some("x\ny\n"));
    let (result, _, _) = apply(vec![accepted(1, "made.txt", &create)], dir.path()).await;
    result?;
    assert_eq!(read(dir.path(), "made.txt"), "x\ny\n");
    assert_eq!(git(dir.path(), &["status", "--porcelain"]), "?? made.txt\n");
    let remove = diff_of(dir.path(), "g.txt", None);
    let (result, _, _) = apply(vec![accepted(1, "g.txt", &remove)], dir.path()).await;
    result?;
    assert!(!dir.path().join("g.txt").exists());
    assert_eq!(
        git(dir.path(), &["status", "--porcelain"]),
        " D g.txt\n?? made.txt\n"
    );
    Ok(())
}

#[tokio::test]
async fn a_conflict_leaves_markers_in_the_file_reports_it_and_stages_nothing() -> TestResult {
    let dir = repo();
    let patch = diff_of(dir.path(), "f.txt", Some(CHANGED));
    write(dir.path(), "f.txt", "one\ntwo\nXXX\nfour\nfive\n");
    git(dir.path(), &["commit", "-qam", "other change"]);
    let head = git(dir.path(), &["rev-parse", "HEAD"]);
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &patch)], dir.path()).await;
    let message = refused(&result);
    assert!(
        message.contains("conflict") && message.contains("f.txt"),
        "{message}"
    );
    assert!(message.contains("nothing is staged"), "{message}");
    let text = read(dir.path(), "f.txt");
    assert!(
        text.contains("<<<<<<<") && text.contains(">>>>>>>"),
        "{text}"
    );
    assert_eq!(git(dir.path(), &["status", "--porcelain"]), " M f.txt\n");
    assert_eq!(git(dir.path(), &["ls-files", "--unmerged"]), "");
    assert_eq!(git(dir.path(), &["rev-parse", "HEAD"]), head);
    Ok(())
}

#[tokio::test]
async fn a_target_with_local_changes_is_refused_and_left_untouched() -> TestResult {
    let patch_dir = repo();
    let patch = diff_of(patch_dir.path(), "f.txt", Some(CHANGED));
    for stage in [false, true] {
        let dir = repo();
        let mine = "one\nmine\nthree\nfour\nfive\n";
        write(dir.path(), "f.txt", mine);
        if stage {
            git(dir.path(), &["add", "f.txt"]);
        }
        let (result, _, _) = apply(vec![accepted(1, "f.txt", &patch)], dir.path()).await;
        let message = refused(&result);
        assert!(message.contains("local changes"), "{message}");
        assert_eq!(read(dir.path(), "f.txt"), mine);
        let expected = if stage { "M  f.txt\n" } else { " M f.txt\n" };
        assert_eq!(git(dir.path(), &["status", "--porcelain"]), expected);
    }
    let dir = repo();
    write(dir.path(), "made.txt", "mine\n");
    let create = diff_of(patch_dir.path(), "made.txt", Some("x\n"));
    let (result, _, _) = apply(vec![accepted(1, "made.txt", &create)], dir.path()).await;
    assert!(refused(&result).contains("local changes"));
    assert_eq!(read(dir.path(), "made.txt"), "mine\n");
    Ok(())
}

#[tokio::test]
async fn a_patch_for_a_dot_git_path_is_refused_and_the_config_is_untouched() -> TestResult {
    let dir = repo();
    let config = read(dir.path(), ".git/config");
    let hostile = "diff --git a/.git/config b/.git/config\n--- a/.git/config\n+++ b/.git/config\n@@ -1 +1,2 @@\n [core]\n+\tfsmonitor = touch /tmp/pwned\n";
    for target in [
        ".git/config",
        ".git/hooks/pre-commit",
        ".GIT/config",
        ".gitmodules",
    ] {
        let body = hostile.replace(".git/config", target);
        let (result, _, stub) = apply(vec![accepted(1, target, &body)], dir.path()).await;
        assert!(refused(&result).contains("safe path"), "{target}");
        assert_eq!(methods(&stub), ["get_edit"]);
    }
    assert_eq!(read(dir.path(), ".git/config"), config);
    assert!(!dir.path().join(".gitmodules").exists());
    Ok(())
}

#[tokio::test]
async fn a_path_through_a_symlink_that_leaves_the_repository_is_refused() -> TestResult {
    let dir = repo();
    let outside = tempfile::tempdir()?;
    write(outside.path(), "x.txt", BASE);
    std::os::unix::fs::symlink(outside.path(), dir.path().join("link"))?;
    let payload = "diff --git a/link/x.txt b/link/x.txt\n--- a/link/x.txt\n+++ b/link/x.txt\n@@ -1,5 +1,5 @@\n one\n two\n-three\n+THREE\n four\n five\n";
    let (result, _, _) = apply(vec![accepted(1, "link/x.txt", payload)], dir.path()).await;
    assert!(refused(&result).contains("symlink"));
    assert_eq!(read(outside.path(), "x.txt"), BASE);
    std::os::unix::fs::symlink(outside.path().join("x.txt"), dir.path().join("leaf.txt"))?;
    let leaf = payload.replace("link/x.txt", "leaf.txt");
    let (result, _, _) = apply(vec![accepted(1, "leaf.txt", &leaf)], dir.path()).await;
    assert!(refused(&result).contains("symlink"));
    assert_eq!(read(outside.path(), "x.txt"), BASE);
    Ok(())
}

#[tokio::test]
async fn hostile_patch_text_is_refused_and_the_tree_is_untouched() -> TestResult {
    let dir = repo();
    let good = diff_of(dir.path(), "f.txt", Some(CHANGED));
    for bad in [
        good.replace('\n', "\r\n"),
        good.replace("THREE", "TH\u{202e}REE"),
        good.replace("THREE", "TH\0REE"),
        good.replace("THREE", "TH\u{85}REE"),
        good.replace("THREE", "TH\u{2028}REE"),
        good.replace("--- a/f.txt", "rename from f.txt\nrename to ../x\n--- a/f.txt"),
        good.replace("index ", "old mode 100644\nnew mode 120000\nindex "),
        format!("{good}diff --git a/g.txt b/g.txt\n--- a/g.txt\n+++ b/g.txt\n@@ -1 +1 @@\n-g\n+x\n"),
        "diff --git a/f.txt b/f.txt\nGIT binary patch\nliteral 0\n".to_owned(),
        "diff --git a/f.txt b/f.txt\nnew file mode 120000\nindex 0000000..1111111\n--- /dev/null\n+++ b/f.txt\n@@ -0,0 +1 @@\n+/etc/passwd\n".to_owned(),
    ] {
        let (result, _, _) = apply(vec![accepted(1, "f.txt", &bad)], dir.path()).await;
        assert!(matches!(result, Err(CliError::Apply(_))), "{bad:?}: {result:?}");
        assert_eq!(read(dir.path(), "f.txt"), BASE);
        assert_eq!(git(dir.path(), &["status", "--porcelain"]), "");
    }
    Ok(())
}

#[tokio::test]
async fn a_patch_at_the_payload_limit_applies_and_one_byte_over_is_refused() -> TestResult {
    let dir = repo();
    let head = "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -1,5 +1,5 @@\n one\n two\n-three\n+";
    let tail = "\n four\n five\n";
    let pad = |len: usize| "y".repeat(len - head.len() - tail.len());
    let at = format!("{head}{}{tail}", pad(MAX_EDIT_PAYLOAD_BYTES));
    assert_eq!(at.len(), MAX_EDIT_PAYLOAD_BYTES);
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &at)], dir.path()).await;
    result?;
    assert!(read(dir.path(), "f.txt").contains("yyyy"));
    git(dir.path(), &["checkout", "-q", "--", "."]);
    let over = format!("{head}{}{tail}", pad(MAX_EDIT_PAYLOAD_BYTES + 1));
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &over)], dir.path()).await;
    assert!(refused(&result).contains("larger than the payload limit"));
    assert_eq!(read(dir.path(), "f.txt"), BASE);
    Ok(())
}

#[tokio::test]
async fn an_edit_that_is_not_an_accepted_file_patch_is_refused_before_git_runs() -> TestResult {
    let dir = repo();
    let patch = diff_of(dir.path(), "f.txt", Some(CHANGED));
    for state in [
        EditState::Pending,
        EditState::Rejected,
        EditState::Stale,
        EditState::Unspecified,
    ] {
        let mut e = accepted(1, "f.txt", &patch);
        e.state = state as i32;
        let (result, _, stub) = apply(vec![e], dir.path()).await;
        assert!(refused(&result).contains("accepted"), "{state:?}");
        assert_eq!(methods(&stub), ["get_edit"]);
        assert_eq!(read(dir.path(), "f.txt"), BASE);
    }
    for kind in [EditKind::SliceOp, EditKind::Pitfall, EditKind::Unspecified] {
        let mut e = accepted(1, "f.txt", &patch);
        e.kind = kind as i32;
        let (result, _, _) = apply(vec![e], dir.path()).await;
        assert!(refused(&result).contains("file patch"), "{kind:?}");
        assert_eq!(read(dir.path(), "f.txt"), BASE);
    }
    let (result, _, _) = apply(Vec::new(), dir.path()).await;
    assert!(matches!(result, Err(CliError::Rpc(s)) if s.code() == Code::NotFound));
    Ok(())
}

#[tokio::test]
async fn a_directory_that_is_not_a_work_tree_is_refused() -> TestResult {
    let patch_dir = repo();
    let patch = diff_of(patch_dir.path(), "f.txt", Some(CHANGED));
    let plain = tempfile::tempdir()?;
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &patch)], plain.path()).await;
    assert!(refused(&result).contains("work tree"));
    assert!(!plain.path().join("f.txt").exists());
    let missing = plain.path().join("absent");
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &patch)], &missing).await;
    assert!(matches!(result, Err(CliError::Apply(_))), "{result:?}");
    let bare = tempfile::tempdir()?;
    git(bare.path(), &["init", "-q", "--bare"]);
    let (result, _, _) = apply(vec![accepted(1, "f.txt", &patch)], bare.path()).await;
    assert!(matches!(result, Err(CliError::Apply(_))), "{result:?}");
    Ok(())
}

#[tokio::test]
async fn a_patch_that_does_not_apply_is_refused_and_git_output_is_scrubbed() -> TestResult {
    let dir = repo();
    let patch = diff_of(dir.path(), "f.txt", Some(CHANGED));
    let gone = patch.replace("f.txt", TOKEN);
    let (result, _, _) = apply(vec![accepted(1, TOKEN, &gone)], dir.path()).await;
    let message = refused(&result);
    assert!(message.contains("does not apply"), "{message}");
    assert!(
        !message.contains(TOKEN) && !message.contains("client-tok"),
        "{message}"
    );
    assert!(clean(&message), "{message:?}");
    let long = patch.replace("f.txt", &"d".repeat(400));
    let (result, _, _) = apply(vec![accepted(1, &"d".repeat(400), &long)], dir.path()).await;
    assert!(refused(&result).len() < 2000);
    assert_eq!(git(dir.path(), &["status", "--porcelain"]), "");
    Ok(())
}
