//! `ImportWork` and `ExportWork`: dry-run by default, idempotent on (project, key), attempt
//! counts that only rise, unparsed lines reported, the hostile-input table, size caps, owner
//! scope, the project row lock before the first read and a byte-stable export round trip. The
//! tests call the handlers directly with a [`Caller`] extension and need a Postgres superuser URL
//! in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_proto::v1::fleet_work_server::FleetWork;
use fleet_proto::v1::{
    CreateWorkProjectRequest, ExportWorkReply, ExportWorkRequest, GetWorkItemRequest,
    ImportWorkReply, ImportWorkRequest, WorkItem,
};
use fleet_proto::{MAX_IMPORT_SLICES_BYTES, MAX_IMPORT_TASKS_BYTES, MAX_IMPORT_TEXT_BYTES};
use fleet_server::auth::Caller;
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::{Code, Request, Status};

const TASKS: &str = r#"[
  {"id":"a","title":"A","acceptance":"do a","slices":["core"],"depends":[],"why":"","passes":false,"fails":0},
  {"id":"b","title":"B","acceptance":"do b","slices":["core"],"depends":["a"],"why":"needs a","passes":true,"fails":2}
]"#;
const SLICES: &str =
    r#"{"slices":{"core":{"role":"the core","paths":["src"]}},"mergeable":["README.md"]}"#;
const BACKLOG: &str =
    "# backlog\n- DEFER [a]: tidy the parser\n- DEFER [zz]: orphan note\nfree text\n";

struct World {
    svc: FleetService,
    pool: PgPool,
    alice: i64,
    bob: i64,
}

fn as_user<T>(user_id: i64, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request.extensions_mut().insert(Caller {
        user_id,
        is_admin: false,
    });
    request
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

async fn world(pool: PgPool) -> World {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let w = World {
        svc: FleetService::new(store),
        pool,
        alice,
        bob,
    };
    for name in ["p", "q"] {
        let request = CreateWorkProjectRequest {
            key: format!("create-{name}"),
            name: name.to_owned(),
            repo: None,
        };
        w.svc
            .create_work_project(as_user(alice, request))
            .await
            .unwrap();
    }
    w
}

fn request(project: &str, apply: bool, tasks: &str) -> ImportWorkRequest {
    ImportWorkRequest {
        project: project.to_owned(),
        apply,
        tasks_json: tasks.to_owned(),
        slices_json: SLICES.to_owned(),
        progress_md: String::new(),
        backlog_md: String::new(),
    }
}

impl World {
    async fn import(&self, req: ImportWorkRequest) -> Result<ImportWorkReply, Status> {
        self.svc
            .import_work(as_user(self.alice, req))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn export(&self, project: &str) -> Result<ExportWorkReply, Status> {
        self.svc
            .export_work(as_user(
                self.alice,
                ExportWorkRequest {
                    project: project.to_owned(),
                },
            ))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn item(&self, project: &str, key: &str) -> WorkItem {
        self.svc
            .get_work_item(as_user(
                self.alice,
                GetWorkItemRequest {
                    project: project.to_owned(),
                    item_key: key.to_owned(),
                },
            ))
            .await
            .unwrap()
            .into_inner()
            .item
            .unwrap()
    }

    async fn count(&self, table: &str) -> i64 {
        let sql: &'static str = match table {
            "work_item" => "SELECT count(*) FROM work_item",
            "work_dep" => "SELECT count(*) FROM work_dep",
            "work_slice" => "SELECT count(*) FROM work_slice",
            "work_item_slice" => "SELECT count(*) FROM work_item_slice",
            "work_mergeable_path" => "SELECT count(*) FROM work_mergeable_path",
            "work_attempt" => "SELECT count(*) FROM work_attempt",
            "work_event" => "SELECT count(*) FROM work_event",
            "work_defer" => "SELECT count(*) FROM work_defer",
            _ => unreachable!(),
        };
        sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
    }

    async fn totals(&self) -> Vec<i64> {
        let mut out = Vec::new();
        for table in [
            "work_item",
            "work_dep",
            "work_slice",
            "work_item_slice",
            "work_mergeable_path",
            "work_attempt",
            "work_event",
            "work_defer",
        ] {
            out.push(self.count(table).await);
        }
        out
    }
}

#[sqlx::test(migrations = false)]
async fn dry_run_is_the_default_and_writes_nothing(pool: PgPool) {
    let w = world(pool).await;
    let before = w.totals().await;
    let mut req = request("p", false, TASKS);
    req.backlog_md = BACKLOG.to_owned();
    let reply = w.import(req).await.unwrap();
    assert!(!reply.applied);
    assert_eq!(reply.items_created, 2);
    assert_eq!(reply.slices_created, 1);
    assert_eq!(reply.mergeable_created, 1);
    assert_eq!(reply.defers_created, 2);
    assert_eq!(w.totals().await, before);
    let default = ImportWorkRequest::default();
    assert!(!default.apply);
}

#[sqlx::test(migrations = false)]
async fn apply_writes_items_edges_slices_attempts_and_defers(pool: PgPool) {
    let w = world(pool).await;
    let mut req = request("p", true, TASKS);
    req.backlog_md = BACKLOG.to_owned();
    let reply = w.import(req).await.unwrap();
    assert!(reply.applied);
    assert_eq!(
        (
            reply.items_created,
            reply.items_unchanged,
            reply.items_raised
        ),
        (2, 0, 0)
    );
    assert_eq!(w.count("work_item").await, 2);
    assert_eq!(w.count("work_dep").await, 1);
    assert_eq!(w.count("work_defer").await, 2);
    assert_eq!(w.count("work_mergeable_path").await, 1);
    let role: String = sqlx::query_scalar("SELECT role FROM work_slice WHERE name = 'core'")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(role, "the core");
    let b = w.item("p", "b").await;
    assert_eq!((b.passes, b.fails), (1, 2));
    assert_eq!(b.deps[0].depends_on, "a");
    assert_eq!(b.deps[0].why, "needs a");
    let a = w.item("p", "a").await;
    assert_eq!((a.passes, a.fails), (0, 0));
    let imported: i64 =
        sqlx::query_scalar("SELECT count(*) FROM work_event WHERE kind = 'imported'")
            .fetch_one(&w.pool)
            .await
            .unwrap();
    assert_eq!(imported, 2);
}

#[sqlx::test(migrations = false)]
async fn a_second_import_changes_nothing(pool: PgPool) {
    let w = world(pool).await;
    let mut req = request("p", true, TASKS);
    req.backlog_md = BACKLOG.to_owned();
    w.import(req.clone()).await.unwrap();
    let after_first = w.totals().await;
    let again = w.import(req).await.unwrap();
    assert_eq!(
        (
            again.items_created,
            again.items_unchanged,
            again.items_raised,
            again.items_differing,
            again.slices_created,
            again.mergeable_created,
            again.defers_created
        ),
        (0, 2, 0, 0, 0, 0, 0)
    );
    assert_eq!(w.totals().await, after_first);
}

#[sqlx::test(migrations = false)]
async fn passes_and_fails_never_regress_and_only_rise(pool: PgPool) {
    let w = world(pool).await;
    w.import(request("p", true, TASKS)).await.unwrap();
    let lower = TASKS.replace(r#""passes":true,"fails":2"#, r#""passes":false,"fails":0"#);
    let reply = w.import(request("p", true, &lower)).await.unwrap();
    assert_eq!((reply.items_raised, reply.items_unchanged), (0, 2));
    let b = w.item("p", "b").await;
    assert_eq!((b.passes, b.fails), (1, 2));
    let higher = TASKS.replace(r#""fails":2"#, r#""fails":5"#).replace(
        r#""id":"a","title":"A","acceptance":"do a","slices":["core"],"depends":[],"why":"","passes":false"#,
        r#""id":"a","title":"A","acceptance":"do a","slices":["core"],"depends":[],"why":"","passes":true"#,
    );
    let reply = w.import(request("p", true, &higher)).await.unwrap();
    assert_eq!(reply.items_raised, 2);
    let (a, b) = (w.item("p", "a").await, w.item("p", "b").await);
    assert_eq!((a.passes, a.fails), (1, 0));
    assert_eq!((b.passes, b.fails), (1, 5));
}

#[sqlx::test(migrations = false)]
async fn a_dry_run_reports_a_raise_without_writing_it(pool: PgPool) {
    let w = world(pool).await;
    w.import(request("p", true, TASKS)).await.unwrap();
    let higher = TASKS.replace(r#""fails":2"#, r#""fails":5"#);
    let reply = w.import(request("p", false, &higher)).await.unwrap();
    assert_eq!(reply.items_raised, 1);
    assert_eq!(w.item("p", "b").await.fails, 2);
}

#[sqlx::test(migrations = false)]
async fn the_server_copy_wins_for_existing_content(pool: PgPool) {
    let w = world(pool).await;
    w.import(request("p", true, TASKS)).await.unwrap();
    let changed = TASKS.replace(r#""title":"A""#, r#""title":"A renamed""#);
    let reply = w.import(request("p", true, &changed)).await.unwrap();
    assert_eq!((reply.items_differing, reply.items_unchanged), (1, 1));
    assert!(
        reply.notes.iter().any(|n| n.starts_with("a: differs")),
        "{:?}",
        reply.notes
    );
    assert_eq!(w.item("p", "a").await.title, "A");
}

#[sqlx::test(migrations = false)]
async fn unparsed_lines_are_returned_with_file_and_line_and_capped(pool: PgPool) {
    let w = world(pool).await;
    let mut req = request("p", false, TASKS);
    req.progress_md = "first\n\nsecond\n".to_owned();
    req.backlog_md = BACKLOG.to_owned();
    let reply = w.import(req).await.unwrap();
    assert_eq!(
        reply.unparsed,
        [
            "progress.md:1: first",
            "progress.md:3: second",
            "docs-backlog.md:1: # backlog",
            "docs-backlog.md:4: free text",
        ]
    );
    assert_eq!(reply.unparsed_dropped, 0);
    let mut over = request("p", false, TASKS);
    over.progress_md = numbered(101);
    let reply = w.import(over).await.unwrap();
    assert_eq!(reply.unparsed.len(), 100);
    assert_eq!(reply.unparsed_dropped, 1);
    let mut edge = request("p", false, TASKS);
    edge.progress_md = numbered(100);
    let reply = w.import(edge).await.unwrap();
    assert_eq!((reply.unparsed.len(), reply.unparsed_dropped), (100, 0));
}

#[sqlx::test(migrations = false)]
async fn unparsed_lines_are_redacted_and_cut(pool: PgPool) {
    let w = world(pool).await;
    let mut req = request("p", false, TASKS);
    req.progress_md = format!("{}\nbad\u{1b}[31m\u{202e}line\n", "x".repeat(500));
    let reply = w.import(req).await.unwrap();
    assert!(
        reply.unparsed[0].chars().count() <= 200,
        "{}",
        reply.unparsed[0].len()
    );
    for line in &reply.unparsed {
        assert!(
            !line.chars().any(|c| c.is_control() || c == '\u{202e}'),
            "{line:?}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn a_defer_line_creates_one_defer_and_a_reimport_adds_none(pool: PgPool) {
    let w = world(pool).await;
    let mut req = request("p", true, TASKS);
    req.backlog_md = "- DEFER [a]: tidy the parser\n- DEFER [a]: tidy the parser\n".to_owned();
    let first = w.import(req.clone()).await.unwrap();
    assert_eq!(first.defers_created, 1);
    assert_eq!(w.import(req).await.unwrap().defers_created, 0);
    assert_eq!(w.count("work_defer").await, 1);
    let vertical: String = sqlx::query_scalar("SELECT vertical FROM work_defer")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(vertical, "ralph");
}

fn numbered(count: usize) -> String {
    let lines: Vec<String> = (0..count).map(|i| format!("line {i}")).collect();
    format!("{}\n", lines.join("\n"))
}

fn hostile_cases() -> Vec<(&'static str, String, String)> {
    let mut cases = hostile_task_cases();
    cases.extend(hostile_slice_cases());
    cases
}

fn hostile_task_cases() -> Vec<(&'static str, String, String)> {
    let task = |extra: &str| {
        format!(r#"[{{"id":"a","title":"A","slices":["core"],{extra}"passes":false}}]"#)
    };
    let title = |t: &str| format!(r#"[{{"id":"a","title":"{t}","slices":["core"]}}]"#);
    let deep = format!("{}1{}", "[".repeat(40), "]".repeat(40));
    vec![
        ("duplicate key", task(r#""title":"B","#), SLICES.to_owned()),
        (
            "duplicate nested key",
            r#"[{"id":"a","title":"A","slices":["core"],"x":{"k":1,"k":2}}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        ("too deep", deep, SLICES.to_owned()),
        ("cr in title", title(r"x\ry"), SLICES.to_owned()),
        ("crlf in title", title(r"x\r\ny"), SLICES.to_owned()),
        ("lf in title", title(r"x\ny"), SLICES.to_owned()),
        ("nel in title", title(r"x\u0085y"), SLICES.to_owned()),
        ("line separator in title", title(r"x\u2028y"), SLICES.to_owned()),
        ("bidi in title", title(r"x\u202ey"), SLICES.to_owned()),
        ("nul in title", title(r"x\u0000y"), SLICES.to_owned()),
        ("escape in title", title(r"x\u001b[31my"), SLICES.to_owned()),
        ("empty title", title(""), SLICES.to_owned()),
        ("over-long title", title(&"t".repeat(201)), SLICES.to_owned()),
        (
            "id with space",
            r#"[{"id":"a b","title":"A","slices":["core"]}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "over-long id",
            format!(r#"[{{"id":"{}","title":"A","slices":["core"]}}]"#, "i".repeat(129)),
            SLICES.to_owned(),
        ),
        (
            "empty id",
            r#"[{"id":"","title":"A","slices":["core"]}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "non-ascii id",
            r#"[{"id":"é","title":"A","slices":["core"]}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "unknown dependency",
            r#"[{"id":"a","title":"A","slices":["core"],"depends":["ghost"],"why":"w"}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "self dependency",
            r#"[{"id":"a","title":"A","slices":["core"],"depends":["a"],"why":"w"}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "cycle",
            r#"[{"id":"a","title":"A","slices":["core"],"depends":["b"],"why":"w"},{"id":"b","title":"B","slices":["core"],"depends":["a"],"why":"w"}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "duplicate id",
            r#"[{"id":"a","title":"A","slices":["core"]},{"id":"a","title":"B","slices":["core"]}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "unknown slice",
            r#"[{"id":"a","title":"A","slices":["nope"]}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        ("not an array", r#"{"id":"a"}"#.to_owned(), SLICES.to_owned()),
        ("trailing garbage", format!("{TASKS} x"), SLICES.to_owned()),
        ("bom", format!("\u{feff}{TASKS}"), SLICES.to_owned()),
        ("empty document", String::new(), SLICES.to_owned()),
        (
            "negative fails",
            r#"[{"id":"a","title":"A","slices":["core"],"fails":-1}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "fails over the cap",
            r#"[{"id":"a","title":"A","slices":["core"],"fails":101}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "passes as string",
            r#"[{"id":"a","title":"A","slices":["core"],"passes":"true"}]"#.to_owned(),
            SLICES.to_owned(),
        ),
        (
            "slices as string",
            r#"[{"id":"a","title":"A","slices":"core"}]"#.to_owned(),
            SLICES.to_owned(),
        ),
    ]
}

fn hostile_slice_cases() -> Vec<(&'static str, String, String)> {
    vec![
        (
            "traversal path",
            TASKS.to_owned(),
            r#"{"slices":{"core":{"paths":["../etc"]}}}"#.to_owned(),
        ),
        (
            "absolute path",
            TASKS.to_owned(),
            r#"{"slices":{"core":{"paths":["/etc"]}}}"#.to_owned(),
        ),
        (
            "backslash path",
            TASKS.to_owned(),
            r#"{"slices":{"core":{"paths":["a\\b"]}}}"#.to_owned(),
        ),
        (
            "overlapping slices",
            TASKS.to_owned(),
            r#"{"slices":{"core":{"paths":["src"]},"other":{"paths":["src/x"]}}}"#.to_owned(),
        ),
        (
            "slice name with newline",
            TASKS.to_owned(),
            r#"{"slices":{"co\nre":{"paths":["src"]}}}"#.to_owned(),
        ),
        (
            "role with newline",
            TASKS.to_owned(),
            r#"{"slices":{"core":{"role":"x\ny","paths":["src"]}}}"#.to_owned(),
        ),
        (
            "duplicate slice key",
            TASKS.to_owned(),
            r#"{"slices":{"core":{"paths":["src"]},"core":{"paths":["src"]}}}"#.to_owned(),
        ),
        (
            "malformed slices json",
            TASKS.to_owned(),
            r#"{"slices":"#.to_owned(),
        ),
    ]
}

#[sqlx::test(migrations = false)]
async fn hostile_input_is_refused_with_a_fixed_message_and_writes_nothing(pool: PgPool) {
    let w = world(pool).await;
    let before = w.totals().await;
    for (name, tasks, slices) in hostile_cases() {
        for apply in [false, true] {
            let mut req = request("p", apply, &tasks);
            req.slices_json = slices.clone();
            let Err(err) = w.import(req).await else {
                panic!("{name} was accepted, apply {apply}");
            };
            assert!(
                matches!(err.code(), Code::InvalidArgument | Code::FailedPrecondition),
                "{name}: {err:?}"
            );
            assert!(
                !err.message()
                    .chars()
                    .any(|c| c.is_control() || c == '\u{202e}'),
                "{name}: {}",
                err.message()
            );
            assert!(
                err.message().chars().count() < 100,
                "{name}: {}",
                err.message()
            );
            assert_eq!(w.totals().await, before, "{name}");
        }
    }
}

#[sqlx::test(migrations = false)]
async fn every_size_cap_refuses_one_byte_over_and_accepts_the_cap(pool: PgPool) {
    let w = world(pool).await;
    let pad = |base: &str, len: usize| format!("{base}{}", " ".repeat(len - base.len()));
    let mut over = request("p", false, &pad("[]", MAX_IMPORT_TASKS_BYTES + 1));
    over.slices_json = String::new();
    assert_eq!(
        w.import(over).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut edge = request("p", false, &pad("[]", MAX_IMPORT_TASKS_BYTES));
    edge.slices_json = String::new();
    w.import(edge).await.unwrap();
    let mut over = request("p", false, "[]");
    over.slices_json = pad("{}", MAX_IMPORT_SLICES_BYTES + 1);
    assert_eq!(
        w.import(over).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut edge = request("p", false, "[]");
    edge.slices_json = pad("{}", MAX_IMPORT_SLICES_BYTES);
    w.import(edge).await.unwrap();
    for backlog in [false, true] {
        let text = |len: usize| " ".repeat(len);
        let mut over = request("p", false, "[]");
        let mut edge = request("p", false, "[]");
        if backlog {
            over.backlog_md = text(MAX_IMPORT_TEXT_BYTES + 1);
            edge.backlog_md = text(MAX_IMPORT_TEXT_BYTES);
        } else {
            over.progress_md = text(MAX_IMPORT_TEXT_BYTES + 1);
            edge.progress_md = text(MAX_IMPORT_TEXT_BYTES);
        }
        assert_eq!(
            w.import(over).await.unwrap_err().code(),
            Code::InvalidArgument
        );
        w.import(edge).await.unwrap();
    }
}

#[sqlx::test(migrations = false)]
async fn too_many_lines_are_refused(pool: PgPool) {
    let w = world(pool).await;
    let mut over = request("p", false, "[]");
    over.progress_md = "\n".repeat(50_001);
    assert_eq!(
        w.import(over).await.unwrap_err().code(),
        Code::InvalidArgument
    );
    let mut edge = request("p", false, "[]");
    edge.progress_md = "\n".repeat(50_000);
    w.import(edge).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn another_users_project_looks_like_a_missing_one(pool: PgPool) {
    let w = world(pool).await;
    let as_bob = |apply| as_user(w.bob, request("p", apply, TASKS));
    let missing = as_user(w.bob, request("nope", false, TASKS));
    let a = w.svc.import_work(as_bob(false)).await.unwrap_err();
    let b = w.svc.import_work(missing).await.unwrap_err();
    assert_eq!((a.code(), a.message()), (b.code(), b.message()));
    assert_eq!(a.code(), Code::NotFound);
    let applied = w.svc.import_work(as_bob(true)).await.unwrap_err();
    assert_eq!(applied.code(), Code::NotFound);
    assert_eq!(w.count("work_item").await, 0);
    let export = |project: &str| {
        as_user(
            w.bob,
            ExportWorkRequest {
                project: project.to_owned(),
            },
        )
    };
    let a = w.svc.export_work(export("p")).await.unwrap_err();
    let b = w.svc.export_work(export("nope")).await.unwrap_err();
    assert_eq!((a.code(), a.message()), (b.code(), b.message()));
    assert_eq!(a.code(), Code::NotFound);
}

#[sqlx::test(migrations = false)]
async fn import_takes_the_project_lock_before_it_reads(pool: PgPool) {
    let w = world(pool).await;
    let mut tx = w.pool.begin().await.unwrap();
    let project: i64 =
        sqlx::query_scalar("SELECT id FROM work_project WHERE name = 'p' FOR NO KEY UPDATE")
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    let svc = w.svc.clone();
    let alice = w.alice;
    let run = tokio::spawn(async move {
        svc.import_work(as_user(alice, request("p", true, TASKS)))
            .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!run.is_finished());
    sqlx::query("INSERT INTO work_item (project_id, key, title) VALUES ($1, 'a', 'rival')")
        .bind(project)
        .execute(&mut *tx)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_inner();
    assert_eq!(reply.items_created, 1);
    assert_eq!(reply.items_differing, 1);
    assert_eq!(w.item("p", "a").await.title, "rival");
    assert_eq!(w.item("p", "b").await.deps.len(), 1);
}

#[sqlx::test(migrations = false)]
async fn a_dry_run_also_waits_for_the_project_lock(pool: PgPool) {
    let w = world(pool).await;
    let mut tx = w.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM work_project WHERE name = 'p' FOR NO KEY UPDATE")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let svc = w.svc.clone();
    let alice = w.alice;
    let run = tokio::spawn(async move {
        svc.import_work(as_user(alice, request("p", false, TASKS)))
            .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!run.is_finished());
    tx.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), run)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn export_is_byte_stable_through_the_real_parser(pool: PgPool) {
    let w = world(pool).await;
    w.import(request("p", true, TASKS)).await.unwrap();
    let first = w.export("p").await.unwrap();
    assert!(first.tasks_json.ends_with('\n') && first.slices_json.ends_with('\n'));
    let mut again = request("q", true, &first.tasks_json);
    again.slices_json = first.slices_json.clone();
    let reply = w.import(again).await.unwrap();
    assert_eq!(reply.items_created, 2);
    let second = w.export("q").await.unwrap();
    assert_eq!(first.tasks_json, second.tasks_json);
    assert_eq!(first.slices_json, second.slices_json);
    let mut same = request("p", false, &first.tasks_json);
    same.slices_json = first.slices_json.clone();
    let reply = w.import(same).await.unwrap();
    assert_eq!(
        (
            reply.items_created,
            reply.items_unchanged,
            reply.items_raised
        ),
        (0, 2, 0)
    );
}

#[sqlx::test(migrations = false)]
async fn export_carries_edges_attempts_roles_and_blocked_state(pool: PgPool) {
    let w = world(pool).await;
    w.import(request("p", true, TASKS)).await.unwrap();
    sqlx::query("UPDATE work_item SET state = 'blocked' WHERE key = 'a'")
        .execute(&w.pool)
        .await
        .unwrap();
    let out = w.export("p").await.unwrap();
    assert!(
        out.tasks_json.contains(r#""blocked": true"#),
        "{}",
        out.tasks_json
    );
    assert!(
        out.tasks_json.contains(r#""why": "needs a""#),
        "{}",
        out.tasks_json
    );
    assert!(
        out.tasks_json.contains(r#""fails": 2"#),
        "{}",
        out.tasks_json
    );
    assert!(
        out.tasks_json.contains(r#""passes": true"#),
        "{}",
        out.tasks_json
    );
    assert!(
        out.slices_json.contains(r#""role": "the core""#),
        "{}",
        out.slices_json
    );
    assert!(out.slices_json.contains("README.md"), "{}", out.slices_json);
}

#[sqlx::test(migrations = false)]
async fn export_of_an_empty_project_parses_back(pool: PgPool) {
    let w = world(pool).await;
    let out = w.export("p").await.unwrap();
    let mut req = request("q", true, &out.tasks_json);
    req.slices_json = out.slices_json.clone();
    let reply = w.import(req).await.unwrap();
    assert_eq!(reply.items_created, 0);
}
