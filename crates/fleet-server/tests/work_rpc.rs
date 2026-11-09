//! `FleetWork` project, slice, item and dependency RPCs: owner scope, graph checks, idempotency
//! keys and the project row lock. The tests call the handlers directly with a [`Caller`]
//! extension. They need a Postgres superuser URL in `DATABASE_URL`, which `#[sqlx::test]`
//! reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_proto::v1::fleet_work_server::FleetWork;
use fleet_proto::v1::{
    AddWorkDepRequest, AddWorkItemRequest, CancelWorkRequest, ClaimWorkRequest,
    CreateWorkProjectRequest, GetWorkItemRequest, ListWorkItemsRequest, ListWorkProjectsRequest,
    NextWorkRequest, RemoveWorkDepRequest, SetWorkSlicesRequest, UnblockWorkRequest, WorkDep,
    WorkItem, WorkItemState, WorkProject, WorkSlice,
};
use fleet_server::auth::Caller;
use fleet_server::service::FleetService;
use fleet_server::store::Store;
use sqlx::PgPool;
use tonic::{Code, Request, Status};

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
    World {
        svc: FleetService::new(store),
        pool,
        alice,
        bob,
    }
}

fn slice(name: &str, paths: &[&str]) -> WorkSlice {
    WorkSlice {
        name: name.to_owned(),
        paths: paths.iter().map(|p| (*p).to_owned()).collect(),
    }
}

impl World {
    async fn project(&self, user: i64, key: &str, name: &str) -> Result<WorkProject, Status> {
        let request = CreateWorkProjectRequest {
            key: key.to_owned(),
            name: name.to_owned(),
            repo: None,
        };
        self.svc
            .create_work_project(as_user(user, request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn slices(
        &self,
        user: i64,
        key: &str,
        project: &str,
        slices: Vec<WorkSlice>,
        mergeable: &[&str],
    ) -> Result<WorkProject, Status> {
        let request = SetWorkSlicesRequest {
            key: key.to_owned(),
            project: project.to_owned(),
            slices,
            mergeable: mergeable.iter().map(|p| (*p).to_owned()).collect(),
        };
        self.svc
            .set_work_slices(as_user(user, request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn item(
        &self,
        user: i64,
        key: &str,
        item_key: &str,
        slices: &[&str],
        deps: &[&str],
    ) -> Result<WorkItem, Status> {
        let request = AddWorkItemRequest {
            key: key.to_owned(),
            project: "p".to_owned(),
            item_key: item_key.to_owned(),
            title: format!("title {item_key}"),
            body: String::new(),
            slices: slices.iter().map(|s| (*s).to_owned()).collect(),
            deps: deps
                .iter()
                .map(|d| WorkDep {
                    depends_on: (*d).to_owned(),
                    why: "needs it".to_owned(),
                })
                .collect(),
        };
        self.svc
            .add_work_item(as_user(user, request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn dep(&self, key: &str, item: &str, on: &str) -> Result<WorkItem, Status> {
        let request = AddWorkDepRequest {
            key: key.to_owned(),
            project: "p".to_owned(),
            item_key: item.to_owned(),
            dep: Some(WorkDep {
                depends_on: on.to_owned(),
                why: "because".to_owned(),
            }),
        };
        self.svc
            .add_work_dep(as_user(self.alice, request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn list(&self, ready_only: bool) -> Vec<WorkItem> {
        let request = ListWorkItemsRequest {
            project: "p".to_owned(),
            state: None,
            ready_only,
        };
        self.svc
            .list_work_items(as_user(self.alice, request))
            .await
            .unwrap()
            .into_inner()
            .items
    }

    async fn count(&self, table: &str) -> i64 {
        let sql = match table {
            "work_project" => "SELECT count(*) FROM work_project",
            "work_item" => "SELECT count(*) FROM work_item",
            "work_dep" => "SELECT count(*) FROM work_dep",
            "work_slice" => "SELECT count(*) FROM work_slice",
            "work_event" => "SELECT count(*) FROM work_event",
            "work_request_key" => "SELECT count(*) FROM work_request_key",
            "work_slice_lease" => "SELECT count(*) FROM work_slice_lease",
            _ => unreachable!("unknown table {table}"),
        };
        sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
    }

    async fn attempt(&self, item_key: &str, verdict: Option<&str>) -> i64 {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO work_attempt (project_id, item_id, holder, expires_at, verdict, closed_at) \
             SELECT project_id, id, 'h', now() + interval '1 hour', $2::text, \
             CASE WHEN $2::text IS NULL THEN NULL ELSE now() END \
             FROM work_item WHERE key = $1 RETURNING id",
        )
        .bind(item_key)
        .bind(verdict)
        .fetch_one(&self.pool)
        .await
        .unwrap();
        id
    }

    async fn lease(&self, slice_name: &str, attempt: i64) {
        sqlx::query(
            "INSERT INTO work_slice_lease (slice_id, project_id, attempt_id) \
             SELECT s.id, s.project_id, $2 FROM work_slice s WHERE s.name = $1",
        )
        .bind(slice_name)
        .bind(attempt)
        .execute(&self.pool)
        .await
        .unwrap();
    }
}

#[track_caller]
fn code<T>(result: Result<T, Status>) -> (Code, String) {
    let status = result.err().unwrap();
    (status.code(), status.message().to_owned())
}

#[sqlx::test(migrations = false)]
async fn create_project_retry_conflict_and_name(pool: PgPool) {
    let w = world(pool).await;
    let first = w.project(w.alice, "k1", "p").await.unwrap();
    assert_eq!(w.project(w.alice, "k1", "p").await.unwrap(), first);
    assert_eq!(w.count("work_project").await, 1);
    assert_eq!(
        code(w.project(w.alice, "k1", "other").await).0,
        Code::AlreadyExists
    );
    assert_eq!(
        code(w.project(w.alice, "k2", "p").await).0,
        Code::AlreadyExists
    );
    w.project(w.bob, "k1", "p").await.unwrap();
    assert_eq!(w.count("work_project").await, 2);
}

#[sqlx::test(migrations = false)]
async fn repo_must_be_registered_and_owned(pool: PgPool) {
    let w = world(pool).await;
    let with_repo = |key: &str, name: &str| CreateWorkProjectRequest {
        key: key.to_owned(),
        name: name.to_owned(),
        repo: Some("https://example.com/org/repo.git".to_owned()),
    };
    let denied = w
        .svc
        .create_work_project(as_user(w.alice, with_repo("a", "r")))
        .await;
    assert_eq!(code(denied).0, Code::FailedPrecondition);
    sqlx::query(
        "INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, 'example.com', 'org/repo', 'github')",
    )
    .bind(w.bob)
    .execute(&w.pool)
    .await
    .unwrap();
    let foreign = w
        .svc
        .create_work_project(as_user(w.alice, with_repo("b", "r")))
        .await;
    assert_eq!(code(foreign).0, Code::FailedPrecondition);
    assert_eq!(w.count("work_project").await, 0);
    let ok = w
        .svc
        .create_work_project(as_user(w.bob, with_repo("c", "r")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(ok.repo.as_deref(), Some("example.com/org/repo"));
}

#[sqlx::test(migrations = false)]
async fn owner_scope_hides_projects(pool: PgPool) {
    let w = world(pool).await;
    w.project(w.alice, "k", "p").await.unwrap();
    w.slices(w.alice, "s", "p", vec![slice("a", &["src"])], &[])
        .await
        .unwrap();
    w.item(w.alice, "i", "one", &["a"], &[]).await.unwrap();
    let before = (
        w.count("work_item").await,
        w.count("work_dep").await,
        w.count("work_slice").await,
        w.count("work_event").await,
        w.count("work_request_key").await,
    );
    let miss = (Code::NotFound, "work project not found".to_owned());
    for who in [w.bob, w.alice] {
        let project = if who == w.bob { "p" } else { "ghost" };
        let svc = &w.svc;
        let results = [
            code(
                svc.set_work_slices(as_user(
                    who,
                    SetWorkSlicesRequest {
                        key: "x1".into(),
                        project: project.into(),
                        slices: vec![],
                        mergeable: vec![],
                    },
                ))
                .await,
            ),
            code(
                svc.add_work_item(as_user(
                    who,
                    AddWorkItemRequest {
                        key: "x2".into(),
                        project: project.into(),
                        item_key: "z".into(),
                        title: "t".into(),
                        ..Default::default()
                    },
                ))
                .await,
            ),
            code(
                svc.list_work_items(as_user(
                    who,
                    ListWorkItemsRequest {
                        project: project.into(),
                        ..Default::default()
                    },
                ))
                .await,
            ),
            code(
                svc.get_work_item(as_user(
                    who,
                    GetWorkItemRequest {
                        project: project.into(),
                        item_key: "one".into(),
                    },
                ))
                .await,
            ),
            code(
                svc.add_work_dep(as_user(
                    who,
                    AddWorkDepRequest {
                        key: "x3".into(),
                        project: project.into(),
                        item_key: "one".into(),
                        dep: Some(WorkDep {
                            depends_on: "one".into(),
                            why: "w".into(),
                        }),
                    },
                ))
                .await,
            ),
            code(
                svc.remove_work_dep(as_user(
                    who,
                    RemoveWorkDepRequest {
                        key: "x4".into(),
                        project: project.into(),
                        item_key: "one".into(),
                        depends_on: "two".into(),
                    },
                ))
                .await,
            ),
            code(
                svc.cancel_work(as_user(
                    who,
                    CancelWorkRequest {
                        key: "x5".into(),
                        project: project.into(),
                        item_key: "one".into(),
                        reason: "r".into(),
                    },
                ))
                .await,
            ),
            code(
                svc.unblock_work(as_user(
                    who,
                    UnblockWorkRequest {
                        key: "x6".into(),
                        project: project.into(),
                        item_key: "one".into(),
                        reason: "r".into(),
                    },
                ))
                .await,
            ),
        ];
        for result in results {
            assert_eq!(result, miss);
        }
    }
    let listed = w
        .svc
        .list_work_projects(as_user(w.bob, ListWorkProjectsRequest {}))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(listed.projects, []);
    let after = (
        w.count("work_item").await,
        w.count("work_dep").await,
        w.count("work_slice").await,
        w.count("work_event").await,
        w.count("work_request_key").await,
    );
    assert_eq!(before, after);
}

#[sqlx::test(migrations = false)]
async fn slice_checks(pool: PgPool) {
    let w = world(pool).await;
    w.project(w.alice, "k", "p").await.unwrap();
    let set = |key: &'static str, slices: Vec<WorkSlice>, merge: &'static [&'static str]| {
        w.slices(w.alice, key, "p", slices, merge)
    };
    let ok = set(
        "s1",
        vec![slice("a", &["src/x/"]), slice("b", &["docs"])],
        &["Cargo.lock"],
    )
    .await
    .unwrap();
    assert_eq!(ok.slices[0].paths, vec!["src/x".to_owned()]);
    let id_a: i64 = sqlx::query_scalar("SELECT id FROM work_slice WHERE name = 'a'")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    let refused = [
        set(
            "s2",
            vec![slice("a", &["src"]), slice("b", &["src/x"])],
            &[],
        )
        .await,
        set("s3", vec![slice("a", &["src"])], &["src/lock"]).await,
        set("s4", vec![slice("a", &["src", "src/y"])], &[]).await,
        set("s5", vec![slice("a", &["../x"])], &[]).await,
        set("s6", vec![slice("a", &["x"]), slice("a", &["y"])], &[]).await,
    ];
    for result in refused {
        assert_eq!(result.err().unwrap().code(), Code::InvalidArgument);
    }
    let kept = set("s7", vec![slice("a", &["lib"])], &[]).await.unwrap();
    assert_eq!(kept.slices.len(), 1);
    let id_after: i64 = sqlx::query_scalar("SELECT id FROM work_slice WHERE name = 'a'")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(id_a, id_after);
    assert_eq!(w.count("work_slice").await, 1);

    w.item(w.alice, "i", "one", &["a"], &[]).await.unwrap();
    let dropped = set("s8", vec![slice("c", &["c"])], &[]).await;
    assert_eq!(dropped.err().unwrap().code(), Code::InvalidArgument);
    let attempt = w.attempt("one", None).await;
    w.lease("a", attempt).await;
    let leased = set("s9", vec![slice("a", &["other"])], &[]).await;
    assert_eq!(
        code(leased),
        (Code::FailedPrecondition, "slice is leased".to_owned())
    );
    let same = set("s10", vec![slice("a", &["lib"])], &[]).await.unwrap();
    assert_eq!(same.slices[0].paths, vec!["lib".to_owned()]);
    assert_eq!(
        set("s10", vec![slice("a", &["lib"])], &[]).await.unwrap(),
        same
    );
}

#[sqlx::test(migrations = false)]
async fn items_deps_and_ready(pool: PgPool) {
    let w = world(pool).await;
    w.project(w.alice, "k", "p").await.unwrap();
    w.slices(
        w.alice,
        "s",
        "p",
        vec![slice("a", &["a"]), slice("b", &["b"])],
        &[],
    )
    .await
    .unwrap();
    let one = w.item(w.alice, "i1", "one", &["a"], &[]).await.unwrap();
    assert!(one.ready && !one.held);
    let two = w
        .item(w.alice, "i2", "two", &["b"], &["one"])
        .await
        .unwrap();
    assert!(!two.ready);
    assert_eq!(two.deps[0].why, "needs it");
    assert_eq!(
        code(w.item(w.alice, "i3", "one", &[], &[]).await).0,
        Code::AlreadyExists
    );
    assert_eq!(
        code(w.item(w.alice, "i4", "x", &["zz"], &[]).await).0,
        Code::InvalidArgument
    );
    assert_eq!(
        code(w.item(w.alice, "i5", "x", &[], &["nope"]).await).0,
        Code::InvalidArgument
    );
    assert_eq!(w.count("work_item").await, 2);
    assert_eq!(
        w.item(w.alice, "i1", "one", &["a"], &[]).await.unwrap(),
        one
    );
    assert_eq!(
        code(w.item(w.alice, "i1", "other", &[], &[]).await).0,
        Code::AlreadyExists
    );
    assert_eq!(
        code(w.slices(w.alice, "i1", "p", vec![], &[]).await).0,
        Code::AlreadyExists
    );

    let held = w.attempt("one", None).await;
    let listed = w.list(false).await;
    assert!(listed.iter().find(|i| i.key == "one").unwrap().held);
    assert_eq!(w.list(true).await, []);
    sqlx::query("UPDATE work_attempt SET verdict = 'pass', closed_at = now() WHERE id = $1")
        .bind(held)
        .execute(&w.pool)
        .await
        .unwrap();
    let ready: Vec<String> = w.list(true).await.into_iter().map(|i| i.key).collect();
    assert_eq!(ready, vec!["two".to_owned()]);
    let passed = w.list(false).await;
    assert_eq!(passed.iter().find(|i| i.key == "one").unwrap().passes, 1);

    let detail = w
        .svc
        .get_work_item(as_user(
            w.alice,
            GetWorkItemRequest {
                project: "p".into(),
                item_key: "one".into(),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(detail.attempts.len(), 1);
    assert_eq!(detail.events.len(), 1);
}

#[sqlx::test(migrations = false)]
async fn dep_graph_rules(pool: PgPool) {
    let w = world(pool).await;
    w.project(w.alice, "k", "p").await.unwrap();
    for (n, key) in ["a", "b", "c"].into_iter().enumerate() {
        w.item(w.alice, &format!("i{n}"), key, &[], &[])
            .await
            .unwrap();
    }
    w.dep("d1", "b", "a").await.unwrap();
    w.dep("d2", "c", "b").await.unwrap();
    assert_eq!(
        code(w.dep("d3", "a", "c").await).0,
        Code::FailedPrecondition
    );
    assert_eq!(
        code(w.dep("d4", "a", "a").await).0,
        Code::FailedPrecondition
    );
    assert_eq!(code(w.dep("d5", "b", "a").await).0, Code::AlreadyExists);
    assert_eq!(code(w.dep("d6", "a", "ghost").await).0, Code::NotFound);
    assert_eq!(w.count("work_dep").await, 2);
    let remove = |key: &str, on: &str| RemoveWorkDepRequest {
        key: key.into(),
        project: "p".into(),
        item_key: "b".into(),
        depends_on: on.into(),
    };
    let gone = w
        .svc
        .remove_work_dep(as_user(w.alice, remove("r1", "a")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(gone.deps, []);
    let missing = w
        .svc
        .remove_work_dep(as_user(w.alice, remove("r2", "a")))
        .await;
    assert_eq!(code(missing).0, Code::NotFound);
    w.dep("d3", "a", "c").await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn hostile_input_table(pool: PgPool) {
    let w = world(pool).await;
    let bad_ident = [
        "",
        " ",
        "a b",
        "a\nb",
        "a\r\nb",
        "a\u{85}b",
        "a\u{2028}b",
        "a/\u{e9}",
        "a\u{0}b",
        "a\tb",
    ];
    for name in bad_ident
        .iter()
        .map(|s| (*s).to_owned())
        .chain([String::from_utf8(vec![b'a'; 129]).unwrap()])
    {
        if name != "a b" && name != "a/\u{e9}" {
            let made = w.project(w.alice, "k", &name).await;
            assert!(made.is_err(), "name {name:?} accepted");
            assert_eq!(code(made).0, Code::InvalidArgument, "name {name:?}");
        }
        assert_eq!(
            code(w.project(w.alice, &name, "p").await).0,
            Code::InvalidArgument,
            "key {name:?}"
        );
    }
    assert_eq!(w.count("work_project").await, 0);
    w.project(w.alice, "k", "p").await.unwrap();
    w.slices(w.alice, "s", "p", vec![slice("a", &["a"])], &[])
        .await
        .unwrap();
    for name in &bad_ident {
        assert_eq!(
            code(w.item(w.alice, "ik", name, &[], &[]).await).0,
            Code::InvalidArgument,
            "item {name:?}"
        );
        assert_eq!(
            code(
                w.slices(w.alice, "sk", "p", vec![slice(name, &["a"])], &[])
                    .await
            )
            .0,
            Code::InvalidArgument,
            "slice {name:?}"
        );
    }
    let hostile_line = [
        "",
        "   ",
        "a\nb",
        "a\rb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{202e}b",
        "a\u{1b}[0m",
    ];
    let long = "t".repeat(201);
    for text in hostile_line.iter().copied().chain([long.as_str()]) {
        let request = AddWorkItemRequest {
            key: "tk".into(),
            project: "p".into(),
            item_key: "t".into(),
            title: text.into(),
            ..Default::default()
        };
        assert_eq!(
            code(w.svc.add_work_item(as_user(w.alice, request)).await).0,
            Code::InvalidArgument,
            "title {text:?}"
        );
        let request = AddWorkItemRequest {
            key: "wk".into(),
            project: "p".into(),
            item_key: "t".into(),
            title: "ok".into(),
            deps: vec![WorkDep {
                depends_on: "x".into(),
                why: text.into(),
            }],
            ..Default::default()
        };
        assert_eq!(
            code(w.svc.add_work_item(as_user(w.alice, request)).await).0,
            Code::InvalidArgument,
            "why {text:?}"
        );
    }
    let big = "b".repeat(16385);
    for body in [
        "a\r\nb",
        "a\u{1b}[31mb",
        "a\u{85}b",
        "a\u{2028}b",
        "a\u{202e}b",
        big.as_str(),
    ] {
        let request = AddWorkItemRequest {
            key: "bk".into(),
            project: "p".into(),
            item_key: "t".into(),
            title: "ok".into(),
            body: body.into(),
            ..Default::default()
        };
        assert_eq!(
            code(w.svc.add_work_item(as_user(w.alice, request)).await).0,
            Code::InvalidArgument,
            "body {body:?}"
        );
    }
    let request = AddWorkItemRequest {
        key: "bk".into(),
        project: "p".into(),
        item_key: "t".into(),
        title: "ok".into(),
        body: "line one\nline two\n".into(),
        ..Default::default()
    };
    w.svc
        .add_work_item(as_user(w.alice, request))
        .await
        .unwrap();
    for reason in ["a\u{85}b", "a\u{2028}b", "a\u{1b}b", &"r".repeat(5000)] {
        let request = CancelWorkRequest {
            key: "ck".into(),
            project: "p".into(),
            item_key: "t".into(),
            reason: reason.into(),
        };
        assert_eq!(
            code(w.svc.cancel_work(as_user(w.alice, request)).await).0,
            Code::InvalidArgument,
            "reason {reason:?}"
        );
    }
    assert_eq!(w.count("work_item").await, 1);
}

#[sqlx::test(migrations = false)]
async fn cancel_and_unblock(pool: PgPool) {
    let w = world(pool).await;
    w.project(w.alice, "k", "p").await.unwrap();
    w.slices(w.alice, "s", "p", vec![slice("a", &["a"])], &[])
        .await
        .unwrap();
    w.item(w.alice, "i1", "one", &["a"], &[]).await.unwrap();
    let attempt = w.attempt("one", None).await;
    w.lease("a", attempt).await;
    let cancel = |key: &str| CancelWorkRequest {
        key: key.into(),
        project: "p".into(),
        item_key: "one".into(),
        reason: "obsolete".into(),
    };
    let unblock = |key: &str| UnblockWorkRequest {
        key: key.into(),
        project: "p".into(),
        item_key: "one".into(),
        reason: "retry".into(),
    };
    w.item(w.alice, "i2", "idle", &[], &[]).await.unwrap();
    let idle = UnblockWorkRequest {
        key: "u0".into(),
        project: "p".into(),
        item_key: "idle".into(),
        reason: "retry".into(),
    };
    let none = w.svc.unblock_work(as_user(w.alice, idle)).await;
    assert_eq!(code(none).0, Code::FailedPrecondition);
    let done = w
        .svc
        .cancel_work(as_user(w.alice, cancel("c1")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(done.state(), WorkItemState::Cancelled);
    assert!(!done.held);
    let verdict: String = sqlx::query_scalar("SELECT verdict FROM work_attempt WHERE id = $1")
        .bind(attempt)
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(verdict, "lost");
    assert_eq!(w.count("work_slice_lease").await, 0);
    let kinds: Vec<String> =
        sqlx::query_scalar("SELECT kind FROM work_event WHERE item_id IS NOT NULL ORDER BY id")
            .fetch_all(&w.pool)
            .await
            .unwrap();
    assert_eq!(kinds, ["created", "created", "lost", "cancelled"]);
    let replay = w
        .svc
        .cancel_work(as_user(w.alice, cancel("c1")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(replay, done);
    assert_eq!(w.count("work_event").await, 6);
    let twice = w.svc.cancel_work(as_user(w.alice, cancel("c2"))).await;
    assert_eq!(code(twice).0, Code::FailedPrecondition);
    let back = w.svc.unblock_work(as_user(w.alice, unblock("u1"))).await;
    assert_eq!(code(back).0, Code::FailedPrecondition);
    sqlx::query("UPDATE work_item SET state = 'blocked' WHERE key = 'idle'")
        .execute(&w.pool)
        .await
        .unwrap();
    let blocked = UnblockWorkRequest {
        key: "u2".into(),
        project: "p".into(),
        item_key: "idle".into(),
        reason: "retry".into(),
    };
    let reopened = w
        .svc
        .unblock_work(as_user(w.alice, blocked))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reopened.state(), WorkItemState::Open);
    assert!(reopened.ready);
}

#[sqlx::test(migrations = false)]
async fn graph_write_waits_for_project_lock(pool: PgPool) {
    let w = world(pool).await;
    w.project(w.alice, "k", "p").await.unwrap();
    let mut tx = w.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM work_project WHERE name = 'p' FOR NO KEY UPDATE")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let svc = w.svc.clone();
    let alice = w.alice;
    let write = tokio::spawn(async move {
        let request = AddWorkItemRequest {
            key: "i".into(),
            project: "p".into(),
            item_key: "one".into(),
            title: "t".into(),
            ..Default::default()
        };
        svc.add_work_item(as_user(alice, request)).await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!write.is_finished());
    tx.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), write)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(w.count("work_item").await, 1);
}

#[sqlx::test(migrations = false)]
async fn concurrent_deps_cannot_form_a_cycle(pool: PgPool) {
    let w = world(pool).await;
    w.project(w.alice, "k", "p").await.unwrap();
    w.item(w.alice, "i1", "a", &[], &[]).await.unwrap();
    w.item(w.alice, "i2", "b", &[], &[]).await.unwrap();
    let (x, y) = tokio::join!(w.dep("d1", "a", "b"), w.dep("d2", "b", "a"));
    assert_eq!(usize::from(x.is_ok()) + usize::from(y.is_ok()), 1);
    assert_eq!(w.count("work_dep").await, 1);
}

#[sqlx::test(migrations = false)]
async fn later_rpcs_are_not_available_yet(pool: PgPool) {
    let w = world(pool).await;
    let next = w
        .svc
        .next_work(as_user(w.alice, NextWorkRequest::default()))
        .await;
    assert_eq!(code(next).0, Code::Unimplemented);
    let claim = w
        .svc
        .claim_work(as_user(w.alice, ClaimWorkRequest::default()))
        .await;
    assert_eq!(code(claim).0, Code::Unimplemented);
    let anonymous = w
        .svc
        .list_work_projects(Request::new(ListWorkProjectsRequest {}))
        .await;
    assert_eq!(code(anonymous).0, Code::PermissionDenied);
}
