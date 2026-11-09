//! `FleetWork` claim, lease, report, note, defer and reaper RPCs: one-transaction claim, lease
//! TTL range, derived counts, evidence redaction before the 8 KiB cut, owner scope and the
//! project row lock. They need a Postgres superuser URL in `DATABASE_URL`, which
//! `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::fleet_work_server::FleetWork;
use fleet_proto::v1::{
    AddWorkItemRequest, AddWorkNoteRequest, ClaimWorkRequest, CreateWorkProjectRequest,
    GetWorkItemRequest, ListWorkDefersRequest, NextWorkRequest, RecordWorkDeferRequest,
    RenewLeaseRequest, ReportAttemptRequest, ResolveWorkDeferRequest, SetWorkSlicesRequest,
    WorkAttempt, WorkDefer, WorkDeferState, WorkDep, WorkItem, WorkSlice, WorkVerdict,
};
use fleet_server::auth::Caller;
use fleet_server::service::FleetService;
use fleet_server::store::{
    DEFAULT_LEASE_TTL_SECS, MAX_EVIDENCE_BYTES, MAX_EVIDENCE_INPUT_BYTES, MAX_LEASE_TTL_SECS,
    MIN_LEASE_TTL_SECS, Store,
};
use sqlx::PgPool;
use tonic::{Code, Request, Status};

const SECRET: &str = "qzqzjxvk-9981";

type Row = (&'static str, Result<(), Status>, Result<(), Status>);

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
    let svc = FleetService::new(store).with_work_redactor(Redactor::new([SECRET]));
    World {
        svc,
        pool,
        alice,
        bob,
    }
}

#[track_caller]
fn code<T>(result: Result<T, Status>) -> (Code, String) {
    let status = result.err().unwrap();
    (status.code(), status.message().to_owned())
}

fn precondition(message: &str) -> (Code, String) {
    (Code::FailedPrecondition, message.to_owned())
}

impl World {
    async fn setup(&self) {
        let project = CreateWorkProjectRequest {
            key: "k".into(),
            name: "p".into(),
            repo: None,
        };
        self.svc
            .create_work_project(as_user(self.alice, project))
            .await
            .unwrap();
        let slices = SetWorkSlicesRequest {
            key: "s".into(),
            project: "p".into(),
            slices: ["a", "b", "c"]
                .iter()
                .map(|name| WorkSlice {
                    name: (*name).to_owned(),
                    paths: vec![format!("src/{name}")],
                })
                .collect(),
            mergeable: Vec::new(),
        };
        self.svc
            .set_work_slices(as_user(self.alice, slices))
            .await
            .unwrap();
    }

    async fn item(&self, item_key: &str, slices: &[&str], deps: &[&str]) -> WorkItem {
        let request = AddWorkItemRequest {
            key: format!("add-{item_key}"),
            project: "p".into(),
            item_key: item_key.into(),
            title: format!("title {item_key}"),
            body: String::new(),
            slices: slices.iter().map(|s| (*s).to_owned()).collect(),
            deps: deps
                .iter()
                .map(|d| WorkDep {
                    depends_on: (*d).to_owned(),
                    why: "needs it".into(),
                })
                .collect(),
        };
        self.svc
            .add_work_item(as_user(self.alice, request))
            .await
            .unwrap()
            .into_inner()
    }

    async fn claim_as(
        &self,
        user: i64,
        key: &str,
        item: &str,
        ttl: u32,
    ) -> Result<WorkAttempt, Status> {
        let request = ClaimWorkRequest {
            key: key.into(),
            project: "p".into(),
            item_key: item.into(),
            holder: "worker-1".into(),
            ttl_secs: ttl,
        };
        self.svc
            .claim_work(as_user(user, request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn claim(&self, item: &str) -> Result<WorkAttempt, Status> {
        self.claim_as(self.alice, &format!("claim-{item}"), item, 0)
            .await
    }

    async fn renew(&self, key: &str, attempt: u64, ttl: u32) -> Result<WorkAttempt, Status> {
        let request = RenewLeaseRequest {
            key: key.into(),
            project: "p".into(),
            attempt_id: attempt,
            ttl_secs: ttl,
        };
        self.svc
            .renew_lease(as_user(self.alice, request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn report(
        &self,
        key: &str,
        attempt: u64,
        verdict: WorkVerdict,
        evidence: &str,
    ) -> Result<WorkAttempt, Status> {
        let request = ReportAttemptRequest {
            key: key.into(),
            project: "p".into(),
            attempt_id: attempt,
            verdict: verdict as i32,
            note: "done".into(),
            evidence_tail: evidence.into(),
        };
        self.svc
            .report_attempt(as_user(self.alice, request))
            .await
            .map(tonic::Response::into_inner)
    }

    async fn show(&self, item: &str) -> fleet_proto::v1::GetWorkItemReply {
        let request = GetWorkItemRequest {
            project: "p".into(),
            item_key: item.into(),
        };
        self.svc
            .get_work_item(as_user(self.alice, request))
            .await
            .unwrap()
            .into_inner()
    }

    async fn count(&self, table: &str) -> i64 {
        let sql = match table {
            "work_attempt" => "SELECT count(*) FROM work_attempt",
            "work_slice_lease" => "SELECT count(*) FROM work_slice_lease",
            "work_event" => "SELECT count(*) FROM work_event",
            "work_defer" => "SELECT count(*) FROM work_defer",
            "work_item" => "SELECT count(*) FROM work_item",
            _ => unreachable!("unknown table {table}"),
        };
        sqlx::query_scalar(sql).fetch_one(&self.pool).await.unwrap()
    }

    async fn ttl_of(&self, attempt: u64) -> i64 {
        sqlx::query_scalar(
            "SELECT extract(epoch FROM expires_at - now())::bigint FROM work_attempt WHERE id = $1",
        )
        .bind(i64::try_from(attempt).unwrap())
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }

    async fn defer(
        &self,
        key: &str,
        item: Option<&str>,
        attempt: Option<u64>,
    ) -> Result<WorkDefer, Status> {
        let request = RecordWorkDeferRequest {
            key: key.into(),
            project: "p".into(),
            item_key: item.map(str::to_owned),
            attempt_id: attempt,
            title: "later".into(),
            reason: "out of scope".into(),
            vertical: "web".into(),
        };
        self.svc
            .record_work_defer(as_user(self.alice, request))
            .await
            .map(tonic::Response::into_inner)
    }
}

#[sqlx::test(migrations = false)]
async fn claim_takes_every_slice_lease_in_one_transaction(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &["a", "b"], &[]).await;
    w.item("two", &["b"], &[]).await;
    w.item("three", &["c"], &[]).await;
    let attempt = w.claim("one").await.unwrap();
    assert_eq!(attempt.item_key, "one");
    assert_eq!(attempt.holder, "worker-1");
    assert_eq!(attempt.verdict, None);
    assert_eq!(w.count("work_slice_lease").await, 2);
    assert_eq!(w.count("work_attempt").await, 1);
    let held = w.show("one").await.item.unwrap();
    assert!(held.held && !held.ready);
    let events = w.show("one").await.events;
    assert!(events.iter().any(|e| e.kind == "claimed"));
    assert_eq!(
        code(w.claim("two").await),
        precondition("work item is not ready")
    );
    assert_eq!(w.count("work_attempt").await, 1);
    assert_eq!(
        code(w.claim_as(w.alice, "second", "one", 0).await),
        precondition("work item is not ready")
    );
    w.claim("three").await.unwrap();
    assert_eq!(w.count("work_slice_lease").await, 3);
}

#[sqlx::test(migrations = false)]
async fn claim_refuses_unready_cancelled_blocked_and_bad_input(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("base", &[], &[]).await;
    w.item("child", &[], &["base"]).await;
    w.item("gone", &[], &[]).await;
    w.item("stuck", &[], &[]).await;
    sqlx::query("UPDATE work_item SET state = 'cancelled' WHERE key = 'gone'")
        .execute(&w.pool)
        .await
        .unwrap();
    sqlx::query("UPDATE work_item SET state = 'blocked' WHERE key = 'stuck'")
        .execute(&w.pool)
        .await
        .unwrap();
    assert_eq!(
        code(w.claim("child").await),
        precondition("work item is not ready")
    );
    assert_eq!(
        code(w.claim("gone").await),
        precondition("work item is cancelled")
    );
    assert_eq!(
        code(w.claim("stuck").await),
        precondition("work item is blocked")
    );
    assert_eq!(code(w.claim("nope").await).0, Code::NotFound);
    let request = |holder: &str, key: &str| ClaimWorkRequest {
        key: key.into(),
        project: "p".into(),
        item_key: "base".into(),
        holder: holder.into(),
        ttl_secs: 0,
    };
    for (holder, key) in [("", "k1"), ("h\u{202e}x", "k2"), ("h", ""), ("h", "k 3")] {
        let result = w
            .svc
            .claim_work(as_user(w.alice, request(holder, key)))
            .await;
        assert_eq!(result.err().unwrap().code(), Code::InvalidArgument);
    }
    assert_eq!(w.count("work_attempt").await, 0);
    let attempt = w.claim("base").await.unwrap();
    w.report("r1", attempt.id, WorkVerdict::Pass, "")
        .await
        .unwrap();
    w.claim("child").await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn slice_lease_conflict_refuses_and_rolls_back(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("holder", &["a"], &[]).await;
    w.item("wants", &["b", "a"], &[]).await;
    sqlx::query(
        "INSERT INTO work_attempt (project_id, item_id, holder, expires_at, verdict, closed_at) \
         SELECT project_id, id, 'old', now() + interval '1 hour', 'fail', now() \
         FROM work_item WHERE key = 'holder'",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO work_slice_lease (slice_id, project_id, attempt_id) \
         SELECT s.id, s.project_id, (SELECT id FROM work_attempt) FROM work_slice s WHERE s.name = 'a'",
    )
    .execute(&w.pool)
    .await
    .unwrap();
    let events = w.count("work_event").await;
    assert_eq!(
        code(w.claim("wants").await),
        precondition("slice is leased")
    );
    assert_eq!(w.count("work_attempt").await, 1);
    assert_eq!(w.count("work_slice_lease").await, 1);
    assert_eq!(w.count("work_event").await, events);
}

#[sqlx::test(migrations = false)]
async fn concurrent_claims_on_a_shared_slice_admit_one(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("x", &["a"], &[]).await;
    w.item("y", &["a"], &[]).await;
    let (one, two) = tokio::join!(w.claim("x"), w.claim("y"));
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    assert_eq!(w.count("work_slice_lease").await, 1);
}

#[sqlx::test(migrations = false)]
async fn claim_replay_and_key_conflict(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &["a"], &[]).await;
    let first = w.claim_as(w.alice, "same", "one", 60).await.unwrap();
    let again = w.claim_as(w.alice, "same", "one", 60).await.unwrap();
    assert_eq!(first, again);
    assert_eq!(w.count("work_attempt").await, 1);
    let other = w.claim_as(w.alice, "same", "one", 61).await;
    assert_eq!(code(other).0, Code::AlreadyExists);
}

#[sqlx::test(migrations = false)]
async fn claim_ttl_range_at_and_over_each_limit(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    for name in ["i1", "i2", "i3", "i4", "i5", "i6"] {
        w.item(name, &[], &[]).await;
    }
    let cases = [
        ("i1", MIN_LEASE_TTL_SECS - 1, false),
        ("i2", MIN_LEASE_TTL_SECS, true),
        ("i3", MAX_LEASE_TTL_SECS, true),
        ("i4", MAX_LEASE_TTL_SECS + 1, false),
        ("i5", 0, true),
        ("i6", u32::MAX, false),
    ];
    for (item, ttl, ok) in cases {
        let result = w.claim_as(w.alice, &format!("c-{item}"), item, ttl).await;
        if ok {
            let secs = w.ttl_of(result.unwrap().id).await;
            let want = i64::from(match ttl {
                0 => DEFAULT_LEASE_TTL_SECS,
                other => other,
            });
            assert!((want - 5..=want).contains(&secs), "{item} {secs} {want}");
        } else {
            assert_eq!(
                code(result),
                (Code::InvalidArgument, "invalid lease ttl".to_owned())
            );
        }
    }
    assert_eq!(w.count("work_attempt").await, 3);
}

#[sqlx::test(migrations = false)]
async fn renew_extends_and_checks_range_and_state(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &["a"], &[]).await;
    let attempt = w.claim_as(w.alice, "c", "one", 60).await.unwrap();
    for (ttl, ok) in [
        (MIN_LEASE_TTL_SECS - 1, false),
        (MIN_LEASE_TTL_SECS, true),
        (MAX_LEASE_TTL_SECS, true),
        (MAX_LEASE_TTL_SECS + 1, false),
    ] {
        let result = w.renew(&format!("r{ttl}"), attempt.id, ttl).await;
        if ok {
            let secs = w.ttl_of(attempt.id).await;
            let want = i64::from(ttl);
            result.unwrap();
            assert!((want - 5..=want).contains(&secs), "{secs} {want}");
        } else {
            assert_eq!(code(result).0, Code::InvalidArgument);
        }
    }
    assert_eq!(
        code(w.renew("x1", attempt.id + 99, 60).await).0,
        Code::NotFound
    );
    sqlx::query("UPDATE work_attempt SET expires_at = now() - interval '1 second'")
        .execute(&w.pool)
        .await
        .unwrap();
    assert_eq!(
        code(w.renew("x2", attempt.id, 60).await),
        precondition("lease expired")
    );
    sqlx::query("UPDATE work_attempt SET expires_at = now() + interval '1 hour'")
        .execute(&w.pool)
        .await
        .unwrap();
    w.report("x3", attempt.id, WorkVerdict::Fail, "")
        .await
        .unwrap();
    assert_eq!(
        code(w.renew("x4", attempt.id, 60).await),
        precondition("attempt is closed")
    );
    assert!(
        w.show("one")
            .await
            .events
            .iter()
            .any(|e| e.kind == "renewed")
    );
}

#[sqlx::test(migrations = false)]
async fn report_derives_counts_and_frees_leases(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &["a", "b"], &[]).await;
    w.item("two", &[], &["one"]).await;
    let failed = w.claim("one").await.unwrap();
    let closed = w
        .report("f", failed.id, WorkVerdict::Fail, "boom")
        .await
        .unwrap();
    assert_eq!(closed.verdict, Some(WorkVerdict::Fail as i32));
    assert_eq!(closed.evidence_tail, "boom");
    assert_eq!(closed.note, "done");
    assert!(closed.closed_at_ms.is_some());
    assert_eq!(w.count("work_slice_lease").await, 0);
    let item = w.show("one").await.item.unwrap();
    assert_eq!(
        (item.passes, item.fails, item.ready, item.held),
        (0, 1, true, false)
    );
    assert_eq!(
        code(w.report("f2", failed.id, WorkVerdict::Pass, "").await),
        precondition("attempt is closed")
    );
    let passed = w.claim_as(w.alice, "again", "one", 0).await.unwrap();
    w.report("p", passed.id, WorkVerdict::Pass, "")
        .await
        .unwrap();
    let item = w.show("one").await.item.unwrap();
    assert_eq!((item.passes, item.fails, item.ready), (1, 1, false));
    assert!(w.show("two").await.item.unwrap().ready);
    let kinds: Vec<String> = w
        .show("one")
        .await
        .events
        .into_iter()
        .map(|e| e.kind)
        .collect();
    assert_eq!(kinds.iter().filter(|k| *k == "failed").count(), 1);
    assert_eq!(kinds.iter().filter(|k| *k == "passed").count(), 1);
}

#[sqlx::test(migrations = false)]
async fn report_input_checks(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &[], &[]).await;
    let attempt = w.claim("one").await.unwrap();
    for verdict in [
        WorkVerdict::Unspecified as i32,
        WorkVerdict::Lost as i32,
        99,
    ] {
        let request = ReportAttemptRequest {
            key: "v".into(),
            project: "p".into(),
            attempt_id: attempt.id,
            verdict,
            ..Default::default()
        };
        let result = w.svc.report_attempt(as_user(w.alice, request)).await;
        assert_eq!(result.err().unwrap().code(), Code::InvalidArgument);
    }
    let over = "n".repeat(4097);
    let hostile = "bad\u{202e}note";
    for note in [over.as_str(), hostile, "nul\0"] {
        let request = ReportAttemptRequest {
            key: "n".into(),
            project: "p".into(),
            attempt_id: attempt.id,
            verdict: WorkVerdict::Pass as i32,
            note: note.into(),
            evidence_tail: String::new(),
        };
        let result = w.svc.report_attempt(as_user(w.alice, request)).await;
        assert_eq!(result.err().unwrap().code(), Code::InvalidArgument);
    }
    let huge = "e".repeat(MAX_EVIDENCE_INPUT_BYTES + 1);
    assert_eq!(
        code(w.report("h", attempt.id, WorkVerdict::Pass, &huge).await),
        (Code::InvalidArgument, "evidence too long".to_owned())
    );
    assert_eq!(w.count("work_slice_lease").await, 0);
    let at_limit = "e".repeat(MAX_EVIDENCE_INPUT_BYTES);
    let kept = w
        .report("h2", attempt.id, WorkVerdict::Pass, &at_limit)
        .await
        .unwrap();
    assert_eq!(kept.evidence_tail.len(), MAX_EVIDENCE_BYTES);
}

#[sqlx::test(migrations = false)]
async fn evidence_cap_and_secret_straddling_it(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    let leaked = ['q', 'z', 'j', 'x', 'v', 'k', '9', '8', '1'];
    for (n, offset) in (0..=SECRET.len() + 1).enumerate() {
        let name = format!("it{n}");
        w.item(&name, &[], &[]).await;
        let attempt = w.claim(&name).await.unwrap();
        let evidence = format!("{}{SECRET}tail", "a".repeat(MAX_EVIDENCE_BYTES - offset));
        let kept = w
            .report(&format!("e{n}"), attempt.id, WorkVerdict::Pass, &evidence)
            .await
            .unwrap()
            .evidence_tail;
        assert!(!kept.contains(leaked), "offset {offset}: {kept:?}");
        assert!(kept.len() <= MAX_EVIDENCE_BYTES);
        let stored: String = sqlx::query_scalar("SELECT evidence FROM work_attempt WHERE id = $1")
            .bind(i64::try_from(attempt.id).unwrap())
            .fetch_one(&w.pool)
            .await
            .unwrap();
        assert_eq!(stored, kept);
    }
    w.item("ctl", &[], &[]).await;
    let attempt = w.claim("ctl").await.unwrap();
    let kept = w
        .report(
            "ctl",
            attempt.id,
            WorkVerdict::Pass,
            &format!("x {SECRET} y"),
        )
        .await
        .unwrap()
        .evidence_tail;
    assert_eq!(kept, "x [REDACTED] y");
    w.item("long", &[], &[]).await;
    let attempt = w.claim("long").await.unwrap();
    let exact = "é".repeat(MAX_EVIDENCE_BYTES / 2 + 1);
    let kept = w
        .report("long", attempt.id, WorkVerdict::Pass, &exact)
        .await
        .unwrap()
        .evidence_tail;
    assert_eq!(kept.len(), MAX_EVIDENCE_BYTES);
}

#[sqlx::test(migrations = false)]
async fn notes_next_and_owner_scope(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &["a"], &[]).await;
    w.item("two", &["a"], &[]).await;
    let next = |user: i64| {
        w.svc.next_work(as_user(
            user,
            NextWorkRequest {
                project: "p".into(),
            },
        ))
    };
    assert_eq!(
        next(w.alice).await.unwrap().into_inner().item.unwrap().key,
        "one"
    );
    assert_eq!(code(next(w.bob).await).0, Code::NotFound);
    let attempt = w.claim("one").await.unwrap();
    assert!(next(w.alice).await.unwrap().into_inner().item.is_none());
    w.report("r", attempt.id, WorkVerdict::Pass, "")
        .await
        .unwrap();
    assert_eq!(
        next(w.alice).await.unwrap().into_inner().item.unwrap().key,
        "two"
    );
    let note = |user: i64, key: &str, item: &str, text: &str| {
        w.svc.add_work_note(as_user(
            user,
            AddWorkNoteRequest {
                key: key.into(),
                project: "p".into(),
                item_key: item.into(),
                note: text.into(),
            },
        ))
    };
    let event = note(w.alice, "n1", "one", "looks good\nsecond line")
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        (event.kind.as_str(), event.item_key.as_deref()),
        ("note", Some("one"))
    );
    assert_eq!(
        note(w.alice, "n1", "one", "looks good\nsecond line")
            .await
            .unwrap()
            .into_inner(),
        event
    );
    assert!(w.show("one").await.events.iter().any(|e| e.id == event.id));
    assert_eq!(code(note(w.bob, "n2", "one", "x").await).0, Code::NotFound);
    assert_eq!(
        code(note(w.alice, "n3", "nope", "x").await).0,
        Code::NotFound
    );
    let long = "n".repeat(4097);
    let ok = "n".repeat(4096);
    for bad in ["", "   ", "x\u{202e}y", long.as_str()] {
        assert_eq!(
            note(w.alice, "n4", "one", bad).await.err().unwrap().code(),
            Code::InvalidArgument
        );
    }
    note(w.alice, "n5", "one", &ok).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn reaper_closes_expired_attempts_and_frees_slices(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("old", &["a", "b"], &[]).await;
    w.item("fresh", &["c"], &[]).await;
    let old = w.claim("old").await.unwrap();
    w.claim("fresh").await.unwrap();
    let store = Store::new(w.pool.clone());
    assert_eq!(store.reap_work_leases().await.unwrap(), 0);
    sqlx::query("UPDATE work_attempt SET expires_at = now() - interval '1 second' WHERE id = $1")
        .bind(i64::try_from(old.id).unwrap())
        .execute(&w.pool)
        .await
        .unwrap();
    assert_eq!(store.reap_work_leases().await.unwrap(), 1);
    assert_eq!(store.reap_work_leases().await.unwrap(), 0);
    assert_eq!(w.count("work_slice_lease").await, 1);
    let shown = w.show("old").await;
    assert_eq!(shown.attempts[0].verdict, Some(WorkVerdict::Lost as i32));
    assert!(shown.item.unwrap().ready);
    let lost: Vec<_> = shown.events.iter().filter(|e| e.kind == "lost").collect();
    assert_eq!(lost.len(), 1);
    assert_eq!(lost[0].actor, "reaper");
    assert!(w.show("fresh").await.item.unwrap().held);
    assert_eq!(
        code(w.report("late", old.id, WorkVerdict::Pass, "").await),
        precondition("attempt is closed")
    );
    w.claim_as(w.alice, "again", "old", 0).await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn defers_record_list_promote_and_drop(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &[], &[]).await;
    let attempt = w.claim("one").await.unwrap();
    let a = w.defer("d1", Some("one"), Some(attempt.id)).await.unwrap();
    assert_eq!(a.item_key.as_deref(), Some("one"));
    assert_eq!(a.attempt_id, Some(attempt.id));
    assert_eq!(a.state(), WorkDeferState::Open);
    assert_eq!(
        w.defer("d1", Some("one"), Some(attempt.id)).await.unwrap(),
        a
    );
    let b = w.defer("d2", None, None).await.unwrap();
    let list = |vertical: Option<&str>, state: Option<WorkDeferState>, user: i64| {
        w.svc.list_work_defers(as_user(
            user,
            ListWorkDefersRequest {
                project: "p".into(),
                vertical: vertical.map(str::to_owned),
                state: state.map(|s| s as i32),
            },
        ))
    };
    assert_eq!(
        list(None, None, w.alice)
            .await
            .unwrap()
            .into_inner()
            .defers
            .len(),
        2
    );
    assert_eq!(
        list(Some("api"), None, w.alice)
            .await
            .unwrap()
            .into_inner()
            .defers
            .len(),
        0
    );
    assert_eq!(code(list(None, None, w.bob).await).0, Code::NotFound);
    assert_eq!(
        list(None, Some(WorkDeferState::Unspecified), w.alice)
            .await
            .err()
            .unwrap()
            .code(),
        Code::InvalidArgument
    );
    let resolve = |key: &str, id: u64, promote: bool, item: Option<&str>, user: i64| {
        w.svc.resolve_work_defer(as_user(
            user,
            ResolveWorkDeferRequest {
                key: key.into(),
                project: "p".into(),
                defer_id: id,
                promote,
                item_key: item.map(str::to_owned),
            },
        ))
    };
    assert_eq!(
        resolve("r0", a.id, true, None, w.alice)
            .await
            .err()
            .unwrap()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        resolve("r0", a.id, false, Some("x"), w.alice)
            .await
            .err()
            .unwrap()
            .code(),
        Code::InvalidArgument
    );
    assert_eq!(
        code(resolve("r1", a.id, true, Some("one"), w.alice).await),
        (Code::AlreadyExists, "work item key already used".to_owned())
    );
    assert_eq!(
        code(resolve("r2", a.id, true, Some("new"), w.bob).await).0,
        Code::NotFound
    );
    assert_eq!(
        code(resolve("r3", 9999, false, None, w.alice).await).0,
        Code::NotFound
    );
    let promoted = resolve("r4", a.id, true, Some("new"), w.alice)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(promoted.state(), WorkDeferState::Promoted);
    assert_eq!(promoted.promoted_item_key.as_deref(), Some("new"));
    assert_eq!(w.show("new").await.item.unwrap().title, "later");
    assert_eq!(
        resolve("r4", a.id, true, Some("new"), w.alice)
            .await
            .unwrap()
            .into_inner(),
        promoted
    );
    assert_eq!(
        code(resolve("r5", a.id, false, None, w.alice).await),
        precondition("defer is already resolved")
    );
    let dropped = resolve("r6", b.id, false, None, w.alice)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(dropped.state(), WorkDeferState::Dropped);
    let open = list(None, Some(WorkDeferState::Open), w.alice)
        .await
        .unwrap()
        .into_inner();
    assert_eq!(open.defers.len(), 0);
}

#[sqlx::test(migrations = false)]
async fn defer_refuses_cross_project_references(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    let other = CreateWorkProjectRequest {
        key: "k2".into(),
        name: "q".into(),
        repo: None,
    };
    w.svc
        .create_work_project(as_user(w.alice, other))
        .await
        .unwrap();
    let add = AddWorkItemRequest {
        key: "qi".into(),
        project: "q".into(),
        item_key: "qitem".into(),
        title: "t".into(),
        ..Default::default()
    };
    w.svc.add_work_item(as_user(w.alice, add)).await.unwrap();
    let foreign: i64 = sqlx::query_scalar(
        "INSERT INTO work_attempt (project_id, item_id, holder, expires_at) \
         SELECT project_id, id, 'h', now() + interval '1 hour' FROM work_item RETURNING id",
    )
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(
        code(
            w.defer("d", None, Some(u64::try_from(foreign).unwrap()))
                .await
        ),
        precondition("work reference crosses projects")
    );
    assert_eq!(
        code(w.defer("d2", Some("qitem"), None).await).0,
        Code::NotFound
    );
    assert_eq!(w.count("work_defer").await, 0);
}

#[sqlx::test(migrations = false)]
async fn writes_wait_for_a_share_lock_on_the_project_row(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &["a"], &[]).await;
    w.item("two", &["b"], &[]).await;
    let attempt = w.claim("two").await.unwrap();
    let mut tx = w.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM work_project WHERE name = 'p' FOR SHARE")
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    let claim = {
        let svc = w.svc.clone();
        let alice = w.alice;
        tokio::spawn(async move {
            let request = ClaimWorkRequest {
                key: "lk".into(),
                project: "p".into(),
                item_key: "one".into(),
                holder: "h".into(),
                ttl_secs: 0,
            };
            svc.claim_work(as_user(alice, request)).await
        })
    };
    let report = {
        let svc = w.svc.clone();
        let alice = w.alice;
        tokio::spawn(async move {
            let request = ReportAttemptRequest {
                key: "lr".into(),
                project: "p".into(),
                attempt_id: attempt.id,
                verdict: WorkVerdict::Pass as i32,
                ..Default::default()
            };
            svc.report_attempt(as_user(alice, request)).await
        })
    };
    let add = {
        let svc = w.svc.clone();
        let alice = w.alice;
        tokio::spawn(async move {
            let request = AddWorkItemRequest {
                key: "la".into(),
                project: "p".into(),
                item_key: "three".into(),
                title: "t".into(),
                ..Default::default()
            };
            svc.add_work_item(as_user(alice, request)).await
        })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!claim.is_finished() && !report.is_finished() && !add.is_finished());
    assert_eq!(w.count("work_attempt").await, 1);
    tx.commit().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        claim.await.unwrap().unwrap();
        report.await.unwrap().unwrap();
        add.await.unwrap().unwrap();
    })
    .await
    .unwrap();
    assert_eq!(w.count("work_attempt").await, 2);
}

#[sqlx::test(migrations = false)]
async fn every_work_claim_rpc_needs_a_user_and_the_owner(pool: PgPool) {
    let w = world(pool).await;
    w.setup().await;
    w.item("one", &["a"], &[]).await;
    let attempt = w.claim("one").await.unwrap();
    let svc = &w.svc;
    let bob = w.bob;
    let attempt_id = attempt.id;
    let rows: Vec<Row> = vec![
        (
            "next",
            svc.next_work(Request::new(NextWorkRequest {
                project: "p".into(),
            }))
            .await
            .map(drop),
            svc.next_work(as_user(
                bob,
                NextWorkRequest {
                    project: "p".into(),
                },
            ))
            .await
            .map(drop),
        ),
        (
            "claim",
            svc.claim_work(Request::new(ClaimWorkRequest {
                key: "z".into(),
                project: "p".into(),
                item_key: "one".into(),
                holder: "h".into(),
                ttl_secs: 0,
            }))
            .await
            .map(drop),
            svc.claim_work(as_user(
                bob,
                ClaimWorkRequest {
                    key: "z".into(),
                    project: "p".into(),
                    item_key: "one".into(),
                    holder: "h".into(),
                    ttl_secs: 0,
                },
            ))
            .await
            .map(drop),
        ),
        (
            "renew",
            svc.renew_lease(Request::new(RenewLeaseRequest {
                key: "z".into(),
                project: "p".into(),
                attempt_id,
                ttl_secs: 0,
            }))
            .await
            .map(drop),
            svc.renew_lease(as_user(
                bob,
                RenewLeaseRequest {
                    key: "z".into(),
                    project: "p".into(),
                    attempt_id,
                    ttl_secs: 0,
                },
            ))
            .await
            .map(drop),
        ),
        (
            "report",
            svc.report_attempt(Request::new(ReportAttemptRequest {
                key: "z".into(),
                project: "p".into(),
                attempt_id,
                verdict: 1,
                ..Default::default()
            }))
            .await
            .map(drop),
            svc.report_attempt(as_user(
                bob,
                ReportAttemptRequest {
                    key: "z".into(),
                    project: "p".into(),
                    attempt_id,
                    verdict: 1,
                    ..Default::default()
                },
            ))
            .await
            .map(drop),
        ),
        (
            "note",
            svc.add_work_note(Request::new(AddWorkNoteRequest {
                key: "z".into(),
                project: "p".into(),
                item_key: "one".into(),
                note: "n".into(),
            }))
            .await
            .map(drop),
            svc.add_work_note(as_user(
                bob,
                AddWorkNoteRequest {
                    key: "z".into(),
                    project: "p".into(),
                    item_key: "one".into(),
                    note: "n".into(),
                },
            ))
            .await
            .map(drop),
        ),
        (
            "record",
            svc.record_work_defer(Request::new(RecordWorkDeferRequest {
                key: "z".into(),
                project: "p".into(),
                title: "t".into(),
                reason: "r".into(),
                vertical: "v".into(),
                ..Default::default()
            }))
            .await
            .map(drop),
            svc.record_work_defer(as_user(
                bob,
                RecordWorkDeferRequest {
                    key: "z".into(),
                    project: "p".into(),
                    title: "t".into(),
                    reason: "r".into(),
                    vertical: "v".into(),
                    ..Default::default()
                },
            ))
            .await
            .map(drop),
        ),
        (
            "resolve",
            svc.resolve_work_defer(Request::new(ResolveWorkDeferRequest {
                key: "z".into(),
                project: "p".into(),
                defer_id: 1,
                ..Default::default()
            }))
            .await
            .map(drop),
            svc.resolve_work_defer(as_user(
                bob,
                ResolveWorkDeferRequest {
                    key: "z".into(),
                    project: "p".into(),
                    defer_id: 1,
                    ..Default::default()
                },
            ))
            .await
            .map(drop),
        ),
        (
            "list",
            svc.list_work_defers(Request::new(ListWorkDefersRequest {
                project: "p".into(),
                ..Default::default()
            }))
            .await
            .map(drop),
            svc.list_work_defers(as_user(
                bob,
                ListWorkDefersRequest {
                    project: "p".into(),
                    ..Default::default()
                },
            ))
            .await
            .map(drop),
        ),
    ];
    assert_eq!(rows.len(), 8);
    for (name, anonymous, foreign) in rows {
        assert_eq!(
            anonymous.err().unwrap().code(),
            Code::PermissionDenied,
            "{name}"
        );
        assert_eq!(foreign.err().unwrap().code(), Code::NotFound, "{name}");
    }
    assert_eq!(w.count("work_attempt").await, 1);
}
