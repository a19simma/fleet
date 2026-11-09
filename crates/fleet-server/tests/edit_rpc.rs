//! Suggested edits (ADR-0066): filing bounds, stale marking, the decide transaction and the
//! identity gate of `DecideEdit` through the production auth layer. The tests need a Postgres
//! superuser URL in `DATABASE_URL` and live in their own binary because the gate tests bind
//! sockets.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fleet_core::Redactor;
use fleet_proto::v1::fleet_edit_client::FleetEditClient;
use fleet_proto::v1::{
    CreateWorkProjectRequest, DecideEditRequest, EditDecision, EditKind, EditState,
    FileEditRequest, GetEditRequest, ListEditsRequest, RecordPitfallRequest, SetWorkSlicesRequest,
    SuggestedEdit, WorkSlice,
};
use fleet_proto::{MAX_EDIT_PAYLOAD_BYTES, MAX_PENDING_EDITS_PER_PROJECT};
use fleet_server::auth::{BearerAuth, USER_TOKEN_REQUIRED};
use fleet_server::config::Token;
use fleet_server::cred::Users;
use fleet_server::service::router;
use fleet_server::store::{
    REASON_DECIDED, REASON_DOES_NOT_APPLY, REASON_STALE, REASON_TOO_MANY_PENDING, Store,
    StoreError, WorkFault,
};
use sqlx::PgPool;
use tonic::metadata::MetadataValue;
use tonic::transport::Endpoint;
use tonic::transport::server::TcpIncoming;
use tonic::{Code, Request};

const BOX: &str = "box-token-0123456789abcdef0123456789";
const CLIENT: &str = "client-token-0123456789abcdef012345";
const CAP: usize = MAX_PENDING_EDITS_PER_PROJECT;
static NEXT: AtomicUsize = AtomicUsize::new(0);

struct World {
    store: Store,
    pool: PgPool,
    alice: i64,
    redactor: Redactor,
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
    let world = World {
        store,
        pool,
        alice,
        redactor: Redactor::new(["s3cr3t-token-value"]),
    };
    world.project(alice, "p").await;
    world
        .slices(&[("core", &["src/core"]), ("web", &["src/web"])])
        .await;
    world
}

impl World {
    async fn project(&self, user: i64, name: &str) {
        self.store
            .create_work_project(
                user,
                &CreateWorkProjectRequest {
                    key: format!("create-{name}"),
                    name: name.to_owned(),
                    repo: None,
                },
            )
            .await
            .unwrap();
    }

    async fn slices(&self, slices: &[(&str, &[&str])]) {
        self.store
            .set_work_slices(
                self.alice,
                &SetWorkSlicesRequest {
                    key: format!("slices-{}", NEXT.fetch_add(1, Ordering::Relaxed)),
                    project: "p".to_owned(),
                    slices: slices
                        .iter()
                        .map(|(name, paths)| WorkSlice {
                            name: (*name).to_owned(),
                            paths: paths.iter().map(|p| (*p).to_owned()).collect(),
                        })
                        .collect(),
                    mergeable: Vec::new(),
                },
            )
            .await
            .unwrap();
    }

    async fn stored(&self) -> BTreeMap<String, Vec<String>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT s.name, p.path FROM work_slice s JOIN work_slice_path p ON p.slice_id = s.id \
             ORDER BY s.name, p.path",
        )
        .fetch_all(&self.pool)
        .await
        .unwrap();
        let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (name, path) in rows {
            map.entry(name).or_default().push(path);
        }
        map
    }

    async fn file_as(
        &self,
        user: i64,
        key: &str,
        kind: EditKind,
        target: &str,
        payload: &str,
        cap: usize,
    ) -> Result<SuggestedEdit, StoreError> {
        let base_hash = if kind == EditKind::FilePatch {
            "blob0".to_owned()
        } else {
            String::new()
        };
        self.store
            .file_edit(
                user,
                &FileEditRequest {
                    key: key.to_owned(),
                    project: "p".to_owned(),
                    kind: kind.into(),
                    target: target.to_owned(),
                    base_hash,
                    payload: payload.to_owned(),
                },
                &self.redactor,
                cap,
            )
            .await
    }

    async fn file(&self, key: &str, kind: EditKind, target: &str, payload: &str) -> SuggestedEdit {
        self.file_as(self.alice, key, kind, target, payload, CAP)
            .await
            .unwrap()
    }

    async fn slice_op(&self, key: &str, target: &str, payload: &str) -> SuggestedEdit {
        self.file(key, EditKind::SliceOp, target, payload).await
    }

    async fn decide(
        &self,
        key: &str,
        id: u64,
        decision: EditDecision,
    ) -> Result<SuggestedEdit, StoreError> {
        self.store
            .decide_edit(
                self.alice,
                &DecideEditRequest {
                    key: key.to_owned(),
                    project: "p".to_owned(),
                    id,
                    decision: decision.into(),
                },
            )
            .await
    }

    async fn state_of(&self, id: u64) -> EditState {
        let edit = self
            .store
            .get_edit(
                self.alice,
                &GetEditRequest {
                    project: "p".to_owned(),
                    id,
                },
            )
            .await
            .unwrap();
        EditState::try_from(edit.state).unwrap()
    }
}

fn refused(result: Result<SuggestedEdit, StoreError>) -> String {
    match result {
        Err(StoreError::Work(fault)) => fault.to_string(),
        other => format!("not refused: {other:?}"),
    }
}

#[sqlx::test]
async fn filing_a_slice_op_stores_a_pending_edit_with_the_target_hash(pool: PgPool) {
    let w = world(pool).await;
    let edit = w.slice_op("k1", "core", "add-path\tsrc/extra").await;
    assert_eq!(EditState::try_from(edit.state).unwrap(), EditState::Pending);
    assert_eq!(edit.base_hash.len(), 64);
    assert_eq!(edit.filed_by, format!("user {}", w.alice));
    let same = w.slice_op("k1", "core", "add-path\tsrc/extra").await;
    assert_eq!(same.id, edit.id);
    let clash = w
        .file_as(
            w.alice,
            "k1",
            EditKind::SliceOp,
            "core",
            "remove-path\tsrc/core",
            CAP,
        )
        .await;
    assert!(matches!(clash, Err(StoreError::KeyConflict)));
}

#[sqlx::test]
async fn bad_filings_are_refused_with_fixed_reasons(pool: PgPool) {
    let w = world(pool).await;
    let cases: [(EditKind, &str, &str, &str); 11] = [
        (
            EditKind::Unspecified,
            "core",
            "add-path\tsrc/x",
            "invalid edit kind",
        ),
        (EditKind::SliceOp, "core", "   ", "empty payload"),
        (EditKind::SliceOp, "core", "add-path", "invalid slice op"),
        (EditKind::SliceOp, "core", "add-path\t../x", "invalid path"),
        (EditKind::SliceOp, "core", "add-path\t/abs", "invalid path"),
        (EditKind::SliceOp, "core", "frob\tsrc/x", "invalid slice op"),
        (
            EditKind::SliceOp,
            "core",
            "add-path\ta\nadd-path\tb",
            "invalid slice op",
        ),
        (
            EditKind::SliceOp,
            "has space",
            "add-path\tsrc/x",
            "invalid edit target",
        ),
        (
            EditKind::Pitfall,
            "sym",
            "only one line",
            "invalid pitfall payload",
        ),
        (EditKind::Pitfall, "", "cause\nfix", "invalid edit target"),
        (EditKind::FilePatch, "../x", "diff", "invalid edit target"),
    ];
    for (n, (kind, target, payload, reason)) in cases.into_iter().enumerate() {
        let got = refused(
            w.file_as(w.alice, &format!("bad{n}"), kind, target, payload, CAP)
                .await,
        );
        assert_eq!(got, reason, "case {n}");
    }
    let hash = w
        .store
        .file_edit(
            w.alice,
            &FileEditRequest {
                key: "h".to_owned(),
                project: "p".to_owned(),
                kind: EditKind::SliceOp.into(),
                target: "core".to_owned(),
                base_hash: "abc".to_owned(),
                payload: "add-path\tsrc/x".to_owned(),
            },
            &w.redactor,
            CAP,
        )
        .await;
    assert_eq!(refused(hash), "base hash is set by the server");
    let missing = w
        .store
        .file_edit(
            w.alice,
            &FileEditRequest {
                key: "m".to_owned(),
                project: "p".to_owned(),
                kind: EditKind::FilePatch.into(),
                target: "a.rs".to_owned(),
                base_hash: String::new(),
                payload: "diff".to_owned(),
            },
            &w.redactor,
            CAP,
        )
        .await;
    assert_eq!(refused(missing), "invalid base hash");
}

#[sqlx::test]
async fn a_diff_is_hostile_text_clean_apart_from_newline_and_tab(pool: PgPool) {
    let w = world(pool).await;
    let clean = "--- a/f\n+++ b/f\n@@ -1 +1 @@\n-a\t1\n+b\t2\n";
    w.file("ok", EditKind::FilePatch, "f", clean).await;
    let hostile = [
        ("cr", "line\rrest"),
        ("crlf", "line\r\nrest"),
        ("nel", "line\u{85}rest"),
        ("ls", "line\u{2028}rest"),
        ("ps", "line\u{2029}rest"),
        ("esc", "line\u{1b}[31mrest"),
        ("nul", "line\0rest"),
        ("bidi", "line\u{202e}rest"),
        ("isolate", "line\u{2066}rest"),
        ("zwsp", "line\u{200b}rest"),
        ("bom", "\u{feff}line"),
        ("del", "line\u{7f}rest"),
        ("tag", "line\u{e0041}rest"),
    ];
    for (name, payload) in hostile {
        let got = refused(
            w.file_as(
                w.alice,
                &format!("h-{name}"),
                EditKind::FilePatch,
                "f",
                payload,
                CAP,
            )
            .await,
        );
        assert_eq!(got, "payload has forbidden characters", "{name}");
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM suggested_edit")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test]
async fn the_payload_limit_holds_in_the_store_and_in_the_table_check(pool: PgPool) {
    let w = world(pool).await;
    let at = "a".repeat(MAX_EDIT_PAYLOAD_BYTES);
    w.file("at", EditKind::FilePatch, "f", &at).await;
    let over = "a".repeat(MAX_EDIT_PAYLOAD_BYTES + 1);
    let got = refused(
        w.file_as(w.alice, "over", EditKind::FilePatch, "f", &over, CAP)
            .await,
    );
    assert_eq!(got, "payload too large");
    let insert = "INSERT INTO suggested_edit (project_id, kind, target, base_hash, payload, filed_by) \
                  SELECT id, 'file_patch', 't', 'h', $1, 'x' FROM work_project";
    sqlx::query(insert)
        .bind(&at)
        .execute(&w.pool)
        .await
        .unwrap();
    let err = sqlx::query(insert)
        .bind(&over)
        .execute(&w.pool)
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("suggested_edit_payload_check"),
        "{err}"
    );
}

#[sqlx::test]
async fn a_secret_in_a_payload_is_refused_and_one_straddling_the_cap_never_reaches_a_row(
    pool: PgPool,
) {
    let w = world(pool).await;
    let inside = "--- a\n+key = s3cr3t-token-value\n";
    assert_eq!(
        refused(
            w.file_as(w.alice, "s1", EditKind::FilePatch, "f", inside, CAP)
                .await
        ),
        "payload holds a secret"
    );
    let secret = "s3cr3t-token-value";
    let mut straddle = "a".repeat(MAX_EDIT_PAYLOAD_BYTES - 4);
    straddle.push_str(secret);
    assert_eq!(
        refused(
            w.file_as(w.alice, "s2", EditKind::FilePatch, "f", &straddle, CAP)
                .await
        ),
        "payload too large"
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM suggested_edit")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test]
async fn the_pending_cap_refuses_the_edit_just_over_it(pool: PgPool) {
    let w = world(pool).await;
    let one = w
        .file_as(w.alice, "a", EditKind::FilePatch, "f", "d1", 2)
        .await
        .unwrap();
    w.file_as(w.alice, "b", EditKind::FilePatch, "f", "d2", 2)
        .await
        .unwrap();
    let got = refused(
        w.file_as(w.alice, "c", EditKind::FilePatch, "f", "d3", 2)
            .await,
    );
    assert_eq!(got, REASON_TOO_MANY_PENDING);
    w.decide("rej", one.id, EditDecision::Reject).await.unwrap();
    w.file_as(w.alice, "d", EditKind::FilePatch, "f", "d4", 2)
        .await
        .unwrap();
}

#[sqlx::test]
async fn a_slice_change_after_filing_makes_the_edit_stale_on_list_and_get(pool: PgPool) {
    let w = world(pool).await;
    let edit = w.slice_op("k", "core", "add-path\tsrc/extra").await;
    let other = w.slice_op("k2", "web", "add-path\tsrc/more").await;
    w.slices(&[("core", &["src/core", "src/other"]), ("web", &["src/web"])])
        .await;
    let listed = w
        .store
        .list_edits(
            w.alice,
            &ListEditsRequest {
                project: "p".to_owned(),
                state: None,
            },
        )
        .await
        .unwrap();
    let states: Vec<(u64, EditState)> = listed
        .edits
        .iter()
        .map(|e| (e.id, EditState::try_from(e.state).unwrap()))
        .collect();
    assert_eq!(
        states,
        [(edit.id, EditState::Stale), (other.id, EditState::Pending)]
    );
    let stale_only = w
        .store
        .list_edits(
            w.alice,
            &ListEditsRequest {
                project: "p".to_owned(),
                state: Some(EditState::Stale.into()),
            },
        )
        .await
        .unwrap();
    assert_eq!(stale_only.edits.len(), 1);
    let third = w.slice_op("k3", "web", "add-path\tsrc/third").await;
    w.slices(&[
        ("core", &["src/core", "src/other"]),
        ("web", &["src/web", "src/w2"]),
    ])
    .await;
    assert_eq!(w.state_of(third.id).await, EditState::Stale);
}

#[sqlx::test]
async fn a_stale_edit_cannot_be_accepted_but_can_be_rejected(pool: PgPool) {
    let w = world(pool).await;
    let edit = w.slice_op("k", "core", "add-path\tsrc/extra").await;
    w.slices(&[("core", &["src/core", "src/other"]), ("web", &["src/web"])])
        .await;
    let got = refused(w.decide("d1", edit.id, EditDecision::Accept).await);
    assert_eq!(got, REASON_STALE);
    let state: String = sqlx::query_scalar("SELECT state FROM suggested_edit WHERE id = $1")
        .bind(i64::try_from(edit.id).unwrap())
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(state, "stale");
    assert_eq!(w.stored().await["core"], ["src/core", "src/other"]);
    let rejected = w.decide("d2", edit.id, EditDecision::Reject).await.unwrap();
    assert_eq!(
        EditState::try_from(rejected.state).unwrap(),
        EditState::Rejected
    );
}

#[sqlx::test]
async fn a_pitfall_change_after_filing_makes_a_pitfall_edit_stale(pool: PgPool) {
    let w = world(pool).await;
    let edit = w
        .file("p1", EditKind::Pitfall, "sqlx consts", "cause one\nfix one")
        .await;
    w.store
        .record_pitfall(
            w.alice,
            &RecordPitfallRequest {
                key: "rp".to_owned(),
                project: Some("p".to_owned()),
                symptom: "sqlx consts".to_owned(),
                cause: "other cause".to_owned(),
                fix: "other fix".to_owned(),
            },
            &w.redactor,
        )
        .await
        .unwrap();
    assert_eq!(w.state_of(edit.id).await, EditState::Stale);
}

#[sqlx::test]
async fn accepting_each_slice_op_applies_it_in_the_decide_transaction(pool: PgPool) {
    let w = world(pool).await;
    let ops: [(&str, &str, &str); 5] = [
        ("core", "add-path\tsrc/extra", "core:src/core,src/extra"),
        ("core", "remove-path\tsrc/core", "core:"),
        ("core", "move-path\tsrc/core\tweb", "web:src/core,src/web"),
        ("fresh", "create-slice\tlib/a\tlib/b", "fresh:lib/a,lib/b"),
        ("web", "delete-slice", "web:"),
    ];
    for (n, (target, payload, expect)) in ops.into_iter().enumerate() {
        w.slices(&[("core", &["src/core"]), ("web", &["src/web"])])
            .await;
        let edit = w.slice_op(&format!("f{n}"), target, payload).await;
        let done = w
            .decide(&format!("d{n}"), edit.id, EditDecision::Accept)
            .await
            .unwrap();
        assert_eq!(
            EditState::try_from(done.state).unwrap(),
            EditState::Accepted,
            "{payload}"
        );
        assert_eq!(done.decided_by, Some(w.alice.try_into().unwrap()));
        let (name, paths) = expect.split_once(':').unwrap();
        let got = w.stored().await;
        let want: Vec<&str> = paths.split(',').filter(|p| !p.is_empty()).collect();
        match got.get(name) {
            Some(have) => assert_eq!(have, &want, "{payload}"),
            None => assert!(want.is_empty(), "{payload}: slice {name} gone"),
        }
        if payload == "delete-slice" {
            assert!(!got.contains_key("web"), "{payload}");
        }
    }
}

#[sqlx::test]
async fn an_accept_that_breaks_the_overlap_rule_rolls_back_and_stays_pending(pool: PgPool) {
    let w = world(pool).await;
    w.slices(&[("core", &["src/core"]), ("web", &["src/web/deep"])])
        .await;
    let edit = w.slice_op("k", "core", "add-path\tsrc/web").await;
    let got = refused(w.decide("d", edit.id, EditDecision::Accept).await);
    assert_eq!(got, REASON_DOES_NOT_APPLY);
    assert_eq!(w.state_of(edit.id).await, EditState::Pending);
    assert_eq!(w.stored().await["core"], ["src/core"]);
    let missing = w.slice_op("k2", "core", "remove-path\tsrc/none").await;
    assert_eq!(
        refused(w.decide("d2", missing.id, EditDecision::Accept).await),
        REASON_DOES_NOT_APPLY
    );
    let exists = w.slice_op("k3", "core", "create-slice\tlib/x").await;
    assert_eq!(
        refused(w.decide("d3", exists.id, EditDecision::Accept).await),
        REASON_DOES_NOT_APPLY
    );
}

#[sqlx::test]
async fn accepting_a_pitfall_edit_creates_then_changes_the_project_pitfall(pool: PgPool) {
    let w = world(pool).await;
    let first = w
        .file("p1", EditKind::Pitfall, "trap", "cause one\nfix one")
        .await;
    w.decide("d1", first.id, EditDecision::Accept)
        .await
        .unwrap();
    let row = |pool: PgPool| async move {
        sqlx::query_as::<_, (String, String)>(
            "SELECT cause, fix FROM pitfall WHERE symptom = 'trap' AND project_id IS NOT NULL",
        )
        .fetch_one(&pool)
        .await
        .unwrap()
    };
    assert_eq!(
        row(w.pool.clone()).await,
        ("cause one".to_owned(), "fix one".to_owned())
    );
    let second = w
        .file("p2", EditKind::Pitfall, "trap", "cause two\nfix two")
        .await;
    w.decide("d2", second.id, EditDecision::Accept)
        .await
        .unwrap();
    assert_eq!(
        row(w.pool.clone()).await,
        ("cause two".to_owned(), "fix two".to_owned())
    );
}

#[sqlx::test]
async fn a_file_patch_is_marked_accepted_and_never_goes_stale_or_applies(pool: PgPool) {
    let w = world(pool).await;
    let before = w.stored().await;
    let edit = w
        .file("fp", EditKind::FilePatch, "src/lib.rs", "--- a\n+++ b\n")
        .await;
    w.slices(&[("core", &["src/core", "src/n"]), ("web", &["src/web"])])
        .await;
    assert_eq!(w.state_of(edit.id).await, EditState::Pending);
    let done = w.decide("d", edit.id, EditDecision::Accept).await.unwrap();
    assert_eq!(
        EditState::try_from(done.state).unwrap(),
        EditState::Accepted
    );
    assert_ne!(w.stored().await, before);
    let pitfalls: i64 = sqlx::query_scalar("SELECT count(*) FROM pitfall")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(pitfalls, 0);
}

#[sqlx::test]
async fn a_decided_edit_cannot_be_decided_again_and_an_unset_decision_is_refused(pool: PgPool) {
    let w = world(pool).await;
    let edit = w.file("fp", EditKind::FilePatch, "a.rs", "d").await;
    w.decide("d1", edit.id, EditDecision::Reject).await.unwrap();
    assert_eq!(
        refused(w.decide("d2", edit.id, EditDecision::Accept).await),
        REASON_DECIDED
    );
    assert_eq!(
        refused(w.decide("d3", edit.id, EditDecision::Unspecified).await),
        "invalid decision"
    );
    assert_eq!(
        refused(w.decide("d4", edit.id + 99, EditDecision::Accept).await),
        "edit not found"
    );
}

#[sqlx::test]
async fn the_bootstrap_user_cannot_decide_even_past_the_auth_layer(pool: PgPool) {
    let w = world(pool).await;
    let bootstrap: i64 = sqlx::query_scalar("SELECT bootstrap_user_id()")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    sqlx::query("INSERT INTO work_project (user_id, name) VALUES ($1, 'p')")
        .bind(bootstrap)
        .execute(&w.pool)
        .await
        .unwrap();
    let edit = w
        .file_as(bootstrap, "b1", EditKind::FilePatch, "a.rs", "d", CAP)
        .await
        .unwrap();
    let got = w
        .store
        .decide_edit(
            bootstrap,
            &DecideEditRequest {
                key: "bd".to_owned(),
                project: "p".to_owned(),
                id: edit.id,
                decision: EditDecision::Accept.into(),
            },
        )
        .await;
    assert!(matches!(
        got,
        Err(StoreError::Work(WorkFault::NotInteractive))
    ));
    let state: String = sqlx::query_scalar("SELECT state FROM suggested_edit WHERE id = $1")
        .bind(i64::try_from(edit.id).unwrap())
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(state, "pending");
}

#[sqlx::test]
async fn another_users_project_answers_not_found_for_every_call(pool: PgPool) {
    let w = world(pool).await;
    let bob = user(&w.pool, "bob").await;
    let edit = w.file("fp", EditKind::FilePatch, "a.rs", "d").await;
    let filed = w
        .file_as(bob, "x", EditKind::FilePatch, "a.rs", "d", CAP)
        .await;
    assert_eq!(refused(filed), "work project not found");
    let list = w
        .store
        .list_edits(
            bob,
            &ListEditsRequest {
                project: "p".to_owned(),
                state: None,
            },
        )
        .await;
    assert!(matches!(
        list,
        Err(StoreError::Work(WorkFault::ProjectNotFound))
    ));
    let get = w
        .store
        .get_edit(
            bob,
            &GetEditRequest {
                project: "p".to_owned(),
                id: edit.id,
            },
        )
        .await;
    assert!(matches!(
        get,
        Err(StoreError::Work(WorkFault::ProjectNotFound))
    ));
    let decide = w
        .store
        .decide_edit(
            bob,
            &DecideEditRequest {
                key: "d".to_owned(),
                project: "p".to_owned(),
                id: edit.id,
                decision: EditDecision::Accept.into(),
            },
        )
        .await;
    assert!(matches!(
        decide,
        Err(StoreError::Work(WorkFault::ProjectNotFound))
    ));
}

async fn blocked_backends(pool: &PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' \
         AND datname = current_database()",
    )
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn decide_blocked_on_the_pitfall_row(
    w: &World,
    edit_id: u64,
    holder_sql: &'static str,
) -> (Result<SuggestedEdit, StoreError>, i64) {
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM pitfall WHERE symptom = 'trap' FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let store = w.store.clone();
    let alice = w.alice;
    let task = tokio::spawn(async move {
        store
            .decide_edit(
                alice,
                &DecideEditRequest {
                    key: "d".to_owned(),
                    project: "p".to_owned(),
                    id: edit_id,
                    decision: EditDecision::Accept.into(),
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while blocked_backends(&w.pool).await == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(!task.is_finished());
    sqlx::query(holder_sql).execute(&mut *holder).await.unwrap();
    holder.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    let rows = sqlx::query_scalar("SELECT count(*) FROM pitfall WHERE symptom = 'trap'")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    (result, rows)
}

async fn pitfall_text(w: &World) -> Vec<(String, String)> {
    sqlx::query_as("SELECT cause, fix FROM pitfall WHERE symptom = 'trap'")
        .fetch_all(&w.pool)
        .await
        .unwrap()
}

async fn record_trap(w: &World, key: &str, cause: &str, fix: &str) {
    w.store
        .record_pitfall(
            w.alice,
            &RecordPitfallRequest {
                key: key.to_owned(),
                project: Some("p".to_owned()),
                symptom: "trap".to_owned(),
                cause: cause.to_owned(),
                fix: fix.to_owned(),
            },
            &w.redactor,
        )
        .await
        .unwrap();
}

#[sqlx::test]
async fn an_accept_whose_pitfall_changed_while_it_waited_for_the_row_lock_is_stale(pool: PgPool) {
    let w = world(pool).await;
    record_trap(&w, "rp", "cause one", "fix one").await;
    let edit = w
        .file("p1", EditKind::Pitfall, "trap", "cause two\nfix two")
        .await;
    let (result, rows) = decide_blocked_on_the_pitfall_row(
        &w,
        edit.id,
        "UPDATE pitfall SET cause = 'raced', fix = 'raced' WHERE symptom = 'trap'",
    )
    .await;
    assert_eq!(refused(result), REASON_STALE);
    assert_eq!(rows, 1);
    assert_eq!(
        pitfall_text(&w).await,
        vec![("raced".to_owned(), "raced".to_owned())]
    );
    assert_eq!(w.state_of(edit.id).await, EditState::Stale);
}

#[sqlx::test]
async fn an_accept_whose_pitfall_was_deleted_while_it_waited_for_the_row_lock_is_stale(
    pool: PgPool,
) {
    let w = world(pool).await;
    record_trap(&w, "rp", "cause one", "fix one").await;
    let edit = w
        .file("p1", EditKind::Pitfall, "trap", "cause two\nfix two")
        .await;
    let (result, rows) = decide_blocked_on_the_pitfall_row(
        &w,
        edit.id,
        "DELETE FROM pitfall WHERE symptom = 'trap'",
    )
    .await;
    assert_eq!(refused(result), REASON_STALE);
    assert_eq!(rows, 0);
    assert_eq!(w.state_of(edit.id).await, EditState::Stale);
}

#[sqlx::test]
async fn decide_waits_on_the_project_row_and_then_sees_what_the_lock_holder_committed(
    pool: PgPool,
) {
    let w = world(pool).await;
    let edit = w.slice_op("k", "core", "add-path\tsrc/extra").await;
    let mut holder = w.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM work_project WHERE name = 'p' FOR UPDATE")
        .execute(&mut *holder)
        .await
        .unwrap();
    let store = w.store.clone();
    let (alice, id) = (w.alice, edit.id);
    let task = tokio::spawn(async move {
        store
            .decide_edit(
                alice,
                &DecideEditRequest {
                    key: "d".to_owned(),
                    project: "p".to_owned(),
                    id,
                    decision: EditDecision::Accept.into(),
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        while blocked_backends(&w.pool).await == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(!task.is_finished());
    sqlx::query(
        "INSERT INTO work_slice_path (slice_id, path) \
         SELECT id, 'src/changed' FROM work_slice WHERE name = 'core'",
    )
    .execute(&mut *holder)
    .await
    .unwrap();
    holder.commit().await.unwrap();
    let got = tokio::time::timeout(Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(refused(got), REASON_STALE);
}

struct Rig {
    addr: std::net::SocketAddr,
    pool: PgPool,
    users: Users,
}

async fn rig(pool: PgPool) -> Rig {
    let store = Store::new(pool.clone());
    store.migrate().await.unwrap();
    let users = Users::new(pool.clone());
    let auth = BearerAuth::new(
        &Token::new(BOX.to_owned()).unwrap(),
        Some(&Token::new(CLIENT.to_owned()).unwrap()),
    )
    .with_users(users.clone());
    let incoming = TcpIncoming::bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = incoming.local_addr().unwrap();
    tokio::spawn(router(&store, &auth).serve_with_incoming(incoming));
    Rig { addr, pool, users }
}

fn bearer<T>(message: T, token: &str) -> Request<T> {
    let mut request = Request::new(message);
    request.metadata_mut().insert(
        "authorization",
        MetadataValue::try_from(format!("Bearer {token}")).unwrap(),
    );
    request
}

#[derive(Clone, Copy, Debug)]
enum Rpc {
    File,
    List,
    Get,
    Decide,
}

async fn call(
    rig: &Rig,
    rpc: Rpc,
    token: &str,
    project: &str,
    id: u64,
) -> Result<(), tonic::Status> {
    let channel = Endpoint::from_shared(format!("http://{}", rig.addr))
        .unwrap()
        .connect_lazy();
    let mut client = FleetEditClient::new(channel);
    let project = project.to_owned();
    match rpc {
        Rpc::File => client
            .file_edit(bearer(
                FileEditRequest {
                    key: format!("f-{token}"),
                    project,
                    kind: EditKind::FilePatch.into(),
                    target: "a.rs".to_owned(),
                    base_hash: "blob".to_owned(),
                    payload: "d".to_owned(),
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::List => client
            .list_edits(bearer(
                ListEditsRequest {
                    project,
                    state: None,
                },
                token,
            ))
            .await
            .map(drop),
        Rpc::Get => client
            .get_edit(bearer(GetEditRequest { project, id }, token))
            .await
            .map(drop),
        Rpc::Decide => client
            .decide_edit(bearer(
                DecideEditRequest {
                    key: format!("d-{token}"),
                    project,
                    id,
                    decision: EditDecision::Reject.into(),
                },
                token,
            ))
            .await
            .map(drop),
    }
}

#[sqlx::test]
async fn every_token_class_meets_the_edit_gate_it_is_owed(pool: PgPool) {
    let rig = rig(pool).await;
    let alice = user(&rig.pool, "alice").await;
    let api = rig.users.create_api_token(alice, "t").await.unwrap();
    let api_value = String::from_utf8(api.token.expose().to_vec()).unwrap();
    let revoked = rig.users.create_api_token(alice, "r").await.unwrap();
    let revoked_value = String::from_utf8(revoked.token.expose().to_vec()).unwrap();
    rig.users.revoke_api_token(alice, revoked.id).await.unwrap();
    let bootstrap = rig.users.bootstrap_user().await.unwrap();
    for owner in [alice, bootstrap] {
        sqlx::query("INSERT INTO work_project (user_id, name) VALUES ($1, 'own')")
            .bind(owner)
            .execute(&rig.pool)
            .await
            .unwrap();
    }
    let rows: [(&str, &str, [Option<Code>; 4]); 5] = [
        (
            "client",
            CLIENT,
            [None, None, None, Some(Code::PermissionDenied)],
        ),
        ("box", BOX, [Some(Code::PermissionDenied); 4]),
        ("api", &api_value, [None, None, None, None]),
        (
            "revoked api",
            &revoked_value,
            [Some(Code::Unauthenticated); 4],
        ),
        (
            "session id as bearer",
            "d5cb2d7a5e1f4c0e9a3b",
            [Some(Code::Unauthenticated); 4],
        ),
    ];
    for (label, token, expect) in rows {
        for (rpc, want) in [Rpc::File, Rpc::List, Rpc::Get, Rpc::Decide]
            .into_iter()
            .zip(expect)
        {
            let got = call(&rig, rpc, token, "own", 1).await;
            match (want, got) {
                (Some(code), Err(status)) => {
                    assert_eq!(status.code(), code, "{label} {rpc:?}");
                    if code == Code::PermissionDenied
                        && matches!(rpc, Rpc::Decide)
                        && label == "client"
                    {
                        assert_eq!(status.message(), USER_TOKEN_REQUIRED);
                    }
                }
                (None, Err(status)) => {
                    assert_eq!(status.code(), Code::NotFound, "{label} {rpc:?}: {status}");
                }
                (None, Ok(())) => {}
                (Some(code), Ok(())) => panic!("{label} {rpc:?} passed, wanted {code:?}"),
            }
        }
    }
}
