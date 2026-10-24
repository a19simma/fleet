//! Store tests. They need a Postgres superuser URL in `DATABASE_URL`, which `#[sqlx::test]`
//! reads to create one database per test. A missing variable fails the test.

use fleet_core::{BoxName, Envelope, EventId, Identity, Source};
use fleet_proto::v1::{BoxStatus, BoxView, HeartbeatRequest, SessionState};
use fleet_server::store::Store;
use serde_json::{Value, json};
use sqlx::PgPool;

fn box_name() -> String {
    format!("box-{}", 1)
}

fn event(kind: &str, tag: &str, session: &str, payload: Value) -> Envelope {
    let identity = Identity {
        box_name: box_name(),
        hostname: "host".into(),
        machine_id: "machine".into(),
        boot_id: "boot".into(),
    };
    let mut env = Envelope::new(
        &identity,
        EventId::derive(kind, &[tag]),
        Source::Hook,
        kind,
        1_790_000_000_000,
    );
    env.session_id = Some(session.to_owned());
    env.payload = payload;
    env
}

fn prompt(tag: &str, text: &str) -> Envelope {
    event(
        "hook.user_prompt_submit",
        tag,
        "s",
        json!({"prompt": text, "synthetic": false}),
    )
}

fn stop(tag: &str, text: &str) -> Envelope {
    event(
        "hook.stop",
        tag,
        "s",
        json!({"last_assistant_message": text}),
    )
}

async fn fleet(store: &Store) -> Result<BoxView, String> {
    let (_, boxes) = store.list_fleet(None).await.map_err(|e| e.to_string())?;
    if boxes.len() != 1 {
        return Err(format!("want one box, got {}", boxes.len()));
    }
    boxes.into_iter().next().ok_or_else(|| "no box".to_owned())
}

async fn session_state(store: &Store) -> Result<(SessionState, BoxView), String> {
    let view = fleet(store).await?;
    let session = view.sessions.first().ok_or("no session row")?;
    let state = SessionState::try_from(session.state).map_err(|e| e.to_string())?;
    Ok((state, view))
}

#[sqlx::test]
async fn duplicate_batch_counts_and_projects_once(pool: PgPool) {
    let store = Store::new(pool);
    let first = vec![(1, prompt("a", "go")), (2, stop("b", "done"))];
    let out = store.ingest(&first).await.unwrap();
    assert_eq!((out.stored, out.duplicate), (2, 0));
    assert_eq!(session_state(&store).await.unwrap().0, SessionState::Idle);

    let again = store.ingest(&[(1, prompt("a", "go"))]).await.unwrap();
    assert_eq!((again.stored, again.duplicate), (0, 1));
    assert_eq!(session_state(&store).await.unwrap().0, SessionState::Idle);
}

#[sqlx::test]
async fn duplicate_inside_one_batch_stores_once(pool: PgPool) {
    let store = Store::new(pool);
    let batch = vec![(1, prompt("a", "go")), (2, prompt("a", "go"))];
    let out = store.ingest(&batch).await.unwrap();
    assert_eq!((out.stored, out.duplicate), (1, 1));
}

#[sqlx::test]
async fn stop_after_prompt_gives_idle(pool: PgPool) {
    let store = Store::new(pool);
    store
        .ingest(&[(1, prompt("a", "fix it")), (2, stop("b", "fixed"))])
        .await
        .unwrap();
    let (state, view) = session_state(&store).await.unwrap();
    assert_eq!(state, SessionState::Idle);
    let session = view.sessions.first().unwrap();
    assert_eq!(session.last_prompt.as_deref(), Some("fix it"));
    assert_eq!(session.last_message.as_deref(), Some("fixed"));
}

#[sqlx::test]
async fn out_of_order_batch_projects_in_seq_order(pool: PgPool) {
    let store = Store::new(pool);
    store
        .ingest(&[(2, stop("b", "fixed")), (1, prompt("a", "fix it"))])
        .await
        .unwrap();
    assert_eq!(session_state(&store).await.unwrap().0, SessionState::Idle);
}

#[sqlx::test]
async fn synthetic_prompt_leaves_last_prompt_and_state(pool: PgPool) {
    let store = Store::new(pool);
    let synthetic = event(
        "hook.user_prompt_submit",
        "c",
        "s",
        json!({"prompt": "<agent-message from=\"x\">hi</agent-message>", "synthetic": true}),
    );
    store
        .ingest(&[
            (1, prompt("a", "real")),
            (2, stop("b", "ok")),
            (3, synthetic),
        ])
        .await
        .unwrap();
    let (state, view) = session_state(&store).await.unwrap();
    assert_eq!(state, SessionState::Idle);
    assert_eq!(
        view.sessions.first().unwrap().last_prompt.as_deref(),
        Some("real")
    );
}

#[sqlx::test]
async fn late_notification_leaves_state(pool: PgPool) {
    let store = Store::new(pool);
    let note = event(
        "hook.notification",
        "n",
        "s",
        json!({"message": "needs permission"}),
    );
    store
        .ingest(&[(1, prompt("a", "go")), (2, stop("b", "ok")), (3, note)])
        .await
        .unwrap();
    assert_eq!(session_state(&store).await.unwrap().0, SessionState::Idle);
}

#[sqlx::test]
async fn ended_reopens_only_on_start_or_real_prompt(pool: PgPool) {
    let store = Store::new(pool);
    let end = event("hook.session_end", "e", "s", json!({}));
    store
        .ingest(&[(1, prompt("a", "go")), (2, end)])
        .await
        .unwrap();
    assert_eq!(session_state(&store).await.unwrap().0, SessionState::Ended);

    let late_stop = stop("b", "late");
    let stalled = event("session.stalled", "t", "s", json!({}));
    let discovered = event("session.discovered", "d", "s", json!({}));
    store
        .ingest(&[(3, late_stop), (4, stalled), (5, discovered)])
        .await
        .unwrap();
    assert_eq!(session_state(&store).await.unwrap().0, SessionState::Ended);

    store.ingest(&[(6, prompt("c", "again"))]).await.unwrap();
    assert_eq!(
        session_state(&store).await.unwrap().0,
        SessionState::Working
    );
}

#[sqlx::test]
async fn discovered_creates_active_only_when_missing(pool: PgPool) {
    let store = Store::new(pool);
    let discovered = event("session.discovered", "d", "s", json!({"cwd": "/w"}));
    store.ingest(&[(1, discovered)]).await.unwrap();
    let (state, view) = session_state(&store).await.unwrap();
    assert_eq!(state, SessionState::Active);
    assert_eq!(
        view.sessions.first().unwrap().workdir.as_deref(),
        Some("/w")
    );

    store.ingest(&[(2, prompt("a", "go"))]).await.unwrap();
    let again = event("session.discovered", "d2", "s", json!({}));
    store.ingest(&[(3, again)]).await.unwrap();
    assert_eq!(
        session_state(&store).await.unwrap().0,
        SessionState::Working
    );
}

#[sqlx::test]
async fn nul_payload_is_rejected_and_acked_without_failing_the_batch(pool: PgPool) {
    let store = Store::new(pool);
    let bad = event(
        "hook.stop",
        "z",
        "s",
        json!({"last_assistant_message": "a\u{0}b"}),
    );
    let out = store
        .ingest(&[(1, bad), (2, prompt("a", "go"))])
        .await
        .unwrap();
    assert_eq!((out.stored, out.duplicate), (1, 0));
    assert_eq!(out.rejected.len(), 1);
    assert_eq!(out.rejected.first().map(|r| r.0), Some(1));
}

fn heartbeat() -> HeartbeatRequest {
    HeartbeatRequest {
        r#box: box_name(),
        hostname: "host".into(),
        machine_id: "machine".into(),
        boot_id: "boot".into(),
        fleetd_version: "0.2.1".into(),
        uptime_s: 100,
        queue_pending: 3,
        queue_oldest_age_s: 7,
        last_ack_age_s: Some(2),
    }
}

#[sqlx::test]
async fn box_status_follows_heartbeat_age(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.ingest(&[(1, prompt("a", "go"))]).await.unwrap();
    let view = fleet(&store).await.unwrap();
    assert_eq!(view.status, i32::from(BoxStatus::Unknown));
    assert_eq!(view.heartbeat_age_s, None);

    let name = BoxName::new(&box_name()).unwrap();
    store.heartbeat(&name, &heartbeat()).await.unwrap();
    let view = fleet(&store).await.unwrap();
    assert_eq!(view.status, i32::from(BoxStatus::Live));
    assert_eq!(view.queue_pending, 3);
    assert_eq!(view.queue_oldest_age_s, 7);
    assert_eq!(view.fleetd_version, "0.2.1");

    let cases = [
        ("89 seconds", BoxStatus::Live),
        ("91 seconds", BoxStatus::Stale),
        ("599 seconds", BoxStatus::Stale),
        ("601 seconds", BoxStatus::Lost),
    ];
    for (age, want) in cases {
        sqlx::query("UPDATE boxes SET last_heartbeat_at = now() - $1::text::interval")
            .bind(age)
            .execute(&pool)
            .await
            .unwrap();
        let view = fleet(&store).await.unwrap();
        assert_eq!(view.status, i32::from(want), "{age}");
        assert!(view.heartbeat_age_s.is_some());
    }
}

#[sqlx::test]
async fn list_fleet_filters_by_box(pool: PgPool) {
    let store = Store::new(pool);
    store.ingest(&[(1, prompt("a", "go"))]).await.unwrap();
    let (_, hit) = store.list_fleet(Some(&box_name())).await.unwrap();
    assert_eq!(hit.len(), 1);
    let (_, miss) = store.list_fleet(Some("other")).await.unwrap();
    assert_eq!(miss.len(), 0);
}
