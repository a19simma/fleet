//! Store tests. They need a Postgres superuser URL in `DATABASE_URL`, which `#[sqlx::test]`
//! reads to create one database per test. A missing variable fails the test.

use fleet_core::{BoxName, Envelope, EventId, Identity, Source};
use fleet_proto::v1::fleet_ingest_server::FleetIngest;
use fleet_proto::v1::{
    BoxStatus, BoxView, HeartbeatRequest, PushEventsRequest, QueuedEvent, SessionState,
};
use fleet_server::service::FleetService;
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

fn at(mut env: Envelope, ts: u64) -> Envelope {
    env.ts = ts;
    env
}

fn on_boot(mut env: Envelope, boot: &str) -> Envelope {
    boot.clone_into(&mut env.boot_id);
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

#[sqlx::test]
async fn out_of_range_timestamps_are_rejected_and_acked(pool: PgPool) {
    let store = Store::new(pool);
    let far = 9_000_000_000_000_000_000;
    let mut occurred = prompt("b", "go");
    occurred.occurred_at = Some(far);
    let out = store
        .ingest(&[
            (1, at(prompt("a", "go"), far)),
            (2, occurred),
            (3, prompt("c", "ok")),
        ])
        .await
        .unwrap();
    assert_eq!((out.stored, out.duplicate), (1, 0));
    let seqs: Vec<u64> = out.rejected.iter().map(|r| r.0).collect();
    assert_eq!(seqs, vec![1, 2]);
}

#[sqlx::test]
async fn unsupported_schema_version_is_rejected(pool: PgPool) {
    let store = Store::new(pool);
    let mut old = prompt("a", "go");
    old.schema_version = 2;
    let out = store.ingest(&[(1, old)]).await.unwrap();
    assert_eq!(out.stored, 0);
    assert_eq!(out.rejected.len(), 1);
    assert_eq!(out.retry_from_seq, Some(1));
}

fn wire(seq: u64, schema_version: u32) -> QueuedEvent {
    QueuedEvent {
        seq,
        envelope: Some(fleet_proto::v1::Envelope {
            id: format!("{seq:0>26}"),
            schema_version,
            r#box: box_name(),
            hostname: "h".into(),
            machine_id: "m".into(),
            boot_id: "b".into(),
            source: "hook".into(),
            kind: "hook.stop".into(),
            ts_ms: 1,
            payload_json: "{}".into(),
            ..fleet_proto::v1::Envelope::default()
        }),
    }
}

async fn stored_events(pool: &PgPool) -> Result<i64, String> {
    sqlx::query_scalar("SELECT count(*) FROM events")
        .fetch_one(pool)
        .await
        .map_err(|err| err.to_string())
}

#[sqlx::test]
async fn unsupported_event_mid_batch_holds_the_ack_and_resend_dedupes(pool: PgPool) {
    let service = FleetService::new(Store::new(pool.clone()));
    let batch = vec![wire(1, 1), wire(2, 2), wire(3, 1)];
    let reply = service
        .push_events(tonic::Request::new(PushEventsRequest {
            events: batch.clone(),
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.acked_through_seq, 1);
    let seqs: Vec<u64> = reply.rejected.iter().map(|r| r.seq).collect();
    assert_eq!(seqs, vec![2]);
    let first: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE seq = 1")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(first, 1);
    let before = stored_events(&pool).await.unwrap();
    let again = service
        .push_events(tonic::Request::new(PushEventsRequest { events: batch }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(again.acked_through_seq, 1);
    assert_eq!(again.stored, 0);
    assert_eq!(stored_events(&pool).await.unwrap(), before);
}

#[sqlx::test]
async fn unsupported_first_event_acks_nothing_and_stores_the_valid_one(pool: PgPool) {
    let service = FleetService::new(Store::new(pool.clone()));
    let reply = service
        .push_events(tonic::Request::new(PushEventsRequest {
            events: vec![wire(1, 2), wire(2, 1)],
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(reply.acked_through_seq, 0);
    assert_eq!(reply.stored, 1);
    let second: i64 = sqlx::query_scalar("SELECT count(*) FROM events WHERE seq = 2")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(second, 1);
}

#[sqlx::test]
async fn duplicate_resend_leaves_box_row_unchanged(pool: PgPool) {
    let store = Store::new(pool.clone());
    store
        .ingest(&[(1, on_boot(prompt("a", "go"), "boot-a"))])
        .await
        .unwrap();
    let before: (String, bool) =
        sqlx::query_as("SELECT boot_id, last_event_at < now() - interval '1 second' FROM boxes")
            .fetch_one(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE boxes SET last_event_at = now() - interval '1 hour'")
        .execute(&pool)
        .await
        .unwrap();
    let stamp = |pool: PgPool| async move {
        sqlx::query_as::<_, (String, String)>("SELECT boot_id, last_event_at::text FROM boxes")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let first = stamp(pool.clone()).await;
    let out = store
        .ingest(&[(1, on_boot(prompt("a", "go"), "boot-b"))])
        .await
        .unwrap();
    assert_eq!((out.stored, out.duplicate), (0, 1));
    assert_eq!(stamp(pool).await, first);
    assert_eq!(before.0, "boot-a");
}

#[sqlx::test]
async fn older_boot_does_not_overwrite_newer_identity(pool: PgPool) {
    let store = Store::new(pool.clone());
    let newer = at(on_boot(prompt("a", "go"), "boot-new"), 1_790_000_005_000);
    let older = at(on_boot(prompt("b", "go"), "boot-old"), 1_790_000_001_000);
    store.ingest(&[(1, newer)]).await.unwrap();
    store.ingest(&[(1, older)]).await.unwrap();
    assert_eq!(fleet(&store).await.unwrap().boot_id, "boot-new");
}

#[sqlx::test]
async fn far_future_timestamp_cannot_freeze_identity(pool: PgPool) {
    let store = Store::new(pool);
    let future = at(
        on_boot(prompt("a", "go"), "boot-future"),
        fleet_server::store::MAX_TS_MS,
    );
    store.ingest(&[(1, future)]).await.unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let later = at(
        on_boot(prompt("b", "go"), "boot-new"),
        u64::try_from(now_ms).unwrap() + 1_000,
    );
    store.ingest(&[(2, later)]).await.unwrap();
    assert_eq!(fleet(&store).await.unwrap().boot_id, "boot-new");
}

#[sqlx::test]
async fn batch_identity_comes_from_newest_new_event(pool: PgPool) {
    let store = Store::new(pool);
    let newer = at(on_boot(prompt("a", "go"), "boot-new"), 1_790_000_005_000);
    let older = at(on_boot(prompt("b", "go"), "boot-old"), 1_790_000_001_000);
    store.ingest(&[(5, older), (1, newer)]).await.unwrap();
    assert_eq!(fleet(&store).await.unwrap().boot_id, "boot-new");
}

#[sqlx::test]
async fn late_state_event_survives_newer_notification(pool: PgPool) {
    let store = Store::new(pool);
    let stopped = at(stop("b", "done"), 1_790_000_010_000);
    let note = at(
        event("hook.notification", "n", "s", json!({"message": "hi"})),
        1_790_000_020_000,
    );
    let stalled = at(
        event("session.stalled", "t", "s", json!({})),
        1_790_000_015_000,
    );
    store.ingest(&[(1, stopped)]).await.unwrap();
    store.ingest(&[(2, note)]).await.unwrap();
    store.ingest(&[(3, stalled)]).await.unwrap();
    assert_eq!(
        session_state(&store).await.unwrap().0,
        SessionState::Stalled
    );
}

#[sqlx::test]
async fn older_prompt_after_stop_leaves_idle(pool: PgPool) {
    let store = Store::new(pool);
    let stopped = at(stop("b", "done"), 1_790_000_010_000);
    let late_prompt = at(prompt("a", "go"), 1_790_000_005_000);
    store.ingest(&[(2, stopped)]).await.unwrap();
    store.ingest(&[(1, late_prompt)]).await.unwrap();
    assert_eq!(session_state(&store).await.unwrap().0, SessionState::Idle);
}

#[sqlx::test]
async fn literal_escape_text_is_stored_and_real_nul_is_rejected(pool: PgPool) {
    let store = Store::new(pool.clone());
    let typed = event(
        "hook.stop",
        "t",
        "s",
        json!({"last_assistant_message": "the text \\u0000 is fine"}),
    );
    let nul_value = event("hook.stop", "v", "s", json!({"a": ["x\u{0}"]}));
    let nul_key = event("hook.stop", "k", "s", json!({"a\u{0}b": 1}));
    let out = store
        .ingest(&[(1, typed), (2, nul_value), (3, nul_key)])
        .await
        .unwrap();
    assert_eq!(out.stored, 1);
    let seqs: Vec<u64> = out.rejected.iter().map(|r| r.0).collect();
    assert_eq!(seqs, vec![2, 3]);
    let view = fleet(&store).await.unwrap();
    assert_eq!(
        view.sessions.first().unwrap().last_message.as_deref(),
        Some("the text \\u0000 is fine")
    );
}

#[sqlx::test]
async fn notification_without_a_row_creates_none(pool: PgPool) {
    let store = Store::new(pool.clone());
    let note = event("hook.notification", "n", "s", json!({"message": "hi"}));
    let out = store.ingest(&[(1, note)]).await.unwrap();
    assert_eq!(out.stored, 1);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);

    store.ingest(&[(2, prompt("a", "go"))]).await.unwrap();
    let again = event("hook.notification", "n2", "s", json!({"message": "later"}));
    store.ingest(&[(3, again)]).await.unwrap();
    let kept: Option<String> = sqlx::query_scalar("SELECT last_notification FROM sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kept.as_deref(), Some("later"));
    assert_eq!(
        session_state(&store).await.unwrap().0,
        SessionState::Working
    );
}

#[sqlx::test]
async fn empty_heartbeat_version_keeps_stored_value(pool: PgPool) {
    let store = Store::new(pool);
    let name = BoxName::new(&box_name()).unwrap();
    store.heartbeat(&name, &heartbeat()).await.unwrap();
    let bare = HeartbeatRequest {
        fleetd_version: String::new(),
        ..heartbeat()
    };
    store.heartbeat(&name, &bare).await.unwrap();
    assert_eq!(fleet(&store).await.unwrap().fleetd_version, "0.2.1");
}

#[sqlx::test]
async fn pre_reboot_event_after_new_boot_heartbeat_keeps_boot_id(pool: PgPool) {
    let store = Store::new(pool);
    let name = BoxName::new(&box_name()).unwrap();
    let before_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let fresh = HeartbeatRequest {
        boot_id: "boot-new".into(),
        ..heartbeat()
    };
    store.heartbeat(&name, &fresh).await.unwrap();
    let late = at(on_boot(prompt("a", "go"), "boot-old"), before_ms);
    store.ingest(&[(1, late)]).await.unwrap();
    assert_eq!(fleet(&store).await.unwrap().boot_id, "boot-new");
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
async fn bad_queue_value_does_not_fail_list_fleet(pool: PgPool) {
    let store = Store::new(pool.clone());
    store.ingest(&[(1, prompt("a", "go"))]).await.unwrap();
    let name = BoxName::new(&box_name()).unwrap();
    store.heartbeat(&name, &heartbeat()).await.unwrap();
    sqlx::query("UPDATE boxes SET state = jsonb_set(state, '{queue_pending}', '\"junk\"')")
        .execute(&pool)
        .await
        .unwrap();
    let view = fleet(&store).await.unwrap();
    assert_eq!(view.queue_pending, 0);
    assert_eq!(view.queue_oldest_age_s, 7);
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
