//! Claim, ack and nack over a temp SQLite file.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code asserts by panicking"
)]

use std::time::Duration;

use fleet_core::{Envelope, Identity, Source};
use fleetd::{Enqueued, Limits, OVERFLOW_KIND, Store, fresh_id, now_ms};
use serde_json::json;
use tempfile::TempDir;

const BIG: Limits = Limits {
    max_bytes: u64::MAX,
    max_age: Duration::from_secs(14 * 86_400),
};

fn envelope(kind: &str, pad: usize) -> Envelope {
    let identity = Identity {
        box_name: "alpha".into(),
        hostname: "host".into(),
        machine_id: "machine".into(),
        boot_id: "boot".into(),
    };
    let ts = now_ms();
    let mut env = Envelope::new(&identity, fresh_id(ts), Source::Fleetd, kind, ts);
    env.payload = json!({ "pad": "x".repeat(pad) });
    env
}

async fn open(dir: &TempDir, limits: Limits) -> Store {
    Store::open(&dir.path().join("q.db"), limits).await.unwrap()
}

async fn fill(store: &Store, count: usize, pad: usize) -> Vec<i64> {
    let mut seqs = Vec::new();
    for _ in 0..count {
        let Enqueued::Stored { seq } = store
            .enqueue(&envelope("hook.stop", pad), now_ms())
            .await
            .unwrap()
        else {
            panic!("event not stored");
        };
        seqs.push(seq);
    }
    seqs
}

fn seqs(batch: &[fleetd::QueuedEvent]) -> Vec<i64> {
    batch.iter().map(|event| event.seq).collect()
}

#[tokio::test]
async fn claim_returns_pending_rows_in_seq_order_and_marks_them_inflight() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, 5, 10).await;
    let batch = store.claim(3, u64::MAX, now_ms()).await.unwrap();
    assert_eq!(seqs(&batch), stored[..3].to_vec());
    assert!(batch.iter().all(|event| event.state == "inflight"));
    let rows = store.list(None).await.unwrap();
    let states: Vec<_> = rows.iter().map(|row| row.state.as_str()).collect();
    assert_eq!(
        states,
        ["inflight", "inflight", "inflight", "pending", "pending"]
    );
    let next = store.claim(10, u64::MAX, now_ms()).await.unwrap();
    assert_eq!(seqs(&next), stored[3..].to_vec());
    let empty = store.claim(10, u64::MAX, now_ms()).await.unwrap();
    assert_eq!(empty.len(), 0);
}

#[tokio::test]
async fn claim_rebuilds_the_envelope() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let sent = envelope("hook.stop", 4);
    store.enqueue(&sent, now_ms()).await.unwrap();
    let batch = store.claim(1, u64::MAX, now_ms()).await.unwrap();
    assert_eq!(batch[0].envelope().unwrap(), sent);
}

#[tokio::test]
async fn claim_stops_at_the_byte_limit_but_returns_at_least_one() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, 4, 500).await;
    let one = store.list(Some(1)).await.unwrap();
    let size = serde_json::to_string(&one[0].payload).unwrap().len() as u64;

    let tiny = store.claim(10, 1, now_ms()).await.unwrap();
    assert_eq!(seqs(&tiny), stored[..1].to_vec());

    let two = store.claim(10, size * 2 + 10, now_ms()).await.unwrap();
    assert_eq!(seqs(&two), stored[1..3].to_vec());
}

#[tokio::test]
async fn claim_skips_rows_not_yet_due() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, 2, 10).await;
    let now = now_ms();
    let first = store.claim(1, u64::MAX, now).await.unwrap();
    store.nack(&seqs(&first), now + 60_000).await.unwrap();
    let batch = store.claim(10, u64::MAX, now).await.unwrap();
    assert_eq!(seqs(&batch), stored[1..].to_vec());
    let later = store.claim(10, u64::MAX, now + 60_000).await.unwrap();
    assert_eq!(seqs(&later), stored[..1].to_vec());
}

#[tokio::test]
async fn ack_removes_claimed_rows_only() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, 3, 10).await;
    let batch = store.claim(2, u64::MAX, now_ms()).await.unwrap();
    let deleted = store.ack(&seqs(&batch)).await.unwrap();
    assert_eq!(deleted, 2);
    let rows = store.list(None).await.unwrap();
    assert_eq!(seqs(&rows), stored[2..].to_vec());
    assert_eq!(store.ack(&stored).await.unwrap(), 0);
    assert_eq!(store.count().await.unwrap(), 1);
}

#[tokio::test]
async fn nack_requeues_with_an_attempt_and_a_retry_time() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    fill(&store, 2, 10).await;
    let batch = store.claim(2, u64::MAX, now_ms()).await.unwrap();
    let retry_at = now_ms() + 5_000;
    assert_eq!(store.nack(&seqs(&batch), retry_at).await.unwrap(), 2);
    let rows = store.list(None).await.unwrap();
    for row in &rows {
        assert_eq!(row.state, "pending");
        assert_eq!(row.attempts, 1);
        assert_eq!(row.next_try_at, i64::try_from(retry_at).unwrap());
    }
}

#[tokio::test]
async fn startup_returns_inflight_rows_to_pending() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, 3, 10).await;
    store.claim(3, u64::MAX, now_ms()).await.unwrap();
    store.close().await.unwrap();
    let reopened = open(&dir, BIG).await;
    let rows = reopened.list(None).await.unwrap();
    assert!(rows.iter().all(|row| row.state == "pending"));
    assert!(rows.iter().all(|row| row.attempts == 0));
    let batch = reopened.claim(10, u64::MAX, now_ms()).await.unwrap();
    assert_eq!(seqs(&batch), stored);
}

#[tokio::test]
async fn enqueue_during_claim_stays_pending_and_is_claimed_next() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, 2, 10).await;
    let extra = envelope("hook.stop", 10);
    let (batch, late) = tokio::join!(
        store.claim(10, u64::MAX, now_ms()),
        store.enqueue(&extra, now_ms()),
    );
    let batch = batch.unwrap();
    let Enqueued::Stored { seq: late } = late.unwrap() else {
        panic!("late event not stored");
    };
    assert!(seqs(&batch).starts_with(&stored));
    store.ack(&seqs(&batch)).await.unwrap();
    let rest = store.claim(10, u64::MAX, now_ms()).await.unwrap();
    let mut all = seqs(&batch);
    all.extend(seqs(&rest));
    let mut expected = stored.clone();
    expected.push(late);
    assert_eq!(all, expected);
}

#[tokio::test]
async fn overflow_while_inflight_goes_to_a_separate_pending_marker() {
    let dir = TempDir::new().unwrap();
    let probe = serde_json::to_string(&envelope("hook.stop", 400))
        .unwrap()
        .len() as u64;
    let store = open(
        &dir,
        Limits {
            max_bytes: probe * 5,
            ..BIG
        },
    )
    .await;
    store
        .enqueue(&envelope("hook.stop", 400), now_ms())
        .await
        .unwrap();
    for _ in 0..8 {
        store
            .enqueue(&envelope("hook.pre_tool_use", 400), now_ms())
            .await
            .unwrap();
    }
    let markers = |rows: &[fleetd::QueuedEvent]| {
        rows.iter()
            .filter(|row| row.kind == OVERFLOW_KIND)
            .map(|row| {
                (
                    row.seq,
                    row.state.clone(),
                    row.payload["payload"]["dropped"].as_u64().unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    let before = markers(&store.list(None).await.unwrap());
    assert_eq!(before.len(), 1);
    let (stale_seq, _, first_count) = before[0].clone();

    let batch = store.claim(100, u64::MAX, now_ms()).await.unwrap();
    assert!(seqs(&batch).contains(&stale_seq));

    for _ in 0..4 {
        store
            .enqueue(&envelope("hook.pre_tool_use", 400), now_ms())
            .await
            .unwrap();
    }
    let during = markers(&store.list(None).await.unwrap());
    assert_eq!(during.len(), 2);
    let inflight = during.iter().find(|m| m.0 == stale_seq).unwrap();
    assert_eq!(inflight.1, "inflight");
    assert_eq!(inflight.2, first_count);
    let fresh = during.iter().find(|m| m.0 != stale_seq).unwrap();
    assert_eq!(fresh.1, "pending");
    assert!(fresh.2 > 0);

    store.ack(&[stale_seq]).await.unwrap();
    let after = markers(&store.list(None).await.unwrap());
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].1, "pending");
    assert_eq!(after[0].2, fresh.2);
}
