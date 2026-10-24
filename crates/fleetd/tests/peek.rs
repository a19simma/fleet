//! Peek and range ack over a temp SQLite file.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test code asserts by panicking"
)]

use std::time::Duration;

use fleet_core::{Envelope, Identity, Source};
use fleetd::{Enqueued, Limits, OVERFLOW_KIND, QueuedEvent, Store, fresh_id, now_ms};
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

async fn fill(store: &Store, kind: &str, count: usize, pad: usize) -> Vec<i64> {
    let mut seqs = Vec::new();
    for _ in 0..count {
        let Enqueued::Stored { seq } = store.enqueue(&envelope(kind, pad), now_ms()).await.unwrap()
        else {
            panic!("event not stored");
        };
        seqs.push(seq);
    }
    seqs
}

async fn push(store: &Store, kind: &str, count: usize, pad: usize) {
    for _ in 0..count {
        store.enqueue(&envelope(kind, pad), now_ms()).await.unwrap();
    }
}

fn seqs(batch: &[QueuedEvent]) -> Vec<i64> {
    batch.iter().map(|event| event.seq).collect()
}

fn marker_counts(rows: &[QueuedEvent]) -> Vec<(i64, u64)> {
    rows.iter()
        .filter(|row| row.kind == OVERFLOW_KIND)
        .map(|row| {
            (
                row.seq,
                row.payload
                    .pointer("/payload/dropped")
                    .unwrap()
                    .as_u64()
                    .unwrap(),
            )
        })
        .collect()
}

#[tokio::test]
async fn peek_returns_the_head_in_seq_order_and_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, "hook.stop", 5, 10).await;
    let batch = store.peek(3, u64::MAX).await.unwrap();
    assert_eq!(seqs(&batch), stored[..3].to_vec());
    assert_eq!(store.count().await.unwrap(), 5);
    let again = store.peek(3, u64::MAX).await.unwrap();
    assert_eq!(seqs(&again), seqs(&batch));
}

#[tokio::test]
async fn peek_rebuilds_the_envelope() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let sent = envelope("hook.stop", 4);
    store.enqueue(&sent, now_ms()).await.unwrap();
    let batch = store.peek(1, u64::MAX).await.unwrap();
    assert_eq!(batch[0].envelope().unwrap(), sent);
}

#[tokio::test]
async fn peek_stops_at_the_byte_limit_but_returns_at_least_one() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, "hook.stop", 4, 500).await;
    let one = store.peek(1, u64::MAX).await.unwrap();
    let size = serde_json::to_string(&one[0].payload).unwrap().len() as u64;

    let tiny = store.peek(10, 1).await.unwrap();
    assert_eq!(seqs(&tiny), stored[..1].to_vec());

    let two = store.peek(10, size * 2 + 10).await.unwrap();
    assert_eq!(seqs(&two), stored[..2].to_vec());
}

#[tokio::test]
async fn peek_on_an_empty_queue_is_empty() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    assert_eq!(store.peek(10, u64::MAX).await.unwrap().len(), 0);
}

#[tokio::test]
async fn ack_through_removes_the_range_and_is_idempotent() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, "hook.stop", 4, 10).await;
    store.peek(4, u64::MAX).await.unwrap();
    assert_eq!(store.ack_through(stored[1]).await.unwrap(), 2);
    let rows = store.list(None).await.unwrap();
    assert_eq!(seqs(&rows), stored[2..].to_vec());
    assert_eq!(store.ack_through(stored[1]).await.unwrap(), 0);
    assert_eq!(store.count().await.unwrap(), 2);
}

#[tokio::test]
async fn enqueue_during_peek_lands_after_the_batch_and_survives_its_ack() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, "hook.stop", 2, 10).await;
    let extra = envelope("hook.stop", 10);
    let (batch, late) = tokio::join!(store.peek(10, u64::MAX), store.enqueue(&extra, now_ms()));
    let batch = batch.unwrap();
    let Enqueued::Stored { seq: late } = late.unwrap() else {
        panic!("late event not stored");
    };
    assert!(seqs(&batch).starts_with(&stored));
    let acked = *seqs(&batch).last().unwrap();
    store.ack_through(acked).await.unwrap();
    let rest = store.peek(10, u64::MAX).await.unwrap();
    if acked < late {
        assert_eq!(seqs(&rest), vec![late]);
    } else {
        assert_eq!(rest.len(), 0);
    }
}

#[tokio::test]
async fn overflow_merges_into_one_marker_and_a_new_one_follows_an_ack() {
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
    push(&store, "hook.stop", 1, 400).await;
    push(&store, "hook.pre_tool_use", 8, 400).await;
    let first = marker_counts(&store.list(None).await.unwrap());
    assert_eq!(first.len(), 1);

    push(&store, "hook.pre_tool_use", 4, 400).await;
    let merged = marker_counts(&store.list(None).await.unwrap());
    assert_eq!(merged.len(), 1);
    assert!(merged[0].1 > first[0].1);

    let batch = store.peek(100, u64::MAX).await.unwrap();
    store
        .ack_through(*seqs(&batch).last().unwrap())
        .await
        .unwrap();
    assert_eq!(marker_counts(&store.list(None).await.unwrap()).len(), 0);

    push(&store, "hook.stop", 4, 400).await;
    push(&store, "hook.pre_tool_use", 3, 400).await;
    let after = marker_counts(&store.list(None).await.unwrap());
    assert_eq!(after.len(), 1);
    assert!(after[0].0 > merged[0].0);
}

#[tokio::test]
async fn evicting_a_peeked_row_is_harmless() {
    let dir = TempDir::new().unwrap();
    let probe = serde_json::to_string(&envelope("hook.pre_tool_use", 400))
        .unwrap()
        .len() as u64;
    let store = open(
        &dir,
        Limits {
            max_bytes: probe * 4,
            ..BIG
        },
    )
    .await;
    let early = fill(&store, "hook.pre_tool_use", 2, 400).await;
    let batch = store.peek(10, u64::MAX).await.unwrap();
    assert_eq!(seqs(&batch), early);
    push(&store, "hook.stop", 4, 400).await;
    let remaining = seqs(&store.list(None).await.unwrap());
    assert!(!remaining.contains(&early[0]));

    let top = *seqs(&batch).last().unwrap();
    store.ack_through(top).await.unwrap();
    let rest = store.list(None).await.unwrap();
    assert!(rest.iter().all(|row| row.seq > top));
    assert!(rest.iter().any(|row| row.kind == "hook.stop"));
}

#[tokio::test]
async fn ack_above_the_peeked_head_deletes_nothing_extra() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    let stored = fill(&store, "hook.stop", 5, 10).await;
    let batch = store.peek(2, u64::MAX).await.unwrap();
    assert_eq!(seqs(&batch), stored[..2].to_vec());
    assert_eq!(store.ack_through(i64::MAX).await.unwrap(), 2);
    assert_eq!(seqs(&store.list(None).await.unwrap()), stored[2..].to_vec());
}

#[tokio::test]
async fn ack_without_a_peek_deletes_nothing() {
    let dir = TempDir::new().unwrap();
    let store = open(&dir, BIG).await;
    fill(&store, "hook.stop", 3, 10).await;
    assert_eq!(store.ack_through(i64::MAX).await.unwrap(), 0);
    assert_eq!(store.count().await.unwrap(), 3);
}

#[tokio::test]
async fn overflow_after_a_peek_inserts_a_new_marker_and_the_count_survives_the_ack() {
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
    push(&store, "hook.stop", 1, 400).await;
    push(&store, "hook.pre_tool_use", 8, 400).await;
    let first = marker_counts(&store.list(None).await.unwrap());
    assert_eq!(first.len(), 1);

    let batch = store.peek(100, u64::MAX).await.unwrap();
    let top = *seqs(&batch).last().unwrap();
    assert!(marker_counts(&batch).iter().any(|m| m.0 == first[0].0));

    push(&store, "hook.pre_tool_use", 4, 400).await;
    let during = marker_counts(&store.list(None).await.unwrap());
    let fresh: Vec<_> = during.iter().filter(|m| m.0 > top).collect();
    assert_eq!(fresh.len(), 1);
    let kept = fresh[0].1;
    assert!(kept > 0);
    let old = during.iter().find(|m| m.0 == first[0].0);
    assert_eq!(old.map(|m| m.1), Some(first[0].1));

    store.ack_through(top).await.unwrap();
    let after = marker_counts(&store.list(None).await.unwrap());
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].1, kept);
}
