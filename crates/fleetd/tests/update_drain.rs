//! Idle drain controller: pause claiming, wait for no lease, cap, resume.
//!
//! Time is paused, so the cap and the poll interval are exact and the cap is shrunk to seconds.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use fleetd::poller::ClaimGate;
use fleetd::update::{DrainController, DrainOutcome, DrainRefused, DrainState};
use tokio::sync::Notify;

const CAP: Duration = Duration::from_secs(60);
const POLL: Duration = Duration::from_secs(1);

struct FakeBox {
    leased: Arc<AtomicBool>,
    claims: Arc<AtomicUsize>,
    job_alive: Arc<AtomicBool>,
    finish: Arc<Notify>,
}

fn controller() -> (DrainController, ClaimGate) {
    let gate = ClaimGate::new();
    (DrainController::new(gate.clone(), CAP, POLL), gate)
}

fn fake_box(gate: &ClaimGate) -> FakeBox {
    let fake = FakeBox {
        leased: Arc::default(),
        claims: Arc::default(),
        job_alive: Arc::default(),
        finish: Arc::default(),
    };
    let (leased, claims, alive, finish, gate) = (
        Arc::clone(&fake.leased),
        Arc::clone(&fake.claims),
        Arc::clone(&fake.job_alive),
        Arc::clone(&fake.finish),
        gate.clone(),
    );
    tokio::spawn(async move {
        loop {
            if !gate.is_paused() && !leased.load(Ordering::SeqCst) {
                claims.fetch_add(1, Ordering::SeqCst);
                leased.store(true, Ordering::SeqCst);
                alive.store(true, Ordering::SeqCst);
                let (leased, alive, finish) =
                    (Arc::clone(&leased), Arc::clone(&alive), Arc::clone(&finish));
                tokio::spawn(async move {
                    finish.notified().await;
                    alive.store(false, Ordering::SeqCst);
                    leased.store(false, Ordering::SeqCst);
                });
            }
            tokio::time::sleep(POLL).await;
        }
    });
    fake
}

async fn secs(n: u64) {
    tokio::time::sleep(Duration::from_secs(n)).await;
}

#[tokio::test(start_paused = true)]
async fn no_claim_after_begin_drain_while_a_lease_is_held() {
    let (control, gate) = controller();
    let fake = fake_box(&gate);
    secs(2).await;
    assert_eq!(fake.claims.load(Ordering::SeqCst), 1);
    let _drain = control.begin_drain().expect("begin");
    fake.finish.notify_waiters();
    secs(30).await;
    assert_eq!(fake.claims.load(Ordering::SeqCst), 1);
    assert!(gate.is_paused());
    assert_eq!(control.state(), DrainState::Draining);
}

#[tokio::test(start_paused = true)]
async fn drain_completes_when_the_last_lease_ends() {
    let (control, gate) = controller();
    let fake = fake_box(&gate);
    secs(2).await;
    let mut drain = control.begin_drain().expect("begin");
    let leased = Arc::clone(&fake.leased);
    let finish = Arc::clone(&fake.finish);
    tokio::spawn(async move {
        secs(20).await;
        finish.notify_waiters();
    });
    let outcome = drain.wait(|| !leased.load(Ordering::SeqCst)).await;
    assert_eq!(outcome, DrainOutcome::Drained);
    assert!(gate.is_paused());
    drop(drain);
    assert!(!gate.is_paused());
    assert_eq!(control.state(), DrainState::Idle);
}

#[tokio::test(start_paused = true)]
async fn the_cap_aborts_and_claiming_resumes() {
    let (control, gate) = controller();
    let fake = fake_box(&gate);
    secs(2).await;
    let mut drain = control.begin_drain().expect("begin");
    let leased = Arc::clone(&fake.leased);
    let started = tokio::time::Instant::now();
    let outcome = drain.wait(|| !leased.load(Ordering::SeqCst)).await;
    assert_eq!(outcome, DrainOutcome::Aborted);
    assert_eq!(started.elapsed(), CAP);
    assert_eq!(control.state(), DrainState::Aborted);
    assert!(!gate.is_paused());
    fake.finish.notify_waiters();
    secs(5).await;
    assert_eq!(fake.claims.load(Ordering::SeqCst), 2);
}

#[tokio::test(start_paused = true)]
async fn the_running_job_is_untouched_at_abort() {
    let (control, gate) = controller();
    let fake = fake_box(&gate);
    secs(2).await;
    let mut drain = control.begin_drain().expect("begin");
    let leased = Arc::clone(&fake.leased);
    assert_eq!(
        drain.wait(|| !leased.load(Ordering::SeqCst)).await,
        DrainOutcome::Aborted
    );
    secs(600).await;
    assert!(fake.job_alive.load(Ordering::SeqCst));
    assert!(fake.leased.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn idle_just_inside_the_cap_drains_and_just_over_aborts() {
    for (idle_at, expected) in [
        (CAP.saturating_sub(POLL), DrainOutcome::Drained),
        (CAP + POLL, DrainOutcome::Aborted),
    ] {
        let (control, _gate) = controller();
        let mut drain = control.begin_drain().expect("begin");
        let origin = tokio::time::Instant::now();
        let outcome = drain.wait(|| origin.elapsed() >= idle_at).await;
        assert_eq!(outcome, expected);
    }
}

#[tokio::test(start_paused = true)]
async fn a_second_begin_is_refused_until_the_first_ends() {
    let (control, gate) = controller();
    let first = control.begin_drain().expect("begin");
    assert_eq!(control.begin_drain().err(), Some(DrainRefused));
    assert!(gate.is_paused());
    drop(first);
    assert!(!gate.is_paused());
    let _again = control.begin_drain().expect("begin after end");
}

#[tokio::test(start_paused = true)]
async fn begin_after_an_abort_is_allowed_and_the_stale_handle_cannot_resume() {
    let (control, gate) = controller();
    let mut stale = control.begin_drain().expect("begin");
    assert_eq!(stale.wait(|| false).await, DrainOutcome::Aborted);
    let _fresh = control.begin_drain().expect("begin after abort");
    drop(stale);
    assert!(gate.is_paused());
    assert_eq!(control.state(), DrainState::Draining);
}

#[tokio::test(start_paused = true)]
async fn waiting_again_on_an_aborted_handle_leaves_a_newer_drain_paused() {
    for idle in [false, true] {
        let (control, gate) = controller();
        let mut stale = control.begin_drain().expect("begin a");
        assert_eq!(stale.wait(|| false).await, DrainOutcome::Aborted);
        let _fresh = control.begin_drain().expect("begin b");
        assert_eq!(stale.wait(move || idle).await, DrainOutcome::Aborted);
        assert!(gate.is_paused());
        assert_eq!(control.state(), DrainState::Draining);
    }
}

#[tokio::test(start_paused = true)]
async fn dropping_the_drain_future_resumes_claiming() {
    let (control, gate) = controller();
    let drain = control.begin_drain().expect("begin");
    let task = tokio::spawn(async move {
        let mut drain = drain;
        drain.wait(|| false).await
    });
    secs(5).await;
    assert!(gate.is_paused());
    task.abort();
    let _ = task.await;
    assert!(!gate.is_paused());
    assert_eq!(control.state(), DrainState::Idle);
}
