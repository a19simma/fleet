//! Shutdown sequencing tests. No sockets or database.

use std::time::Duration;

use fleet_server::supervise::{BoxError, ReaperDied, supervise};
use tokio::sync::watch;
use tokio::time::timeout;

const LIMIT: Duration = Duration::from_secs(5);

fn reaper_until_stop(mut rx: watch::Receiver<bool>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let _ = rx.wait_for(|stop| *stop).await;
    })
}

async fn until_stop(mut rx: watch::Receiver<bool>) -> Result<(), BoxError> {
    let _ = rx.wait_for(|stop| *stop).await;
    Ok(())
}

#[tokio::test]
async fn a_failing_server_stops_and_joins_the_reaper() {
    let (tx, rx) = watch::channel(false);
    let reaper = reaper_until_stop(rx);
    let served = async { Err::<(), BoxError>("listener failed".into()) };
    let result = timeout(LIMIT, supervise(served, reaper, &tx))
        .await
        .expect("supervise hung");
    assert_eq!(result.unwrap_err().to_string(), "listener failed");
    assert!(*tx.borrow());
}

#[tokio::test]
async fn a_clean_server_exit_stops_the_reaper() {
    let (tx, rx) = watch::channel(false);
    let reaper = reaper_until_stop(rx);
    let result = timeout(LIMIT, supervise(async { Ok(()) }, reaper, &tx))
        .await
        .expect("supervise hung");
    assert!(result.is_ok());
    assert!(*tx.borrow());
}

#[tokio::test]
async fn an_external_stop_ends_both_cleanly() {
    let (tx, rx) = watch::channel(false);
    let reaper = reaper_until_stop(rx.clone());
    let run = supervise(until_stop(rx), reaper, &tx);
    let trigger = async { tx.send_replace(true) };
    let (result, _) = timeout(LIMIT, async { tokio::join!(run, trigger) })
        .await
        .expect("supervise hung");
    assert!(result.is_ok());
}

#[tokio::test]
async fn a_reaper_panic_stops_the_servers_and_fails() {
    let (tx, rx) = watch::channel(false);
    let reaper = tokio::spawn(async { panic!("reaper boom") });
    let result = timeout(LIMIT, supervise(until_stop(rx), reaper, &tx))
        .await
        .expect("supervise hung");
    let err = result.unwrap_err();
    assert!(err.downcast_ref::<ReaperDied>().is_some());
    assert!(*tx.borrow());
}

#[tokio::test]
async fn a_reaper_that_returns_early_fails() {
    let (tx, rx) = watch::channel(false);
    let reaper = tokio::spawn(async {});
    let result = timeout(LIMIT, supervise(until_stop(rx), reaper, &tx))
        .await
        .expect("supervise hung");
    assert!(result.unwrap_err().downcast_ref::<ReaperDied>().is_some());
}

#[tokio::test]
async fn a_server_error_wins_over_a_dead_reaper() {
    let (tx, _rx) = watch::channel(false);
    let reaper = tokio::spawn(async { panic!("reaper boom") });
    let failing = async {
        let mut stop = tx.subscribe();
        let _ = stop.wait_for(|s| *s).await;
        Err::<(), BoxError>("listener failed".into())
    };
    let result = timeout(LIMIT, supervise(failing, reaper, &tx))
        .await
        .expect("supervise hung");
    assert_eq!(result.unwrap_err().to_string(), "listener failed");
}

#[tokio::test]
async fn a_reaper_that_ends_after_a_stop_request_is_not_a_death() {
    let (tx, rx) = watch::channel(false);
    tx.send_replace(true);
    let reaper = tokio::spawn(async {});
    let served = async {
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        until_stop(rx).await
    };
    let result = timeout(LIMIT, supervise(served, reaper, &tx))
        .await
        .expect("supervise hung");
    assert!(result.is_ok());
}
