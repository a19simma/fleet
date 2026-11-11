//! `HostStore` add, list and remove (ADR-0068): caps, audit rows, the in-use refusals and the
//! lock order against the credential store. The tests need a Postgres superuser URL in
//! `DATABASE_URL`.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::Duration;

use fleet_core::host::{Host, HostName};
use fleet_server::hosts::{AddOutcome, ApproveOutcome, HostStore, RemoveOutcome};
use fleet_server::store::Store;
use sqlx::PgPool;
use tokio::time::{sleep, timeout};

async fn migrated(pool: &PgPool) {
    Store::new(pool.clone()).migrate().await.unwrap();
}

async fn user(pool: &PgPool, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO users (username) VALUES ($1) RETURNING id")
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn host(name: &str) -> Host {
    Host::user_added(name).unwrap()
}

fn name(text: &str) -> HostName {
    HostName::normalise(text).unwrap()
}

async fn audit(pool: &PgPool, user_id: i64) -> Vec<(String, String, String)> {
    sqlx::query_as("SELECT host, action, outcome FROM host_audit WHERE user_id = $1 ORDER BY id")
        .bind(user_id)
        .fetch_all(pool)
        .await
        .unwrap()
}

fn row(host: &str, action: &str, outcome: &str) -> (String, String, String) {
    (host.to_owned(), action.to_owned(), outcome.to_owned())
}

async fn credential(pool: &PgPool, user_id: i64, host: &str) {
    sqlx::query(
        "INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint, host) \
         VALUES ($1, 'forgejo_pat', 'static_secret', '\\x00', 'k', 'f', $2)",
    )
    .bind(user_id)
    .bind(host)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = false)]
async fn add_inserts_a_forgejo_row_and_one_audit_row(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone());
    let AddOutcome::Added(added) = store.add(alice, &host("Git.Example.com")).await.unwrap() else {
        panic!("not added");
    };
    assert_eq!(added.host, "git.example.com");
    assert_eq!(added.kind, "forgejo");
    assert_eq!(added.added_by, Some(alice));
    assert!(!added.allow_private);
    assert_eq!(added.approved_ips, Vec::<String>::new());
    assert_eq!(
        audit(&pool, alice).await,
        [row("git.example.com", "add", "added")]
    );
}

#[sqlx::test(migrations = false)]
async fn a_second_add_returns_the_first_row_and_audits_exists(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("git.example.com")).await.unwrap();
    let AddOutcome::Exists(existing) = store.add(bob, &host("git.example.com")).await.unwrap()
    else {
        panic!("not exists");
    };
    assert_eq!(existing.added_by, Some(alice));
    assert_eq!(
        audit(&pool, bob).await,
        [row("git.example.com", "add", "exists")]
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM git_hosts WHERE host = 'git.example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = false)]
async fn the_per_user_cap_refuses_one_past_it_and_leaves_other_users_alone(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let store = HostStore::new(pool.clone()).with_caps(2, 100);
    for n in 0..2 {
        let outcome = store
            .add(alice, &host(&format!("a{n}.example.com")))
            .await
            .unwrap();
        assert!(matches!(outcome, AddOutcome::Added(_)));
    }
    assert_eq!(
        store.add(alice, &host("a2.example.com")).await.unwrap(),
        AddOutcome::UserFull
    );
    assert!(matches!(
        store.add(bob, &host("b0.example.com")).await.unwrap(),
        AddOutcome::Added(_)
    ));
    assert_eq!(
        audit(&pool, alice).await.last().unwrap(),
        &row("a2.example.com", "add", "refused")
    );
    assert!(store.find(&name("a2.example.com")).await.unwrap().is_none());
}

#[sqlx::test(migrations = false)]
async fn the_global_cap_counts_the_seed_row_and_every_user(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let store = HostStore::new(pool.clone()).with_caps(10, 3);
    store.add(alice, &host("a.example.com")).await.unwrap();
    store.add(bob, &host("b.example.com")).await.unwrap();
    assert_eq!(
        store.add(alice, &host("c.example.com")).await.unwrap(),
        AddOutcome::TableFull
    );
    assert_eq!(store.list().await.unwrap().len(), 3);
}

#[sqlx::test(migrations = false)]
async fn the_per_user_cap_wins_when_both_caps_are_reached(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone()).with_caps(1, 2);
    store.add(alice, &host("a.example.com")).await.unwrap();
    assert_eq!(
        store.add(alice, &host("b.example.com")).await.unwrap(),
        AddOutcome::UserFull
    );
}

#[sqlx::test(migrations = false)]
async fn concurrent_adds_by_one_user_never_pass_the_cap(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone()).with_caps(3, 100);
    let tasks: Vec<_> = (0..8)
        .map(|n| {
            let store = store.clone();
            tokio::spawn(async move {
                store
                    .add(alice, &host(&format!("h{n}.example.com")))
                    .await
                    .unwrap()
            })
        })
        .collect();
    let mut added = 0;
    for task in tasks {
        if matches!(task.await.unwrap(), AddOutcome::Added(_)) {
            added += 1;
        }
    }
    assert_eq!(added, 3);
}

#[sqlx::test(migrations = false)]
async fn concurrent_adds_by_many_users_never_pass_the_global_cap(pool: PgPool) {
    migrated(&pool).await;
    let store = HostStore::new(pool.clone()).with_caps(10, 4);
    let mut tasks = Vec::new();
    for n in 0..8 {
        let id = user(&pool, &format!("u{n}")).await;
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store
                .add(id, &host(&format!("h{n}.example.com")))
                .await
                .unwrap()
        }));
    }
    let mut added = 0;
    for task in tasks {
        if matches!(task.await.unwrap(), AddOutcome::Added(_)) {
            added += 1;
        }
    }
    assert_eq!(added, 3);
}

#[sqlx::test(migrations = false)]
async fn a_missing_user_adds_nothing(pool: PgPool) {
    migrated(&pool).await;
    let store = HostStore::new(pool.clone());
    let err = store
        .add(999_999, &host("a.example.com"))
        .await
        .unwrap_err();
    assert_eq!(err.to_string(), "user not found");
    assert!(store.find(&name("a.example.com")).await.unwrap().is_none());
}

#[sqlx::test(migrations = false)]
async fn list_returns_every_row_ordered_with_added_by_and_allow_private(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("z.example.com")).await.unwrap();
    store.add(alice, &host("b.example.com")).await.unwrap();
    sqlx::query("UPDATE git_hosts SET allow_private = true, approved_ips = ARRAY['10.0.0.5']::inet[], approved_by = $1, approved_at = now() WHERE host = 'b.example.com'")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    let rows = store.list().await.unwrap();
    let hosts: Vec<_> = rows.iter().map(|row| row.host.as_str()).collect();
    assert_eq!(hosts, ["b.example.com", "github.com", "z.example.com"]);
    let b = &rows[0];
    assert!(b.allow_private);
    assert_eq!(b.approved_ips, ["10.0.0.5"]);
    assert_eq!(b.added_by, Some(alice));
    assert_eq!(b.approved_by, Some(alice));
    assert!(b.approved_at_ms.is_some());
    assert_eq!(rows[1].added_by, None);
}

#[sqlx::test(migrations = false)]
async fn remove_deletes_an_unused_host_and_audits_it(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let admin = user(&pool, "root").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("a.example.com")).await.unwrap();
    assert_eq!(
        store.remove(admin, &name("a.example.com")).await.unwrap(),
        RemoveOutcome::Removed
    );
    assert!(store.find(&name("a.example.com")).await.unwrap().is_none());
    assert_eq!(
        audit(&pool, admin).await,
        [row("a.example.com", "remove", "removed")]
    );
}

#[sqlx::test(migrations = false)]
async fn remove_refuses_a_host_with_a_credential(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("a.example.com")).await.unwrap();
    credential(&pool, alice, "a.example.com").await;
    assert_eq!(
        store.remove(alice, &name("a.example.com")).await.unwrap(),
        RemoveOutcome::InUse
    );
    assert!(store.find(&name("a.example.com")).await.unwrap().is_some());
    assert_eq!(
        audit(&pool, alice).await.last().unwrap(),
        &row("a.example.com", "remove", "refused")
    );
}

#[sqlx::test(migrations = false)]
async fn remove_refuses_a_host_with_a_repository_and_nothing_else(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("a.example.com")).await.unwrap();
    store.add(alice, &host("b.example.com")).await.unwrap();
    sqlx::query("INSERT INTO user_repos (user_id, host, path, forge_kind) VALUES ($1, 'a.example.com', 'o/r', 'forgejo')")
        .bind(alice)
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store.remove(alice, &name("a.example.com")).await.unwrap(),
        RemoveOutcome::InUse
    );
    assert_eq!(
        store.remove(alice, &name("b.example.com")).await.unwrap(),
        RemoveOutcome::Removed
    );
}

#[sqlx::test(migrations = false)]
async fn remove_refuses_a_tombstoned_credential_host(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("a.example.com")).await.unwrap();
    credential(&pool, alice, "a.example.com").await;
    sqlx::query("UPDATE credentials SET tombstoned_at = now() WHERE host = 'a.example.com'")
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(
        store.remove(alice, &name("a.example.com")).await.unwrap(),
        RemoveOutcome::InUse
    );
}

#[sqlx::test(migrations = false)]
async fn remove_of_an_unknown_host_and_of_the_seed_are_refused(pool: PgPool) {
    migrated(&pool).await;
    let admin = user(&pool, "root").await;
    let store = HostStore::new(pool.clone());
    assert_eq!(
        store
            .remove(admin, &name("nope.example.com"))
            .await
            .unwrap(),
        RemoveOutcome::Unknown
    );
    assert_eq!(
        store.remove(admin, &name("github.com")).await.unwrap(),
        RemoveOutcome::InUse
    );
    assert_eq!(
        audit(&pool, admin).await,
        [
            row("nope.example.com", "remove", "refused"),
            row("github.com", "remove", "refused")
        ]
    );
}

#[sqlx::test(migrations = false)]
async fn remove_waits_for_a_credential_put_in_flight_and_then_refuses(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("a.example.com")).await.unwrap();
    let mut put = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM git_hosts WHERE host = 'a.example.com' FOR SHARE")
        .execute(&mut *put)
        .await
        .unwrap();
    let remover = {
        let store = store.clone();
        tokio::spawn(async move { store.remove(alice, &name("a.example.com")).await.unwrap() })
    };
    sleep(Duration::from_millis(1500)).await;
    assert!(!remover.is_finished());
    sqlx::query(
        "INSERT INTO credentials (user_id, kind, shape, ciphertext, key_id, fingerprint, host) \
         VALUES ($1, 'forgejo_pat', 'static_secret', '\\x00', 'k', 'f', 'a.example.com')",
    )
    .bind(alice)
    .execute(&mut *put)
    .await
    .unwrap();
    put.commit().await.unwrap();
    let outcome = timeout(Duration::from_secs(20), remover)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(outcome, RemoveOutcome::InUse);
}

#[sqlx::test(migrations = false)]
async fn remove_never_waits_on_a_credential_row_a_delete_holds(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let store = HostStore::new(pool.clone());
    store.add(alice, &host("a.example.com")).await.unwrap();
    credential(&pool, alice, "a.example.com").await;
    let mut delete = pool.begin().await.unwrap();
    sqlx::query("SELECT 1 FROM credentials WHERE host = 'a.example.com' FOR UPDATE")
        .execute(&mut *delete)
        .await
        .unwrap();
    let outcome = timeout(
        Duration::from_secs(10),
        store.remove(alice, &name("a.example.com")),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(outcome, RemoveOutcome::InUse);
    delete.rollback().await.unwrap();
}

#[sqlx::test(migrations = false)]
async fn host_audit_rejects_update_delete_and_truncate(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    HostStore::new(pool.clone())
        .add(alice, &host("a.example.com"))
        .await
        .unwrap();
    for statement in [
        "UPDATE host_audit SET outcome = 'exists'",
        "DELETE FROM host_audit",
        "TRUNCATE host_audit",
    ] {
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err();
        assert!(
            err.to_string().contains("insert-only"),
            "{statement}: {err}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn host_audit_takes_the_private_actions_with_addresses_and_refuses_the_rest(pool: PgPool) {
    migrated(&pool).await;
    let admin = user(&pool, "root").await;
    let insert = |action: &'static str, outcome: &'static str| {
        sqlx::query(
            "INSERT INTO host_audit (user_id, host, action, outcome, addresses) \
             VALUES ($1, 'git.example.com', $2, $3, ARRAY['192.168.3.1']::inet[])",
        )
        .bind(admin)
        .bind(action)
        .bind(outcome)
        .execute(&pool)
    };
    for (action, outcome) in [
        ("approve_private", "approved"),
        ("approve_private", "refused"),
        ("revoke_private", "revoked"),
        ("revoke_private", "refused"),
    ] {
        insert(action, outcome).await.unwrap();
    }
    for (action, outcome) in [
        ("approve_private", "revoked"),
        ("approve_private", "added"),
        ("revoke_private", "approved"),
        ("revoke_private", "removed"),
        ("add", "approved"),
        ("add", "revoked"),
        ("remove", "approved"),
        ("remove", "revoked"),
        ("grant_private", "approved"),
        ("", "refused"),
    ] {
        let err = insert(action, outcome).await.unwrap_err();
        assert!(
            err.to_string().contains("host_audit_"),
            "{action}/{outcome}: {err}"
        );
    }
    let old = sqlx::query(
        "INSERT INTO host_audit (user_id, host, action, outcome) \
         VALUES ($1, 'git.example.com', 'add', 'added')",
    )
    .bind(admin)
    .execute(&pool)
    .await;
    old.unwrap();
    let empty: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM host_audit WHERE action = 'add' AND addresses = '{}'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(empty, 1);
    for statement in [
        "UPDATE host_audit SET addresses = '{}'",
        "DELETE FROM host_audit",
        "TRUNCATE host_audit",
    ] {
        let err = sqlx::query(statement).execute(&pool).await.unwrap_err();
        assert!(
            err.to_string().contains("insert-only"),
            "{statement}: {err}"
        );
    }
}

#[sqlx::test(migrations = false)]
async fn one_pending_request_per_user_and_host(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let bob = user(&pool, "bob").await;
    let insert = |who: i64, host: &'static str, status: &'static str| {
        sqlx::query("INSERT INTO git_host_requests (host, user_id, status) VALUES ($1, $2, $3)")
            .bind(host)
            .bind(who)
            .bind(status)
            .execute(&pool)
    };
    insert(alice, "a.example.com", "pending").await.unwrap();
    insert(bob, "a.example.com", "pending").await.unwrap();
    insert(alice, "b.example.com", "pending").await.unwrap();
    insert(alice, "a.example.com", "denied").await.unwrap();
    insert(alice, "a.example.com", "approved").await.unwrap();
    let err = insert(alice, "a.example.com", "pending").await.unwrap_err();
    assert!(
        err.to_string().contains("git_host_requests_pending_key"),
        "{err}"
    );
}

async fn add_waits_while(pool: &PgPool, lock: &'static str, bind_user: Option<i64>) {
    let alice = user(pool, "alice").await;
    let store = HostStore::new(pool.clone());
    let mut holder = pool.begin().await.unwrap();
    let query = sqlx::query(lock);
    match bind_user {
        Some(_) => query.bind(alice).execute(&mut *holder).await.unwrap(),
        None => query.execute(&mut *holder).await.unwrap(),
    };
    let adder = {
        let store = store.clone();
        tokio::spawn(async move { store.add(alice, &host("a.example.com")).await.unwrap() })
    };
    sleep(Duration::from_millis(1500)).await;
    assert!(!adder.is_finished(), "{lock}");
    holder.commit().await.unwrap();
    let outcome = timeout(Duration::from_secs(20), adder)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(outcome, AddOutcome::Added(_)));
}

#[sqlx::test(migrations = false)]
async fn add_queues_behind_a_lock_on_the_user_row(pool: PgPool) {
    migrated(&pool).await;
    add_waits_while(
        &pool,
        "SELECT id FROM users WHERE id = $1 FOR NO KEY UPDATE",
        Some(0),
    )
    .await;
}

#[sqlx::test(migrations = false)]
async fn add_queues_behind_the_global_cap_lock(pool: PgPool) {
    migrated(&pool).await;
    add_waits_while(&pool, "SELECT pg_advisory_xact_lock(6850, 1)", None).await;
}

#[sqlx::test(migrations = false)]
async fn approve_and_add_run_concurrently_without_a_deadlock(pool: PgPool) {
    migrated(&pool).await;
    let alice = user(&pool, "alice").await;
    let admin = user(&pool, "admin").await;
    let store = HostStore::new(pool.clone()).with_caps(1000, 1000);
    let private: Vec<std::net::IpAddr> = vec!["10.0.0.5".parse().unwrap()];
    for n in 0..200 {
        let pending = name(&format!("p{n}.example.com"));
        assert!(
            store
                .record_request(alice, &pending, &private)
                .await
                .unwrap()
        );
        let approver = {
            let store = store.clone();
            let private = private.clone();
            tokio::spawn(async move { store.approve(admin, &pending, &private).await })
        };
        let adder = {
            let store = store.clone();
            tokio::spawn(async move { store.add(alice, &host(&format!("a{n}.example.com"))).await })
        };
        let approved = timeout(Duration::from_secs(20), approver)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(approved, ApproveOutcome::Approved(_)), "{n}");
        let added = timeout(Duration::from_secs(20), adder)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(matches!(added, AddOutcome::Added(_)), "{n}");
    }
}
