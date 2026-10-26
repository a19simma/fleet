//! `Store::stats` over seeded jobs and summaries. The tests need a Postgres superuser URL
//! in `DATABASE_URL`, which `#[sqlx::test]` reads to create one database per test.

#![expect(clippy::unwrap_used, reason = "test code asserts by panicking")]

use std::time::{SystemTime, UNIX_EPOCH};

use fleet_proto::v1::{GetStatsReply, GetStatsRequest, StatsGroup, StatsGroupBy};
use fleet_server::store::{Store, StoreError};
use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;

const DAY: i64 = 86_400;
const REPO_A: &str = "https://example.com/org/alpha.git";
const REPO_B: &str = "https://example.com/org/beta.git";
const TIMED_OUT: &str = "agent timed out";
const LAST_SECOND: i64 = 253_402_300_799;

fn name(n: u32) -> String {
    format!("box-{n}")
}

fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

async fn store(pool: PgPool) -> Store {
    let store = Store::new(pool);
    store.migrate().await.unwrap();
    store
}

struct Seed<'a> {
    id: &'a str,
    state: &'a str,
    repo: &'a str,
    box_name: String,
    error: Option<&'a str>,
    created: i64,
}

fn seed<'a>(id: &'a str, state: &'a str) -> Seed<'a> {
    Seed {
        id,
        state,
        repo: REPO_A,
        box_name: name(1),
        error: None,
        created: now() - 60,
    }
}

async fn insert(pool: &PgPool, job: &Seed<'_>) {
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state, box, error, \
         created_at) VALUES ($1, 'p', $2, 'main', 'swarm/x', true, $3, $4, $5, to_timestamp($6))",
    )
    .bind(job.id)
    .bind(job.repo)
    .bind(job.state)
    .bind(&job.box_name)
    .bind(job.error)
    .bind(job.created)
    .execute(pool)
    .await
    .unwrap();
}

#[derive(Default)]
struct Fig {
    turns: Option<i64>,
    duration_ms: Option<i64>,
    cost: Option<f64>,
    tokens_in: Option<i64>,
    tokens_out: Option<i64>,
    cache_read: Option<i64>,
    cache_write: Option<i64>,
    tool_calls: Option<i64>,
    tool_errors: Option<i64>,
    bash_calls: Option<i64>,
    bash_nonzero: Option<i64>,
    denials: Option<i64>,
    api_retries: Option<i64>,
    first_edit_ms: Option<i64>,
    complete: bool,
}

async fn summarize(pool: &PgPool, id: &str, fig: &Fig) {
    sqlx::query(
        "INSERT INTO job_summary (job_id, turns, duration_ms, cost_est_usd, tokens_in, \
         tokens_out, tokens_cache_read, tokens_cache_write, tool_calls, tool_errors, \
         bash_calls, bash_nonzero, denials, api_retries, first_edit_ms, complete, missing) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, '{}')",
    )
    .bind(id)
    .bind(fig.turns)
    .bind(fig.duration_ms)
    .bind(fig.cost)
    .bind(fig.tokens_in)
    .bind(fig.tokens_out)
    .bind(fig.cache_read)
    .bind(fig.cache_write)
    .bind(fig.tool_calls)
    .bind(fig.tool_errors)
    .bind(fig.bash_calls)
    .bind(fig.bash_nonzero)
    .bind(fig.denials)
    .bind(fig.api_retries)
    .bind(fig.first_edit_ms)
    .bind(fig.complete)
    .execute(pool)
    .await
    .unwrap();
}

async fn with_duration(pool: &PgPool, id: &str, ms: i64) {
    summarize(
        pool,
        id,
        &Fig {
            duration_ms: Some(ms),
            complete: true,
            ..Fig::default()
        },
    )
    .await;
}

fn request(group_by: StatsGroupBy) -> GetStatsRequest {
    GetStatsRequest {
        group_by: group_by.into(),
        ..GetStatsRequest::default()
    }
}

async fn run(store: &Store, request: &GetStatsRequest) -> GetStatsReply {
    store.stats(request).await.unwrap()
}

async fn one(store: &Store) -> StatsGroup {
    let reply = run(store, &request(StatsGroupBy::None)).await;
    assert_eq!(reply.groups.len(), 1);
    let group = reply.groups.into_iter().next().unwrap();
    assert_eq!(group.key, "");
    group
}

fn close(left: f64, right: f64) {
    assert!((left - right).abs() < 1e-9, "{left} != {right}");
}

fn keys(reply: &GetStatsReply) -> Vec<&str> {
    reply.groups.iter().map(|g| g.key.as_str()).collect()
}

fn invalid(result: &Result<GetStatsReply, StoreError>) {
    assert!(
        matches!(result, Err(StoreError::InvalidJob(_))),
        "{result:?}"
    );
}

#[sqlx::test(migrations = false)]
async fn nulls_are_excluded_and_n_counts_contributors(pool: PgPool) {
    let store = store(pool.clone()).await;
    for id in ["a", "b", "c", "d"] {
        insert(&pool, &seed(id, "SUCCEEDED")).await;
    }
    summarize(
        &pool,
        "a",
        &Fig {
            turns: Some(4),
            duration_ms: Some(1000),
            cost: Some(0.5),
            tool_calls: Some(10),
            tool_errors: Some(0),
            first_edit_ms: Some(300),
            complete: true,
            ..Fig::default()
        },
    )
    .await;
    summarize(
        &pool,
        "b",
        &Fig {
            tool_calls: Some(30),
            first_edit_ms: Some(700),
            ..Fig::default()
        },
    )
    .await;
    let group = one(&store).await;
    assert_eq!(group.jobs, 4);
    assert_eq!(group.with_summary, 2);
    assert_eq!(group.complete, 1);
    let duration = group.duration_ms.unwrap();
    assert_eq!(duration.n, 1);
    close(duration.p50, 1000.0);
    close(duration.p95, 1000.0);
    assert_eq!(group.turns.unwrap().n, 1);
    let cost = group.cost_est_usd.unwrap();
    assert_eq!(cost.n, 1);
    close(cost.sum, 0.5);
    let calls = group.tool_calls.unwrap();
    assert_eq!((calls.n, calls.sum), (2, 40));
    let errors = group.tool_errors.unwrap();
    assert_eq!((errors.n, errors.sum), (1, 0));
    let first = group.first_edit_ms.unwrap();
    assert_eq!(first.n, 2);
    close(first.p50, 500.0);
    assert!(group.tokens_in.is_none());
    assert!(group.tokens_out.is_none());
    assert!(group.tokens_cache_read.is_none());
    assert!(group.tokens_cache_write.is_none());
    assert!(group.bash_calls.is_none());
    assert!(group.bash_nonzero.is_none());
    assert!(group.denials.is_none());
    assert!(group.api_retries.is_none());
}

#[sqlx::test(migrations = false)]
async fn every_metric_is_summed_from_its_own_column(pool: PgPool) {
    let store = store(pool.clone()).await;
    insert(&pool, &seed("a", "SUCCEEDED")).await;
    insert(&pool, &seed("b", "FAILED")).await;
    for (id, base) in [("a", 1), ("b", 2)] {
        summarize(
            &pool,
            id,
            &Fig {
                turns: Some(base),
                duration_ms: Some(base * 10),
                cost: Some(f64::from(i32::try_from(base).unwrap())),
                tokens_in: Some(base * 100),
                tokens_out: Some(base * 200),
                cache_read: Some(base * 300),
                cache_write: Some(base * 400),
                tool_calls: Some(base * 500),
                tool_errors: Some(base * 600),
                bash_calls: Some(base * 700),
                bash_nonzero: Some(base * 800),
                denials: Some(base * 900),
                api_retries: Some(base * 1000),
                first_edit_ms: Some(base * 1100),
                complete: true,
            },
        )
        .await;
    }
    let g = one(&store).await;
    let sums = [
        (g.tokens_in, 300),
        (g.tokens_out, 600),
        (g.tokens_cache_read, 900),
        (g.tokens_cache_write, 1200),
        (g.tool_calls, 1500),
        (g.tool_errors, 1800),
        (g.bash_calls, 2100),
        (g.bash_nonzero, 2400),
        (g.denials, 2700),
        (g.api_retries, 3000),
    ];
    for (total, sum) in sums {
        let total = total.unwrap();
        assert_eq!((total.n, total.sum), (2, sum));
    }
    let turns = g.turns.unwrap();
    close(turns.p50, 1.5);
    close(turns.p95, 1.95);
    close(g.duration_ms.unwrap().p50, 15.0);
    let first_edit = g.first_edit_ms.unwrap();
    close(first_edit.p50, 1650.0);
    close(first_edit.p95, 2145.0);
    close(g.cost_est_usd.unwrap().sum, 3.0);
}

#[sqlx::test(migrations = false)]
async fn terminal_states_are_split_and_unfinished_jobs_are_other(pool: PgPool) {
    let store = store(pool.clone()).await;
    let timed_out = Seed {
        error: Some(TIMED_OUT),
        ..seed("t", "FAILED")
    };
    let plain_failure = Seed {
        error: Some("exit 1"),
        ..seed("f", "FAILED")
    };
    insert(&pool, &timed_out).await;
    insert(&pool, &plain_failure).await;
    insert(&pool, &seed("f2", "FAILED")).await;
    for (id, state) in [
        ("s1", "SUCCEEDED"),
        ("s2", "SUCCEEDED"),
        ("s3", "SUCCEEDED"),
        ("c1", "CANCELLED"),
        ("c2", "CANCELLED"),
        ("c3", "CANCELLED"),
        ("c4", "CANCELLED"),
        ("l1", "LOST"),
        ("l2", "LOST"),
        ("l3", "LOST"),
        ("l4", "LOST"),
        ("l5", "LOST"),
        ("q1", "QUEUED"),
        ("q2", "QUEUED"),
        ("q3", "QUEUED"),
        ("r1", "RUNNING"),
        ("r2", "RUNNING"),
        ("r3", "RUNNING"),
    ] {
        insert(&pool, &seed(id, state)).await;
    }
    let g = one(&store).await;
    assert_eq!(g.jobs, 21);
    assert_eq!(g.succeeded, 3);
    assert_eq!(g.failed, 2);
    assert_eq!(g.timed_out, 1);
    assert_eq!(g.cancelled, 4);
    assert_eq!(g.lost, 5);
    assert_eq!(g.other, 6);
    assert_eq!(g.with_summary, 0);
    assert_eq!(g.complete, 0);
    assert!(g.duration_ms.is_none());
    assert!(g.cost_est_usd.is_none());
}

#[sqlx::test(migrations = false)]
async fn percentiles_of_one_two_and_many_rows(pool: PgPool) {
    let store = store(pool.clone()).await;
    insert(&pool, &seed("a", "SUCCEEDED")).await;
    with_duration(&pool, "a", 100).await;
    let d = one(&store).await.duration_ms.unwrap();
    assert_eq!(d.n, 1);
    close(d.p50, 100.0);
    close(d.p95, 100.0);

    insert(&pool, &seed("b", "SUCCEEDED")).await;
    with_duration(&pool, "b", 200).await;
    let d = one(&store).await.duration_ms.unwrap();
    assert_eq!(d.n, 2);
    close(d.p50, 150.0);
    close(d.p95, 195.0);

    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state) \
         SELECT 'm' || i, 'p', 'https://example.com/org/alpha.git', 'main', 'swarm/x', true, \
         'SUCCEEDED' FROM generate_series(1, 101) AS i",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO job_summary (job_id, duration_ms, cost_est_usd, complete, missing) \
         SELECT 'm' || i, i, i, true, '{}' FROM generate_series(1, 101) AS i",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("DELETE FROM job_summary WHERE job_id IN ('a', 'b')")
        .execute(&pool)
        .await
        .unwrap();
    let g = one(&store).await;
    let d = g.duration_ms.unwrap();
    assert_eq!(d.n, 101);
    close(d.p50, 51.0);
    close(d.p95, 96.0);
    let cost = g.cost_est_usd.unwrap();
    assert_eq!(cost.n, 101);
    close(cost.sum, 5151.0);
    close(cost.p50, 51.0);
    close(cost.p95, 96.0);
}

#[sqlx::test(migrations = false)]
async fn group_by_repo_orders_by_job_count_then_key(pool: PgPool) {
    let store = store(pool.clone()).await;
    insert(&pool, &seed("a1", "SUCCEEDED")).await;
    let b1 = Seed {
        repo: REPO_B,
        ..seed("b1", "SUCCEEDED")
    };
    let b2 = Seed {
        repo: REPO_B,
        ..seed("b2", "FAILED")
    };
    insert(&pool, &b1).await;
    insert(&pool, &b2).await;
    let reply = run(&store, &request(StatsGroupBy::Repo)).await;
    assert_eq!(keys(&reply), [REPO_B, REPO_A]);
    assert_eq!(reply.groups[0].jobs, 2);
    assert_eq!(reply.groups[0].failed, 1);
    assert_eq!(reply.groups[1].jobs, 1);
    assert!(!reply.truncated);
}

#[sqlx::test(migrations = false)]
async fn group_by_box_and_state_use_their_own_columns(pool: PgPool) {
    let store = store(pool.clone()).await;
    insert(&pool, &seed("a", "SUCCEEDED")).await;
    let on_two = Seed {
        box_name: name(2),
        ..seed("b", "FAILED")
    };
    insert(&pool, &on_two).await;
    let also_two = Seed {
        box_name: name(2),
        ..seed("c", "FAILED")
    };
    insert(&pool, &also_two).await;
    let by_box = run(&store, &request(StatsGroupBy::Box)).await;
    assert_eq!(keys(&by_box), [name(2), name(1)]);
    let by_state = run(&store, &request(StatsGroupBy::State)).await;
    assert_eq!(keys(&by_state), ["FAILED", "SUCCEEDED"]);
    assert_eq!(by_state.groups[0].jobs, 2);
}

#[sqlx::test(migrations = false)]
async fn group_by_day_is_chronological_in_utc_whatever_the_session_zone(pool: PgPool) {
    store(pool.clone()).await;
    let zoned = PgPoolOptions::new()
        .max_connections(1)
        .after_connect(|connection, _| {
            Box::pin(async move {
                sqlx::query("SET TIME ZONE 'Pacific/Auckland'")
                    .execute(connection)
                    .await
                    .map(|_| ())
            })
        })
        .connect_with((*pool.connect_options()).clone())
        .await
        .unwrap();
    let store = Store::new(zoned);
    let day = (now() / DAY - 3) * DAY;
    for (id, at) in [
        ("edge", day + DAY - 1),
        ("late", day + DAY + 100),
        ("later", day + DAY + 200),
    ] {
        let job = Seed {
            created: at,
            ..seed(id, "SUCCEEDED")
        };
        insert(&pool, &job).await;
    }
    let reply = run(&store, &request(StatsGroupBy::Day)).await;
    let label = |at: i64| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT to_char(to_timestamp($1) AT TIME ZONE 'UTC', 'YYYY-MM-DD')",
            )
            .bind(at)
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let first = label(day).await;
    let second = label(day + DAY).await;
    assert_eq!(keys(&reply), [first.as_str(), second.as_str()]);
    assert_eq!(reply.groups[0].jobs, 1);
    assert_eq!(reply.groups[1].jobs, 2);
}

#[sqlx::test(migrations = false)]
async fn each_summed_metric_counts_its_own_contributors(pool: PgPool) {
    let store = store(pool.clone()).await;
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state) \
         SELECT 'n' || i, 'p', 'https://example.com/org/alpha.git', 'main', 'swarm/x', true, \
         'SUCCEEDED' FROM generate_series(1, 11) AS i",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO job_summary (job_id, tokens_in, tokens_out, tokens_cache_read, \
         tokens_cache_write, tool_calls, tool_errors, bash_calls, bash_nonzero, denials, \
         api_retries, complete, missing) \
         SELECT 'n' || i, CASE WHEN i <= 1 THEN 1 END, CASE WHEN i <= 2 THEN 1 END, \
         CASE WHEN i <= 3 THEN 1 END, CASE WHEN i <= 4 THEN 1 END, CASE WHEN i <= 5 THEN 1 END, \
         CASE WHEN i <= 6 THEN 1 END, CASE WHEN i <= 7 THEN 1 END, CASE WHEN i <= 8 THEN 1 END, \
         CASE WHEN i <= 9 THEN 1 END, CASE WHEN i <= 10 THEN 1 END, true, '{}' \
         FROM generate_series(1, 11) AS i",
    )
    .execute(&pool)
    .await
    .unwrap();
    let g = one(&store).await;
    let totals = [
        g.tokens_in,
        g.tokens_out,
        g.tokens_cache_read,
        g.tokens_cache_write,
        g.tool_calls,
        g.tool_errors,
        g.bash_calls,
        g.bash_nonzero,
        g.denials,
        g.api_retries,
    ];
    for (index, total) in totals.into_iter().enumerate() {
        let want = u64::try_from(index + 1).unwrap();
        let total = total.unwrap();
        assert_eq!((total.n, total.sum), (want, want), "metric {index}");
    }
}

#[sqlx::test(migrations = false)]
async fn repo_and_box_filters_narrow_the_set(pool: PgPool) {
    let store = store(pool.clone()).await;
    insert(&pool, &seed("a", "SUCCEEDED")).await;
    let other_repo = Seed {
        repo: REPO_B,
        ..seed("b", "SUCCEEDED")
    };
    insert(&pool, &other_repo).await;
    let other_box = Seed {
        box_name: name(2),
        ..seed("c", "SUCCEEDED")
    };
    insert(&pool, &other_box).await;
    let by_repo = GetStatsRequest {
        repo: Some(REPO_B.to_owned()),
        ..GetStatsRequest::default()
    };
    assert_eq!(one_of(&store, &by_repo).await.jobs, 1);
    let by_box = GetStatsRequest {
        r#box: Some(name(2)),
        ..GetStatsRequest::default()
    };
    assert_eq!(one_of(&store, &by_box).await.jobs, 1);
    let both = GetStatsRequest {
        repo: Some(REPO_A.to_owned()),
        r#box: Some(name(2)),
        ..GetStatsRequest::default()
    };
    assert_eq!(one_of(&store, &both).await.jobs, 1);
    let none = GetStatsRequest {
        repo: Some(REPO_B.to_owned()),
        r#box: Some(name(2)),
        ..GetStatsRequest::default()
    };
    assert_eq!(run(&store, &none).await.groups.len(), 0);
}

async fn one_of(store: &Store, request: &GetStatsRequest) -> StatsGroup {
    let reply = run(store, request).await;
    assert_eq!(reply.groups.len(), 1);
    reply.groups.into_iter().next().unwrap()
}

#[sqlx::test(migrations = false)]
async fn window_is_half_open_and_defaults_to_seven_days(pool: PgPool) {
    let store = store(pool.clone()).await;
    let until = now() - 1000;
    let since = until - 500;
    for (id, at) in [
        ("before", since - 1),
        ("at_since", since),
        ("inside", since + 1),
        ("last", until - 1),
        ("at_until", until),
    ] {
        let job = Seed {
            created: at,
            ..seed(id, "SUCCEEDED")
        };
        insert(&pool, &job).await;
    }
    let reply = run(
        &store,
        &GetStatsRequest {
            since: Some(since),
            until: Some(until),
            ..GetStatsRequest::default()
        },
    )
    .await;
    assert_eq!(reply.groups[0].jobs, 3);
    assert_eq!((reply.since, reply.until), (since, until));
    assert!(!reply.clamped);

    let seven = run(
        &store,
        &GetStatsRequest {
            until: Some(until),
            ..GetStatsRequest::default()
        },
    )
    .await;
    assert_eq!((seven.since, seven.until), (until - 7 * DAY, until));

    let empty = run(
        &store,
        &GetStatsRequest {
            since: Some(since),
            until: Some(since),
            ..GetStatsRequest::default()
        },
    )
    .await;
    assert_eq!(empty.groups.len(), 0);
}

#[sqlx::test(migrations = false)]
async fn default_window_ends_now_and_spans_seven_days(pool: PgPool) {
    let store = store(pool.clone()).await;
    let current = Seed {
        created: now() - 6 * DAY,
        ..seed("in", "SUCCEEDED")
    };
    let old = Seed {
        created: now() - 8 * DAY,
        ..seed("out", "SUCCEEDED")
    };
    insert(&pool, &current).await;
    insert(&pool, &old).await;
    let reply = run(&store, &request(StatsGroupBy::None)).await;
    assert_eq!(reply.groups[0].jobs, 1);
    assert!((reply.until - now()).abs() < 60);
    assert_eq!(reply.until - reply.since, 7 * DAY);
}

#[sqlx::test(migrations = false)]
async fn a_window_over_ninety_days_is_clamped_to_the_newest_ninety(pool: PgPool) {
    let store = store(pool.clone()).await;
    let until = now();
    for (id, days) in [("in", 89), ("old", 95)] {
        let job = Seed {
            created: until - days * DAY,
            ..seed(id, "SUCCEEDED")
        };
        insert(&pool, &job).await;
    }
    let wide = run(
        &store,
        &GetStatsRequest {
            since: Some(until - 100 * DAY),
            until: Some(until),
            ..GetStatsRequest::default()
        },
    )
    .await;
    assert!(wide.clamped);
    assert_eq!(wide.since, until - 90 * DAY);
    assert_eq!(wide.until, until);
    assert_eq!(wide.groups[0].jobs, 1);

    let exact = run(
        &store,
        &GetStatsRequest {
            since: Some(until - 90 * DAY),
            until: Some(until),
            ..GetStatsRequest::default()
        },
    )
    .await;
    assert!(!exact.clamped);
    assert_eq!(exact.since, until - 90 * DAY);
}

#[sqlx::test(migrations = false)]
async fn bad_requests_are_invalid(pool: PgPool) {
    let store = store(pool).await;
    let at = now();
    let window = |since, until| GetStatsRequest {
        since,
        until,
        ..GetStatsRequest::default()
    };
    invalid(&store.stats(&window(Some(at), Some(at - 1))).await);
    invalid(&store.stats(&window(Some(-1), Some(at))).await);
    invalid(&store.stats(&window(Some(0), Some(-1))).await);
    invalid(&store.stats(&window(Some(at), Some(i64::MAX))).await);
    invalid(&store.stats(&window(Some(i64::MAX), None)).await);
    invalid(&store.stats(&window(Some(at + DAY), None)).await);
    invalid(
        &store
            .stats(&window(Some(LAST_SECOND + 1), Some(LAST_SECOND + 1)))
            .await,
    );
    invalid(
        &store
            .stats(&window(Some(LAST_SECOND), Some(LAST_SECOND + 1)))
            .await,
    );
    assert!(store.stats(&window(Some(0), Some(0))).await.is_ok());
    assert!(
        store
            .stats(&window(Some(LAST_SECOND), Some(LAST_SECOND)))
            .await
            .is_ok()
    );
    let filter = |repo: Option<&str>, box_name: Option<&str>| GetStatsRequest {
        repo: repo.map(str::to_owned),
        r#box: box_name.map(str::to_owned),
        ..GetStatsRequest::default()
    };
    invalid(&store.stats(&filter(Some(""), None)).await);
    invalid(&store.stats(&filter(Some("a\0b"), None)).await);
    invalid(&store.stats(&filter(Some(&"x".repeat(2049)), None)).await);
    invalid(&store.stats(&filter(None, Some(""))).await);
    invalid(&store.stats(&filter(None, Some("a\0b"))).await);
    invalid(&store.stats(&filter(None, Some(&"x".repeat(2049)))).await);
    let group = GetStatsRequest {
        group_by: 99,
        ..GetStatsRequest::default()
    };
    invalid(&store.stats(&group).await);
    assert!(
        store
            .stats(&filter(Some(&"x".repeat(2048)), Some(&"y".repeat(2048))))
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = false)]
async fn groups_are_capped_at_two_hundred_and_truncation_is_flagged(pool: PgPool) {
    let store = store(pool.clone()).await;
    sqlx::query(
        "INSERT INTO jobs (job_id, prompt, repo, base_ref, branch, open_pr, state, box) \
         SELECT 'j' || i, 'p', 'https://example.com/org/alpha.git', 'main', 'swarm/x', true, \
         'SUCCEEDED', 'b' || lpad(i::text, 4, '0') FROM generate_series(1, 200) AS i",
    )
    .execute(&pool)
    .await
    .unwrap();
    let reply = run(&store, &request(StatsGroupBy::Box)).await;
    assert_eq!(reply.groups.len(), 200);
    assert!(!reply.truncated);
    insert(
        &pool,
        &Seed {
            box_name: "b9999".to_owned(),
            ..seed("extra", "SUCCEEDED")
        },
    )
    .await;
    let reply = run(&store, &request(StatsGroupBy::Box)).await;
    assert_eq!(reply.groups.len(), 200);
    assert!(reply.truncated);
}

#[sqlx::test(migrations = false)]
async fn group_by_state_never_reads_request_text_as_sql(pool: PgPool) {
    let store = store(pool.clone()).await;
    insert(&pool, &seed("a", "SUCCEEDED")).await;
    let hostile = GetStatsRequest {
        repo: Some("x' OR '1'='1".to_owned()),
        ..GetStatsRequest::default()
    };
    assert_eq!(run(&store, &hostile).await.groups.len(), 0);
}

async fn mark_stuck(pool: &PgPool, id: &str, rule: &str) {
    sqlx::query("UPDATE job_summary SET stuck_rule = $2, stuck_at_seq = 3, stuck_at_ms = 40 WHERE job_id = $1")
        .bind(id)
        .bind(rule)
        .execute(pool)
        .await
        .unwrap();
}

#[sqlx::test(migrations = false)]
async fn stuck_jobs_count_summaries_with_a_rule_against_summarized_jobs(pool: PgPool) {
    let store = store(pool.clone()).await;
    for id in ["a", "b", "c", "d", "e"] {
        insert(&pool, &seed(id, "SUCCEEDED")).await;
    }
    for id in ["a", "b", "c", "d"] {
        with_duration(&pool, id, 100).await;
    }
    mark_stuck(&pool, "a", "repeat_error").await;
    mark_stuck(&pool, "b", "monologue").await;
    let group = one(&store).await;
    assert_eq!(group.jobs, 5);
    assert_eq!(group.with_summary, 4);
    assert_eq!(group.stuck_jobs, 2);
}

#[sqlx::test(migrations = false)]
async fn stuck_jobs_is_zero_when_no_summary_has_a_rule(pool: PgPool) {
    let store = store(pool.clone()).await;
    insert(&pool, &seed("a", "SUCCEEDED")).await;
    with_duration(&pool, "a", 100).await;
    assert_eq!(one(&store).await.stuck_jobs, 0);
}
