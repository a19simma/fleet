use sqlx::PgPool;

use super::{WorkFault, insert_event};
use crate::store::StoreError;

async fn project(pool: &PgPool, user: i64, name: &str) -> i64 {
    sqlx::query_scalar("INSERT INTO work_project (user_id, name) VALUES ($1, $2) RETURNING id")
        .bind(user)
        .bind(name)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[sqlx::test]
async fn event_refuses_item_or_attempt_of_another_project(pool: PgPool) {
    let user: i64 = sqlx::query_scalar("INSERT INTO users (username) VALUES ('u') RETURNING id")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (one, two) = (
        project(&pool, user, "one").await,
        project(&pool, user, "two").await,
    );
    let item: i64 = sqlx::query_scalar(
        "INSERT INTO work_item (project_id, key, title) VALUES ($1, 'i', 't') RETURNING id",
    )
    .bind(one)
    .fetch_one(&pool)
    .await
    .unwrap();
    let attempt: i64 = sqlx::query_scalar(
        "INSERT INTO work_attempt (project_id, item_id, holder, expires_at) \
         VALUES ($1, $2, 'h', now() + interval '1 hour') RETURNING id",
    )
    .bind(one)
    .bind(item)
    .fetch_one(&pool)
    .await
    .unwrap();
    let mut conn = pool.acquire().await.unwrap();
    for (project_id, item_id, attempt_id) in [
        (two, Some(item), None),
        (two, None, Some(attempt)),
        (one, Some(item), Some(attempt + 1000)),
    ] {
        let result =
            insert_event(&mut conn, project_id, item_id, attempt_id, "note", "a", "").await;
        assert!(matches!(
            result,
            Err(StoreError::Work(WorkFault::CrossProject))
        ));
    }
    insert_event(&mut conn, one, Some(item), Some(attempt), "note", "a", "")
        .await
        .unwrap();
    insert_event(&mut conn, two, None, None, "note", "a", "")
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM work_event")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 2);
}
