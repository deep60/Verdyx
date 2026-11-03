//! Schema/query integration test for api-gateway.
//!
//! Applies the embedded migrations to a real Postgres database and exercises the
//! submissions insert used by `create_file_submission`. Runs only when
//! `API_GATEWAY_DATABASE_URL` (or `DATABASE_URL`) is set; otherwise it is a no-op.
//! All writes run inside a rolled-back transaction.

use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

fn test_database_url() -> Option<String> {
    std::env::var("API_GATEWAY_DATABASE_URL")
        .or_else(|_| std::env::var("DATABASE_URL"))
        .ok()
        .filter(|s| !s.is_empty())
}

#[tokio::test]
async fn same_file_from_two_users_keeps_both_submissions() {
    let Some(database_url) = test_database_url() else {
        eprintln!("skipping api-gateway schema test; API_GATEWAY_DATABASE_URL not set");
        return;
    };

    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(&database_url)
        .await
        .expect("connect to test database");

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations apply cleanly");

    let mut tx = pool.begin().await.expect("begin tx");
    let file_hash = format!("{:064x}", Uuid::new_v4().as_u128());
    let alice = Uuid::new_v4();
    let bob = Uuid::new_v4();

    // Mirrors the insert in create_file_submission.
    for submitter in [alice, bob] {
        sqlx::query(
            r#"
            INSERT INTO submissions (
                id, submitter_id, original_filename, file_hash, url, file_size,
                mime_type, file_path, submission_type, analysis_status,
                metadata, created_at, updated_at
            )
            VALUES ($1, $2, 'sample.exe', $3, NULL, 4, 'executable', NULL, 'file',
                    'pending', '{}'::jsonb, NOW(), NOW())
            "#,
        )
        .bind(Uuid::new_v4())
        .bind(submitter)
        .bind(&file_hash)
        .execute(&mut *tx)
        .await
        .expect("insert submission");
    }

    let owners: Vec<Uuid> = sqlx::query_scalar(
        "SELECT submitter_id FROM submissions WHERE file_hash = $1 ORDER BY submitter_id",
    )
    .bind(&file_hash)
    .fetch_all(&mut *tx)
    .await
    .expect("read submissions");

    let mut expected = vec![alice, bob];
    expected.sort();
    assert_eq!(owners, expected, "each uploader keeps their own submission");

    tx.rollback().await.expect("rollback");
}
