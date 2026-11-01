/// PostgreSQL-specific utilities and helpers
use sqlx::postgres::PgPool;
use sqlx::Row;

use super::{DatabaseError, DatabaseResult};

/// Check if a table exists in the database
pub async fn table_exists(pool: &PgPool, table_name: &str) -> DatabaseResult<bool> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = $1
        )
        "#,
    )
    .bind(table_name)
    .fetch_one(pool)
    .await
    .map_err(DatabaseError::Connection)?;

    Ok(row.0)
}

/// Get the current database version from migrations
pub async fn get_database_version(pool: &PgPool) -> DatabaseResult<Option<i64>> {
    let version_exists = table_exists(pool, "_sqlx_migrations").await?;

    if !version_exists {
        return Ok(None);
    }

    let row: Option<(i64,)> =
        sqlx::query_as("SELECT MAX(version) FROM _sqlx_migrations WHERE success = true")
            .fetch_optional(pool)
            .await
            .map_err(DatabaseError::Connection)?;

    Ok(row.map(|r| r.0))
}

/// Get database statistics
pub async fn get_database_stats(pool: &PgPool) -> DatabaseResult<DatabaseMetrics> {
    let row = sqlx::query(
        r#"
        SELECT
            pg_database_size(current_database()) as size,
            numbackends as connections,
            xact_commit as commits,
            xact_rollback as rollbacks
        FROM pg_stat_database
        WHERE datname = current_database()
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(DatabaseError::Connection)?;

    Ok(DatabaseMetrics {
        database_size_bytes: row.try_get("size").unwrap_or(0),
        active_connections: row.try_get("connections").unwrap_or(0),
        total_commits: row.try_get("commits").unwrap_or(0),
        total_rollbacks: row.try_get("rollbacks").unwrap_or(0),
    })
}

/// PostgreSQL database metrics
#[derive(Debug, Clone)]
pub struct DatabaseMetrics {
    pub database_size_bytes: i64,
    pub active_connections: i32,
    pub total_commits: i64,
    pub total_rollbacks: i64,
}

/// Vacuum analyze a table to optimize query performance
pub async fn vacuum_analyze_table(pool: &PgPool, table_name: &str) -> DatabaseResult<()> {
    // Note: VACUUM cannot be executed inside a transaction block
    let query = format!("VACUUM ANALYZE {}", table_name);

    sqlx::query(&query)
        .execute(pool)
        .await
        .map_err(DatabaseError::Connection)?;

    Ok(())
}
