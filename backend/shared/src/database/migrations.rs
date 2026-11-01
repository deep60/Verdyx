/// Database migration utilities and helpers
use sqlx::postgres::PgPool;
use tracing::{info, warn};

use super::{DatabaseError, DatabaseResult};

/// Migration status information
#[derive(Debug, Clone)]
pub struct MigrationInfo {
    pub version: i64,
    pub description: String,
    pub installed_on: chrono::DateTime<chrono::Utc>,
    pub execution_time: i64,
    pub success: bool,
}

/// Get all applied migrations
pub async fn get_applied_migrations(pool: &PgPool) -> DatabaseResult<Vec<MigrationInfo>> {
    let migrations = sqlx::query_as::<_, (i64, String, chrono::DateTime<chrono::Utc>, i64, bool)>(
        r#"
        SELECT version, description, installed_on, execution_time, success
        FROM _sqlx_migrations
        ORDER BY version
        "#,
    )
    .fetch_all(pool)
    .await
    .map_err(DatabaseError::Connection)?;

    Ok(migrations
        .into_iter()
        .map(
            |(version, description, installed_on, execution_time, success)| MigrationInfo {
                version,
                description,
                installed_on,
                execution_time,
                success,
            },
        )
        .collect())
}

/// Get pending migrations count
pub async fn get_pending_migrations_count(pool: &PgPool) -> DatabaseResult<usize> {
    // This is a simplified check - actual pending migrations would need
    // to compare with available migration files
    let _applied = get_applied_migrations(pool).await?;

    // For now, just return 0 as we're using sqlx's built-in migration system
    Ok(0)
}

/// Check if migrations table exists
pub async fn migrations_table_exists(pool: &PgPool) -> DatabaseResult<bool> {
    let row: (bool,) = sqlx::query_as(
        r#"
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_schema = 'public'
            AND table_name = '_sqlx_migrations'
        )
        "#,
    )
    .fetch_one(pool)
    .await
    .map_err(DatabaseError::Connection)?;

    Ok(row.0)
}

/// Run migrations and return the number of migrations applied
pub async fn run_migrations(pool: &PgPool) -> DatabaseResult<usize> {
    info!("Running database migrations...");

    let before = if migrations_table_exists(pool).await? {
        get_applied_migrations(pool).await?.len()
    } else {
        0
    };

    // Run migrations using sqlx's built-in migration system
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| DatabaseError::Migration(e.to_string()))?;

    let after = get_applied_migrations(pool).await?.len();
    let applied = after - before;

    if applied > 0 {
        info!("Successfully applied {} migration(s)", applied);
    } else {
        info!("No new migrations to apply");
    }

    Ok(applied)
}

/// Rollback last migration (if supported)
pub async fn rollback_last_migration(_pool: &PgPool) -> DatabaseResult<()> {
    warn!("Migration rollback requested");

    // Note: SQLx doesn't support automatic rollbacks
    // This would need to be implemented manually with down migrations

    Err(DatabaseError::Migration(
        "Automatic rollback not supported. Please create manual down migrations.".to_string(),
    ))
}

/// Get latest migration version
pub async fn get_latest_migration_version(pool: &PgPool) -> DatabaseResult<Option<i64>> {
    if !migrations_table_exists(pool).await? {
        return Ok(None);
    }

    let row: Option<(i64,)> =
        sqlx::query_as("SELECT MAX(version) FROM _sqlx_migrations WHERE success = true")
            .fetch_optional(pool)
            .await
            .map_err(DatabaseError::Connection)?;

    Ok(row.map(|r| r.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_info_creation() {
        let info = MigrationInfo {
            version: 1,
            description: "Initial migration".to_string(),
            installed_on: chrono::Utc::now(),
            execution_time: 100,
            success: true,
        };

        assert_eq!(info.version, 1);
        assert!(info.success);
    }
}
