use sqlx::{
    migrate::MigrateDatabase,
    postgres::{PgConnection, PgPoolOptions},
    Pool, Postgres,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;
use tracing::{debug, error, info, warn};

use super::{DatabaseConfig, DatabaseError, DatabaseResult};

/// Type alias for the database pool
pub type DbPool = Pool<Postgres>;
/// Type alias for database connection
pub type DbConnection = PgConnection;

/// Global database pool instance
static DATABASE_POOL: OnceCell<Arc<DbPool>> = OnceCell::const_new();

/// Database manager that handles connection pooling and database operations
#[derive(Debug)]
pub struct DatabaseManager {
    pool: Arc<DbPool>,
    config: DatabaseConfig,
}

impl DatabaseManager {
    /// Create a new database manager with the given configuration
    pub async fn new(config: DatabaseConfig) -> DatabaseResult<Self> {
        let pool = create_connection_pool(&config).await?;

        Ok(Self {
            pool: Arc::new(pool),
            config,
        })
    }

    /// Get a reference to the connection pool
    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    /// Test the database connection
    pub async fn test_connection(&self) -> DatabaseResult<()> {
        test_connection(&self.pool).await
    }

    /// Run database migrations
    pub async fn migrate(&self) -> DatabaseResult<()> {
        migrate_database(&self.pool).await
    }

    /// Get database statistics
    pub async fn get_stats(&self) -> DatabaseStats {
        DatabaseStats {
            active_connections: self.pool.size(),
            idle_connections: self.pool.num_idle() as u32,
            max_connections: self.config.max_connections,
            min_connections: self.config.min_connections,
        }
    }

    /// Initialize the global database pool
    pub async fn initialize_global_pool(config: DatabaseConfig) -> DatabaseResult<()> {
        let pool = create_connection_pool(&config).await?;

        DATABASE_POOL
            .set(Arc::new(pool))
            .map_err(|_| DatabaseError::Config("Failed to set global database pool".to_string()))?;

        info!("Global database pool initialized successfully");
        Ok(())
    }
}

/// Create a new connection pool with the given configuration
pub async fn create_connection_pool(config: &DatabaseConfig) -> DatabaseResult<DbPool> {
    info!("Creating database connection pool...");
    debug!(
        "Database config: host={}, port={}, database={}",
        config.host, config.port, config.database_name
    );

    let database_url = config.database_url();

    // Ensure database exists
    ensure_database_exists(&database_url, &config.database_name).await?;

    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.connection_timeout))
        .idle_timeout(Some(Duration::from_secs(config.idle_timeout)))
        .max_lifetime(Some(Duration::from_secs(1800))) // 30 minutes
        .test_before_acquire(true)
        .connect(&database_url)
        .await
        .map_err(|e| {
            error!("Failed to create connection pool: {}", e);
            DatabaseError::Connection(e)
        })?;

    info!(
        "Database connection pool created successfully with {} max connections",
        config.max_connections
    );

    Ok(pool)
}

/// Get a connection from the global pool
pub async fn get_connection() -> DatabaseResult<Arc<DbPool>> {
    DATABASE_POOL
        .get()
        .ok_or_else(|| DatabaseError::Config("Database pool not initialized".to_string()))
        .cloned()
}

/// Test database connection
pub async fn test_connection(pool: &DbPool) -> DatabaseResult<()> {
    debug!("Testing database connection...");

    let row: (i32,) = sqlx::query_as("SELECT 1")
        .fetch_one(pool)
        .await
        .map_err(|e| {
            error!("Database connection test failed: {}", e);
            DatabaseError::Connection(e)
        })?;

    if row.0 != 1 {
        return Err(DatabaseError::Query(
            "Unexpected result from connection test".to_string(),
        ));
    }

    info!("Database connection test successful");
    Ok(())
}

/// Ensure the database exists, create if it doesn't
async fn ensure_database_exists(database_url: &str, database_name: &str) -> DatabaseResult<()> {
    // Parse URL to get connection without database name
    let parts: Vec<&str> = database_url.splitn(4, '/').collect();
    if parts.len() < 4 {
        return Err(DatabaseError::Config(
            "Invalid database URL format".to_string(),
        ));
    }

    // Remove database name and query params for initial connection
    let base_url = parts[0..3].join("/");
    let _server_url = if base_url.contains('?') {
        format!("{}/postgres", base_url.split('?').next().unwrap())
    } else {
        format!("{}/postgres", base_url)
    };

    debug!("Checking if database '{}' exists...", database_name);

    if !Postgres::database_exists(database_url)
        .await
        .unwrap_or(false)
    {
        info!("Database '{}' does not exist, creating...", database_name);

        Postgres::create_database(database_url).await.map_err(|e| {
            error!("Failed to create database '{}': {}", database_name, e);
            DatabaseError::Migration(format!("Failed to create database: {}", e))
        })?;

        info!("Database '{}' created successfully", database_name);
    } else {
        debug!("Database '{}' already exists", database_name);
    }

    Ok(())
}

/// Run database migrations
pub async fn migrate_database(pool: &DbPool) -> DatabaseResult<()> {
    info!("Running database migrations...");

    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| {
            error!("Migration failed: {}", e);
            DatabaseError::Migration(e.to_string())
        })?;

    info!("Database migrations completed successfully");
    Ok(())
}

/// Database connection statistics
#[derive(Debug, Clone)]
pub struct DatabaseStats {
    pub active_connections: u32,
    pub idle_connections: u32,
    pub max_connections: u32,
    pub min_connections: u32,
}

/// Transaction helper for running multiple operations atomically
pub async fn with_transaction<F, Fut, R>(pool: &DbPool, f: F) -> DatabaseResult<R>
where
    F: FnOnce(&mut sqlx::Transaction<'_, Postgres>) -> Fut,
    Fut: std::future::Future<Output = DatabaseResult<R>>,
{
    let mut tx = pool.begin().await.map_err(DatabaseError::Connection)?;

    let res = f(&mut tx).await;
    match res {
        Ok(result) => {
            tx.commit()
                .await
                .map_err(|e| DatabaseError::Transaction(e.to_string()))?;
            Ok(result)
        }
        Err(e) => {
            if let Err(rollback_err) = tx.rollback().await {
                warn!("Failed to rollback transaction: {}", rollback_err);
            }
            Err(e)
        }
    }
}

/// Connection health check
pub async fn health_check(pool: &DbPool) -> DatabaseResult<bool> {
    match test_connection(pool).await {
        Ok(()) => Ok(true),
        Err(e) => {
            warn!("Database health check failed: {}", e);
            Ok(false)
        }
    }
}

/// Close database connections gracefully
pub async fn close_connections(pool: &DbPool) {
    info!("Closing database connections...");
    pool.close().await;
    info!("Database connections closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[tokio::test]
    async fn test_database_config_from_env() {
        // Set test environment variables
        env::set_var("DATABASE_USER", "test_user");
        env::set_var("DATABASE_PASSWORD", "test_pass");
        env::set_var("DATABASE_NAME", "test_db");

        let config = DatabaseConfig::from_env().unwrap();
        assert_eq!(config.username, "test_user");
        assert_eq!(config.password, "test_pass");
        assert_eq!(config.database_name, "test_db");
    }

    #[test]
    fn test_database_url_generation() {
        let config = DatabaseConfig {
            host: "localhost".to_string(),
            port: 5432,
            username: "user".to_string(),
            password: "pass".to_string(),
            database_name: "db".to_string(),
            ssl_mode: "require".to_string(),
            ..Default::default()
        };

        let expected_url = "postgresql://user:pass@localhost:5432/db?sslmode=require";
        assert_eq!(config.database_url(), expected_url);
    }
}
