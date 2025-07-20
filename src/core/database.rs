use crate::core::{config::Config, errors::AppError};
use sqlx::{sqlite::SqlitePool, Connection, SqliteConnection};

#[derive(Clone)]
pub struct DatabasePool {
    pub pool: SqlitePool,
}

impl DatabasePool {
    pub async fn new(config: &Config) -> Result<Self, AppError> {
        log::info!("Connecting to database: {}", config.database_url);

        let pool = SqlitePool::connect(&config.database_url)
            .await
            .map_err(|e| {
                log::error!("Failed to connect to database: {}", e);
                AppError::from(e)
            })?;

        log::info!("Database connection established successfully");

        Ok(DatabasePool { pool })
    }

    pub fn get_pool(&self) -> &SqlitePool {
        &self.pool
    }
}

// pub async fn create_tables(database_url: &str) -> Result<(), AppError> {
//     let mut conn = SqliteConnection::connect(database_url).await?;

//     // Create users table
//     sqlx::query(
//         r#"
//         CREATE TABLE IF NOT EXISTS users (
//             id TEXT PRIMARY KEY,
//             username TEXT UNIQUE NOT NULL,
//             email TEXT UNIQUE NOT NULL,
//             password_hash TEXT NOT NULL,
//             is_active BOOLEAN DEFAULT TRUE,
//             created_at TEXT NOT NULL,
//             updated_at TEXT NOT NULL
//         )
//         "#,
//     )
//     .execute(&mut conn)
//     .await?;

//     // Create roles table
//     sqlx::query(
//         r#"
//         CREATE TABLE IF NOT EXISTS roles (
//             id TEXT PRIMARY KEY,
//             name TEXT UNIQUE NOT NULL,
//             description TEXT,
//             created_at TEXT NOT NULL,
//             updated_at TEXT NOT NULL
//         )
//         "#,
//     )
//     .execute(&mut conn)
//     .await?;

//     // Create policies table
//     sqlx::query(
//         r#"
//         CREATE TABLE IF NOT EXISTS policies (
//             id TEXT PRIMARY KEY,
//             name TEXT UNIQUE NOT NULL,
//             description TEXT,
//             document TEXT NOT NULL,
//             created_at TEXT NOT NULL,
//             updated_at TEXT NOT NULL
//         )
//         "#,
//     )
//     .execute(&mut conn)
//     .await?;

//     // Create user_roles junction table
//     sqlx::query(
//         r#"
//         CREATE TABLE IF NOT EXISTS user_roles (
//             user_id TEXT NOT NULL,
//             role_id TEXT NOT NULL,
//             created_at TEXT NOT NULL,
//             PRIMARY KEY (user_id, role_id),
//             FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
//             FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
//         )
//         "#,
//     )
//     .execute(&mut conn)
//     .await?;

//     // Create role_policies junction table
//     sqlx::query(
//         r#"
//         CREATE TABLE IF NOT EXISTS role_policies (
//             role_id TEXT NOT NULL,
//             policy_id TEXT NOT NULL,
//             created_at TEXT NOT NULL,
//             PRIMARY KEY (role_id, policy_id),
//             FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
//             FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE
//         )
//         "#,
//     )
//     .execute(&mut conn)
//     .await?;

//     // Create user_policies junction table (direct policy assignment)
//     sqlx::query(
//         r#"
//         CREATE TABLE IF NOT EXISTS user_policies (
//             user_id TEXT NOT NULL,
//             policy_id TEXT NOT NULL,
//             created_at TEXT NOT NULL,
//             PRIMARY KEY (user_id, policy_id),
//             FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
//             FOREIGN KEY (policy_id) REFERENCES policies (id) ON DELETE CASCADE
//         )
//         "#,
//     )
//     .execute(&mut conn)
//     .await?;

//     Ok(())
// }

pub async fn create_tables(database_url: &str) -> Result<(), AppError> {
    log::info!("Creating database tables from whoami.sql");

    let mut conn = SqliteConnection::connect(database_url).await.map_err(|e| {
        log::error!("Failed to connect to database for table creation: {}", e);
        AppError::from(e)
    })?;

    // Read SQL from file
    log::debug!("Reading SQL schema from whoami.sql");
    let sql_content = std::fs::read_to_string("whoami.sql").map_err(|e| {
        log::error!("Failed to read whoami.sql file: {}", e);
        AppError::InternalError(format!("Failed to read whoami.sql: {}", e))
    })?;

    log::info!("Successfully read SQL schema file, executing statements");

    // Split SQL file by semicolons and execute each statement
    let mut statement_count = 0;
    for statement in sql_content.split(';') {
        let statement = statement.trim();
        if !statement.is_empty() && !statement.starts_with("--") {
            log::debug!(
                "Executing SQL statement: {}",
                statement.lines().next().unwrap_or("")
            );

            sqlx::query(statement)
                .execute(&mut conn)
                .await
                .map_err(|e| {
                    log::error!("Failed to execute SQL statement: {}", e);
                    AppError::from(e)
                })?;

            statement_count += 1;
        }
    }

    log::info!("Successfully executed {} SQL statements", statement_count);
    log::info!("Database tables created successfully");

    Ok(())
}
