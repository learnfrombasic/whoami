use crate::core::errors::AppError;
use crate::models::{Policy, Role, User};
use chrono::Utc;
use sqlx::SqlitePool;

pub struct UserRepository {
    pool: SqlitePool,
}

impl UserRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, user: &User) -> Result<User, AppError> {
        log::debug!("Creating user in database: {}", user.username);

        let created_user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (id, username, email, password_hash, is_active, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            RETURNING *
            "#,
        )
        .bind(&user.id)
        .bind(&user.username)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(user.is_active)
        .bind(&user.created_at)
        .bind(&user.updated_at)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            log::error!("Failed to create user {} in database: {}", user.username, e);
            AppError::from(e)
        })?;

        log::debug!("User created successfully in database: {}", user.username);
        Ok(created_user)
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    pub async fn find_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = ?1")
            .bind(username)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = ?1")
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;

        Ok(user)
    }

    pub async fn list_all(&self) -> Result<Vec<User>, AppError> {
        let users = sqlx::query_as::<_, User>("SELECT * FROM users ORDER BY created_at DESC")
            .fetch_all(&self.pool)
            .await?;

        Ok(users)
    }

    pub async fn update(
        &self,
        id: &str,
        username: Option<String>,
        email: Option<String>,
        is_active: Option<bool>,
    ) -> Result<User, AppError> {
        let now = Utc::now();

        // Build dynamic update query
        let mut query_parts = Vec::new();
        let mut params: Vec<String> = Vec::new();
        let mut param_index = 1;

        if let Some(username) = username {
            query_parts.push(format!("username = ?{}", param_index));
            params.push(username);
            param_index += 1;
        }

        if let Some(email) = email {
            query_parts.push(format!("email = ?{}", param_index));
            params.push(email);
            param_index += 1;
        }

        if let Some(is_active) = is_active {
            query_parts.push(format!("is_active = ?{}", param_index));
            params.push(is_active.to_string());
            param_index += 1;
        }

        query_parts.push(format!("updated_at = ?{}", param_index));
        params.push(now.to_rfc3339());
        params.push(id.to_string());

        let query = format!(
            "UPDATE users SET {} WHERE id = ?{} RETURNING *",
            query_parts.join(", "),
            param_index + 1
        );

        let mut sqlx_query = sqlx::query_as::<_, User>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let user = sqlx_query.fetch_one(&self.pool).await?;
        Ok(user)
    }

    pub async fn delete(&self, id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM users WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn assign_role(&self, user_id: &str, role_id: &str) -> Result<(), AppError> {
        let now = Utc::now();

        sqlx::query(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id, created_at) VALUES (?1, ?2, ?3)",
        )
        .bind(user_id)
        .bind(role_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn remove_role(&self, user_id: &str, role_id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2")
            .bind(user_id)
            .bind(role_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_user_roles(&self, user_id: &str) -> Result<Vec<Role>, AppError> {
        let roles = sqlx::query_as::<_, Role>(
            r#"
            SELECT r.* FROM roles r
            INNER JOIN user_roles ur ON r.id = ur.role_id
            WHERE ur.user_id = ?1
            ORDER BY r.name
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(roles)
    }

    pub async fn assign_policy(&self, user_id: &str, policy_id: &str) -> Result<(), AppError> {
        let now = Utc::now();

        sqlx::query(
            "INSERT OR IGNORE INTO user_policies (user_id, policy_id, created_at) VALUES (?1, ?2, ?3)"
        )
        .bind(user_id)
        .bind(policy_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn remove_policy(&self, user_id: &str, policy_id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM user_policies WHERE user_id = ?1 AND policy_id = ?2")
            .bind(user_id)
            .bind(policy_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_user_policies(&self, user_id: &str) -> Result<Vec<Policy>, AppError> {
        let policies = sqlx::query_as::<_, Policy>(
            r#"
            SELECT p.* FROM policies p
            INNER JOIN user_policies up ON p.id = up.policy_id
            WHERE up.user_id = ?1
            ORDER BY p.name
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(policies)
    }

    pub async fn get_all_user_policies(&self, user_id: &str) -> Result<Vec<Policy>, AppError> {
        // Get policies directly assigned to user and through roles
        let policies = sqlx::query_as::<_, Policy>(
            r#"
            SELECT DISTINCT p.* FROM policies p
            WHERE p.id IN (
                SELECT policy_id FROM user_policies WHERE user_id = ?1
                UNION
                SELECT rp.policy_id FROM role_policies rp
                INNER JOIN user_roles ur ON rp.role_id = ur.role_id
                WHERE ur.user_id = ?1
            )
            ORDER BY p.name
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(policies)
    }
}
