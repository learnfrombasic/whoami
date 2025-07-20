use crate::core::errors::AppError;
use crate::models::{Policy, Role, User};
use chrono::Utc;
use sqlx::SqlitePool;

pub struct PolicyRepository {
    pool: SqlitePool,
}

impl PolicyRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, policy: &Policy) -> Result<Policy, AppError> {
        let created_policy = sqlx::query_as::<_, Policy>(
            r#"
            INSERT INTO policies (id, name, description, document, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            RETURNING *
            "#,
        )
        .bind(&policy.id)
        .bind(&policy.name)
        .bind(&policy.description)
        .bind(&policy.document)
        .bind(&policy.created_at)
        .bind(&policy.updated_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(created_policy)
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<Policy>, AppError> {
        let policy = sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(policy)
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<Policy>, AppError> {
        let policy = sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(policy)
    }

    pub async fn list_all(&self) -> Result<Vec<Policy>, AppError> {
        let policies = sqlx::query_as::<_, Policy>("SELECT * FROM policies ORDER BY name")
            .fetch_all(&self.pool)
            .await?;

        Ok(policies)
    }

    pub async fn update(
        &self,
        id: &str,
        name: Option<String>,
        description: Option<String>,
        document: Option<String>,
    ) -> Result<Policy, AppError> {
        let now = Utc::now();

        let mut query_parts = Vec::new();
        let mut params: Vec<String> = Vec::new();
        let mut param_index = 1;

        if let Some(name) = name {
            query_parts.push(format!("name = ?{}", param_index));
            params.push(name);
            param_index += 1;
        }

        if let Some(description) = description {
            query_parts.push(format!("description = ?{}", param_index));
            params.push(description);
            param_index += 1;
        }

        if let Some(document) = document {
            query_parts.push(format!("document = ?{}", param_index));
            params.push(document);
            param_index += 1;
        }

        query_parts.push(format!("updated_at = ?{}", param_index));
        params.push(now.to_rfc3339());
        params.push(id.to_string());

        let query = format!(
            "UPDATE policies SET {} WHERE id = ?{} RETURNING *",
            query_parts.join(", "),
            param_index + 1
        );

        let mut sqlx_query = sqlx::query_as::<_, Policy>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let policy = sqlx_query.fetch_one(&self.pool).await?;
        Ok(policy)
    }

    pub async fn delete(&self, id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM policies WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_attached_roles(&self, policy_id: &str) -> Result<Vec<Role>, AppError> {
        let roles = sqlx::query_as::<_, Role>(
            r#"
            SELECT r.* FROM roles r
            INNER JOIN role_policies rp ON r.id = rp.role_id
            WHERE rp.policy_id = ?1
            ORDER BY r.name
            "#,
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(roles)
    }

    pub async fn get_attached_users(&self, policy_id: &str) -> Result<Vec<User>, AppError> {
        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT u.* FROM users u
            INNER JOIN user_policies up ON u.id = up.user_id
            WHERE up.policy_id = ?1 AND u.is_active = 1 AND u.deleted_at IS NULL    
            ORDER BY u.username
            "#,
        )
        .bind(policy_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }
}
