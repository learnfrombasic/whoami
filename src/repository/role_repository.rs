use crate::core::errors::AppError;
use crate::models::{Policy, Role, User};
use chrono::Utc;
use sqlx::SqlitePool;

pub struct RoleRepository {
    pool: SqlitePool,
}

impl RoleRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn create(&self, role: &Role) -> Result<Role, AppError> {
        let created_role = sqlx::query_as::<_, Role>(
            r#"
            INSERT INTO roles (id, name, description, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5)
            RETURNING *
            "#,
        )
        .bind(&role.id)
        .bind(&role.name)
        .bind(&role.description)
        .bind(&role.created_at)
        .bind(&role.updated_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(created_role)
    }

    pub async fn find_by_id(&self, id: &str) -> Result<Option<Role>, AppError> {
        let role = sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE id = ?1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;

        Ok(role)
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Option<Role>, AppError> {
        let role = sqlx::query_as::<_, Role>("SELECT * FROM roles WHERE name = ?1")
            .bind(name)
            .fetch_optional(&self.pool)
            .await?;

        Ok(role)
    }

    pub async fn list_all(&self) -> Result<Vec<Role>, AppError> {
        let roles = sqlx::query_as::<_, Role>("SELECT * FROM roles ORDER BY name")
            .fetch_all(&self.pool)
            .await?;

        Ok(roles)
    }

    pub async fn update(
        &self,
        id: &str,
        name: Option<String>,
        description: Option<String>,
    ) -> Result<Role, AppError> {
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

        query_parts.push(format!("updated_at = ?{}", param_index));
        params.push(now.to_rfc3339());
        params.push(id.to_string());

        let query = format!(
            "UPDATE roles SET {} WHERE id = ?{} RETURNING *",
            query_parts.join(", "),
            param_index + 1
        );

        let mut sqlx_query = sqlx::query_as::<_, Role>(&query);
        for param in params {
            sqlx_query = sqlx_query.bind(param);
        }

        let role = sqlx_query.fetch_one(&self.pool).await?;
        Ok(role)
    }

    pub async fn delete(&self, id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM roles WHERE id = ?1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn attach_policy(&self, role_id: &str, policy_id: &str) -> Result<(), AppError> {
        let now = Utc::now();

        sqlx::query(
            "INSERT OR IGNORE INTO role_policies (role_id, policy_id, created_at) VALUES (?1, ?2, ?3)"
        )
        .bind(role_id)
        .bind(policy_id)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn detach_policy(&self, role_id: &str, policy_id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM role_policies WHERE role_id = ?1 AND policy_id = ?2")
            .bind(role_id)
            .bind(policy_id)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_role_policies(&self, role_id: &str) -> Result<Vec<Policy>, AppError> {
        let policies = sqlx::query_as::<_, Policy>(
            r#"
            SELECT p.* FROM policies p
            INNER JOIN role_policies rp ON p.id = rp.policy_id
            WHERE rp.role_id = ?1
            ORDER BY p.name
            "#,
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(policies)
    }

    pub async fn get_role_users(&self, role_id: &str) -> Result<Vec<User>, AppError> {
        let users = sqlx::query_as::<_, User>(
            r#"
            SELECT u.* FROM users u
            INNER JOIN user_roles ur ON u.id = ur.user_id
            WHERE ur.role_id = ?1
            ORDER BY u.username
            "#,
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users)
    }
}
