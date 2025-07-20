use crate::core::errors::AppError;
use crate::models::User;
use crate::repository::{PolicyRepository, RoleRepository, UserRepository};
use crate::schemas::user::{PolicyInfo, RoleInfo};
use crate::schemas::{CreateUserRequest, UpdateUserRequest, UserWithRolesResponse};
use bcrypt::{hash, DEFAULT_COST};

pub struct UserService {
    user_repo: UserRepository,
    role_repo: RoleRepository,
    policy_repo: PolicyRepository,
}

impl UserService {
    pub fn new(
        user_repo: UserRepository,
        role_repo: RoleRepository,
        policy_repo: PolicyRepository,
    ) -> Self {
        Self {
            user_repo,
            role_repo,
            policy_repo,
        }
    }

    pub async fn create_user(&self, request: CreateUserRequest) -> Result<User, AppError> {
        // Check if user already exists
        if self
            .user_repo
            .find_by_username(&request.username)
            .await?
            .is_some()
        {
            return Err(AppError::BadRequest("Username already exists".to_string()));
        }

        if self
            .user_repo
            .find_by_email(&request.email)
            .await?
            .is_some()
        {
            return Err(AppError::BadRequest("Email already exists".to_string()));
        }

        // Hash password
        let password_hash = hash(&request.password, DEFAULT_COST)
            .map_err(|_| AppError::InternalError("Failed to hash password".to_string()))?;

        // Create user
        let user = User::new(request.username, request.email, password_hash);
        let created_user = self.user_repo.create(&user).await?;

        Ok(created_user)
    }

    pub async fn get_user(&self, id: &str) -> Result<User, AppError> {
        self.user_repo
            .find_by_id(id)
            .await?
            .ok_or(AppError::UserNotFound)
    }

    pub async fn get_user_with_roles(&self, id: &str) -> Result<UserWithRolesResponse, AppError> {
        let user = self.get_user(id).await?;
        let roles = self.user_repo.get_user_roles(id).await?;
        let policies = self.user_repo.get_user_policies(id).await?;

        Ok(UserWithRolesResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            is_active: user.is_active,
            roles: roles
                .into_iter()
                .map(|r| RoleInfo {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                })
                .collect(),
            policies: policies
                .into_iter()
                .map(|p| PolicyInfo {
                    id: p.id,
                    name: p.name,
                    description: p.description,
                })
                .collect(),
        })
    }

    pub async fn list_users(&self) -> Result<Vec<User>, AppError> {
        self.user_repo.list_all().await
    }

    pub async fn update_user(
        &self,
        id: &str,
        request: UpdateUserRequest,
    ) -> Result<User, AppError> {
        // Check if user exists
        self.get_user(id).await?;

        // Check for username/email conflicts if they're being changed
        if let Some(ref username) = request.username {
            if let Some(existing) = self.user_repo.find_by_username(username).await? {
                if existing.id != id {
                    return Err(AppError::BadRequest("Username already exists".to_string()));
                }
            }
        }

        if let Some(ref email) = request.email {
            if let Some(existing) = self.user_repo.find_by_email(email).await? {
                if existing.id != id {
                    return Err(AppError::BadRequest("Email already exists".to_string()));
                }
            }
        }

        self.user_repo
            .update(id, request.username, request.email, request.is_active)
            .await
    }

    pub async fn delete_user(&self, id: &str) -> Result<(), AppError> {
        // Check if user exists
        self.get_user(id).await?;

        self.user_repo.delete(id).await
    }

    pub async fn assign_role(&self, user_id: &str, role_id: &str) -> Result<(), AppError> {
        // Check if user and role exist
        self.get_user(user_id).await?;
        self.role_repo
            .find_by_id(role_id)
            .await?
            .ok_or(AppError::RoleNotFound)?;

        self.user_repo.assign_role(user_id, role_id).await
    }

    pub async fn remove_role(&self, user_id: &str, role_id: &str) -> Result<(), AppError> {
        // Check if user exists
        self.get_user(user_id).await?;

        self.user_repo.remove_role(user_id, role_id).await
    }

    pub async fn assign_policy(&self, user_id: &str, policy_id: &str) -> Result<(), AppError> {
        // Check if user and policy exist
        self.get_user(user_id).await?;
        self.policy_repo
            .find_by_id(policy_id)
            .await?
            .ok_or(AppError::PolicyNotFound)?;

        self.user_repo.assign_policy(user_id, policy_id).await
    }

    pub async fn remove_policy(&self, user_id: &str, policy_id: &str) -> Result<(), AppError> {
        // Check if user exists
        self.get_user(user_id).await?;

        self.user_repo.remove_policy(user_id, policy_id).await
    }
}
