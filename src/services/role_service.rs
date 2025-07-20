use crate::core::errors::AppError;
use crate::models::Role;
use crate::repository::{PolicyRepository, RoleRepository};
use crate::schemas::role::{PolicyInfo, UserInfo};
use crate::schemas::{CreateRoleRequest, RoleWithPoliciesResponse, UpdateRoleRequest};

pub struct RoleService {
    role_repo: RoleRepository,
    policy_repo: PolicyRepository,
}

impl RoleService {
    pub fn new(role_repo: RoleRepository, policy_repo: PolicyRepository) -> Self {
        Self {
            role_repo,
            policy_repo,
        }
    }

    pub async fn create_role(&self, request: CreateRoleRequest) -> Result<Role, AppError> {
        // Check if role already exists
        if self.role_repo.find_by_name(&request.name).await?.is_some() {
            return Err(AppError::BadRequest("Role name already exists".to_string()));
        }

        let role = Role::new(request.name, request.description);
        self.role_repo.create(&role).await
    }

    pub async fn get_role(&self, id: &str) -> Result<Role, AppError> {
        self.role_repo
            .find_by_id(id)
            .await?
            .ok_or(AppError::RoleNotFound)
    }

    pub async fn get_role_with_policies(
        &self,
        id: &str,
    ) -> Result<RoleWithPoliciesResponse, AppError> {
        let role = self.get_role(id).await?;
        let policies = self.role_repo.get_role_policies(id).await?;
        let users = self.role_repo.get_role_users(id).await?;

        Ok(RoleWithPoliciesResponse {
            id: role.id,
            name: role.name,
            description: role.description,
            policies: policies
                .into_iter()
                .map(|p| PolicyInfo {
                    id: p.id,
                    name: p.name,
                    description: p.description,
                })
                .collect(),
            users: users
                .into_iter()
                .map(|u| UserInfo {
                    id: u.id,
                    username: u.username,
                    email: u.email,
                })
                .collect(),
        })
    }

    pub async fn list_roles(&self) -> Result<Vec<Role>, AppError> {
        self.role_repo.list_all().await
    }

    pub async fn update_role(
        &self,
        id: &str,
        request: UpdateRoleRequest,
    ) -> Result<Role, AppError> {
        // Check if role exists
        self.get_role(id).await?;

        // Check for name conflicts if name is being changed
        if let Some(ref name) = request.name {
            if let Some(existing) = self.role_repo.find_by_name(name).await? {
                if existing.id != id {
                    return Err(AppError::BadRequest("Role name already exists".to_string()));
                }
            }
        }

        self.role_repo
            .update(id, request.name, request.description)
            .await
    }

    pub async fn delete_role(&self, id: &str) -> Result<(), AppError> {
        // Check if role exists
        self.get_role(id).await?;

        self.role_repo.delete(id).await
    }

    pub async fn attach_policy(&self, role_id: &str, policy_id: &str) -> Result<(), AppError> {
        // Check if role and policy exist
        self.get_role(role_id).await?;
        self.policy_repo
            .find_by_id(policy_id)
            .await?
            .ok_or(AppError::PolicyNotFound)?;

        self.role_repo.attach_policy(role_id, policy_id).await
    }

    pub async fn detach_policy(&self, role_id: &str, policy_id: &str) -> Result<(), AppError> {
        // Check if role exists
        self.get_role(role_id).await?;

        self.role_repo.detach_policy(role_id, policy_id).await
    }
}
