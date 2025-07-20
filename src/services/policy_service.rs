use crate::core::errors::AppError;
use crate::models::Policy;
use crate::repository::PolicyRepository;
use crate::schemas::policy::{RoleInfo, UserInfo};
use crate::schemas::{CreatePolicyRequest, PolicyWithDetailsResponse, UpdatePolicyRequest};

pub struct PolicyService {
    policy_repo: PolicyRepository,
}

impl PolicyService {
    pub fn new(policy_repo: PolicyRepository) -> Self {
        Self { policy_repo }
    }

    pub async fn create_policy(&self, request: CreatePolicyRequest) -> Result<Policy, AppError> {
        // Check if policy already exists
        if self
            .policy_repo
            .find_by_name(&request.name)
            .await?
            .is_some()
        {
            return Err(AppError::BadRequest(
                "Policy name already exists".to_string(),
            ));
        }

        let policy = Policy::new(request.name, request.description, request.document)
            .map_err(|e| AppError::BadRequest(format!("Invalid policy document: {}", e)))?;

        self.policy_repo.create(&policy).await
    }

    pub async fn get_policy(&self, id: &str) -> Result<Policy, AppError> {
        self.policy_repo
            .find_by_id(id)
            .await?
            .ok_or(AppError::PolicyNotFound)
    }

    pub async fn get_policy_with_details(
        &self,
        id: &str,
    ) -> Result<PolicyWithDetailsResponse, AppError> {
        let policy = self.get_policy(id).await?;
        let roles = self.policy_repo.get_attached_roles(id).await?;
        let users = self.policy_repo.get_attached_users(id).await?;

        let document = policy.get_document().map_err(|e| {
            AppError::InternalError(format!("Failed to parse policy document: {}", e))
        })?;

        Ok(PolicyWithDetailsResponse {
            id: policy.id,
            name: policy.name,
            description: policy.description,
            document,
            attached_roles: roles
                .into_iter()
                .map(|r| RoleInfo {
                    id: r.id,
                    name: r.name,
                    description: r.description,
                })
                .collect(),
            attached_users: users
                .into_iter()
                .map(|u| UserInfo {
                    id: u.id,
                    username: u.username,
                    email: u.email,
                })
                .collect(),
        })
    }

    pub async fn list_policies(&self) -> Result<Vec<Policy>, AppError> {
        self.policy_repo.list_all().await
    }

    pub async fn update_policy(
        &self,
        id: &str,
        request: UpdatePolicyRequest,
    ) -> Result<Policy, AppError> {
        // Check if policy exists
        self.get_policy(id).await?;

        // Check for name conflicts if name is being changed
        if let Some(ref name) = request.name {
            if let Some(existing) = self.policy_repo.find_by_name(name).await? {
                if existing.id != id {
                    return Err(AppError::BadRequest(
                        "Policy name already exists".to_string(),
                    ));
                }
            }
        }

        // Serialize document if provided
        let document_json = if let Some(doc) = request.document {
            Some(
                serde_json::to_string(&doc)
                    .map_err(|e| AppError::BadRequest(format!("Invalid policy document: {}", e)))?,
            )
        } else {
            None
        };

        self.policy_repo
            .update(id, request.name, request.description, document_json)
            .await
    }

    pub async fn delete_policy(&self, id: &str) -> Result<(), AppError> {
        // Check if policy exists
        self.get_policy(id).await?;

        self.policy_repo.delete(id).await
    }
}
