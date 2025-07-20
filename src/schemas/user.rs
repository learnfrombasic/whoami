use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub is_active: Option<bool>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignRoleRequest {
    pub role_id: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AssignPolicyRequest {
    pub policy_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserWithRolesResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_active: bool,
    pub roles: Vec<RoleInfo>,
    pub policies: Vec<PolicyInfo>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RoleInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PolicyInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}
