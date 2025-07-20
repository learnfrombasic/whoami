use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AttachPolicyRequest {
    pub policy_id: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RoleWithPoliciesResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub policies: Vec<PolicyInfo>,
    pub users: Vec<UserInfo>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PolicyInfo {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct UserInfo {
    pub id: String,
    pub username: String,
    pub email: String,
}
