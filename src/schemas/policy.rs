use crate::models::policy::PolicyDocument;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePolicyRequest {
    pub name: String,
    pub description: Option<String>,
    pub document: PolicyDocument,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePolicyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub document: Option<PolicyDocument>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyWithDetailsResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub document: PolicyDocument,
    pub attached_roles: Vec<RoleInfo>,
    pub attached_users: Vec<UserInfo>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RoleInfo {
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
