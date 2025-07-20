use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, ToSchema)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub document: String, // JSON policy document
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyDocument {
    pub version: String,
    pub statement: Vec<PolicyStatement>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyStatement {
    pub effect: Effect,
    pub action: Vec<String>,
    pub resource: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "PascalCase")]
pub enum Effect {
    Allow,
    Deny,
}

impl Policy {
    pub fn new(
        name: String,
        description: Option<String>,
        document: PolicyDocument,
    ) -> Result<Self, serde_json::Error> {
        let now = Utc::now();
        let document_json = serde_json::to_string(&document)?;

        Ok(Policy {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            document: document_json,
            created_at: now,
            updated_at: now,
        })
    }

    pub fn get_document(&self) -> Result<PolicyDocument, serde_json::Error> {
        serde_json::from_str(&self.document)
    }
}

// Default policies for common use cases
impl PolicyDocument {
    pub fn admin_policy() -> Self {
        PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                effect: Effect::Allow,
                action: vec!["*".to_string()],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        }
    }

    pub fn read_only_policy() -> Self {
        PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![PolicyStatement {
                effect: Effect::Allow,
                action: vec![
                    "user:GetUser".to_string(),
                    "user:ListUsers".to_string(),
                    "role:GetRole".to_string(),
                    "role:ListRoles".to_string(),
                    "policy:GetPolicy".to_string(),
                    "policy:ListPolicies".to_string(),
                ],
                resource: vec!["*".to_string()],
                condition: None,
            }],
        }
    }
}
