use crate::core::errors::AppError;
use crate::models::{
    policy::Effect, User,
};
use crate::repository::UserRepository;
use crate::schemas::auth::UserInfo;
use crate::schemas::{Claims, LoginRequest, LoginResponse, RegisterRequest, TokenResponse};
use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct AuthService {
    user_repo: UserRepository,
    jwt_secret: String,
}

impl AuthService {
    pub fn new(user_repo: UserRepository, jwt_secret: String) -> Self {
        Self {
            user_repo,
            jwt_secret,
        }
    }

    pub async fn register(&self, request: RegisterRequest) -> Result<User, AppError> {
        log::info!("Registration attempt for username: {}", request.username);

        // Check if user already exists
        if self
            .user_repo
            .find_by_username(&request.username)
            .await?
            .is_some()
        {
            log::warn!(
                "Registration failed: Username '{}' already exists",
                request.username
            );
            return Err(AppError::BadRequest("Username already exists".to_string()));
        }

        if self
            .user_repo
            .find_by_email(&request.email)
            .await?
            .is_some()
        {
            log::warn!(
                "Registration failed: Email '{}' already exists",
                request.email
            );
            return Err(AppError::BadRequest("Email already exists".to_string()));
        }

        // Hash password
        log::debug!("Hashing password for user: {}", request.username);
        let password_hash = hash(&request.password, DEFAULT_COST).map_err(|e| {
            log::error!(
                "Failed to hash password for user {}: {}",
                request.username,
                e
            );
            AppError::InternalError("Failed to hash password".to_string())
        })?;

        // Create user
        log::debug!("Creating user record for: {}", request.username);
        let user = User::new(request.username.clone(), request.email, password_hash);
        let created_user = self.user_repo.create(&user).await.map_err(|e| {
            log::error!("Failed to create user {}: {}", request.username, e);
            e
        })?;

        log::info!(
            "User registration successful: {} (ID: {})",
            request.username,
            created_user.id
        );
        Ok(created_user)
    }

    pub async fn login(&self, request: LoginRequest) -> Result<LoginResponse, AppError> {
        log::info!("Login attempt for username: {}", request.username);

        // Find user by username
        let user = self
            .user_repo
            .find_by_username(&request.username)
            .await?
            .ok_or_else(|| {
                log::warn!("Login failed: User '{}' not found", request.username);
                AppError::InvalidCredentials
            })?;

        // Verify password
        log::debug!("Verifying password for user: {}", request.username);
        let is_valid = verify(&request.password, &user.password_hash).map_err(|e| {
            log::error!(
                "Password verification error for user {}: {}",
                request.username,
                e
            );
            AppError::InternalError("Failed to verify password".to_string())
        })?;

        if !is_valid {
            log::warn!(
                "Login failed: Invalid password for user '{}'",
                request.username
            );
            return Err(AppError::InvalidCredentials);
        }

        if !user.is_active {
            log::warn!(
                "Login failed: User '{}' account is inactive",
                request.username
            );
            return Err(AppError::AuthError("User account is inactive".to_string()));
        }

        // Generate JWT token
        log::debug!("Generating JWT token for user: {}", request.username);
        let token = self.generate_token(&user).map_err(|e| {
            log::error!(
                "Token generation failed for user {}: {}",
                request.username,
                e
            );
            e
        })?;
        let expires_in = 24 * 60 * 60; // 24 hours

        log::info!(
            "Login successful for user: {} (ID: {})",
            request.username,
            user.id
        );

        Ok(LoginResponse {
            access_token: token,
            token_type: "Bearer".to_string(),
            expires_in,
            user: UserInfo {
                id: user.id,
                username: user.username,
                email: user.email,
                is_active: user.is_active,
            },
        })
    }

    pub fn generate_token(&self, user: &User) -> Result<String, AppError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            exp: now + 24 * 60 * 60, // 24 hours
            iat: now,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_ref()),
        )
        .map_err(|_| AppError::InternalError("Failed to generate token".to_string()))
    }

    pub fn verify_token(&self, token: &str) -> Result<Claims, AppError> {
        log::debug!("Verifying JWT token");
        let validation = Validation::default();

        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_ref()),
            &validation,
        )
        .map(|data| {
            log::debug!(
                "Token verification successful for user: {}",
                data.claims.username
            );
            data.claims
        })
        .map_err(|e| {
            log::warn!("Token verification failed: {}", e);
            AppError::InvalidToken
        })
    }

    pub async fn get_current_user(&self, token: &str) -> Result<User, AppError> {
        let claims = self.verify_token(token)?;

        self.user_repo
            .find_by_id(&claims.sub)
            .await?
            .ok_or(AppError::UserNotFound)
    }

    // Policy evaluation engine (simple version of AWS IAM evaluation)
    pub async fn check_permission(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
    ) -> Result<bool, AppError> {
        // Get all policies for the user (direct and through roles)
        let policies = self.user_repo.get_all_user_policies(user_id).await?;

        // Evaluate policies - explicit deny takes precedence
        let mut has_allow = false;

        for policy in policies {
            if let Ok(policy_doc) = policy.get_document() {
                for statement in policy_doc.statement {
                    if self.matches_action(&statement.action, action)
                        && self.matches_resource(&statement.resource, resource)
                    {
                        match statement.effect {
                            Effect::Deny => return Ok(false), // Explicit deny wins
                            Effect::Allow => has_allow = true,
                        }
                    }
                }
            }
        }

        Ok(has_allow)
    }

    fn matches_action(&self, policy_actions: &[String], requested_action: &str) -> bool {
        for action in policy_actions {
            if action == "*" || action == requested_action {
                return true;
            }

            // Support wildcard matching (simple version)
            if action.ends_with('*') {
                let prefix = &action[..action.len() - 1];
                if requested_action.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }

    fn matches_resource(&self, policy_resources: &[String], requested_resource: &str) -> bool {
        for resource in policy_resources {
            if resource == "*" || resource == requested_resource {
                return true;
            }

            // Support wildcard matching (simple version)
            if resource.ends_with('*') {
                let prefix = &resource[..resource.len() - 1];
                if requested_resource.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }

    pub async fn refresh_token(&self, token: &str) -> Result<TokenResponse, AppError> {
        let user = self.get_current_user(token).await?;
        let new_token = self.generate_token(&user)?;
        let expires_in = 24 * 60 * 60; // 24 hours

        Ok(TokenResponse {
            access_token: new_token,
            token_type: "Bearer".to_string(),
            expires_in,
        })
    }
}
