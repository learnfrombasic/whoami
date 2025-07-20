# WHOAMI - Security Guide

## Overview

This document outlines the security considerations, best practices, and implementation details for the WHOAMI IAM service. **This service is designed for educational purposes and should not be used in production without proper security review and hardening.**

---

## Authentication Security

### Password Security

#### Password Hashing
- **Algorithm**: bcrypt with configurable cost factor
- **Default Cost**: 12 (adjustable based on performance requirements)
- **Salt**: Automatically generated and unique per password

```rust
use bcrypt::{hash, verify, DEFAULT_COST};

// Hashing passwords
let password_hash = hash(password, DEFAULT_COST)?;

// Verifying passwords
let is_valid = verify(password, &stored_hash)?;
```

#### Password Requirements (Recommended)

```rust
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < 8 {
        return Err("Password must be at least 8 characters long".to_string());
    }
    
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;':\",./<>?".contains(c));
    
    if !has_uppercase || !has_lowercase || !has_digit || !has_special {
        return Err("Password must contain uppercase, lowercase, digit, and special character".to_string());
    }
    
    Ok(())
}
```

#### Password Storage
- **Never store plaintext passwords**
- **Use secure memory allocation** for temporary password handling
- **Clear password variables** after use

```rust
use zeroize::Zeroize;

pub struct SecureString(String);

impl Drop for SecureString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
```

### JWT Token Security

#### Token Generation
```rust
use jsonwebtoken::{encode, EncodingKey, Header, Algorithm};
use chrono::{Utc, Duration};

pub struct JwtConfig {
    secret: String,
    algorithm: Algorithm,
    expiration: Duration,
}

impl JwtConfig {
    pub fn new(secret: String) -> Self {
        Self {
            secret,
            algorithm: Algorithm::HS256,
            expiration: Duration::hours(24),
        }
    }
    
    pub fn generate_token(&self, user: &User) -> Result<String, JwtError> {
        let now = Utc::now();
        let claims = Claims {
            sub: user.id.clone(),
            username: user.username.clone(),
            email: user.email.clone(),
            iat: now.timestamp() as usize,
            exp: (now + self.expiration).timestamp() as usize,
        };
        
        let header = Header::new(self.algorithm);
        encode(&header, &claims, &EncodingKey::from_secret(self.secret.as_ref()))
            .map_err(|e| JwtError::GenerationError(e.to_string()))
    }
}
```

#### Token Validation
```rust
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};

pub fn validate_token(token: &str, secret: &str) -> Result<Claims, JwtError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;
    validation.validate_nbf = true;
    validation.leeway = 60; // 60 seconds leeway for clock skew
    
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &validation
    )
    .map(|data| data.claims)
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => JwtError::Expired,
        jsonwebtoken::errors::ErrorKind::InvalidToken => JwtError::Invalid,
        _ => JwtError::ValidationError(e.to_string()),
    })
}
```

#### Token Security Best Practices

1. **Short Expiration Times**: Default 24 hours, configurable
2. **Secure Secret Management**: Use environment variables, never hardcode
3. **Token Rotation**: Implement refresh tokens for long-lived sessions
4. **Blacklist Mechanism**: For immediate token revocation

```rust
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct TokenBlacklist {
    revoked_tokens: Arc<RwLock<HashSet<String>>>,
}

impl TokenBlacklist {
    pub fn new() -> Self {
        Self {
            revoked_tokens: Arc::new(RwLock::new(HashSet::new())),
        }
    }
    
    pub async fn revoke_token(&self, token_id: &str) {
        let mut tokens = self.revoked_tokens.write().await;
        tokens.insert(token_id.to_string());
    }
    
    pub async fn is_revoked(&self, token_id: &str) -> bool {
        let tokens = self.revoked_tokens.read().await;
        tokens.contains(token_id)
    }
}
```

---

## Authorization Security

### Policy-Based Access Control (PBAC)

#### Policy Evaluation Engine

The system implements AWS IAM-style policy evaluation:

```rust
pub struct PolicyEvaluator {
    user_repo: UserRepository,
}

impl PolicyEvaluator {
    pub async fn evaluate_permission(
        &self,
        user_id: &str,
        action: &str,
        resource: &str,
        context: &EvaluationContext,
    ) -> Result<PolicyDecision, AppError> {
        // Step 1: Get all applicable policies
        let policies = self.get_applicable_policies(user_id).await?;
        
        // Step 2: Evaluate explicit deny first
        for policy in &policies {
            if let Some(decision) = self.evaluate_policy(policy, action, resource, context)? {
                if decision == PolicyDecision::Deny {
                    return Ok(PolicyDecision::Deny); // Explicit deny always wins
                }
            }
        }
        
        // Step 3: Evaluate explicit allow
        for policy in &policies {
            if let Some(decision) = self.evaluate_policy(policy, action, resource, context)? {
                if decision == PolicyDecision::Allow {
                    return Ok(PolicyDecision::Allow);
                }
            }
        }
        
        // Step 4: Default deny
        Ok(PolicyDecision::Deny)
    }
    
    fn evaluate_policy(
        &self,
        policy: &Policy,
        action: &str,
        resource: &str,
        context: &EvaluationContext,
    ) -> Result<Option<PolicyDecision>, AppError> {
        let document = policy.get_document()?;
        
        for statement in document.statement {
            if self.matches_action(&statement.action, action) && 
               self.matches_resource(&statement.resource, resource) &&
               self.evaluate_conditions(&statement.condition, context)? {
                return Ok(Some(match statement.effect {
                    Effect::Allow => PolicyDecision::Allow,
                    Effect::Deny => PolicyDecision::Deny,
                }));
            }
        }
        
        Ok(None)
    }
}

#[derive(Debug, PartialEq)]
pub enum PolicyDecision {
    Allow,
    Deny,
}

pub struct EvaluationContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub current_time: DateTime<Utc>,
}
```

#### Action and Resource Matching

```rust
impl PolicyEvaluator {
    fn matches_action(&self, policy_actions: &[String], requested_action: &str) -> bool {
        for action in policy_actions {
            if action == "*" {
                return true;
            }
            
            if action == requested_action {
                return true;
            }
            
            // Wildcard matching
            if action.ends_with('*') {
                let prefix = &action[..action.len() - 1];
                if requested_action.starts_with(prefix) {
                    return true;
                }
            }
            
            // Service-level wildcards (e.g., "user:*")
            if let Some((service, action_part)) = action.split_once(':') {
                if action_part == "*" {
                    if let Some((req_service, _)) = requested_action.split_once(':') {
                        if service == req_service {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }
    
    fn matches_resource(&self, policy_resources: &[String], requested_resource: &str) -> bool {
        for resource in policy_resources {
            if resource == "*" {
                return true;
            }
            
            if resource == requested_resource {
                return true;
            }
            
            // Path-based matching for hierarchical resources
            if resource.ends_with("/*") {
                let prefix = &resource[..resource.len() - 2];
                if requested_resource.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }
}
```

### Principle of Least Privilege

#### Default Policies

```rust
impl PolicyDocument {
    pub fn read_only_policy() -> Self {
        PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![
                PolicyStatement {
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
                }
            ],
        }
    }
    
    pub fn user_self_management_policy(user_id: &str) -> Self {
        PolicyDocument {
            version: "2012-10-17".to_string(),
            statement: vec![
                PolicyStatement {
                    effect: Effect::Allow,
                    action: vec![
                        "user:GetUser".to_string(),
                        "user:UpdateUser".to_string(),
                    ],
                    resource: vec![format!("user:{}", user_id)],
                    condition: None,
                }
            ],
        }
    }
}
```

---

## Transport Security

### HTTPS Configuration

```rust
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};

pub fn create_tls_config(cert_file: &str, key_file: &str) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(cert_file)?;
    let key_file = std::fs::File::open(key_file)?;
    
    let cert_chain = certs(&mut std::io::BufReader::new(cert_file))?
        .into_iter()
        .map(Certificate)
        .collect();
    
    let mut keys = pkcs8_private_keys(&mut std::io::BufReader::new(key_file))?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();
    
    if keys.is_empty() {
        return Err("No private key found".into());
    }
    
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, keys.remove(0))?;
    
    Ok(config)
}
```

### Security Headers

```rust
use actix_web::{HttpResponse, middleware::DefaultHeaders};

pub fn security_headers() -> DefaultHeaders {
    DefaultHeaders::new()
        .add(("X-Content-Type-Options", "nosniff"))
        .add(("X-Frame-Options", "DENY"))
        .add(("X-XSS-Protection", "1; mode=block"))
        .add(("Strict-Transport-Security", "max-age=31536000; includeSubDomains"))
        .add(("Content-Security-Policy", "default-src 'self'"))
        .add(("Referrer-Policy", "strict-origin-when-cross-origin"))
}
```

### CORS Configuration

```rust
use actix_cors::Cors;

pub fn cors_config(allowed_origins: &[String]) -> Cors {
    let mut cors = Cors::default()
        .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
        .allowed_headers(vec![
            actix_web::http::header::AUTHORIZATION,
            actix_web::http::header::ACCEPT,
            actix_web::http::header::CONTENT_TYPE,
        ])
        .max_age(3600);
    
    for origin in allowed_origins {
        cors = cors.allowed_origin(origin);
    }
    
    cors
}
```

---

## Input Validation and Sanitization

### Request Validation

```rust
use validator::{Validate, ValidationError};
use regex::Regex;

lazy_static! {
    static ref USERNAME_REGEX: Regex = Regex::new(r"^[a-zA-Z0-9_]{3,50}$").unwrap();
    static ref EMAIL_REGEX: Regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
}

#[derive(Deserialize, Validate)]
pub struct CreateUserRequest {
    #[validate(regex = "USERNAME_REGEX")]
    pub username: String,
    
    #[validate(regex = "EMAIL_REGEX")]
    pub email: String,
    
    #[validate(length(min = 8, max = 128))]
    pub password: String,
}

fn validate_username(username: &str) -> Result<(), ValidationError> {
    if !USERNAME_REGEX.is_match(username) {
        return Err(ValidationError::new("invalid_username"));
    }
    
    // Check for reserved usernames
    let reserved = ["admin", "root", "system", "api", "null", "undefined"];
    if reserved.contains(&username.to_lowercase().as_str()) {
        return Err(ValidationError::new("reserved_username"));
    }
    
    Ok(())
}
```

### SQL Injection Prevention

```rust
// Good: Using parameterized queries with SQLx
pub async fn find_user_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
    let user = sqlx::query_as!(
        User,
        "SELECT * FROM users WHERE username = ?1",
        username  // This is properly parameterized
    )
    .fetch_optional(&self.pool)
    .await?;
    
    Ok(user)
}

// Bad: String concatenation (vulnerable to SQL injection)
// Never do this:
// let query = format!("SELECT * FROM users WHERE username = '{}'", username);
```

### XSS Prevention

```rust
use htmlescape::encode_minimal;

pub fn sanitize_output(input: &str) -> String {
    encode_minimal(input)
}

// For JSON responses, actix-web handles this automatically
// But be careful with raw HTML responses
```

---

## Session Security

### Session Management

```rust
use uuid::Uuid;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use tokio::sync::RwLock;

pub struct SessionManager {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    max_session_duration: Duration,
}

impl SessionManager {
    pub fn new(max_session_duration: Duration) -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            max_session_duration,
        }
    }
    
    pub async fn create_session(&self, user_id: &str) -> Result<String, AppError> {
        let session_id = Uuid::new_v4().to_string();
        let expires_at = Utc::now() + self.max_session_duration;
        
        let session = Session {
            id: session_id.clone(),
            user_id: user_id.to_string(),
            created_at: Utc::now(),
            expires_at,
            last_activity: Utc::now(),
        };
        
        let mut sessions = self.sessions.write().await;
        sessions.insert(session_id.clone(), session);
        
        Ok(session_id)
    }
    
    pub async fn validate_session(&self, session_id: &str) -> Result<Option<String>, AppError> {
        let mut sessions = self.sessions.write().await;
        
        if let Some(session) = sessions.get_mut(session_id) {
            if session.expires_at > Utc::now() {
                session.last_activity = Utc::now();
                Ok(Some(session.user_id.clone()))
            } else {
                sessions.remove(session_id);
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }
    
    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Utc::now();
        sessions.retain(|_, session| session.expires_at > now);
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
}
```

---

## Audit Logging

### Security Event Logging

```rust
use serde_json::json;
use tracing::{info, warn, error};

pub struct SecurityLogger;

impl SecurityLogger {
    pub fn log_authentication_success(user_id: &str, ip: Option<&str>) {
        info!(
            event = "authentication_success",
            user_id = user_id,
            ip_address = ip,
            timestamp = %Utc::now()
        );
    }
    
    pub fn log_authentication_failure(username: &str, ip: Option<&str>, reason: &str) {
        warn!(
            event = "authentication_failure",
            username = username,
            ip_address = ip,
            reason = reason,
            timestamp = %Utc::now()
        );
    }
    
    pub fn log_authorization_failure(user_id: &str, action: &str, resource: &str, ip: Option<&str>) {
        warn!(
            event = "authorization_failure",
            user_id = user_id,
            action = action,
            resource = resource,
            ip_address = ip,
            timestamp = %Utc::now()
        );
    }
    
    pub fn log_policy_change(admin_user_id: &str, policy_id: &str, action: &str) {
        info!(
            event = "policy_change",
            admin_user_id = admin_user_id,
            policy_id = policy_id,
            action = action,
            timestamp = %Utc::now()
        );
    }
    
    pub fn log_suspicious_activity(user_id: &str, activity: &str, details: serde_json::Value) {
        error!(
            event = "suspicious_activity",
            user_id = user_id,
            activity = activity,
            details = %details,
            timestamp = %Utc::now()
        );
    }
}
```

### Audit Trail Storage

```rust
pub struct AuditEvent {
    pub id: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub action: String,
    pub resource: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
}

pub struct AuditRepository {
    pool: SqlitePool,
}

impl AuditRepository {
    pub async fn log_event(&self, event: &AuditEvent) -> Result<(), AppError> {
        sqlx::query!(
            r#"
            INSERT INTO audit_events (id, event_type, user_id, action, resource, ip_address, user_agent, timestamp, details)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
            "#,
            event.id,
            event.event_type,
            event.user_id,
            event.action,
            event.resource,
            event.ip_address,
            event.user_agent,
            event.timestamp,
            event.details.to_string()
        )
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
}
```

---

## Rate Limiting

### Implementation

```rust
use std::collections::HashMap;
use std::net::IpAddr;
use tokio::time::{Duration, Instant};
use tokio::sync::RwLock;

pub struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window_duration: Duration,
}

impl RateLimiter {
    pub fn new(max_requests: usize, window_duration: Duration) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window_duration,
        }
    }
    
    pub async fn is_allowed(&self, identifier: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        let entry = requests.entry(identifier.to_string()).or_insert_with(Vec::new);
        
        // Remove expired entries
        entry.retain(|&time| now.duration_since(time) < self.window_duration);
        
        if entry.len() >= self.max_requests {
            false
        } else {
            entry.push(now);
            true
        }
    }
    
    pub async fn cleanup_expired(&self) {
        let mut requests = self.requests.write().await;
        let now = Instant::now();
        
        requests.retain(|_, times| {
            times.retain(|&time| now.duration_since(time) < self.window_duration);
            !times.is_empty()
        });
    }
}

// Actix-web middleware
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, HttpResponse,
};

pub struct RateLimitingMiddleware {
    rate_limiter: Arc<RateLimiter>,
}

impl RateLimitingMiddleware {
    pub fn new(rate_limiter: Arc<RateLimiter>) -> Self {
        Self { rate_limiter }
    }
}
```

---

## Data Protection

### Sensitive Data Handling

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
pub struct SensitiveData {
    data: Vec<u8>,
}

impl SensitiveData {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
    
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

// Automatically zeroes memory on drop
```

### Database Encryption at Rest

```rust
// For SQLite with encryption (requires SQLCipher)
pub fn create_encrypted_connection(database_url: &str, key: &str) -> Result<SqliteConnectOptions, sqlx::Error> {
    SqliteConnectOptions::from_str(database_url)?
        .pragma("key", format!("'{}'", key))
        .pragma("cipher_page_size", "4096")
        .pragma("kdf_iter", "256000")
        .pragma("cipher_hmac_algorithm", "HMAC_SHA512")
        .pragma("cipher_kdf_algorithm", "PBKDF2_HMAC_SHA512")
}
```

---

## Security Headers and Middleware

### Comprehensive Security Middleware

```rust
use actix_web::{
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    http::HeaderValue,
    Error, HttpMessage,
};

pub struct SecurityHeadersMiddleware;

impl<S, B> Transform<S, ServiceRequest> for SecurityHeadersMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersService { service }))
    }
}

pub struct SecurityHeadersService<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_web::dev::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let fut = self.service.call(req);

        Box::pin(async move {
            let mut res = fut.await?;
            
            let headers = res.headers_mut();
            headers.insert(
                actix_web::http::header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(
                actix_web::http::header::X_FRAME_OPTIONS,
                HeaderValue::from_static("DENY"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static("1; mode=block"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("strict-transport-security"),
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            );
            headers.insert(
                actix_web::http::header::HeaderName::from_static("content-security-policy"),
                HeaderValue::from_static("default-src 'self'; script-src 'self' 'unsafe-inline'"),
            );
            
            Ok(res)
        })
    }
}
```

---

## Vulnerability Assessment

### Common Vulnerabilities to Test

1. **SQL Injection**: Test all input fields with SQL payloads
2. **XSS**: Test with JavaScript payloads in all text inputs
3. **JWT Vulnerabilities**: Test with modified, expired, and malformed tokens
4. **Authorization Bypass**: Test accessing resources without proper permissions
5. **Password Attacks**: Test with common passwords and brute force attempts
6. **Session Fixation**: Test session handling security
7. **CORS Misconfiguration**: Test cross-origin requests

### Security Testing Tools

```bash
# Static analysis
cargo clippy -- -W clippy::all -W clippy::pedantic -W clippy::nursery

# Dependency audit
cargo audit

# Fuzzing with cargo-fuzz
cargo install cargo-fuzz
cargo fuzz init
cargo fuzz run fuzz_target_1
```

---

## Security Configuration Checklist

### Production Security Checklist

- [ ] Strong JWT secret (32+ characters, random)
- [ ] HTTPS enabled with valid certificates
- [ ] Security headers configured
- [ ] Rate limiting implemented
- [ ] Input validation on all endpoints
- [ ] SQL injection prevention verified
- [ ] XSS prevention verified
- [ ] CORS properly configured
- [ ] Audit logging enabled
- [ ] Error messages don't leak sensitive information
- [ ] Database connection encrypted (if required)
- [ ] Sensitive data properly handled
- [ ] Dependencies regularly updated
- [ ] Security patches applied
- [ ] Penetration testing performed

### Environment Variables

```bash
# Production environment security
JWT_SECRET=<generate-strong-random-secret-32-chars-min>
DATABASE_URL=sqlite:/secure/path/whoami.db
RUST_LOG=info  # Don't use debug in production
ENABLE_HTTPS=true
CERT_FILE=/path/to/cert.pem
KEY_FILE=/path/to/key.pem
ALLOWED_ORIGINS=https://yourdomain.com
MAX_REQUEST_RATE=100
SESSION_TIMEOUT=3600
```

---

## Incident Response

### Security Incident Response Plan

1. **Detection**: Monitor logs for suspicious activities
2. **Assessment**: Determine the scope and impact
3. **Containment**: Immediately revoke affected tokens/sessions
4. **Investigation**: Analyze logs and audit trail
5. **Recovery**: Restore services and apply fixes
6. **Lessons Learned**: Update security measures

### Emergency Procedures

```rust
// Emergency token revocation
pub async fn emergency_revoke_all_tokens(&self) -> Result<(), AppError> {
    // Change JWT secret to invalidate all tokens
    self.update_jwt_secret().await?;
    
    // Clear all active sessions
    self.session_manager.clear_all_sessions().await?;
    
    // Log the emergency action
    SecurityLogger::log_emergency_action("all_tokens_revoked");
    
    Ok(())
}

// Account lockout
pub async fn lock_user_account(&self, user_id: &str, reason: &str) -> Result<(), AppError> {
    // Disable user account
    self.user_repo.update(user_id, None, None, Some(false)).await?;
    
    // Revoke all user sessions
    self.session_manager.revoke_user_sessions(user_id).await?;
    
    // Log the action
    SecurityLogger::log_account_lockout(user_id, reason);
    
    Ok(())
}
```

**Remember: This is an educational project. For production use, conduct thorough security reviews, penetration testing, and compliance assessments.** 