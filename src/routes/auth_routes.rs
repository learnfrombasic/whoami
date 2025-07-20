use crate::schemas::{LoginRequest, RegisterRequest};
use crate::services::AuthService;
use actix_web::{web, HttpResponse, ResponseError, Result};

pub fn configure_auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(register))
            .route("/login", web::post().to(login))
            .route("/refresh", web::post().to(refresh_token))
            .route("/me", web::get().to(get_current_user)),
    );
}

/// Register a new user
#[utoipa::path(
    post,
    path = "/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = UserResponse),
        (status = 400, description = "Bad request")
    ),
    tag = "Authentication"
)]
async fn register(
    auth_service: web::Data<AuthService>,
    request: web::Json<RegisterRequest>,
) -> Result<HttpResponse> {
    log::info!("POST /auth/register - Registration request received");

    match auth_service.register(request.into_inner()).await {
        Ok(user) => {
            log::info!("Registration endpoint: User created successfully");
            Ok(HttpResponse::Created().json(user.to_response()))
        }
        Err(err) => {
            log::warn!("Registration endpoint failed: {}", err);
            Ok(err.error_response())
        }
    }
}

/// Login with username and password
#[utoipa::path(
    post,
    path = "/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = LoginResponse),
        (status = 401, description = "Invalid credentials")
    ),
    tag = "Authentication"
)]
async fn login(
    auth_service: web::Data<AuthService>,
    request: web::Json<LoginRequest>,
) -> Result<HttpResponse> {
    log::info!("POST /auth/login - Login request received");

    match auth_service.login(request.into_inner()).await {
        Ok(response) => {
            log::info!("Login endpoint: Authentication successful");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(err) => {
            log::warn!("Login endpoint failed: {}", err);
            Ok(err.error_response())
        }
    }
}

/// Refresh access token
#[utoipa::path(
    post,
    path = "/auth/refresh",
    responses(
        (status = 200, description = "Token refreshed", body = TokenResponse),
        (status = 401, description = "Invalid token")
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "Authentication"
)]
async fn refresh_token(
    auth_service: web::Data<AuthService>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    log::info!("POST /auth/refresh - Token refresh request received");

    let token = match extract_token_from_header(&req) {
        Some(token) => token,
        None => {
            log::warn!("Token refresh failed: No authorization token provided");
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "No authorization token provided"
            })));
        }
    };

    match auth_service.refresh_token(&token).await {
        Ok(response) => {
            log::info!("Token refresh successful");
            Ok(HttpResponse::Ok().json(response))
        }
        Err(err) => {
            log::warn!("Token refresh failed: {}", err);
            Ok(err.error_response())
        }
    }
}

/// Get current user information
#[utoipa::path(
    get,
    path = "/auth/me",
    responses(
        (status = 200, description = "Current user info", body = UserResponse),
        (status = 401, description = "Invalid token")
    ),
    security(
        ("bearerAuth" = [])
    ),
    tag = "Authentication"
)]
async fn get_current_user(
    auth_service: web::Data<AuthService>,
    req: actix_web::HttpRequest,
) -> Result<HttpResponse> {
    log::info!("GET /auth/me - Current user request received");

    let token = match extract_token_from_header(&req) {
        Some(token) => token,
        None => {
            log::warn!("Get current user failed: No authorization token provided");
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "No authorization token provided"
            })));
        }
    };

    match auth_service.get_current_user(&token).await {
        Ok(user) => {
            log::info!("Get current user successful for user: {}", user.username);
            Ok(HttpResponse::Ok().json(user.to_response()))
        }
        Err(err) => {
            log::warn!("Get current user failed: {}", err);
            Ok(err.error_response())
        }
    }
}

fn extract_token_from_header(req: &actix_web::HttpRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|auth_header| {
            if auth_header.starts_with("Bearer ") {
                Some(auth_header.trim_start_matches("Bearer ").to_string())
            } else {
                None
            }
        })
}
