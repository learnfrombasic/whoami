use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

mod core;
mod models;
mod repository;
mod routes;
mod schemas;
mod services;

use crate::repository::{UserRepository, RoleRepository, PolicyRepository};
use crate::services::{AuthService, UserService, RoleService, PolicyService};
use crate::core::{
    config::Config,
    database::{create_tables, DatabasePool},
};
use crate::models::policy::{Effect, PolicyDocument, PolicyStatement};
use crate::routes::{
    configure_auth_routes, configure_policy_routes, configure_role_routes, configure_user_routes,
};
use crate::schemas::auth::UserInfo;
use crate::schemas::{LoginRequest, LoginResponse, RegisterRequest, TokenResponse};

#[derive(OpenApi)]
#[openapi(
    paths(
        // crate::routes::auth_routes::register,
        // crate::routes::auth_routes::login,
        // crate::routes::auth_routes::refresh_token,
        // crate::routes::auth_routes::get_current_user,
    ),
    components(
        schemas(
            RegisterRequest,
            LoginRequest,
            LoginResponse,
            TokenResponse,
            UserInfo,
            PolicyDocument,
            PolicyStatement,
            Effect,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Authentication", description = "Authentication and authorization endpoints"),
        (name = "Users", description = "User management endpoints"),
        (name = "Roles", description = "Role management endpoints"),
        (name = "Policies", description = "Policy management endpoints"),
    )
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{Http, HttpAuthScheme, SecurityScheme};

        let components = openapi.components.as_mut().unwrap();
        components.add_security_scheme(
            "bearerAuth",
            SecurityScheme::Http(Http::new(HttpAuthScheme::Bearer)),
        )
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    log::info!("🚀 Starting WHOAMI IAM Service");
    log::info!("Version: {}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    log::info!("Loading configuration from environment");
    let config = Config::from_env().expect("Failed to load configuration");
    log::info!("Configuration loaded successfully");
    log::debug!("Database URL: {}", config.database_url);
    log::debug!(
        "Server address: {}:{}",
        config.server_host,
        config.server_port
    );

    // Create database tables
    if let Err(e) = create_tables(&config.database_url).await {
        log::error!("❌ Failed to create database tables: {}", e);
        std::process::exit(1);
    }

    // Initialize database pool
    let db_pool = match DatabasePool::new(&config).await {
        Ok(pool) => {
            log::info!("✅ Database pool initialized successfully");
            pool
        }
        Err(e) => {
            log::error!("❌ Failed to create database pool: {}", e);
            std::process::exit(1);
        }
    };

    log::info!("Setting up application data and middleware");
    let pool_data = web::Data::new(db_pool.get_pool().clone());
    let jwt_secret = web::Data::new(config.jwt_secret.clone());

    // Create services
    let auth_service = web::Data::new(AuthService::new(
        UserRepository::new(db_pool.get_pool().clone()), 
        config.jwt_secret.clone()
    ));
    let user_service = web::Data::new(UserService::new(
        UserRepository::new(db_pool.get_pool().clone()),
        RoleRepository::new(db_pool.get_pool().clone()),
        PolicyRepository::new(db_pool.get_pool().clone())
    ));
    let role_service = web::Data::new(RoleService::new(
        RoleRepository::new(db_pool.get_pool().clone()),
        PolicyRepository::new(db_pool.get_pool().clone())
    ));
    let policy_service = web::Data::new(PolicyService::new(
        PolicyRepository::new(db_pool.get_pool().clone())
    ));

    let server_addr = config.server_addr();

    log::info!("🌐 Starting HTTP server on {}", server_addr);
    log::info!("📖 API Documentation: http://{}/docs", server_addr);
    log::info!("🔗 API Base URL: http://{}/api/v1", server_addr);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .app_data(pool_data.clone())
            .app_data(jwt_secret.clone())
            .app_data(auth_service.clone())
            .app_data(user_service.clone())
            .app_data(role_service.clone())
            .app_data(policy_service.clone())
            .wrap(cors)
            .wrap(Logger::default())
            .service(
                web::scope("/api/v1")
                    .configure(configure_auth_routes)
                    .configure(configure_user_routes)
                    .configure(configure_role_routes)
                    .configure(configure_policy_routes),
            )
            .service(
                SwaggerUi::new("/docs/{_:.*}").url("/api-docs/openapi.json", ApiDoc::openapi()),
            )
    })
    .bind(&server_addr)
    .map_err(|e| {
        log::error!("❌ Failed to bind to address {}: {}", server_addr, e);
        e
    })?
    .run()
    .await
    .map_err(|e| {
        log::error!("❌ Server runtime error: {}", e);
        e
    })
}
