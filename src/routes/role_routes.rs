use crate::services::RoleService;
use actix_web::{web, HttpResponse, Result};

pub fn configure_role_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/roles")
            .route("", web::get().to(list_roles))
            .route("", web::post().to(create_role))
            .route("/{id}", web::get().to(get_role))
            .route("/{id}", web::put().to(update_role))
            .route("/{id}", web::delete().to(delete_role)),
    );
}

async fn list_roles(_role_service: web::Data<RoleService>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Role routes not yet implemented"
    })))
}

async fn create_role(_role_service: web::Data<RoleService>) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Create role endpoint not yet implemented"
    })))
}

async fn get_role(
    _path: web::Path<String>,
    _role_service: web::Data<RoleService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Get role endpoint not yet implemented"
    })))
}

async fn update_role(
    _path: web::Path<String>,
    _role_service: web::Data<RoleService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Update role endpoint not yet implemented"
    })))
}

async fn delete_role(
    _path: web::Path<String>,
    _role_service: web::Data<RoleService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Delete role endpoint not yet implemented"
    })))
}
