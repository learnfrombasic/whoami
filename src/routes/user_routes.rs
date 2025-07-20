use crate::services::UserService;
use actix_web::{web, HttpResponse, Result};

pub fn configure_user_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/users")
            .route("", web::get().to(list_users))
            .route("", web::post().to(create_user))
            .route("/{id}", web::get().to(get_user))
            .route("/{id}", web::put().to(update_user))
            .route("/{id}", web::delete().to(delete_user)),
    );
}

async fn list_users(_user_service: web::Data<UserService>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "User routes not yet implemented"
    })))
}

async fn create_user(_user_service: web::Data<UserService>) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Create user endpoint not yet implemented"
    })))
}

async fn get_user(
    _path: web::Path<String>,
    _user_service: web::Data<UserService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Get user endpoint not yet implemented"
    })))
}

async fn update_user(
    _path: web::Path<String>,
    _user_service: web::Data<UserService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Update user endpoint not yet implemented"
    })))
}

async fn delete_user(
    _path: web::Path<String>,
    _user_service: web::Data<UserService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Delete user endpoint not yet implemented"
    })))
}
