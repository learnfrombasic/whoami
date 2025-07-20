use crate::services::PolicyService;
use actix_web::{web, HttpResponse, Result};

pub fn configure_policy_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/policies")
            .route("", web::get().to(list_policies))
            .route("", web::post().to(create_policy))
            .route("/{id}", web::get().to(get_policy))
            .route("/{id}", web::put().to(update_policy))
            .route("/{id}", web::delete().to(delete_policy)),
    );
}

async fn list_policies(_policy_service: web::Data<PolicyService>) -> Result<HttpResponse> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Policy routes not yet implemented"
    })))
}

async fn create_policy(_policy_service: web::Data<PolicyService>) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Create policy endpoint not yet implemented"
    })))
}

async fn get_policy(
    _path: web::Path<String>,
    _policy_service: web::Data<PolicyService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Get policy endpoint not yet implemented"
    })))
}

async fn update_policy(
    _path: web::Path<String>,
    _policy_service: web::Data<PolicyService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Update policy endpoint not yet implemented"
    })))
}

async fn delete_policy(
    _path: web::Path<String>,
    _policy_service: web::Data<PolicyService>,
) -> Result<HttpResponse> {
    Ok(HttpResponse::NotImplemented().json(serde_json::json!({
        "message": "Delete policy endpoint not yet implemented"
    })))
}
