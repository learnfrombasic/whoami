pub mod auth_routes;
pub mod policy_routes;
pub mod role_routes;
pub mod user_routes;

pub use auth_routes::configure_auth_routes;
pub use policy_routes::configure_policy_routes;
pub use role_routes::configure_role_routes;
pub use user_routes::configure_user_routes;
