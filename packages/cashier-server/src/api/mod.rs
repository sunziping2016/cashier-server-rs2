pub mod app_state;
pub mod errors;
pub mod handlers;
pub mod extractors;
pub mod fields;

use actix_web::{web};

pub fn api_v1(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/v1")
            .configure(handlers::tokens::tokens_api)
            .configure(handlers::users::users_api)
    );
}
