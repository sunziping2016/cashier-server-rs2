pub mod app_state;
pub mod errors;
pub mod handlers;
pub mod extractors;
pub mod fields;

use actix_web::web;

pub fn api_v1(state: &web::Data<app_state::AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let tokens_api = handlers::tokens::tokens_api(state);
    let users_api = handlers::users::users_api(state);
    Box::new(|cfg| {
        cfg.service(
            web::scope("/api/v1")
                .configure(tokens_api)
                .configure(users_api)
        );
    })
}
