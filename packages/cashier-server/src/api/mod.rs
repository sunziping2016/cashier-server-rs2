pub mod app_state;
pub mod errors;
pub mod handlers;
pub mod extractors;
pub mod fields;

use actix_web::{web, HttpResponse, Error};

async fn websocket() -> Result<HttpResponse, Error> {
    unimplemented!()
}

pub fn api_v1(state: &web::Data<app_state::AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let tokens_api = handlers::tokens::tokens_api(state);
    let users_api = handlers::users::users_api(state);
    let state = state.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("/api/v1")
                .configure(tokens_api)
                .configure(users_api)
                .service(
                    web::scope("/ws")
                        .app_data(state)
                        .route("", web::route().to(websocket))
                )
        );
    })
}
