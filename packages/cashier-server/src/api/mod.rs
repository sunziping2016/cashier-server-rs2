pub mod app_state;
pub mod errors;
pub mod handlers;
pub mod extractors;
pub mod fields;
pub mod cursor;

use crate::{
    websocket::client_subscriber::ClientSubscriber,
    api::app_state::AppState,
};
use actix_web::{web, HttpResponse, Error, HttpRequest};
use actix_web_actors::ws;
use crate::api::extractors::config::{default_json_config, default_path_config, default_query_config, default_global_rate_limit};

async fn websocket(
    req: HttpRequest,
    stream: web::Payload,
    app_data: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    ws::start(
        ClientSubscriber::new(
            &app_data,
        ),
        &req,
        stream,
    )
}

pub fn api_v1(state: &web::Data<app_state::AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let tokens_api = handlers::tokens::tokens_api(state);
    let users_api = handlers::users::users_api(state);
    let state = state.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("/api/v1")
                .wrap(default_global_rate_limit(state.clone()))
                .app_data(state.clone())
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
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
