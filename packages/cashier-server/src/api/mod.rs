pub mod app_state;
pub mod errors;
pub mod handlers;
pub mod extractors;
pub mod fields;

use crate::{
    webscoket::client_subscriber::ClientSubscriber,
    api::{
        app_state::AppState,
        extractors::auth::Auth,
    },
};
use actix_web::{web, HttpResponse, Error, HttpRequest};
use actix_web_actors::ws;

async fn websocket(
    req: HttpRequest,
    stream: web::Payload,
    app_data: web::Data<AppState>,
    auth: Auth, // In fact, browsers do not support carry a header in websocket
) -> Result<HttpResponse, Error> {
    ws::start(
        ClientSubscriber::new(
            &app_data,
            &auth,
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
