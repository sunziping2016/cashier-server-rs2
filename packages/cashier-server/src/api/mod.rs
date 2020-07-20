pub mod app_state;
pub mod errors;
pub mod handlers;
pub mod extractors;
pub mod fields;
pub mod cursor;

use crate::{
    websocket::client_subscriber::ClientSubscriber,
};
use actix_web::{web, HttpResponse, Error, HttpRequest};
use actix_web_actors::ws;
use crate::api::extractors::config::{default_json_config, default_path_config, default_query_config, default_global_rate_limit};

async fn websocket(
    req: HttpRequest,
    stream: web::Payload,
    database: web::Data<app_state::AppDatabase>,
    subscriber: web::Data<app_state::AppSubscriber>,
) -> Result<HttpResponse, Error> {
    ws::start(
        ClientSubscriber::new(
            database,
            subscriber,
        ),
        &req,
        stream,
    )
}

pub fn api_v1(
    config: &web::Data<app_state::AppConfig>,
    database: &web::Data<app_state::AppDatabase>,
    subscriber: &web::Data<app_state::AppSubscriber>,
    smtp: &web::Data<app_state::AppSmtp>,
) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let tokens_api = handlers::tokens::tokens_api(
        database,
    );
    let users_api = handlers::users::users_api(
        config,
        database,
        subscriber,
        smtp,
    );
    let config = config.clone();
    let database = database.clone();
    let subscriber = subscriber.clone();
    let smtp = smtp.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("/api/v1")
                .wrap(default_global_rate_limit(database.clone()))
                .app_data(config.clone())
                .app_data(database.clone())
                .app_data(subscriber.clone())
                .app_data(smtp.clone())
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
                .configure(tokens_api)
                .configure(users_api)
                .service(
                    web::scope("/ws")
                        .app_data(config.clone())
                        .app_data(database.clone())
                        .app_data(subscriber.clone())
                        .app_data(smtp.clone())
                        .route("", web::route().to(websocket))
                )
        );
    })
}
