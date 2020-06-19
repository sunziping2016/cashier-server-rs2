use crate::{
    actors::{
        server_subscriber::ServerSubscriber,
        messages::AnyMessage,
    },
    api::app_state::AppState,
    queries::tokens::JwtClaims,
};
use actix::{Addr, Actor, Handler};
use actix_web::web;
use actix_web_actors::ws;
use chrono::{DateTime, Utc, NaiveDateTime};
use log::error;

pub struct ClientSubscriber {
    app_data: web::Data<AppState>,
    user_id: i32,
    jwt_id: i32,
    expires_at: DateTime<Utc>,
    heart_beat: DateTime<Utc>,
}

impl ClientSubscriber {
    pub fn new(app_data: &web::Data<AppState>, claims: &JwtClaims) -> Self {
        Self {
            app_data: app_data.clone(),
            user_id: claims.uid,
            jwt_id: claims.jti,
            expires_at: DateTime::from_utc(NaiveDateTime::from_timestamp(claims.exp, 0), Utc),
            heart_beat: Utc::now(),
        }
    }
}

impl Actor for ClientSubscriber {
    type Context = ws::WebsocketContext<Self>;
}

impl Handler<AnyMessage> for ClientSubscriber {
    type Result = ();

    fn handle(&mut self, msg: AnyMessage, ctx: &mut Self::Context) -> Self::Result {
        match serde_json::to_string(&msg) {
            Ok(s) => ctx.text(s),
            Err(e) => {
                error!("client failed to encode message {}", e);
                return;
            }
        }
        // TODO: update permission
    }
}