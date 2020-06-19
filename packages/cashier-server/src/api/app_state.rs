use crate::{
    config::StartConfig,
    queries::Query,
    actors::{
        server_subscriber::ServerSubscriber,
        messages::{AnyMessage, InnerAnyMessage}
    },
    api::extractors::auth::Auth,
};
use actix::Addr;
use chrono::Utc;
use tokio::sync::RwLock;

pub struct AppState {
    pub config: StartConfig,
    pub db: RwLock<tokio_postgres::Client>,
    pub query: Query,
    pub subscriber: Addr<ServerSubscriber>,
}

impl AppState {
    pub fn send(&self, message: InnerAnyMessage, auth: &Auth) {
        let (sender_uid, sender_jti) = auth.claims.as_ref()
            .map(|claims| (Some(claims.uid), Some(claims.jti)))
            .unwrap_or_else(|| (None, None));
        self.subscriber.do_send(AnyMessage {
            // subject,
            sender_uid,
            sender_jti,
            message,
            created_at: Utc::now(),
        })
    }
}