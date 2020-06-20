use crate::{
    config::StartConfig,
    queries::Query,
    webscoket::{
        main_subscriber::MainSubscriber,
        push_messages::{PushMessage, InnerPushMessage}
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
    pub subscriber: Addr<MainSubscriber>,
}

impl AppState {
    pub fn send(&self, message: InnerPushMessage, auth: &Auth) {
        let (sender_uid, sender_jti) = auth.claims.as_ref()
            .map(|claims| (Some(claims.uid), Some(claims.jti)))
            .unwrap_or_else(|| (None, None));
        self.subscriber.do_send(PushMessage {
            // subject,
            sender_uid,
            sender_jti,
            message,
            created_at: Utc::now(),
        })
    }
}