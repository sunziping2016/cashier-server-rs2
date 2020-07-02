use crate::{
    config::StartConfig,
    queries::Query,
    websocket::{
        main_subscriber::MainSubscriber,
        push_messages::{InternalMessage, InnerInternalMessage}
    },
    api::extractors::auth::Auth,
};
use actix::{Addr, MailboxError};
use chrono::Utc;
use lettre::SmtpTransport;
use std::result::Result;
use tokio::sync::RwLock;

pub struct AppState {
    pub config: StartConfig,
    pub db: RwLock<tokio_postgres::Client>,
    pub query: Query,
    pub subscriber: Addr<MainSubscriber>,
    pub smtp: SmtpTransport,
}

impl AppState {
    pub async fn send<T: Into<InnerInternalMessage>>(
        &self, message: T, auth: &Auth
    ) -> Result<(), MailboxError> {
        self.send_all(vec![message.into()], auth).await
    }
    pub async fn send_all(
        &self, messages: Vec<InnerInternalMessage>, auth: &Auth
    ) -> Result<(), MailboxError> {
        let (sender_uid, sender_jti) = auth.claims.as_ref()
            .map(|claims| (Some(claims.uid), Some(claims.jti)))
            .unwrap_or_else(|| (None, None));
        self.subscriber.send(InternalMessage {
            // subject,
            sender_uid,
            sender_jti,
            messages,
            created_at: Utc::now(),
        })
            .await
            .map(|_| ())
    }
}