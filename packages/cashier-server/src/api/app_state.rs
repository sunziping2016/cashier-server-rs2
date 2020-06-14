use crate::{
    config::StartConfig,
    queries::Query,
};
use tokio::sync::RwLock;

pub struct AppState {
    pub config: StartConfig,
    pub db: RwLock<tokio_postgres::Client>,
    pub query: Query,
}
