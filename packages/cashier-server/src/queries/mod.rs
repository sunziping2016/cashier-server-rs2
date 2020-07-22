pub mod errors;
pub mod users;
pub mod tokens;
pub mod email;
pub mod limits;

use tokio_postgres::{
    Client,
};
use tokio::sync::RwLock;

pub struct AppDatabase {
    pub db: RwLock<tokio_postgres::Client>,
    pub user: users::Query,
    pub token: tokens::Query,
    pub limit: limits::Query,
}

impl AppDatabase {
    pub async fn new(client: Client) -> Self {
        let user = users::Query::new(&client).await;
        let token = tokens::Query::new(&client).await;
        let limit = limits::Query::new(&client).await;
        Self {
            db: RwLock::from(client),
            user,
            token,
            limit,
        }
    }
}
