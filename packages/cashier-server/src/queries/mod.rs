pub mod errors;
pub mod users;
pub mod tokens;

use tokio_postgres::{
    Client,
};

pub struct Query {
    pub user: users::Query,
    pub token: tokens::Query,
}

impl Query {
    pub async fn new(client: &Client) -> Self {
        let user = users::Query::new(client).await;
        let token = tokens::Query::new(client).await;
        Self {
            user,
            token,
        }
    }
}