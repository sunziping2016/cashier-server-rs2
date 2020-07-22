use tokio_postgres::{Client, Statement, types::Type, IsolationLevel};
use crate::queries::errors::Result;
use crate::api::app_state::AppDatabase;

pub struct Query {
    pub update_bucket: Statement,
    pub acquire_token_from_bucket: Statement,
}

impl Query {
    pub async fn new(client: &Client) -> Self {
        let update_bucket = client.prepare_typed(
            "INSERT INTO limits (subject, remote, available_tokens, last_time) \
                VALUES ($1, $2, $3, NOW()) \
            ON CONFLICT (subject, remote) \
            DO UPDATE SET \
                available_tokens = LEAST(limits.available_tokens + \
                    $4 * EXTRACT(EPOCH from excluded.last_time - limits.last_time), $3), \
                last_time = EXCLUDED.last_time \
            RETURNING available_tokens",
            &[Type::TEXT, Type::TEXT, Type::FLOAT8, Type::FLOAT8],
        ).await.unwrap();
        let acquire_token_from_bucket = client.prepare_typed(
            "UPDATE limits SET available_tokens = GREATEST(available_tokens - 1.0, 0.0) \
            WHERE subject = $1 AND remote = $2",
            &[Type::TEXT, Type::TEXT]
        ).await.unwrap();
        Self {
            update_bucket,
            acquire_token_from_bucket,
        }
    }
}

impl AppDatabase {
    pub async fn limit_try_acquire_token(
        &self, subject: &str, remote: &str, burst: f64, rate: f64, reset_on_fail: bool,
    ) -> Result<bool> {
        let mut writable_client = self.db.write().await;
        let transaction = writable_client.build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        let tokens: f64 = transaction
            .query_one(&self.limit.update_bucket, &[&subject, &remote, &burst, &rate])
            .await?
            .get("available_tokens");
        let success = tokens >= 1.0;
        if success || reset_on_fail {
            transaction
                .query(&self.limit.acquire_token_from_bucket, &[&subject, &remote])
                .await?;
        }
        transaction.commit().await?;
        Ok(success)
    }
}