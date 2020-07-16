use tokio_postgres::{Client, Statement, types::Type, IsolationLevel};
use crate::queries::errors::Result;

pub struct Query {
    update_bucket: Statement,
    acquire_token_from_bucket: Statement,
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
    pub async fn update_bucket(
        &self, client: &Client,
        subject: &str, remote: &str, burst: f64, rate: f64
    ) -> Result<f64> {
        Ok(client
            .query_one(&self.update_bucket, &[&subject, &remote, &burst, &rate])
            .await?
            .get("available_tokens")
        )
    }
    pub async fn try_acquire_token(
        &self, client: &mut Client,
        subject: &str, remote: &str, burst: f64, rate: f64, reset_on_fail: bool,
    ) -> Result<bool> {
        let transaction = client.build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        let tokens: f64 = transaction
            .query_one(&self.update_bucket, &[&subject, &remote, &burst, &rate])
            .await?
            .get("available_tokens");
        let success = tokens >= 1.0;
        if success || reset_on_fail {
            transaction
                .query(&self.acquire_token_from_bucket, &[&subject, &remote])
                .await?;
        }
        transaction.commit().await?;
        Ok(success)
    }
}