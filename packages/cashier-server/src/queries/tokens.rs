use super::errors::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tokio_postgres::{
    Client, Statement,
    types::Type
};
use jsonwebtoken::{
    encode, EncodingKey, Header,
    decode, DecodingKey, Validation,
};

pub struct Query {
    create_token: Statement,
    get_secret: Statement,
    check_token_revoked: Statement,
    revoke_token: Statement,
    find_tokens_from_user: Statement,
    revoke_tokens_from_user: Statement,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtClaims {
    pub uid: i32,
    pub iat: i64,
    pub exp: i64,
    pub jti: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Token {
    pub id: i32,
    pub user: i32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub acquire_method: String,
    pub acquire_host: String,
    pub acquire_remote: Option<String>,
    pub acquire_user_agent: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenIdUser {
    pub id: i32,
    pub user: i32,
}

impl Query {
    pub async fn new(client: &Client) -> Self {
        let create_token = client.prepare_typed(&format!(
            "INSERT INTO token (\"user\", issued_at, expires_at, acquire_method, \
                                    acquire_host, acquire_remote, acquire_user_agent, revoked) \
                VALUES ($1, NOW(), NOW() + INTERVAL '{}', $2, $3, $4, $5, false) \
                RETURNING id, issued_at, expires_at", crate::constants::JWT_EXPIRE),
                                           &[Type::INT4, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
        ).await.unwrap();
        let get_secret = client.prepare(
            "SELECT jwt_secret FROM global_settings LIMIT 1",
        ).await.unwrap();
        let check_token_revoked = client.prepare_typed(
            "SELECT 0 FROM token WHERE id = $1 AND NOT revoked LIMIT 1",
            &[Type::INT4],
        ).await.unwrap();
        let revoke_token = client.prepare_typed(
            "UPDATE token SET revoked = true WHERE id = $1 AND NOT revoked",
            &[Type::INT4]
        ).await.unwrap();
        let find_tokens_from_user = client.prepare_typed(
            "SELECT id, \"user\", issued_at, expires_at, acquire_method, \
                    acquire_host, acquire_remote, acquire_user_agent FROM token \
                 WHERE \"user\" = $1 AND expires_at > NOW() AND NOT revoked",
            &[Type::INT4]
        ).await.unwrap();
        let revoke_tokens_from_user = client.prepare_typed(
            "UPDATE token SET revoked = true \
                WHERE \"user\" = $1 AND NOT revoked \
                RETURNING id, \"user\"",
            &[Type::INT4]
        ).await.unwrap();
        Self {
            create_token,
            get_secret,
            check_token_revoked,
            revoke_token,
            find_tokens_from_user,
            revoke_tokens_from_user,
        }
    }
    pub async fn create_token(
        &self, client: &Client, user: i32, method: &str,
        host: &str, remote: Option<&str>, user_agent: Option<&str>,
    ) -> Result<(String, JwtClaims)> {
        let row = client
            .query_one(&self.create_token, &[&user, &method, &host, &remote, &user_agent])
            .await?;
        let id: i32 = row.get("id");
        let issued_at: DateTime<Utc> = row.get("issued_at");
        let expires_at: DateTime<Utc> = row.get("expires_at");
        let claims = JwtClaims {
            uid: user,
            iat: issued_at.timestamp(),
            exp: expires_at.timestamp(),
            jti: id,
        };
        let secret = self.get_secret(client).await?;
        let jwt = encode(&Header::default(), &claims, &EncodingKey::from_secret(&secret))?;
        Ok((jwt, claims))
    }
    pub async fn get_secret(&self, client: &Client) -> Result<Vec<u8>> {
        let row = client.query_one(&self.get_secret, &[]).await?;
        Ok(row.get("jwt_secret"))
    }
    pub async fn verify_token(&self, client: &Client, token: &str) -> Result<JwtClaims> {
        let secret = self.get_secret(client).await?;
        let claims = decode::<JwtClaims>(&token, &DecodingKey::from_secret(&secret), &Validation::default())
            .map_err(|err| Error::InvalidToken { error: format!("{:?}", err.into_kind()) })?
            .claims;
        Ok(claims)
    }
    pub async fn check_token_revoked(&self, client: &Client, id: i32) -> Result<()> {
        let rows = client
            .query(&self.check_token_revoked, &[&id])
            .await?;
        if rows.is_empty() {
            return Err(Error::TokenNotFound);
        }
        Ok(())
    }
    pub async fn revoke_token(&self, client: &Client, id: i32) -> Result<u64> {
        let count = client
            .execute(&self.revoke_token, &[&id])
            .await?;
        Ok(count)
    }
    pub async fn find_tokens_from_user(&self, client: &Client, user: i32) -> Result<Vec<Token>> {
        let rows = client
            .query(&self.find_tokens_from_user, &[&user])
            .await?;
        let results = rows.iter()
            .map(|row| Token {
                id: row.get("id"),
                user: row.get("user"),
                issued_at: row.get("issued_at"),
                expires_at: row.get("expires_at"),
                acquire_method: row.get("acquire_method"),
                acquire_host: row.get("acquire_host"),
                acquire_remote: row.get("acquire_remote"),
                acquire_user_agent: row.get("acquire_user_agent"),
            })
            .collect();
        Ok(results)
    }
    pub async fn revoke_tokens_from_user(&self, client: &Client, user: i32) -> Result<Vec<TokenIdUser>> {
        let rows = client
            .query(&self.revoke_tokens_from_user, &[&user])
            .await?;
        let results = rows.iter()
            .map(|row| TokenIdUser {
                id: row.get("id"),
                user: row.get("user"),
            })
            .collect();
        Ok(results)
    }
}