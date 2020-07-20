use super::errors::{Error, Result};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use tokio_postgres::{Client, Statement, types::Type, Row};
use jsonwebtoken::{
    encode, EncodingKey, Header,
    decode, DecodingKey, Validation,
};
use crate::api::cursor::{Result as CursorResult, Cursor, PrimaryCursor};
use std::borrow::Borrow;
use geoip::{CityInfo, ASInfo};
use std::convert::TryFrom;

pub struct Query {
    create_token: Statement,
    get_secret: Statement,
    check_token_revoked: Statement,
    revoke_token: Statement,
    revoke_token_with_uid: Statement,
    read_token: Statement,
    read_token_with_uid: Statement,
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
#[serde(rename_all = "camelCase")]
pub struct Token {
    pub id: i32,
    pub user: i32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub acquire_method: String,
    pub acquire_host: String,
    pub acquire_remote: Option<String>,
    pub acquire_remote_country: Option<String>,
    pub acquire_remote_country_name: Option<String>,
    pub acquire_remote_region: Option<String>,
    pub acquire_remote_region_name: Option<String>,
    pub acquire_remote_as_number: Option<u32>,
    pub acquire_remote_as_name: Option<String>,
    pub acquire_user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenCursor {
    pub token: Token,
    pub cursor: String,
}

impl TokenCursor {
    pub fn try_from_token(token: Token, sort: &Option<String>) -> CursorResult<Self> {
        let cursor = Cursor::new(token.id.to_string(), match sort.as_ref().map(String::borrow) {
            Some(field) => match field {
                "id" => Some(PrimaryCursor { k: "id".into(), v: Some(token.id.to_string()) }),
                "user" => Some(PrimaryCursor { k: "user".into(), v: Some(token.user.to_string()) }),
                "issuedAt" => Some(PrimaryCursor { k: "issuedAt".into(),
                    v: Some(token.issued_at.to_rfc3339()) }),
                "expiresAt" => Some(PrimaryCursor { k: "expiresAt".into(),
                    v: Some(token.expires_at.to_rfc3339()) }),
                "acquireMethod" => Some(PrimaryCursor { k: "acquireMethod".into(),
                    v: Some(token.acquire_method.clone()) }),
                "acquireHost" => Some(PrimaryCursor { k: "acquireHost".into(),
                    v: Some(token.acquire_host.clone()) }),
                "acquireRemote" => Some(PrimaryCursor { k: "acquireRemote".into(),
                    v: token.acquire_remote.clone() }),
                "acquireUserAgent" => Some(PrimaryCursor { k: "acquireUserAgent".into(),
                    v: token.acquire_user_agent.clone() }),
                "acquireRemoteCountry" => Some(PrimaryCursor { k: "acquireRemoteCountry".into(),
                    v: token.acquire_remote_country.clone() }),
                "acquireRemoteCountryName" => Some(PrimaryCursor { k: "acquireRemoteCountryName".into(),
                    v: token.acquire_remote_country_name.clone() }),
                "acquireRemoteRegion" => Some(PrimaryCursor { k: "acquireRemoteRegion".into(),
                    v: token.acquire_remote_region.clone() }),
                "acquireRemoteRegionName" => Some(PrimaryCursor { k: "acquireRemoteRegionName".into(),
                    v: token.acquire_remote_region_name.clone() }),
                "acquireRemoteAsNumber" => Some(PrimaryCursor { k: "acquireRemoteAsNumber".into(),
                    v: token.acquire_remote_as_number.as_ref().map(u32::to_string) }),
                "acquireRemoteAsName" => Some(PrimaryCursor { k: "acquireRemoteAsName".into(),
                    v: token.acquire_remote_as_name.clone() }),
                _ => None
            },
            _ => None,
        });
        cursor.try_to_str()
            .map(|cursor| TokenCursor {
                token,
                cursor,
            })
    }
}

impl From<&Row> for Token {
    fn from(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            user: row.get("user"),
            issued_at: row.get("issued_at"),
            expires_at: row.get("expires_at"),
            acquire_method: row.get("acquire_method"),
            acquire_host: row.get("acquire_host"),
            acquire_remote: row.get("acquire_remote"),
            acquire_user_agent: row.get("acquire_user_agent"),
            acquire_remote_country: row.get("acquire_remote_country"),
            acquire_remote_country_name: row.get("acquire_remote_country_name"),
            acquire_remote_region: row.get("acquire_remote_region"),
            acquire_remote_region_name: row.get("acquire_remote_region_name"),
            acquire_remote_as_number: row.get::<&str, Option<i64>>("acquire_remote_as_number")
                .map(|x| u32::try_from(x).ok())
                .flatten(),
            acquire_remote_as_name: row.get("acquire_remote_as_name"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenIdUser {
    pub id: i32,
    pub user: i32,
}

impl Query {
    pub async fn new(client: &Client) -> Self {
        let create_token = client.prepare_typed(
            &format!("INSERT INTO token (\"user\", issued_at, expires_at, acquire_method, \
                                         acquire_host, acquire_remote, \
                                         acquire_remote_country, acquire_remote_country_name, \
                                         acquire_remote_region, acquire_remote_region_name, \
                                         acquire_remote_as_number, acquire_remote_as_name, \
                                         acquire_user_agent, revoked) \
                VALUES ($1, NOW(), NOW() + INTERVAL '{}', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, false) \
                RETURNING id, issued_at, expires_at", crate::constants::JWT_EXPIRE),
            &[Type::INT4, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT,
                Type::TEXT, Type::TEXT, Type::INT8, Type::TEXT, Type::TEXT],
        ).await.unwrap();
        let get_secret = client.prepare(
            "SELECT jwt_secret FROM global_settings LIMIT 1",
        ).await.unwrap();
        let check_token_revoked = client.prepare_typed(
            "SELECT 0 FROM token WHERE id = $1 AND NOT revoked LIMIT 1",
            &[Type::INT4],
        ).await.unwrap();
        let revoke_token = client.prepare_typed(
            "UPDATE token SET revoked = true \
                WHERE id = $1 AND NOT revoked \
                RETURNING id, \"user\"",
            &[Type::INT4],
        ).await.unwrap();
        let revoke_token_with_uid = client.prepare_typed(
            "UPDATE token SET revoked = true \
                WHERE id = $1 AND \"user\" = $2 AND NOT revoked \
                RETURNING id, \"user\"",
            &[Type::INT4, Type::INT4],
        ).await.unwrap();
        let read_token = client.prepare_typed(
            "SELECT id, \"user\", issued_at, expires_at, acquire_method, \
                acquire_host, acquire_remote, acquire_user_agent, \
                acquire_remote_country, acquire_remote_country_name, \
                acquire_remote_region, acquire_remote_region_name, \
                acquire_remote_as_number, acquire_remote_as_name FROM token \
                WHERE id = $1 AND NOT revoked",
            &[Type::INT4],
        ).await.unwrap();
        let read_token_with_uid = client.prepare_typed(
            "SELECT id, \"user\", issued_at, expires_at, acquire_method, \
                acquire_host, acquire_remote, acquire_user_agent, \
                acquire_remote_country, acquire_remote_country_name, \
                acquire_remote_region, acquire_remote_region_name, \
                acquire_remote_as_number, acquire_remote_as_name FROM token \
                WHERE id = $1 AND \"user\" = $2 AND NOT revoked",
            &[Type::INT4],
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
            revoke_token_with_uid,
            read_token,
            read_token_with_uid,
            revoke_tokens_from_user,
        }
    }
    pub async fn create_token(
        &self, client: &Client, user: i32, method: &str,
        host: &str, remote: Option<&str>, user_agent: Option<&str>,
        city_info: &Option<CityInfo>, as_info: &Option<ASInfo>,
    ) -> Result<(String, JwtClaims)> {
        let row = client
            .query_one(&self.create_token, &[
                &user, &method, &host, &remote,
                &city_info.as_ref().map(|x| x.country_code.clone()).flatten(),
                &city_info.as_ref().map(|x| x.country_name.clone()).flatten(),
                &city_info.as_ref().map(|x| x.region.clone()).flatten(),
                &city_info.as_ref().map(|x| x.city.clone()).flatten(),
                &as_info.as_ref().map(|x| i64::from(x.asn)),
                &as_info.as_ref().map(|x| x.name.clone()),
                &user_agent
            ])
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
    pub async fn revoke_token(&self, client: &Client, id: i32, uid: Option<i32>) -> Result<TokenIdUser> {
        let rows = match uid {
            Some(uid) => client
                .query(&self.revoke_token_with_uid, &[&id, &uid])
                .await?,
            None => client
                .query(&self.revoke_token, &[&id])
                .await?,
        };
        let row = rows
            .get(0)
            .ok_or_else(|| Error::TokenNotFound)?;
        Ok(TokenIdUser {
            id: row.get("id"),
            user: row.get("user"),
        })
    }
    pub async fn read_token(&self, client: &Client, id: i32, uid: Option<i32>) -> Result<Token> {
        let rows = match uid {
            Some(uid) => client
                .query(&self.read_token_with_uid, &[&id, &uid])
                .await?,
            None => client
                .query(&self.read_token, &[&id])
                .await?,
        };
        let row = rows
            .get(0)
            .ok_or_else(|| Error::TokenNotFound)?;
        Ok(Token::from(row))
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