use crate::queries::tokens::Token;
use actix::Message;
use chrono::{DateTime, Utc};
use derive_more::From;
use serde::{Serialize, Deserialize, Deserializer};

// From https://stackoverflow.com/questions/44331037/how-can-i-distinguish-between-a-deserialized-field-that-is-missing-and-one-that
fn deserialize_optional_field<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> {
    Ok(Some(Option::deserialize(deserializer)?))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct JwtAcquired(pub Token);

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JwtRevoked {
    pub jti: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserCreated {
    pub id: i32,
    pub username: String,
    pub roles: Vec<String>,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserUpdated {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<()>, // True suggest password changed
    #[serde(deserialize_with = "deserialize_optional_field")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<Option<String>>,
    #[serde(deserialize_with = "deserialize_optional_field")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<Option<String>>,
    #[serde(deserialize_with = "deserialize_optional_field")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<Option<String>>,
    #[serde(deserialize_with = "deserialize_optional_field")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar128: Option<Option<String>>,
    #[serde(deserialize_with = "deserialize_optional_field")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked: Option<Option<bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, From, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InnerAnyMessage {
    JwtAcquired(JwtAcquired),
    JwtRevoked(JwtRevoked),
    UserCreated(UserCreated),
    UserUpdated(UserUpdated),
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "()")]
pub struct AnyMessage {
    // pub subject: String,
    pub sender_uid: Option<i32>,
    pub sender_jti: Option<i32>,
    pub message: InnerAnyMessage,
    pub created_at: DateTime<Utc>,
}