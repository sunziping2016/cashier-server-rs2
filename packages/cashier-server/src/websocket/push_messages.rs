use crate::{
    queries::tokens::Token,
};
use actix::Message;
use chrono::{DateTime, Utc};
use derive_more::From;
use serde::{Serialize, Deserialize, Deserializer};
use std::{
    convert::Infallible,
    result::Result,
};
use strum_macros::AsRefStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionIdSubjectAction {
    pub id: i32,
    pub subject: String,
    pub action: String,
}

// From https://github.com/serde-rs/serde/issues/984#issuecomment-314143738
pub fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> {
    Deserialize::deserialize(de).map(Some)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
pub struct TokenAcquired(pub Token);

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TokenRevoked {
    pub jti: i32,
    pub uid: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserCreated {
    pub id: i32,
    pub username: String,
    pub roles: Vec<String>,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserDeleted {
    pub id: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserUpdated {
    pub id: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<()>,
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar128: Option<Option<String>>,
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<Option<bool>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InternalUserRoleCreated {
    pub user: i32,
    pub role: i32,
    pub role_permissions: Vec<PermissionIdSubjectAction>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserRoleCreated {
    pub user: i32,
    pub role: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserRoleDeleted {
    pub user: i32,
    pub role: i32,
}


#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InternalRolePermissionCreated {
    pub role: i32,
    pub permission: i32,
    pub subject: String,
    pub action: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RolePermissionCreated {
    pub role: i32,
    pub permission: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RolePermissionDeleted {
    pub role: i32,
    pub permission: i32,
}

#[derive(Debug, Serialize, Deserialize, From, Clone, AsRefStr)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InnerInternalMessage {
    TokenAcquired(TokenAcquired),
    TokenRevoked(TokenRevoked),
    UserCreated(UserCreated),
    UserUpdated(UserUpdated),
    UserDeleted(UserDeleted),
    UserRoleCreated(InternalUserRoleCreated),
    UserRoleDeleted(UserRoleDeleted),
    RolePermissionCreated(InternalRolePermissionCreated),
    RolePermissionDeleted(RolePermissionDeleted),
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "Result<(), Infallible>")]
#[serde(rename_all = "camelCase")]
pub struct InternalMessage {
    pub sender_uid: Option<i32>,
    pub sender_jti: Option<i32>,
    pub messages: Vec<InnerInternalMessage>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, From, Clone, AsRefStr)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InnerPublicMessage {
    TokenAcquired(TokenAcquired),
    TokenRevoked(TokenRevoked),
    UserCreated(UserCreated),
    UserUpdated(UserUpdated),
    UserDeleted(UserDeleted),
    UserRoleCreated(UserRoleCreated),
    UserRoleDeleted(UserRoleDeleted),
    RolePermissionCreated(RolePermissionCreated),
    RolePermissionDeleted(RolePermissionDeleted),
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "Result<(), Infallible>")]
#[serde(rename_all = "camelCase")]
pub struct PublicMessage {
    pub sender_uid: Option<i32>,
    pub sender_jti: Option<i32>,
    pub messages: Vec<InnerPublicMessage>,
    pub created_at: DateTime<Utc>,
}