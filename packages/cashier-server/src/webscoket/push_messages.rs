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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionIdSubjectAction {
    pub id: i32,
    pub subject: String,
    pub action: String,
}

// From https://stackoverflow.com/questions/44331037/how-can-i-distinguish-between-a-deserialized-field-that-is-missing-and-one-that
fn deserialize_optional_field<'de, T, D>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> {
    Ok(Some(Option::deserialize(deserializer)?))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(transparent)]
pub struct JwtAcquired(pub Token);

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct JwtRevoked {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InternalUserRoleCreatedItem {
    pub user: i32,
    pub role: i32,
    pub role_permissions: Vec<PermissionIdSubjectAction>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserRoleUpdatedItem {
    pub user: i32,
    pub role: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InternalUserRoleUpdated {
    pub created: Vec<InternalUserRoleCreatedItem>,
    pub deleted: Vec<UserRoleUpdatedItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UserRoleUpdated {
    pub created: Vec<UserRoleUpdatedItem>,
    pub deleted: Vec<UserRoleUpdatedItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InternalRolePermissionCreatedItem {
    pub role: i32,
    pub permission: i32,
    pub subject: String,
    pub action: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RolePermissionUpdatedItem {
    pub role: i32,
    pub permission: i32,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct InternalRolePermissionUpdated {
    pub created: Vec<InternalRolePermissionCreatedItem>,
    pub deleted: Vec<RolePermissionUpdatedItem>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RolePermissionUpdated {
    pub created: Vec<RolePermissionUpdatedItem>,
    pub deleted: Vec<RolePermissionUpdatedItem>,
}

#[derive(Debug, Serialize, Deserialize, From, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InnerInternalPushMessage {
    TokenAcquired(JwtAcquired),
    TokenRevoked(JwtRevoked),
    UserCreated(UserCreated),
    UserUpdated(UserUpdated),
    UserDeleted(UserDeleted),
    UserRoleUpdated(InternalUserRoleUpdated),
    RolePermissionUpdated(InternalRolePermissionUpdated),
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "Result<(), Infallible>")]
pub struct InternalPushMessage {
    pub sender_uid: Option<i32>,
    pub sender_jti: Option<i32>,
    pub message: InnerInternalPushMessage,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, From, Clone)]
#[serde(tag = "type")]
#[serde(rename_all = "kebab-case")]
pub enum InnerPublicPushMessage {
    TokenAcquired(JwtAcquired),
    TokenRevoked(JwtRevoked),
    UserCreated(UserCreated),
    UserUpdated(UserUpdated),
    UserDeleted(UserDeleted),
    UserRoleUpdated(UserRoleUpdated),
    RolePermissionUpdated(RolePermissionUpdated),
}

#[derive(Debug, Serialize, Deserialize, Message, Clone)]
#[rtype(result = "Result<(), Infallible>")]
pub struct PublicPushMessage {
    pub sender_uid: Option<i32>,
    pub sender_jti: Option<i32>,
    pub message: InnerPublicPushMessage,
    pub created_at: DateTime<Utc>,
}