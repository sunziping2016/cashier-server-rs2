use derive_more::{Deref, AsRef, From, Into};
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Serialize, Deserialize};
use validator::Validate;
use validator_derive::Validate;
use crate::queries::users::{UserAccessLevel, RoleAccessLevel, PermissionAccessLevel};

lazy_static! {
    pub static ref USERNAME_REGEX: Regex = Regex::new(r"(?i)^[a-z\d_-]*$").unwrap();
    pub static ref PASSWORD_REGEX: Regex = Regex::new(r"^[^\s]*$").unwrap();
    pub static ref ROLE_REGEX: Regex = Regex::new(r"(?i)^[a-z\d_-]*$").unwrap();
    pub static ref BASE64_REGEX: Regex = Regex::new("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$").unwrap();
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Password {
    #[validate(regex(path = "PASSWORD_REGEX", message = "should contain only non-whitespace chars"))]
    #[validate(length(min = 6, max = 24, message = "should have 6 to 24 chars"))]
    inner: String,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Username {
    #[validate(regex(path = "USERNAME_REGEX", message = "should contain only alpha numeric and underscore chars"))]
    #[validate(length(min = 3, max = 24, message = "should have 3 to 24 chars"))]
    inner: String,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Email {
    #[validate(email(message = "should be a valid email"))]
    inner: String,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct RoleName {
    #[validate(regex(path = "ROLE_REGEX", message = "should contain only alpha numeric and underscore chars"))]
    #[validate(length(min = 3, max = 24, message = "should have 3 to 24 chars"))]
    pub inner: String,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Nickname {
    #[validate(length(min = 3, max = 24, message = "should have 3 to 24 chars"))]
    inner: String,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Any24 {
    #[validate(length(equal = 24, message = "should have 24 chars"))]
    inner: String,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Any6 {
    #[validate(length(equal = 6, message = "should have 6 chars"))]
    inner: String,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Id {
    id: i32,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct PopulateUser {
    level: UserAccessLevel,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct PopulateRole {
    level: RoleAccessLevel,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct PopulatePermission {
    level: PermissionAccessLevel,
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct PaginationSize {
    #[validate(range(max=50, message = "should be less or equal than 50"))]
    inner: usize,
}

impl Default for PaginationSize {
    fn default() -> Self {
        PaginationSize { inner: 10 }
    }
}

#[derive(Debug, Validate, Serialize, Deserialize, Deref, AsRef, From, Into, Clone)]
#[serde(transparent)]
pub struct Cursor {
    #[validate(regex(path = "BASE64_REGEX", message = "invalid cursor"))]
    inner: String,
}
