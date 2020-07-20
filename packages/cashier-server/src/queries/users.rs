use super::errors::{Error, Result};
use super::email::{register_user_email, update_user_email};
use actix_web::web::{self, block};
use chrono::{DateTime, Utc};
use derive_more::From;
use lettre::Transport;
use rand::{Rng, thread_rng};
use rand::distributions::{Alphanumeric, Distribution};
use serde::{Serialize, Deserialize};
use std::collections::{HashSet, HashMap};
use std::iter;
use tokio_postgres::{
    Client, Statement, types::Type,
    IsolationLevel, Row,
};
use crate::api::app_state::AppSmtp;
use crate::api::cursor::{Result as CursorResult, Cursor, PrimaryCursor};
use std::borrow::Borrow;

struct Digit;

impl Distribution<char> for Digit {
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> char {
        const RANGE: u32 = 10;
        const GEN_ASCII_STR_CHARSET: &[u8] = b"0123456789";
        GEN_ASCII_STR_CHARSET[(rng.next_u32() % RANGE) as usize] as char
    }
}

#[derive(Debug)]
pub struct UserIdPasswordBlocked {
    pub id: i32,
    pub password: String,
    pub blocked: Option<bool>,
}

#[derive(Debug)]
pub struct UserIdCreatedAt {
    pub id: i32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct UserCreatedByRegistration {
    pub id: i32,
    pub username: String,
    pub roles: Vec<String>,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug)]
pub struct UserIdEmailUpdatedAt {
    pub id: i32,
    pub email: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PermissionSubjectAction {
    pub subject: String,
    pub action: String,
}

#[derive(Debug)]
pub struct UserAvatars {
    pub avatar: Option<String>,
    pub avatar128: Option<String>,
}

pub enum EitherUsernameOrEmail {
    Username(String),
    Email(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserPublic {
    pub id: i32,
    pub username: String,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub avatar128: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<&Row> for UserPublic {
    fn from(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            username: row.get("username"),
            nickname: row.get("nickname"),
            avatar: row.get("avatar"),
            avatar128: row.get("avatar128"),
            created_at: row.get("created_at"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserAll {
    pub id: i32,
    pub username: String,
    pub roles: Vec<i32>,
    pub email: Option<String>,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub avatar128: Option<String>,
    pub blocked: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Row> for UserAll {
    fn from(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            username: row.get("username"),
            roles: row.get("roles"),
            email: row.get("email"),
            nickname: row.get("nickname"),
            avatar: row.get("avatar"),
            avatar128: row.get("avatar128"),
            blocked: row.get("blocked"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(From, Serialize, Deserialize, Debug)]
#[serde(tag = "access")]
#[serde(rename_all = "kebab-case")]
pub enum User {
    Public(UserPublic),
    All(UserAll),
}

impl User {
    pub fn map_avatars(&mut self, mapping: impl Fn(&String) -> String) {
        match self {
            User::Public(user) => {
                user.avatar = user.avatar.as_ref().map(&mapping);
                user.avatar128 = user.avatar128.as_ref().map(&mapping);
            }
            User::All(user) => {
                user.avatar = user.avatar.as_ref().map(&mapping);
                user.avatar128 = user.avatar128.as_ref().map(&mapping);
            }
        }
    }
    pub fn id(&self) -> i32 {
        match self {
            User::Public(user) => user.id,
            User::All(user) => user.id,
        }
    }
    pub fn username(&self) -> &String {
        match self {
            User::Public(user) => &user.username,
            User::All(user) => &user.username,
        }
    }
    pub fn email(&self) -> Option<&Option<String>> {
        match self {
            User::Public(_) => None,
            User::All(user) => Some(&user.email),
        }
    }
    pub fn nickname(&self) -> &Option<String> {
        match self {
            User::Public(user) => &user.nickname,
            User::All(user) => &user.nickname,
        }
    }
    pub fn blocked(&self) -> Option<&Option<bool>> {
        match self {
            User::Public(_) => None,
            User::All(user) => Some(&user.blocked),
        }
    }
    pub fn created_at(&self) -> &DateTime<Utc> {
        match self {
            User::Public(user) => &user.created_at,
            User::All(user) => &user.created_at,
        }
    }
    pub fn updated_at(&self) -> Option<&DateTime<Utc>> {
        match self {
            User::Public(_) => None,
            User::All(user) => Some(&user.created_at),
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserCursor {
    pub user: User,
    pub cursor: String,
}

impl UserCursor {
    pub fn try_from_user(user: User, sort: &Option<String>) -> CursorResult<Self> {
        let cursor = Cursor::new(user.id().to_string(), match sort.as_ref().map(String::borrow) {
            Some(field) => match field {
                "id" => Some(PrimaryCursor { k: "id".into(), v: Some(user.id().to_string()) }),
                "username" => Some(PrimaryCursor {
                    k: "username".into(),
                    v: Some(user.username().clone()) }),
                "email" => user.email().map(|email| PrimaryCursor {
                    k: "email".into(),
                    v: email.clone() }),
                "nickname" => Some(PrimaryCursor {
                    k: "nickname".into(),
                    v: user.nickname().clone() }),
                "blocked" => user.blocked().map(|blocked| PrimaryCursor {
                    k: "blocked".into(),
                    v: blocked.clone().as_ref().map(bool::to_string) }),
                "createdAt" => Some(PrimaryCursor {
                    k: "createdAt".into(),
                    v: Some(user.created_at().to_rfc3339()) }),
                "updatedAt" => user.updated_at().map(|updated_at| PrimaryCursor {
                    k: "updatedAt".into(),
                    v: Some(updated_at.to_rfc3339()) }),
                _ => None
            },
            _ => None,
        });
        cursor.try_to_str()
            .map(|cursor| UserCursor {
                user,
                cursor,
            })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RoleShort {
    id: i32,
    name: String,
    permissions: Vec<i32>,
}

impl From<&Row> for RoleShort {
    fn from(x: &Row) -> Self {
        Self {
            id: x.get("id"),
            name: x.get("name"),
            permissions: x.get("permissions")
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAll {
    id: i32,
    name: String,
    permissions: Vec<i32>,
    display_name: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<&Row> for RoleAll {
    fn from(x: &Row) -> Self {
        Self {
            id: x.get("id"),
            name: x.get("name"),
            permissions: x.get("permissions"),
            display_name: x.get("display_name"),
            description: x.get("description"),
            created_at: x.get("created_at"),
            updated_at: x.get("updated_at"),
        }
    }
}

#[derive(From, Serialize, Deserialize, Debug)]
#[serde(tag = "access")]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Short(RoleShort),
    All(RoleAll),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionShort {
    id: i32,
    subject: String,
    action: String,
}

impl From<&Row> for PermissionShort {
    fn from(x: &Row) -> Self {
        Self {
            id: x.get("id"),
            subject: x.get("subject"),
            action: x.get("action"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionAll {
    id: i32,
    subject: String,
    action: String,
    display_name: String,
    description: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl From<&Row> for PermissionAll {
    fn from(x: &Row) -> Self {
        Self {
            id: x.get("id"),
            subject: x.get("subject"),
            action: x.get("action"),
            display_name: x.get("display_name"),
            description: x.get("description"),
            created_at: x.get("created_at"),
            updated_at: x.get("updated_at"),
        }
    }
}

#[derive(From, Serialize, Deserialize, Debug)]
#[serde(tag = "access")]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    Short(PermissionShort),
    All(PermissionAll),
}

#[derive(Debug, PartialEq, Clone)]
pub struct PermissionTree {
    map: HashMap<i32, HashMap<i32, PermissionSubjectAction>>,
}

impl PermissionTree {
    pub fn new(map: HashMap<i32, HashMap<i32, PermissionSubjectAction>>) -> Self {
        Self { map }
    }
    pub fn get(&self) -> HashMap<i32, PermissionSubjectAction> {
        self.map.values()
            .flat_map(|x| x.iter())
            .map(|x| (x.0.to_owned(), x.1.to_owned()))
            .collect()
    }
    pub fn get_subscribe(&self) -> HashSet<String> {
        self.get().values()
            .filter(|x| x.action == "subscribe")
            .map(|x| x.subject.clone())
            .collect()
    }
    pub fn add_role(&mut self, role: i32, permissions: HashMap<i32, PermissionSubjectAction>) {
        self.map.insert(role, permissions);
    }
    pub fn remove_role(&mut self, role: i32) {
        self.map.remove(&role);
    }
    pub fn add_permission(&mut self, role: i32, permission: i32, subject: String, action: String) {
        if let Some(permissions) = self.map.get_mut(&role) {
            permissions.insert(permission, PermissionSubjectAction {
                subject,
                action,
            });
        }
    }
    pub fn remove_permission(&mut self, role: i32, permission: i32) {
        if let Some(permissions) = self.map.get_mut(&role) {
            permissions.remove(&permission);
        }
    }
}

impl Default for PermissionTree {
    fn default() -> Self {
        Self { map: HashMap::new() }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserRegistration {
    pub id: String,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserRegistrationPublic {
    pub id: String,
    pub username: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed: Option<bool>,
}

impl From<&Row> for UserRegistrationPublic {
    fn from(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            username: row.get("username"),
            email: row.get("email"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            completed: row.get("completed"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserEmailUpdating {
    pub id: String,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserEmailUpdatingPublic {
    pub id: String,
    pub user: i32,
    pub new_email: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub completed: Option<bool>,
}

impl From<&Row> for UserEmailUpdatingPublic {
    fn from(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            user: row.get("user"),
            new_email: row.get("new_email"),
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
            completed: row.get("completed"),
        }
    }
}

pub struct Query {
    find_one_from_username_to_id_password_blocked: Statement,
    find_one_from_email_to_id_password_blocked: Statement,
    find_one_from_username_to_id: Statement,
    find_one_from_email_to_id: Statement,
    check_user_blocked: Statement,
    fetch_permission: Statement,
    fetch_default_permission: Statement,
    check_extra_roles: Statement,
    find_one_from_username_to_username_email: Statement,
    find_one_from_username_email_to_username_email: Statement,
    insert_one: Statement,
    insert_one_roles: Statement,
    fetch_avatars: Statement,
    update_avatars: Statement,
    find_one_with_roles: Statement,
    find_one_public: Statement,
    find_one_to_username: Statement,
    fetch_permission_tree: Statement,
    fetch_default_permission_tree: Statement,
    insert_one_into_user_registration: Statement,
    find_one_from_user_registration: Statement,
    find_one_from_user_registration_without_password: Statement,
    insert_one_registered_user: Statement,
    find_default_roles: Statement,
    complete_registration: Statement,
    query_registration: Statement,
    update_user: Statement,
    insert_one_into_user_email_updating: Statement,
    find_one_from_user_email_updating: Statement,
    find_one_from_user_email_updating_join_user: Statement,
    update_email: Statement,
    complete_email_updating: Statement,
    query_email_updating: Statement,
    find_one_to_password: Statement,
    update_password: Statement,
}

impl Query {
    pub async fn new(client: &Client) -> Self {
        let find_one_from_username_to_id_password_blocked = client.prepare_typed(
            "SELECT id, password, blocked FROM \"user\" \
                WHERE username = $1 AND NOT deleted LIMIT 1",
            &[Type::TEXT],
        ).await.unwrap();
        let find_one_from_email_to_id_password_blocked = client.prepare_typed(
            "SELECT id, password, blocked FROM \"user\" \
                WHERE email = $1 AND NOT deleted LIMIT 1",
            &[Type::TEXT],
        ).await.unwrap();
        let find_one_from_username_to_id = client.prepare_typed(
            "SELECT id FROM \"user\" \
                WHERE username = $1 AND NOT deleted LIMIT 1",
            &[Type::TEXT],
        ).await.unwrap();
        let find_one_from_email_to_id = client.prepare_typed(
            "SELECT id FROM \"user\" \
                WHERE email = $1 AND NOT deleted LIMIT 1",
            &[Type::TEXT],
        ).await.unwrap();
        let check_user_blocked = client.prepare_typed(
            "SELECT blocked FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
            &[Type::INT4],
        ).await.unwrap();
        let fetch_permission = client.prepare_typed(
            "SELECT DISTINCT subject, action from ( \
                    SELECT role.id from user_role, role \
                        WHERE user_role.user = $1 AND user_role.role = role.id AND NOT role.deleted \
                    UNION \
                    SELECT role.id from role \
                        WHERE role.name = 'default' AND NOT role.deleted \
                ) as role, role_permission, permission \
                    WHERE role.id = role_permission.role \
                    AND role_permission.permission = permission.id AND NOT permission.deleted",
            &[Type::INT4],
        ).await.unwrap();
        let fetch_default_permission = client.prepare(
            "SELECT DISTINCT subject, action from role, role_permission, permission \
                WHERE role.name = 'default' AND NOT role.deleted AND role.id = role_permission.role \
                AND role_permission.permission = permission.id AND NOT permission.deleted"
        ).await.unwrap();
        let check_extra_roles = client.prepare_typed(
            "SELECT UNNEST($1) EXCEPT \
                SELECT role.name from user_role, role WHERE user_role.user = $2 \
                AND user_role.role = role.id AND NOT role.deleted",
            &[Type::TEXT_ARRAY, Type::INT4]
        ).await.unwrap();
        let find_one_from_username_to_username_email = client.prepare_typed(
            "SELECT username, email FROM \"user\" \
                WHERE username = $1 AND NOT deleted LIMIT 1",
            &[Type::TEXT],
        ).await.unwrap();
        let find_one_from_username_email_to_username_email = client.prepare_typed(
            "SELECT username, email FROM \"user\" \
                WHERE (username = $1 OR email = $2) AND NOT deleted LIMIT 1",
            &[Type::TEXT, Type::TEXT],
        ).await.unwrap();
        let insert_one = client.prepare_typed(
            "INSERT INTO \"user\" (username, password, email, nickname, \
                                   created_at, updated_at, deleted) \
                VALUES ($1, $2, $3, $4, NOW(), NOW(), false) \
                RETURNING id, created_at",
            &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
        ).await.unwrap();
        let insert_one_roles = client.prepare_typed(
            "INSERT INTO user_role (\"user\", role) \
                SELECT $1, role.id FROM (SELECT UNNEST($2) AS role) AS temp, role \
                WHERE role.name = temp.role AND NOT role.deleted",
            &[Type::INT4, Type::TEXT_ARRAY],
        ).await.unwrap();
        let fetch_avatars = client.prepare_typed(
            "SELECT avatar, avatar128 FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
            &[Type::INT4],
        ).await.unwrap();
        let update_avatars = client.prepare_typed(
            "UPDATE \"user\" SET avatar = $1, avatar128 = $2, updated_at = NOW() \
                WHERE id = $3 AND NOT deleted \
                RETURNING updated_at",
            &[Type::TEXT, Type::TEXT, Type::INT4]
        ).await.unwrap();
        let find_one_with_roles = client.prepare_typed(
            "SELECT \"user\".id, username, email, nickname, avatar, avatar128, \
                     blocked, \"user\".created_at, \"user\".updated_at, ARRAY_AGG(role.id) as roles \
            FROM \"user\", user_role, role \
            WHERE \"user\".id = $1 AND NOT \"user\".deleted AND user_role.user = \"user\".id \
                AND user_role.role = role.id AND NOT role.deleted \
            GROUP BY \"user\".id",
            &[Type::INT4],
        ).await.unwrap();
        let find_one_public = client.prepare_typed(
            "SELECT id, username, nickname, avatar, avatar128, created_at FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
            &[Type::INT4],
        ).await.unwrap();
        let find_one_to_username = client.prepare_typed(
            "SELECT username FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
            &[Type::INT4],
        ).await.unwrap();
        let fetch_permission_tree = client.prepare_typed(
            "SELECT DISTINCT role.id as role_id, permission.id as permission_id, subject, action from ( \
                    SELECT role.id from user_role, role \
                        WHERE user_role.user = $1 AND user_role.role = role.id AND NOT role.deleted \
                    UNION \
                    SELECT role.id from role \
                        WHERE role.name = 'default' AND NOT role.deleted \
                ) as role, role_permission, permission \
                    WHERE role.id = role_permission.role \
                    AND role_permission.permission = permission.id AND NOT permission.deleted",
            &[Type::INT4],
        ).await.unwrap();
        let fetch_default_permission_tree = client.prepare(
            "SELECT DISTINCT role.id as role_id, permission.id as permission_id, subject, action \
                    from role, role_permission, permission \
                WHERE role.name = 'default' AND NOT role.deleted AND role.id = role_permission.role \
                AND role_permission.permission = permission.id AND NOT permission.deleted"
        ).await.unwrap();
        let insert_one_into_user_registration = client.prepare_typed(
            &format!("INSERT INTO user_registration (id, code, username, password, \
                                                     email, created_at, expires_at) \
                VALUES ($1, $2, $3, $4, $5, NOW(), NOW() + INTERVAL '{}') \
                RETURNING created_at, expires_at", crate::constants::USER_REGISTRATION_EXPIRE),
            &[Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT, Type::TEXT],
        ).await.unwrap();
        let find_one_from_user_registration = client.prepare_typed(
            "SELECT code, username, password, email, expires_at FROM user_registration \
            WHERE id = $1 AND completed IS NULL LIMIT 1",
            &[Type::TEXT]
        ).await.unwrap();
        let find_one_from_user_registration_without_password = client.prepare_typed(
            "SELECT code, username, email, expires_at FROM user_registration \
            WHERE id = $1 AND completed IS NULL LIMIT 1",
            &[Type::TEXT]
        ).await.unwrap();
        let insert_one_registered_user = client.prepare_typed(
            "INSERT INTO \"user\" (username, password, email, \
                                   created_at, updated_at, deleted) \
                VALUES ($1, $2, $3, NOW(), NOW(), false) \
                RETURNING id, created_at",
            &[Type::TEXT, Type::TEXT, Type::TEXT],
        ).await.unwrap();
        let find_default_roles = client.prepare(
            "SELECT name FROM role \
            WHERE \"default\" = TRUE AND NOT deleted",
        ).await.unwrap();
        let complete_registration = client.prepare_typed(
            "UPDATE user_registration SET completed = TRUE \
             WHERE id = $1 AND completed IS NULL",
            &[Type::TEXT],
        ).await.unwrap();
        let query_registration = client.prepare_typed(
            "SELECT id, username, email, created_at, expires_at, completed \
            FROM user_registration WHERE id = $1 LIMIT 1",
            &[Type::TEXT]
        ).await.unwrap();
        let update_user = client.prepare_typed(
            "UPDATE \"user\" \
                SET username = CASE WHEN $1 THEN $2 ELSE username END, \
                    email = CASE WHEN $3 THEN $4 ELSE email END, \
                    nickname = CASE WHEN $5 THEN $6 ELSE nickname END, \
                    blocked = CASE WHEN $7 THEN $8 ELSE blocked END, \
                    updated_at = NOW() \
                WHERE id = $9 AND NOT DELETED \
                RETURNING updated_at",
            &[Type::BOOL, Type::TEXT, Type::BOOL, Type::TEXT,
                Type::BOOL, Type::TEXT, Type::BOOL, Type::BOOL, Type::INT4]
        ).await.unwrap();
        let insert_one_into_user_email_updating = client.prepare_typed(
            &format!("INSERT INTO user_email_updating (id, code, \"user\", new_email, \
                                                       created_at, expires_at) \
                VALUES ($1, $2, $3, $4, NOW(), NOW() + INTERVAL '{}') \
                RETURNING created_at, expires_at", crate::constants::USER_UPDATING_EMAIL_EXPIRE),
            &[Type::TEXT, Type::TEXT, Type::INT4, Type::TEXT]
        ).await.unwrap();
        let find_one_from_user_email_updating = client.prepare_typed(
            "SELECT code, \"user\", new_email, expires_at FROM user_email_updating \
            WHERE id = $1 AND completed IS NULL LIMIT 1",
            &[Type::TEXT]
        ).await.unwrap();
        let find_one_from_user_email_updating_join_user = client.prepare_typed(
            "SELECT code, new_email, \"user\".id as uid, \"user\".username, expires_at \
            FROM user_email_updating, \"user\" \
            WHERE user_email_updating.id = $1 AND completed IS NULL AND \
                user_email_updating.user = \"user\".id AND NOT \"user\".deleted \
            LIMIT 1",
            &[Type::TEXT],
        ).await.unwrap();
        let update_email = client.prepare_typed(
            "UPDATE \"user\" SET email = $1, updated_at = NOW() \
                WHERE id = $2 AND NOT deleted \
                RETURNING updated_at",
            &[Type::TEXT, Type::INT4]
        ).await.unwrap();
        let complete_email_updating = client.prepare_typed(
            "UPDATE user_email_updating SET completed = TRUE \
            WHERE id = $1 AND completed IS NULL",
            &[Type::TEXT]
        ).await.unwrap();
        let query_email_updating = client.prepare_typed(
            "SELECT id, \"user\", new_email, created_at, expires_at, completed \
            FROM user_email_updating WHERE id = $1 LIMIT 1",
            &[Type::TEXT]
        ).await.unwrap();
        let find_one_to_password = client.prepare_typed(
            "SELECT password FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
            &[Type::INT4]
        ).await.unwrap();
        let update_password = client.prepare_typed(
            "UPDATE \"user\" SET password = $1 \
                WHERE id = $2 AND NOT DELETED \
                RETURNING updated_at",
            &[Type::TEXT, Type::INT4]
        ).await.unwrap();
        Self {
            find_one_from_username_to_id_password_blocked,
            find_one_from_email_to_id_password_blocked,
            find_one_from_username_to_id,
            find_one_from_email_to_id,
            check_user_blocked,
            fetch_permission,
            fetch_default_permission,
            check_extra_roles,
            find_one_from_username_to_username_email,
            find_one_from_username_email_to_username_email,
            insert_one,
            insert_one_roles,
            fetch_avatars,
            update_avatars,
            find_one_with_roles,
            find_one_public,
            find_one_to_username,
            fetch_permission_tree,
            fetch_default_permission_tree,
            insert_one_into_user_registration,
            find_one_from_user_registration,
            find_one_from_user_registration_without_password,
            insert_one_registered_user,
            find_default_roles,
            complete_registration,
            query_registration,
            update_user,
            insert_one_into_user_email_updating,
            find_one_from_user_email_updating,
            find_one_from_user_email_updating_join_user,
            update_email,
            complete_email_updating,
            query_email_updating,
            find_one_to_password,
            update_password,
        }
    }
    pub async fn find_one_from_username_to_id_password_blocked(
        &self, client: &Client, username: &str,
    ) -> Result<UserIdPasswordBlocked> {
        let rows = client
            .query(&self.find_one_from_username_to_id_password_blocked, &[&username])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        Ok(UserIdPasswordBlocked {
            id: row.get("id"),
            password: row.get("password"),
            blocked: row.get("blocked"),
        })
    }
    pub async fn find_one_from_email_to_id_password_blocked(
        &self, client: &Client, email: &str,
    ) -> Result<UserIdPasswordBlocked> {
        let rows = client
            .query(&self.find_one_from_email_to_id_password_blocked, &[&email])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        Ok(UserIdPasswordBlocked {
            id: row.get("id"),
            password: row.get("password"),
            blocked: row.get("blocked"),
        })
    }
    pub async fn check_user_valid_by_id(
        &self, client: &Client, id: i32,
    ) -> Result<()>
    {
        let rows = client
            .query(&self.check_user_blocked, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        if row.get::<&str, Option<bool>>("blocked").contains(&true) {
            return Err(Error::UserBlocked);
        }
        Ok(())
    }
    pub async fn fetch_permission(
        &self, client: &Client, id: i32,
    ) -> Result<Vec<PermissionSubjectAction>> {
        let rows = client
            .query(&self.fetch_permission, &[&id])
            .await?;
        Ok(rows.iter()
            .map(|row| PermissionSubjectAction {
                subject: row.get("subject"),
                action: row.get("action"),
            })
            .collect())
    }
    pub async fn fetch_default_permission(
        &self, client: &Client,
    ) -> Result<Vec<PermissionSubjectAction>> {
        let rows = client
            .query(&self.fetch_default_permission, &[])
            .await?;
        Ok(rows.iter()
            .map(|row| PermissionSubjectAction {
                subject: row.get("subject"),
                action: row.get("action"),
            })
            .collect())
    }
    pub async fn check_extra_roles(
        &self, client: &Client, id: i32, roles: &[String],
    ) -> Result<Vec<String>> {
        let rows = client
            .query(&self.check_extra_roles, &[&roles, &id])
            .await?;
        let results = rows.iter()
            .map(|x| x.get(0))
            .collect();
        Ok(results)
    }
    pub async fn insert_one(
        &self, client: &mut Client, username: &str, password: &str,
        roles: &[String], email: &Option<String>, nickname: &Option<String>,
    ) -> Result<UserIdCreatedAt> {
        let transaction = client.build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        let duplicated_rows = match email {
            Some(email) => transaction
                .query(&self.find_one_from_username_email_to_username_email, &[&username, &email])
                .await?,
            None => transaction
                .query(&self.find_one_from_username_to_username_email, &[&username])
                .await?,
        };
        if let Some(row) = duplicated_rows.get(0) {
            return Err(Error::DuplicatedUser {
                field: if row.get::<&str, String>("username") == username { "username".into() }
                else { "email".into() }
            });
        }
        let password = String::from(password);
        let password = block(move || bcrypt::hash(password, crate::constants::BCRYPT_COST))
            .await?;
        let user = transaction
            .query_one(&self.insert_one, &[&username, &password, &email, &nickname])
            .await?;
        let id: i32 = user.get("id");
        if !roles.is_empty() {
            transaction
                .query(&self.insert_one_roles, &[&id, &roles])
                .await?;
        }
        transaction.commit()
            .await?;
        Ok(UserIdCreatedAt {
            id,
            created_at: user.get("created_at"),
        })
    }
    pub async fn check_user_valid(
        &self, client: &Client, credit: &EitherUsernameOrEmail, password: &str,
    ) -> Result<i32> {
        let user = match credit {
            EitherUsernameOrEmail::Username(username) =>
                self.find_one_from_username_to_id_password_blocked(client, username)
                    .await?,
            EitherUsernameOrEmail::Email(email) =>
                self.find_one_from_email_to_id_password_blocked(client, email)
                    .await?,
        };
        let password = String::from(password);
        let hash = user.password.clone();
        let verified = block(move || bcrypt::verify(password, &hash))
            .await?;
        if !verified {
            return Err(Error::WrongPassword);
        }
        if user.blocked.contains(&true) {
            return Err(Error::UserBlocked);
        }
        Ok(user.id)
    }
    pub async fn fetch_avatars(
        &self, client: &Client, id: i32,
    ) -> Result<UserAvatars> {
        let rows = client
            .query(&self.fetch_avatars, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        Ok(UserAvatars {
            avatar: row.get("avatar"),
            avatar128: row.get("avatar128"),
        })
    }
    pub async fn update_avatars(
        &self, client: &Client, id: i32,
        avatar: &Option<String>, avatar128: &Option<String>
    ) -> Result<DateTime<Utc>> {
        let rows = client
            .query(&self.update_avatars, &[avatar, avatar128, &id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        Ok(row.get("updated_at"))
    }
    pub async fn find_one_all(
        &self, client: &Client, uid: i32,
    ) -> Result<UserAll> {
        let rows = client
            .query(&self.find_one_with_roles, &[&uid])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        Ok(UserAll::from(row))
    }
    pub async fn find_one_public(
        &self, client: &Client, uid: i32,
    ) -> Result<UserPublic> {
        let rows = client
            .query(&self.find_one_public, &[&uid])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        Ok(UserPublic::from(row))
    }
    pub async fn fetch_permission_tree(
        &self, client: &Client, id: Option<i32>,
    ) -> Result<PermissionTree> {
        let rows = match id {
            Some(id) => client
                .query(&self.fetch_permission_tree, &[&id])
                .await?,
            None => client
                .query(&self.fetch_default_permission_tree, &[])
                .await?,
        };
        let mut tree = HashMap::new();
        for row in rows {
            let id: i32 = row.get("role_id");
            tree.entry(id)
                .or_insert_with(HashMap::new)
                .insert(row.get("permission_id"), PermissionSubjectAction {
                    subject: row.get("subject"),
                    action: row.get("action"),
                });
        }
        Ok(PermissionTree::new(tree))
    }
    pub async fn check_username_existence(
        &self, client: &Client, username: &str,
    ) -> Result<bool> {
        let rows = client
            .query(&self.find_one_from_username_to_id, &[&username])
            .await?;
        Ok(!rows.is_empty())
    }
    pub async fn check_email_existence(
        &self, client: &Client, email: &str,
    ) -> Result<bool> {
        let rows = client
            .query(&self.find_one_from_email_to_id, &[&email])
            .await?;
        Ok(!rows.is_empty())
    }
    pub async fn register_user(
        &self, client: &Client,
        smtp: web::Data<AppSmtp>, // for smtp
        sender: &str, site: &str,
        username: &str, email: &str, password: &str,
    ) -> Result<UserRegistration> {
        let duplicated_rows = client
            .query(&self.find_one_from_username_email_to_username_email,
                   &[&username, &email])
            .await?;
        if let Some(row) = duplicated_rows.get(0) {
            return Err(Error::DuplicatedUser {
                field: if row.get::<&str, String>("username") == username { "username".into() }
                else { "email".into() }
            });
        }
        let mut rng = thread_rng();
        let id: String = iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(24)
            .collect();
        let code: String = iter::repeat(())
            .map(|()| rng.sample(Digit))
            .take(6)
            .collect();
        let message = register_user_email(sender.parse()?, email.parse()?,
                                        site, username, &id, &code)?;
        block(move || smtp.smtp.send(&message))
            .await?;
        let password = String::from(password);
        let password = block(move || bcrypt::hash(password, crate::constants::BCRYPT_COST))
            .await?;
        let row = client
            .query_one(&self.insert_one_into_user_registration,
                       &[&id, &code, &username, &password, &email])
            .await?;
        Ok(UserRegistration {
            id,
            code,
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        })
    }
    pub async fn confirm_registration(
        &self, client: &mut Client, id: &str, code: &Option<String>,
    ) -> Result<UserCreatedByRegistration> {
        let transaction = client.build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        let rows = transaction
            .query(&self.find_one_from_user_registration, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserRegistrationNotFound)?;
        let real_code: String = row.get("code");
        let username: String = row.get("username");
        let password: String = row.get("password");
        let email: String = row.get("email");
        let expires_at: DateTime<Utc> = row.get("expires_at");
        if expires_at < Utc::now() {
            return Err(Error::UserRegistrationExpired);
        }
        if let Some(code) = code {
            if real_code != *code {
                return Err(Error::UserRegistrationWrongCode);
            }
        }
        let duplicated_rows = transaction
            .query(&self.find_one_from_username_email_to_username_email,
                   &[&username, &email])
            .await?;
        if let Some(row) = duplicated_rows.get(0) {
            return Err(Error::DuplicatedUser {
                field: if row.get::<&str, String>("username") == username { "username".into() }
                else { "email".into() }
            });
        }
        let user = transaction
            .query_one(&self.insert_one_registered_user, &[&username, &password, &email])
            .await?;
        let user_id: i32 = user.get("id");
        let roles = transaction
            .query(&self.find_default_roles, &[])
            .await?
            .iter()
            .map(|x| x.get("name"))
            .collect::<Vec<String>>();
        transaction
            .query(&self.insert_one_roles, &[&user_id, &roles])
            .await?;
        transaction
            .query(&self.complete_registration, &[&id])
            .await?;
        transaction.commit().await?;
        Ok(UserCreatedByRegistration {
            id: user_id,
            username,
            roles,
            email: Some(email),
            created_at: user.get("created_at"),
        })
    }
    pub async fn query_registration(
        &self, client: &Client, id: &str,
    ) -> Result<UserRegistrationPublic> {
        let rows = client
            .query(&self.query_registration, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserRegistrationNotFound)?;
        let registration = UserRegistrationPublic::from(row);
        if registration.completed.is_none() && registration.expires_at < Utc::now() {
            return Err(Error::UserRegistrationExpired);
        }
        Ok(registration)
    }
    pub async fn resend_registration_email(
        &self, client: &Client,
        smtp: web::Data<AppSmtp>,
        sender: &str, site: &str, id: &str,
    ) -> Result<()> {
        let rows = client
            .query(&self.find_one_from_user_registration_without_password, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserRegistrationNotFound)?;
        let code: String = row.get("code");
        let username: String = row.get("username");
        let email: String = row.get("email");
        let expires_at: DateTime<Utc> = row.get("expires_at");
        if expires_at < Utc::now() {
            return Err(Error::UserRegistrationExpired);
        }
        let message = register_user_email(sender.parse()?, email.parse()?,
                                          site, &username, &id, &code)?;
        block(move || smtp.smtp.send(&message))
            .await?;
        Ok(())
    }
    pub async fn update_user(
        &self, client: &mut Client, id: i32,
        username: &Option<String>, email: &Option<Option<String>>,
        nickname: &Option<Option<String>>, blocked: &Option<Option<bool>>,
    ) -> Result<DateTime<Utc>> {
        let transaction = client.build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        match username {
            Some(username) => if transaction
                .query(&self.find_one_from_username_to_id, &[&username])
                .await?
                .get(0)
                .map(|x| x.get::<&str, i32>("id"))
                .is_some() {
                return Err(Error::DuplicatedUser { field: "username".into() });
            }
            _ => ()
        }
        match email {
            Some(Some(email)) => if transaction
                .query(&self.find_one_from_email_to_id, &[&email])
                .await?
                .get(0)
                .map(|x| x.get::<&str, i32>("id"))
                .is_some() {
                return Err(Error::DuplicatedUser { field: "email".into() });
            }
            _ => ()
        }
        let enable_username = username.is_some();
        let enable_email = email.is_some();
        let enable_nickname = nickname.is_some();
        let enable_blocked = blocked.is_some();
        let rows = transaction
            .query(&self.update_user,
                   &[&enable_username, &username,
                       &enable_email, &email.clone().flatten(),
                       &enable_nickname, &nickname.clone().flatten(),
                       &enable_blocked, &blocked.clone().flatten(),
                   &id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        transaction.commit()
            .await?;
        Ok(row.get("updated_at"))
    }
    pub async fn update_email(
        &self, client: &Client,
        smtp: web::Data<AppSmtp>, // for smtp
        sender: &str, site: &str,
        uid: i32, new_email: &str,
    ) -> Result<UserEmailUpdating> {
        let username: String = client
            .query(&self.find_one_to_username, &[&uid])
            .await?
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?
            .get("username");
        let rows = client
            .query(&self.find_one_from_email_to_id, &[&new_email])
            .await?;
        if !rows.is_empty() {
            return Err(Error::DuplicatedUser { field: "email".into() });
        }
        let mut rng = thread_rng();
        let id: String = iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(24)
            .collect();
        let code: String = iter::repeat(())
            .map(|()| rng.sample(Digit))
            .take(6)
            .collect();
        let message = update_user_email(sender.parse()?, new_email.parse()?,
                                        site, &username, &id, &code)?;
        block(move || smtp.smtp.send(&message))
            .await?;
        let row = client
            .query_one(&self.insert_one_into_user_email_updating,
                       &[&id, &code, &uid, &new_email])
            .await?;
        Ok(UserEmailUpdating {
            id,
            code,
            created_at: row.get("created_at"),
            expires_at: row.get("expires_at"),
        })
    }
    pub async fn confirm_email_updating(
        &self, client: &mut Client, id: &str, code: &Option<String>, required_uid: &Option<i32>,
    ) -> Result<UserIdEmailUpdatedAt> {
        let transaction = client.build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        let rows = transaction
            .query(&self.find_one_from_user_email_updating, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserEmailUpdatingNotFound)?;
        let real_code: String = row.get("code");
        let user: i32 = row.get("user");
        let new_email: String = row.get("new_email");
        let expires_at: DateTime<Utc> = row.get("expires_at");
        if let Some(required_uid) = required_uid {
            if *required_uid != user {
                return Err(Error::UserNotMatch);
            }
        }
        if expires_at < Utc::now() {
            return Err(Error::UserEmailUpdatingExpired);
        }
        if let Some(code) = code {
            if real_code != *code {
                return Err(Error::UserEmailUpdatingWrongCode);
            }
        }
        let rows = transaction
            .query(&self.find_one_from_email_to_id, &[&new_email])
            .await?;
        if !rows.is_empty() {
            return Err(Error::DuplicatedUser { field: "email".into() });
        }
        let rows = transaction
            .query(&self.update_email, &[&new_email, &user])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        transaction
            .query(&self.complete_email_updating, &[&id])
            .await?;
        transaction.commit().await?;
        Ok(UserIdEmailUpdatedAt {
            id: user,
            email: new_email,
            updated_at: row.get("updated_at"),
        })
    }
    pub async fn query_email_updating(
        &self, client: &Client, id: &str, required_uid: Option<i32>,
    ) -> Result<UserEmailUpdatingPublic> {
        let rows = client
            .query(&self.query_email_updating, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserEmailUpdatingNotFound)?;
        let registration = UserEmailUpdatingPublic::from(row);
        match required_uid {
            Some(required_uid) => if required_uid != registration.user {
                return Err(Error::UserNotMatch)
            }
            None => (),
        }
        if registration.completed.is_none() && registration.expires_at < Utc::now() {
            return Err(Error::UserEmailUpdatingExpired);
        }
        Ok(registration)
    }
    pub async fn resend_email_updating_email(
        &self, client: &Client,
        smtp: web::Data<AppSmtp>,
        sender: &str, site: &str, id: &str,
        required_uid: Option<i32>,
    ) -> Result<()> {
        let rows = client
            .query(&self.find_one_from_user_email_updating_join_user, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserEmailUpdatingNotFound)?;
        let code: String = row.get("code");
        let uid: i32 = row.get("uid");
        let username: String = row.get("username");
        let email: String = row.get("new_email");
        let expires_at: DateTime<Utc> = row.get("expires_at");
        match required_uid {
            Some(required_uid) => if required_uid != uid {
                return Err(Error::UserNotMatch)
            }
            None => (),
        }
        if expires_at < Utc::now() {
            return Err(Error::UserEmailUpdatingExpired);
        }
        let message = update_user_email(sender.parse()?, email.parse()?,
                                        site, &username, &id, &code)?;
        block(move || smtp.smtp.send(&message))
            .await?;
        Ok(())
    }
    pub async fn update_password(
        &self, client: &mut Client, id: i32, password: String, old_password: Option<String>
    ) -> Result<DateTime<Utc>> {
        let transaction = client.build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .start()
            .await?;
        if let Some(old_password) = old_password {
            let old_password_hash: String = transaction
                .query(&self.find_one_to_password, &[&id])
                .await?
                .get(0)
                .ok_or_else(|| Error::UserNotFound)?
                .get("password");
            let verified = block(move || bcrypt::verify(old_password, &old_password_hash))
                .await?;
            if !verified {
                return Err(Error::WrongPassword);
            }
        }
        let password_hash = block(move || bcrypt::hash(password, crate::constants::BCRYPT_COST))
            .await?;
        let updated_at = transaction
            .query(&self.update_password, &[&password_hash, &id])
            .await?
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?
            .get("updated_at");
        transaction.commit().await?;
        Ok(updated_at)
    }
}
