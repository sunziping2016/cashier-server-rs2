use crate::batch::{batch_values};
use super::errors::{Error, Result};
use actix_web::web::block;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::{HashSet, HashMap};
use tokio_postgres::{
    Client, Statement, types::Type, types::ToSql,
    IsolationLevel, Row,
};

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

#[derive(Debug, Hash, Eq, PartialEq)]
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
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: Option<String>,
    pub nickname: Option<String>,
    pub avatar: Option<String>,
    pub avatar128: Option<String>,
    pub blocked: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<&Row> for User {
    fn from(row: &Row) -> Self {
        Self {
            id: row.get("id"),
            username: row.get("username"),
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

#[derive(Debug, Hash, Eq, PartialEq, Clone, Serialize, Deserialize)]
pub struct PermissionIdSubjectAction {
    pub id: i32,
    pub subject: String,
    pub action: String,
}

#[derive(Debug, PartialEq)]
pub struct PermissionTree {
    map: HashMap<i32, HashSet<PermissionIdSubjectAction>>,
}

impl PermissionTree {
    pub fn new(map: HashMap<i32, HashSet<PermissionIdSubjectAction>>) -> Self {
        Self { map }
    }
    pub fn get(&self) -> HashSet<PermissionIdSubjectAction> {
        self.map.values()
            .flat_map(|x| x.iter())
            .map(|x| x.clone())
            .collect()
    }
    pub fn get_subscribe(&self) -> HashSet<String> {
        self.get().iter()
            .filter(|x| x.action == "subscribe")
            .map(|x| x.subject.clone())
            .collect()
    }
}

impl Default for PermissionTree {
    fn default() -> Self {
        Self { map: HashMap::new() }
    }
}

pub struct Query {
    find_one_from_username_to_id_password_blocked: Statement,
    find_one_from_email_to_id_password_blocked: Statement,
    check_user_blocked: Statement,
    fetch_permission: Statement,
    fetch_default_permission: Statement,
    find_one_from_username_to_username_email: Statement,
    find_one_from_username_email_to_username_email: Statement,
    insert_one: Statement,
    fetch_avatars: Statement,
    update_avatars: Statement,
    find_one: Statement,
    fetch_permission_tree: Statement,
    fetch_default_permission_tree: Statement,
}

impl Query {
    pub async fn new(client: &Client) -> Self {
        Self {
            find_one_from_username_to_id_password_blocked: client.prepare_typed(
                "SELECT id, password, blocked FROM \"user\" \
                WHERE username = $1 AND NOT deleted LIMIT 1",
                &[Type::VARCHAR],
            ).await.unwrap(),
            find_one_from_email_to_id_password_blocked: client.prepare_typed(
                "SELECT id, password, blocked FROM \"user\" \
                WHERE email = $1 AND NOT deleted LIMIT 1",
                &[Type::VARCHAR],
            ).await.unwrap(),
            check_user_blocked: client.prepare_typed(
                "SELECT blocked FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
                &[Type::INT4],
            ).await.unwrap(),
            fetch_permission: client.prepare_typed(
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
            ).await.unwrap(),
            fetch_default_permission: client.prepare(
                "SELECT DISTINCT subject, action from role, role_permission, permission \
                WHERE role.name = 'default' AND NOT role.deleted AND role.id = role_permission.role \
                AND role_permission.permission = permission.id AND NOT permission.deleted"
            ).await.unwrap(),
            find_one_from_username_to_username_email: client.prepare_typed(
                "SELECT username, email FROM \"user\" \
                WHERE username = $1 AND NOT deleted LIMIT 1",
                &[Type::VARCHAR],
            ).await.unwrap(),
            find_one_from_username_email_to_username_email: client.prepare_typed(
                "SELECT username, email FROM \"user\" \
                WHERE (username = $1 OR email = $2) AND NOT deleted LIMIT 1",
                &[Type::VARCHAR, Type::VARCHAR],
            ).await.unwrap(),
            insert_one: client.prepare_typed(
                "INSERT INTO \"user\" (username, password, email, nickname, \
                                       created_at, updated_at, deleted) \
                VALUES ($1, $2, $3, $4, NOW(), NOW(), false) \
                RETURNING id, created_at",
                &[Type::VARCHAR, Type::VARCHAR, Type::VARCHAR, Type::VARCHAR],
            ).await.unwrap(),
            fetch_avatars: client.prepare_typed(
                "SELECT avatar, avatar128 FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
                &[Type::INT4],
            ).await.unwrap(),
            update_avatars: client.prepare_typed(
                "UPDATE \"user\" SET avatar = $1, avatar128 = $2 \
                WHERE id = $3 AND NOT deleted",
                &[Type::VARCHAR, Type::VARCHAR, Type::INT4]
            ).await.unwrap(),
            find_one: client.prepare_typed(
                "SELECT id, username, email, nickname, avatar, avatar128, \
                        blocked, created_at, updated_at FROM \"user\" \
                WHERE id = $1 AND NOT deleted LIMIT 1",
                &[Type::INT4],
            ).await.unwrap(),
            fetch_permission_tree: client.prepare_typed(
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
            ).await.unwrap(),
            fetch_default_permission_tree: client.prepare(
                "SELECT DISTINCT role.id as role_id, permission.id as permission_id, subject, action \
                    from role, role_permission, permission \
                WHERE role.name = 'default' AND NOT role.deleted AND role.id = role_permission.role \
                AND role_permission.permission = permission.id AND NOT permission.deleted"
            ).await.unwrap(),
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
        let mut values = roles.iter()
            .map(|x| x as &(dyn ToSql + std::marker::Sync))
            .collect::<Vec<_>>();
        values.push(&id);
        let rows = client.query(
            &format!("\
            VALUES {} EXCEPT \
            SELECT role.name from user_role, role WHERE user_role.user = ${} \
                AND user_role.role = role.id AND NOT role.deleted",
                     batch_values(roles.len(), |i| format!("${}", i + 1)),
                     roles.len() + 1
            )[..], &values[..])
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
        let id = user.get("id");
        let mut values = vec![&id as &(dyn ToSql + std::marker::Sync)];
        values.extend(
            roles.iter()
            .map(|x| x as &(dyn ToSql + std::marker::Sync)));
        if !roles.is_empty() {
            transaction
                .query(&format!("\
                INSERT INTO user_role (\"user\", role) \
                SELECT $1, role.id FROM (VALUES {}) AS temp(role), role \
                WHERE role.name = temp.role AND NOT role.deleted\
                ", batch_values(roles.len(), |i| format!("${}", i + 2)))[..], &values[..])
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
    ) -> Result<u64> {
        let count = client
            .execute(&self.update_avatars, &[avatar, avatar128, &id])
            .await?;
        Ok(count)
    }
    pub async fn find_one(
        &self, client: &Client, id: i32,
    ) -> Result<User> {
        let rows = client
            .query(&self.find_one, &[&id])
            .await?;
        let row = rows
            .get(0)
            .ok_or_else(|| Error::UserNotFound)?;
        Ok(row.into())
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
                .or_insert_with(HashSet::new)
                .insert(PermissionIdSubjectAction {
                    id: row.get("permission_id"),
                    subject: row.get("subject"),
                    action: row.get("action"),
                });
        }
        Ok(PermissionTree::new(tree))
    }
}
