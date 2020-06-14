use crate::{
    config::InitConfig,
    constants::{BCRYPT_COST, JWT_SECRET_LENGTH},
    batch::{batch_values, batch_slots, ToSql}
};
use super::predefined;
use err_derive::Error;
use log::{info, error};
use tokio_postgres::{
    Client,
    Error as PostgresError,
    NoTls,
};

#[derive(Debug, Error)]
pub enum InitError {
    #[error(display = "{}", _0)]
    Db(#[error(source)]#[error(from)] PostgresError),
    #[error(display = "Failed to prompt password")]
    PromptPasswordError,
    #[error(display = "{}", _0)]
    Bcrypt(#[error(source)] #[error(from)] bcrypt::BcryptError),
}

pub type Result<T> = std::result::Result<T, InitError>;

pub async fn drop_permission(client: &Client) -> Result<()> {
    // Drop old table
    client
        .query("DROP TABLE IF EXISTS permission", &[])
        .await?;
    Ok(())
}

pub async fn init_permission(client: &Client) -> Result<()> {
    // Create table
    client
        .query("\
            CREATE TABLE IF NOT EXISTS permission (\
                id serial PRIMARY KEY,\
                subject VARCHAR (24) NOT NULL,\
                action VARCHAR (24) NOT NULL,\
                display_name VARCHAR (40) NOT NULL,\
                description TEXT NOT NULL,\
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                deleted BOOL NOT NULL\
            )", &[])
        .await?;
    // Create index
    client
        .query("\
            CREATE UNIQUE INDEX IF NOT EXISTS permission_subject_action \
            ON permission (subject, action) \
            WHERE NOT deleted", &[])
        .await?;
    // Insert items
    const ITEMS: &[predefined::PredefinedPermission] = predefined::PREDEFINED_PERMISSIONS;
    let result = client
        .execute(&format!("\
        INSERT INTO permission (subject, action, display_name, description, \
                                created_at, updated_at, deleted) \
        VALUES {} \
        ON CONFLICT (subject, action) WHERE NOT deleted \
        DO UPDATE SET \
            display_name = EXCLUDED.display_name, \
            description = EXCLUDED.description, \
            updated_at = EXCLUDED.updated_at\
        ", batch_values(ITEMS.len(), |i|
            format!("{},NOW(),NOW(),FALSE",
                    batch_slots(i * 4 + 1, (i + 1) * 4 + 1)))
        )[..], &ITEMS.iter()
            .flat_map(|item| vec![
                &item.0 as &ToSql, &item.1, &item.2, &item.3,
            ])
            .collect::<Vec<_>>()[..],
        )
        .await?;
    info!("modify {} rows in permission table", result);
    Ok(())
}

pub async fn drop_role(client: &Client) -> Result<()> {
    // Drop role_permission table
    client
        .query("DROP TABLE IF EXISTS role_permission", &[])
        .await?;
    // Drop role table
    client
        .query("DROP TABLE IF EXISTS role", &[])
        .await?;
    Ok(())
}

pub async fn init_role(client: &Client) -> Result<()> {
    // Create role table
    client
        .query("\
            CREATE TABLE IF NOT EXISTS role (\
                id serial PRIMARY KEY,\
                name VARCHAR(24) NOT NULL,\
                display_name VARCHAR (40) NOT NULL,\
                description TEXT NOT NULL,\
                \"default\" BOOL NOT NULL,\
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                deleted BOOL NOT NULL\
            )", &[])
        .await?;
    // Create index
    client
        .query("\
            CREATE UNIQUE INDEX IF NOT EXISTS role_name \
            ON role (name) WHERE NOT deleted", &[])
        .await?;
    // Create role_permission table
    client
        .query("\
            CREATE TABLE IF NOT EXISTS role_permission (\
                role INTEGER REFERENCES role(id) ON DELETE CASCADE NOT NULL,\
                permission INTEGER REFERENCES permission(id) ON DELETE CASCADE NOT NULL,\
                UNIQUE (role, permission)\
            )", &[])
        .await?;
    // Insert Items
    const ITEMS: &[predefined::PredefinedRole] = predefined::PREDEFINED_ROLES;
    let result = client
        .execute(&format!("\
        INSERT INTO role (name, display_name, description, \"default\", \
                          created_at, updated_at, deleted) \
        VALUES {} \
        ON CONFLICT (name) WHERE NOT deleted \
        DO UPDATE SET \
            display_name = EXCLUDED.display_name, \
            description = EXCLUDED.description, \
            \"default\" = EXCLUDED.\"default\", \
            updated_at = EXCLUDED.updated_at\
        ", batch_values(ITEMS.len(), |i| {
            format!("{},NOW(),NOW(),FALSE",
                    batch_slots(i * 4 + 1, (i + 1) * 4 + 1))
        }))[..], &ITEMS.iter()
            .flat_map(|item| vec![
                &item.0 as &ToSql, &item.2, &item.3, &item.4,
            ])
            .collect::<Vec<_>>()[..]
        )
        .await?;
    info!("modify {} rows in role table", result);
    let items = ITEMS.iter()
        .flat_map(|role| role.1.iter()
            .map(move |permission| (role.0, permission.0, permission.1)))
        .collect::<Vec<_>>();
    let result = client
        .execute(&format!("\
        INSERT INTO role_permission (role, permission) \
        SELECT role.id, permission.id FROM (VALUES {}) AS temp(role, subject, action) \
              JOIN permission ON permission.subject = temp.subject and permission.action = temp.action \
              JOIN role ON role.name = temp.role \
        ON CONFLICT (role, permission) DO NOTHING\
        ", batch_values(items.len(), |i|
            batch_slots(i * 3 + 1, (i + 1) * 3 + 1))
        )[..], &items.iter()
            .flat_map(|item| vec![&item.0 as &ToSql, &item.1, &item.2])
            .collect::<Vec<_>>()[..]
        )
        .await?;
    info!("modify {} rows in role_permission table", result);
    Ok(())
}

pub async fn drop_user(client: &Client) -> Result<()> {
    // Drop user_role table
    client
        .query("DROP TABLE IF EXISTS user_role", &[])
        .await?;
    // Drop user table
    client
        .query("DROP TABLE IF EXISTS \"user\"", &[])
        .await?;
    Ok(())
}

pub async fn init_user(client: &Client, config: &InitConfig) -> Result<()> {
    // Create user table
    client
        .query("\
            CREATE TABLE IF NOT EXISTS \"user\" (\
                id serial PRIMARY KEY,\
                username VARCHAR(24) NOT NULL,\
                password VARCHAR(72) NOT NULL,\
                email VARCHAR (254),\
                nickname VARCHAR(24),\
                avatar VARCHAR(128),\
                avatar128 VARCHAR(128),\
                blocked BOOL,\
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                deleted BOOL NOT NULL\
            )", &[])
        .await?;
    // Create index
    client
        .query("\
            CREATE UNIQUE INDEX IF NOT EXISTS user_username \
            ON \"user\" (username) WHERE NOT deleted", &[])
        .await?;
    client
        .query("\
            CREATE UNIQUE INDEX IF NOT EXISTS user_email \
            ON \"user\" (email) WHERE NOT deleted", &[])
        .await?;
    // Create user_role table
    client
        .query("\
            CREATE TABLE IF NOT EXISTS user_role (\
                \"user\" INTEGER REFERENCES \"user\"(id) ON DELETE CASCADE NOT NULL,\
                role INTEGER REFERENCES role(id) ON DELETE CASCADE NOT NULL,\
                UNIQUE (\"user\", role)\
            )", &[])
        .await?;
    if let Some(superuser_username) = &config.superuser_username {
        // Insert Items
        let superuser_password = if let Some(password) = &config.superuser_password {
            password.clone()
        } else {
            rpassword::read_password_from_tty(Some("Please enter the password for superuser: "))
                .map_err(|_| InitError::PromptPasswordError)?
        };
        let superuser_password = bcrypt::hash(superuser_password, BCRYPT_COST)?;
        let result = client
            .execute("\
            INSERT INTO \"user\" (username, password, created_at, updated_at, deleted) \
            VALUES ($1, $2, NOW(), NOW(), false) \
            ON CONFLICT (username) WHERE NOT deleted \
            DO UPDATE SET \
                password = EXCLUDED.password, \
                updated_at = EXCLUDED.updated_at\
            ", &[&superuser_username, &superuser_password])
            .await?;
        info!("modify {} rows in user table", result);
        let items = predefined::SUPERUSER_ROLES.iter()
            .map(|role| (superuser_username.clone(), *role))
            .collect::<Vec<_>>();
        let result = client
            .execute(&format!("\
            INSERT INTO user_role (\"user\", role) \
            SELECT \"user\".id, role.id FROM (VALUES {}) AS temp(username, role) \
                  JOIN role ON role.name = temp.role AND NOT role.deleted \
                  JOIN \"user\" ON \"user\".username = temp.username \
            ON CONFLICT (\"user\", role) DO NOTHING", batch_values(items.len(), |i|
                batch_slots(i * 2 + 1, (i + 1) * 2 + 1))
            )[..], &items.iter()
                .flat_map(|item| vec![&item.0 as &ToSql, &item.1])
                .collect::<Vec<_>>()[..]
            )
            .await?;
        info!("modify {} rows in user_role table", result);
    }
    Ok(())
}

pub async fn drop_token(client: &Client) -> Result<()> {
    // Drop token table
    client
        .query("DROP TABLE IF EXISTS token", &[])
        .await?;
    Ok(())
}

pub async fn init_token(client: &Client) -> Result<()> {
    // Create token table
    client
        .query("\
            CREATE TABLE IF NOT EXISTS token (\
                id serial PRIMARY KEY,\
                \"user\" INTEGER REFERENCES \"user\"(id) ON DELETE CASCADE NOT NULL,\
                issued_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,\
                expires_at TIMESTAMP(0) WITH TIME ZONE NOT NULL,\
                acquire_method VARCHAR(24) NOT NULL,\
                acquire_host VARCHAR(60) NOT NULL,\
                acquire_remote VARCHAR(60),\
                acquire_user_agent TEXT,\
                revoked BOOL NOT NULL\
            )", &[])
        .await?;
    // Create index
    client
        .query("CREATE INDEX IF NOT EXISTS \"token_user\" ON token (\"user\")", &[])
        .await?;
    Ok(())
}

pub async fn drop_global_settings(client: &Client) -> Result<()> {
    // Drop global_settings table
    client
        .query("DROP TABLE IF EXISTS global_settings", &[])
        .await?;
    Ok(())
}

pub async fn init_global_settings(client: &Client) -> Result<()> {
    // Create global_settings table
    client
        .query("\
            CREATE TABLE IF NOT EXISTS global_settings (\
                id INTEGER PRIMARY KEY,\
                jwt_secret BYTEA NOT NULL,\
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                updated_at TIMESTAMP WITH TIME ZONE NOT NULL\
            )", &[])
        .await?;
    let jwt_secret: Vec<u8> = (0..JWT_SECRET_LENGTH).map(|_| { rand::random::<u8>() }).collect();
    let result = client
        .execute("\
        INSERT INTO global_settings (id, jwt_secret, created_at, updated_at) \
        VALUES (1, $1, NOW(), NOW())\
        ON CONFLICT (id) \
        DO UPDATE SET \
            jwt_secret = EXCLUDED.jwt_secret, \
            updated_at = EXCLUDED.updated_at\
         ", &[&jwt_secret])
        .await?;
    info!("modify {} rows in global_settings table", result);
    Ok(())
}

pub async fn init(config: &InitConfig) -> Result<()> {
    let (client, connection) = tokio_postgres::connect(&config.db, NoTls).await?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            error!("connection error: {}", e);
        }
    });
    if config.reset {
        // in reverse order
        drop_global_settings(&client).await?;
        drop_token(&client).await?;
        drop_user(&client).await?;
        drop_role(&client).await?;
        drop_permission(&client).await?;
    }
    // Now call init function one by one
    init_permission(&client).await?;
    init_role(&client).await?;
    init_user(&client, config).await?;
    init_token(&client).await?;
    init_global_settings(&client).await?;
    Ok(())
}
