use crate::{
    config::InitConfig,
    constants::{BCRYPT_COST, JWT_SECRET_LENGTH},
};
use super::predefined;
use err_derive::Error;
use log::{info, error};
use tokio_postgres::{
    Client,
    Error as PostgresError,
    NoTls,
};
use unzip_n::unzip_n;

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
                subject TEXT NOT NULL,\
                action TEXT NOT NULL,\
                display_name TEXT NOT NULL,\
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
    unzip_n!(4);
    let (subjects, actions, display_names, descriptions):
        (Vec<_>, Vec<_>, Vec<_>, Vec<_>) = ITEMS.iter()
        .map(|x| (x.0, x.1, x.2, x.3))
        .unzip_n();
    let result = client
        .execute("\
        INSERT INTO permission (subject, action, display_name, description, \
                                created_at, updated_at, deleted) \
        SELECT UNNEST($1::TEXT[]), UNNEST($2::TEXT[]), UNNEST($3::TEXT[]), UNNEST($4::TEXT[]), \
               NOW(), NOW(), FALSE \
        ON CONFLICT (subject, action) WHERE NOT deleted \
        DO UPDATE SET \
            display_name = EXCLUDED.display_name, \
            description = EXCLUDED.description, \
            updated_at = EXCLUDED.updated_at\
        ", &[&subjects, &actions, &display_names, &descriptions],
        )
        .await?;
    info!("modify {}/{} rows in permission table", result, ITEMS.len());
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
                name TEXT NOT NULL,\
                display_name TEXT NOT NULL,\
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
    unzip_n!(4);
    let (names, display_names, descriptions, defaults):
        (Vec<_>, Vec<_>, Vec<_>, Vec<_>) = ITEMS.iter()
        .map(|x| (x.0, x.2, x.3, x.4))
        .unzip_n();
    let result = client
        .execute("\
        INSERT INTO role (name, display_name, description, \"default\", \
                          created_at, updated_at, deleted) \
        SELECT UNNEST($1::TEXT[]), UNNEST($2::TEXT[]), UNNEST($3::TEXT[]), UNNEST($4::BOOLEAN[]), \
               NOW(), NOW(), FALSE \
        ON CONFLICT (name) WHERE NOT deleted \
        DO UPDATE SET \
            display_name = EXCLUDED.display_name, \
            description = EXCLUDED.description, \
            \"default\" = EXCLUDED.\"default\", \
            updated_at = EXCLUDED.updated_at\
        ", &[&names, &display_names, &descriptions, &defaults])
        .await?;
    info!("modify {}/{} rows in role table", result, ITEMS.len());
    unzip_n!(3);
    let (roles, subjects, actions): (Vec<_>, Vec<_>, Vec<_>) = ITEMS.iter()
        .flat_map(|role| role.1.iter()
            .map(move |permission| (role.0, permission.0, permission.1)))
        .unzip_n();
    let result = client
        .execute("\
        INSERT INTO role_permission (role, permission) \
        SELECT role.id, permission.id FROM \
            (SELECT UNNEST($1::TEXT[]) AS role, UNNEST($2::TEXT[]) AS subject,\
                    UNNEST($3::TEXT[]) AS action) AS temp \
                JOIN permission ON permission.subject = temp.subject and permission.action = temp.action \
                JOIN role ON role.name = temp.role \
        ON CONFLICT (role, permission) DO NOTHING\
        ", &[&roles, &subjects, &actions])
        .await?;
    info!("modify {}/{} rows in role_permission table", result, roles.len());
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
                username TEXT NOT NULL,\
                password TEXT NOT NULL,\
                email TEXT,\
                nickname TEXT,\
                avatar TEXT,\
                avatar128 TEXT,\
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
        info!("modify {}/{} rows in user table", result, 1);
        let result = client
            .execute("\
            INSERT INTO user_role (\"user\", role) \
            SELECT \"user\".id, role.id FROM (SELECT UNNEST($1::TEXT[]) AS role) AS temp \
                  JOIN role ON role.name = temp.role AND NOT role.deleted \
                  JOIN \"user\" ON \"user\".username = $2 \
            ON CONFLICT (\"user\", role) DO NOTHING\
            ", &[&predefined::SUPERUSER_ROLES, &superuser_username])
            .await?;
        info!("modify {}/{} rows in user_role table", result, predefined::SUPERUSER_ROLES.len());
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
                acquire_method TEXT NOT NULL,\
                acquire_host TEXT NOT NULL,\
                acquire_remote TEXT,\
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
    info!("modify {}/{} rows in global_settings table", result, 1);
    Ok(())
}

pub async fn drop_user_registration(client: &Client) -> Result<()> {
    // Drop user registration table
    client
        .query("DROP TABLE IF EXISTS user_registration", &[])
        .await?;
    Ok(())
}

pub async fn init_user_registration(client: &Client) -> Result<()> {
    client
        .query("\
            CREATE TABLE IF NOT EXISTS user_registration(\
                id CHAR(24) PRIMARY KEY,\
                code CHAR(6) NOT NULL,\
                username TEXT NOT NULL,\
                password TEXT NOT NULL,\
                email TEXT NOT NULL,\
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                completed BOOL\
            )", &[])
        .await?;
    Ok(())
}

pub async fn drop_user_email_updating(client: &Client) -> Result<()> {
    client
        .query("DROP TABLE IF EXISTS user_email_updating", &[])
        .await?;
    Ok(())
}

pub async fn init_user_email_updating(client: &Client) -> Result<()> {
    client
        .query("\
            CREATE TABLE IF NOT EXISTS user_email_updating(\
                id CHAR(24) PRIMARY KEY,\
                code CHAR(6) NOT NULL,\
                \"user\" INTEGER REFERENCES \"user\"(id) ON DELETE CASCADE NOT NULL,\
                new_email TEXT NOT NULL,\
                created_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                expires_at TIMESTAMP WITH TIME ZONE NOT NULL,\
                completed BOOL\
            )", &[])
        .await?;
    Ok(())
}

pub async fn drop_limits(client: &Client) -> Result<()> {
    client
        .query("DROP TABLE IF EXISTS limits", &[])
        .await?;
    Ok(())
}

pub async fn init_limits(client: &Client) -> Result<()> {
    client
        .query("\
            CREATE TABLE IF NOT EXISTS limits (\
                subject TEXT NOT NULL,\
                remote TEXT NOT NULL,\
                available_tokens DOUBLE PRECISION NOT NULL,\
                last_time TIMESTAMP WITH TIME ZONE NOT NULL,\
                PRIMARY KEY (subject, remote)\
            )", &[])
        .await?;
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
        drop_limits(&client).await?;
        drop_user_email_updating(&client).await?;
        drop_user_registration(&client).await?;
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
    init_user_registration(&client).await?;
    init_user_email_updating(&client).await?;
    init_limits(&client).await?;
    Ok(())
}
