use crate::{
    api::{
        extractors::{
            auth::Auth,
            multer::Multer,
            config::{
                default_json_config,
                default_path_config,
                default_query_config,
                avatar_multer_config,
            },
        },
        errors::{ApiError, ApiResult, respond},
        app_state::{AppConfig, AppDatabase, AppSubscriber, AppSmtp},
        fields::{
            Username,
            Password,
            Email,
            RoleName,
            Nickname,
            Id,
            Any24,
            Any6,
            Cursor as CursorField,
        },
    },
    queries::{
        errors::Error as QueryError,
        users::{
            User,
            UserRegistrationPublic,
            UserEmailUpdatingPublic,
        },
    },
    websocket::push_messages::{UserCreated, UserUpdated, TokenRevoked, double_option},
    internal_server_error,
};
use actix_web::{
    web::{self, block},
    error::BlockingError,
};
use actix_web_validator::{ValidatedJson, ValidatedPath, ValidatedQuery};
use chrono::{DateTime, Utc};
use image::{
    GenericImageView,
    error::ImageError,
};
use log::error;
use rand::{Rng, thread_rng, distributions::Alphanumeric};
use serde::{Serialize, Deserialize};
use std::{
    convert::Infallible,
    iter,
    path::{Path, PathBuf},
    cmp::Ordering,
};
use validator::Validate;
use validator_derive::Validate;
use cashier_query::generator::{QueryConfig, FieldConfig, escape_unquoted};
use lazy_static::lazy_static;
use crate::api::fields::PaginationSize;
use crate::queries::users::{UserCursor, UserAll, UserRegisterInfo};
use crate::api::cursor::process_query;
use futures::FutureExt;
use crate::api::extractors::config::default_confirm_rate_limit;

#[derive(Debug, Validate, Deserialize)]
struct CreateUserRequest {
    #[validate]
    username: Username,
    #[validate]
    password: Password,
    // roles must be a subset of creator's roles
    #[validate]
    roles: Vec<RoleName>,
    #[validate]
    email: Option<Email>,
    #[validate]
    nickname: Option<Nickname>,
}

#[derive(Debug, Serialize)]
struct CreateUserResponse {
    id: i32,
    created_at: DateTime<Utc>,
}

async fn create_user(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    data: ValidatedJson<CreateUserRequest>,
    auth: Auth,
) -> ApiResult<CreateUserResponse> {
    auth.try_permission("user", "create")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let mut roles = data.roles.iter()
        .map(|x| x.clone().into())
        .collect::<Vec<_>>();
    roles.dedup();
    let extra_roles = database
        .user_check_extra_roles(uid, &roles[..])
        .await
        .map_err(|e| internal_server_error!(e))?;
    if !extra_roles.is_empty() {
        return Err(ApiError::AttemptToElevateRole { roles: extra_roles });
    }
    let email = data.email.as_ref().map(|x| x.clone().into());
    let nickname = data.nickname.as_ref().map(|x| x.clone().into());
    let user = database
        .user_insert_one(&data.username[..], &data.password[..], &roles[..],
                         &email, &nickname)
        .await
        .map_err(|err| match err {
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    subscriber.send(UserCreated {
        id: user.id,
        username: String::from(data.username.clone()),
        roles,
        email,
        created_at: user.created_at,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(CreateUserResponse {
        id: user.id,
        created_at: user.created_at,
    })
}

#[derive(Debug, Validate, Deserialize)]
struct UidPath {
    #[validate]
    uid: Id,
}

#[derive(Debug, Serialize)]
struct UploadAvatarResponse {
    avatar: String,
    avatar128: Option<String>,
}

fn join_avatar_file<P1: AsRef<Path>, P2: AsRef<Path>>(root: P1, path: P2) -> PathBuf {
    Path::new(root.as_ref())
        .join(crate::constants::AVATAR_FOLDER)
        .join(path.as_ref())
}

fn join_avatar_url(url: &str, path: &str) -> String {
    String::from(url) + "/" + crate::constants::AVATAR_FOLDER + "/" + path
}

fn remove_avatar_file<P1: AsRef<Path>, P2: AsRef<Path>>(root: P1, path: P2) {
    if let Err(e) = std::fs::remove_file(join_avatar_file(root, path)) {
        error!("failed to remove file {}", e);
    }
}

async fn upload_avatar_impl(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    uid: i32,
    data: Multer,
    auth: &Auth,
) -> ApiResult<UploadAvatarResponse> {
    // Fetch old avatars
    let old_avatars = database
        .user_fetch_avatars(uid)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    // Crop and resize new avatars
    let root = config.config.media.root.clone();
    let (avatar, avatar128) = block(move || {
        let content = data.get_single("avatar").extra().content().unwrap();
        let avatar = image::load_from_memory(content)?;
        let (width, height) = avatar.dimensions();
        let size = std::cmp::min(width, height);
        let cropped_avatar = match width.cmp(&height) {
            Ordering::Less => avatar.crop_imm(0, (height - size) / 2, size, size),
            Ordering::Greater => avatar.crop_imm((width - size) / 2, 0, size, size),
            Ordering::Equal => avatar,
        };
        let mut rng = thread_rng();
        let filename = iter::repeat(())
            .map(|_| rng.sample(Alphanumeric))
            .take(crate::constants::AVATAR_FILENAME_LENGTH)
            .collect::<String>();
        let origin_filename = format!("{}.{}x{}.png", filename, size, size);
        cropped_avatar.save_with_format(join_avatar_file(&root, &origin_filename),
                                        image::ImageFormat::Png)?;
        let thumbnail_filename = if size <= 128 { None } else {
            let thumbnail = cropped_avatar.resize(128, 128,image::imageops::FilterType::Triangle);
            let thumbnail_filename = filename + ".thumb.128x128.png";
            thumbnail.save_with_format(join_avatar_file(&root, &thumbnail_filename),
                                       image::ImageFormat::Png)
                .map_err(|e| {
                    remove_avatar_file(&root, &origin_filename);
                    e
                })?;
            Some(thumbnail_filename)
        };
        Ok((origin_filename, thumbnail_filename))
    })
        .await
        .map_err(|err| match err {
            BlockingError::Error(ImageError::Decoding(_))
            => ApiError::AvatarError { error: "cannot decode the uploaded avatar".into(), },
            e => internal_server_error!(e),
        })?;
    // Save new avatars to database
    let updated_at = match database
        .user_update_avatars(uid, &Some(avatar.clone()), &avatar128)
        .await {
        Ok(v) => v,
        Err(e) => {
            let avatar = avatar.clone();
            let avatar128 = avatar128.clone();
            let root = config.config.media.root.clone();
            block(move || {
                remove_avatar_file(&root, &avatar);
                if let Some(avatar128) = avatar128 {
                    remove_avatar_file(&root, &avatar128);
                }
                Ok::<(), Infallible>(())
            })
                .await
                .map_err(|e| internal_server_error!(e))?;
            return Err(match e {
                QueryError::UserNotFound => ApiError::UserNotFound,
                e => internal_server_error!(e),
            });
        }
    };
    let root = &config.config.media.root;
    // Remove old avatars
    if let Some(old_avatar) = old_avatars.avatar.as_ref() {
        remove_avatar_file(root, old_avatar);
    }
    if let Some(old_avatar128) = old_avatars.avatar128.as_ref() {
        remove_avatar_file(root, old_avatar128);
    }
    let url = &config.config.media.url;
    let avatar = join_avatar_url(url, &avatar);
    let avatar128 = avatar128.map(|x| join_avatar_url(url, &x));
    subscriber.send(UserUpdated {
        id: uid,
        username: None,
        email: None,
        password: None,
        nickname: None,
        avatar: Some(Some(avatar.clone())),
        avatar128: Some(avatar128.clone()),
        blocked: None,
        updated_at,
    }, auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(UploadAvatarResponse {
        avatar,
        avatar128,
    })
}

async fn upload_avatar_for_me(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    data: Multer,
    auth: Auth,
) -> ApiResult<UploadAvatarResponse> {
    auth.try_permission("user-avatar", "update-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    upload_avatar_impl(config, database, subscriber, uid, data, &auth).await
}

async fn upload_avatar(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    uid_path: ValidatedPath<UidPath>,
    data: Multer,
    auth: Auth,
) -> ApiResult<UploadAvatarResponse> {
    auth.try_permission("user-avatar", "update")?;
    let uid = uid_path.uid.clone().into();
    upload_avatar_impl(config, database, subscriber, uid, data, &auth).await
}

async fn delete_avatar_impl(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    uid: i32,
    auth: &Auth,
) -> ApiResult<()> {
    // Fetch old avatars
    let old_avatars = database
        .user_fetch_avatars(uid)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    // Save new avatars to database
    let updated_at = database
        .user_update_avatars(uid, &None, &None)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    let root = &config.config.media.root;
    // Remove old avatars
    if let Some(old_avatar) = old_avatars.avatar.as_ref() {
        remove_avatar_file(root, old_avatar);
    }
    if let Some(old_avatar128) = old_avatars.avatar128.as_ref() {
        remove_avatar_file(root, old_avatar128);
    }
    subscriber.send(UserUpdated {
        id: uid,
        username: None,
        email: None,
        password: None,
        nickname: None,
        avatar: Some(None),
        avatar128: Some(None),
        blocked: None,
        updated_at,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn delete_avatar_for_me(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-avatar", "delete-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    delete_avatar_impl(config, database, subscriber, uid, &auth).await
}

async fn delete_avatar(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-avatar", "update")?;
    let uid = uid_path.uid.clone().into();
    delete_avatar_impl(config, database, subscriber, uid, &auth).await
}

#[derive(Serialize, Debug)]
struct ReadUserResponse {
    user: User,
}

async fn read_user_impl(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    uid: i32,
) -> ApiResult<ReadUserResponse> {
    let mut user = User::All(database
        .user_find_one(uid)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?);
    let media_url = &config.config.media.url;
    user.map_avatars(|x| join_avatar_url(media_url, x));
    respond(ReadUserResponse {
        user
    })
}

async fn read_user_for_me(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    auth.try_permission("user", "read-self")?;
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    read_user_impl(config, database, uid).await
}

async fn read_user(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    auth.try_permission("user", "read")?;
    let uid = uid_path.uid.clone().into();
    read_user_impl(config, database, uid).await
}

async fn read_user_public(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    auth.try_permission("user-public", "read")?;
    let uid = uid_path.uid.clone().into();
    let mut user = User::Public(database
        .user_find_one_public(uid)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?);
    let media_url = &config.config.media.url;
    user.map_avatars(|x| join_avatar_url(media_url, x));
    respond(ReadUserResponse {
        user
    })
}

#[derive(Debug, Validate, Deserialize)]
struct RegisterUserRequest {
    #[validate]
    username: Username,
    #[validate]
    email: Email,
    #[validate]
    password: Password,
}

#[derive(Debug, Serialize)]
struct RegisterUserResponse {
    id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn register_user(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    smtp: web::Data<AppSmtp>,
    request: ValidatedJson<RegisterUserRequest>,
    auth: Auth,
) -> ApiResult<RegisterUserResponse> {
    auth.try_permission("registration", "create")?;
    let result = database
        .user_register(smtp,
                       &config.config.smtp.sender, &config.config.site,
                       UserRegisterInfo {
                           username: &request.username[..],
                           email: &request.email[..],
                           password: &request.password[..],
                       })
        .await
        .map_err(|err| match err {
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    respond(RegisterUserResponse {
        id: result.id,
        created_at: result.created_at,
        expires_at: result.expires_at,
    })
}

#[derive(Debug, Validate, Deserialize)]
struct RegIdPath {
    #[validate]
    reg_id: Any24,
}

#[derive(Debug, Validate, Deserialize)]
struct ConfirmRegistrationRequest {
    #[validate]
    code: Any6,
}

async fn confirm_registration_impl(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    reg_id: &str,
    code: &Option<String>,
    auth: &Auth,
) -> ApiResult<()> {
    let result = database
        .user_confirm_registration(reg_id, code)
        .await
        .map_err(|err| match err {
            QueryError::UserRegistrationNotFound => ApiError::UserRegistration { reason: "NotFound".into() },
            QueryError::UserRegistrationExpired => ApiError::UserRegistration { reason: "Expired".into() },
            QueryError::UserRegistrationWrongCode => ApiError::UserRegistration { reason: "WrongCode".into() },
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    subscriber.send(UserCreated {
        id: result.id,
        username: result.username,
        roles: result.roles,
        email: result.email,
        created_at: result.created_at,
    }, auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn confirm_registration(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    request: ValidatedJson<ConfirmRegistrationRequest>,
    path: ValidatedPath<RegIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("registration", "confirm")?;
    confirm_registration_impl(database, subscriber, &path.reg_id[..],
                              &Some(request.code.clone().into()), &auth).await
}

async fn confirm_registration_for_others(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    path: ValidatedPath<RegIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("registration", "confirm-others")?;
    confirm_registration_impl(database, subscriber, &path.reg_id[..], &None, &auth).await
}

#[derive(Debug, Validate, Deserialize)]
struct CheckUsernameExistenceRequest {
    #[validate]
    username: Username,
}

#[derive(Debug, Validate, Deserialize)]
struct CheckEmailExistenceRequest {
    #[validate]
    email: Email,
}

#[derive(Debug, Serialize)]
struct CheckExistenceResponse {
    exists: bool,
}

async fn check_username_existence(
    database: web::Data<AppDatabase>,
    request: ValidatedQuery<CheckUsernameExistenceRequest>,
    auth: Auth,
) -> ApiResult<CheckExistenceResponse> {
    auth.try_permission("user-username", "check-existence")?;
    let exists = database
        .user_check_username_existence(&request.username[..])
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(CheckExistenceResponse {
        exists
    })
}

async fn check_email_existence(
    database: web::Data<AppDatabase>,
    request: ValidatedQuery<CheckEmailExistenceRequest>,
    auth: Auth,
) -> ApiResult<CheckExistenceResponse> {
    auth.try_permission("user-username", "check-existence")?;
    let exists = database
        .user_check_email_existence(&request.email[..])
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(CheckExistenceResponse {
        exists
    })
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
enum QueryRegistrationResponse {
    NotFound,
    Expired,
    Processing(UserRegistrationPublic),
    Passed(UserRegistrationPublic),
    Rejected(UserRegistrationPublic),
}

async fn query_registration(
    database: web::Data<AppDatabase>,
    path: ValidatedPath<RegIdPath>,
    auth: Auth,
) -> ApiResult<QueryRegistrationResponse> {
    auth.try_permission("registration", "read")?;
    let result = match database
        .user_query_registration(&path.reg_id[..])
        .await {
        Ok(value) => match value.completed {
            Some(true) => QueryRegistrationResponse::Passed(value),
            Some(false) => QueryRegistrationResponse::Rejected(value),
            None => QueryRegistrationResponse::Processing(value),
        },
        Err(QueryError::UserRegistrationExpired) => QueryRegistrationResponse::Expired,
        Err(QueryError::UserRegistrationNotFound) => QueryRegistrationResponse::NotFound,
        Err(e) => return Err(internal_server_error!(e)),
    };
    respond(result)
}

async fn resend_registration_email(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    smtp: web::Data<AppSmtp>,
    path: ValidatedPath<RegIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("registration", "resend")?;
    database
        .user_resend_registration_email(
            smtp, &config.config.smtp.sender, &config.config.site,
            &path.reg_id[..])
        .await
        .map_err(|err| match err {
            QueryError::UserRegistrationNotFound => ApiError::UserRegistration { reason: "NotFound".into() },
            QueryError::UserRegistrationExpired => ApiError::UserRegistration { reason: "Expired".into() },
            e => internal_server_error!(e),
        })?;
    respond(())
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateUserRequest {
    #[validate]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<Username>,
    #[validate]
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<Option<Email>>,
    #[validate]
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<Option<Nickname>>,
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<Option<bool>>,
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateSelfRequest {
    #[validate]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<Username>,
    #[validate]
    #[serde(deserialize_with = "double_option")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nickname: Option<Option<Nickname>>,
}

struct UpdateUserInfo {
    uid: i32,
    username: Option<Username>,
    email: Option<Option<Email>>,
    nickname: Option<Option<Nickname>>,
    blocked: Option<Option<bool>>,
}

async fn update_user_impl(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: &Auth,
    info: UpdateUserInfo,
) -> ApiResult<()> {
    let UpdateUserInfo { uid, username, email, nickname, blocked } = info;
    let username = username.map(|x| x.into());
    let email = email.map(|x| x.map(|x| x.into()));
    let nickname = nickname.map(|x| x.map(|x| x.into()));
    let updated_at = database
        .user_update(info.uid, &username, &email, &nickname, &blocked)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    subscriber.send(UserUpdated {
        id: uid,
        username,
        email,
        password: None,
        nickname,
        avatar: None,
        avatar128: None,
        blocked,
        updated_at,
    }, auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn update_user_for_me(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    request: ValidatedJson<UpdateSelfRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user", "update-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    update_user_impl(database, subscriber, &auth, UpdateUserInfo {
        uid,
        username: request.username.clone(),
        email: None,
        nickname: request.nickname.clone(),
        blocked: None,
    }).await
}

async fn update_user(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    uid_path: ValidatedPath<UidPath>,
    request: ValidatedJson<UpdateUserRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user", "update")?;
    let uid = uid_path.uid.clone().into();
    update_user_impl(database, subscriber, &auth, UpdateUserInfo {
        uid,
        username: request.username.clone(),
        email: request.email.clone(),
        nickname: request.nickname.clone(),
        blocked: request.blocked,
    }).await
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdateEmailRequest {
    #[validate]
    pub email: Email,
}

#[derive(Debug, Serialize)]
struct UpdateEmailResponse {
    id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

async fn update_user_email(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    smtp: web::Data<AppSmtp>,
    request: ValidatedJson<UpdateEmailRequest>,
    auth: Auth,
) -> ApiResult<UpdateEmailResponse> {
    auth.try_permission("user-email-updating", "create")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let result = database
        .user_update_email(
            smtp, &config.config.smtp.sender, &config.config.site,
            uid, &request.email[..],
        )
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    respond(UpdateEmailResponse {
        id: result.id,
        created_at: result.created_at,
        expires_at: result.expires_at,
    })
}

#[derive(Debug, Validate, Deserialize)]
struct UpdateIdPath {
    #[validate]
    update_id: Any24,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status")]
enum QueryEmailUpdatingResponse {
    NotFound,
    Expired,
    Processing(UserEmailUpdatingPublic),
    Passed(UserEmailUpdatingPublic),
    Rejected(UserEmailUpdatingPublic),
}

async fn query_email_updating_impl(
    database: web::Data<AppDatabase>,
    updated_id: &str,
    uid: Option<i32>
) -> ApiResult<QueryEmailUpdatingResponse> {
    let result = match database
        .user_query_email_updating(updated_id, uid)
        .await {
        Ok(value) => {
            match value.completed {
                Some(true) => QueryEmailUpdatingResponse::Passed(value),
                Some(false) => QueryEmailUpdatingResponse::Rejected(value),
                None => QueryEmailUpdatingResponse::Processing(value),
            }
        },
        Err(QueryError::UserNotMatch) => return Err(ApiError::PermissionDenied {
            subject: "user-email-updating".into(),
            action: "read".into(),
        }),
        Err(QueryError::UserEmailUpdatingExpired) => QueryEmailUpdatingResponse::Expired,
        Err(QueryError::UserEmailUpdatingNotFound) => QueryEmailUpdatingResponse::NotFound,
        Err(e) => return Err(internal_server_error!(e)),
    };
    respond(result)
}

async fn query_email_updating(
    database: web::Data<AppDatabase>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<QueryEmailUpdatingResponse> {
    auth.try_permission("user-email-updating", "read")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    query_email_updating_impl(database, &path.update_id[..], Some(uid)).await
}

async fn query_email_updating_for_others(
    database: web::Data<AppDatabase>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<QueryEmailUpdatingResponse> {
    auth.try_permission("user-email-updating", "read-others")?;
    query_email_updating_impl(database, &path.update_id[..], None).await
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmEmailUpdatingRequest {
    #[validate]
    code: Any6,
}

async fn confirm_email_updating_impl(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: &Auth,
    update_id: &str,
    code: &Option<String>,
    uid: &Option<i32>
) -> ApiResult<()> {
    let result = database
        .user_confirm_email_updating(update_id, code, uid)
        .await
        .map_err(|err| match err {
            QueryError::UserEmailUpdatingNotFound => ApiError::UserEmailUpdating { reason: "NotFound".into() },
            QueryError::UserEmailUpdatingExpired => ApiError::UserEmailUpdating { reason: "Expired".into() },
            QueryError::UserEmailUpdatingWrongCode => ApiError::UserEmailUpdating { reason: "WrongCode".into() },
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            QueryError::UserNotFound => ApiError::UserNotFound,
            QueryError::UserNotMatch => ApiError::PermissionDenied {
                subject: "user-email-updating".into(),
                action: "confirm".into(),
            },
            e => internal_server_error!(e),
        })?;
    subscriber.send(UserUpdated {
        id: result.id,
        username: None,
        email: Some(Some(result.email)),
        password: None,
        nickname: None,
        avatar: None,
        avatar128: None,
        blocked: None,
        updated_at: result.updated_at,
    }, auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn confirm_email_updating(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    request: ValidatedJson<ConfirmEmailUpdatingRequest>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "confirm")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    confirm_email_updating_impl(database, subscriber, &auth, &path.update_id[..], &Some(request.code.clone().into()), &Some(uid)).await
}

async fn confirm_email_updating_for_others(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "confirm-others")?;
    confirm_email_updating_impl(database, subscriber, &auth, &path.update_id[..], &None, &None).await
}

async fn resend_email_updating_email_impl(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    smtp: web::Data<AppSmtp>,
    update_id: &str,
    uid: Option<i32>,
) -> ApiResult<()> {
    database
        .user_resend_email_updating_email(
            smtp, &config.config.smtp.sender, &config.config.site,
            update_id, uid)
        .await
        .map_err(|err| match err {
            QueryError::UserEmailUpdatingNotFound => ApiError::UserEmailUpdating { reason: "NotFound".into() },
            QueryError::UserEmailUpdatingExpired => ApiError::UserEmailUpdating { reason: "Expired".into() },
            QueryError::UserNotMatch => ApiError::PermissionDenied {
                subject: "user-email-updating".into(),
                action: "resend".into(),
            },
            e => internal_server_error!(e),
        })?;
    respond(())
}

async fn resend_email_updating_email(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    smtp: web::Data<AppSmtp>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "resend")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    resend_email_updating_email_impl(config, database, smtp, &path.update_id[..], Some(uid)).await
}

async fn resend_email_updating_email_for_others(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    smtp: web::Data<AppSmtp>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "resend-others")?;
    resend_email_updating_email_impl(config, database, smtp, &path.update_id[..], None).await
}

async fn update_password_impl(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: &Auth,
    uid: i32,
    password: String,
    old_password: Option<String>,
) -> ApiResult<()> {
    let updated_at = database
        .user_update_password(uid, password, old_password)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            QueryError::WrongPassword => ApiError::WrongUserOrPassword,
            e => internal_server_error!(e),
        })?;
    let results = database
        .token_revoke_by_user(uid)
        .await
        .map_err(|e| internal_server_error!(e))?;
    subscriber.send_all(
        iter::once(UserUpdated {
            id: uid,
            username: None,
            email: None,
            password: Some(()),
            nickname: None,
            avatar: None,
            avatar128: None,
            blocked: None,
            updated_at,
        }.into()).chain(
            results.into_iter()
                .map(|result| TokenRevoked {
                    jti: result.id,
                    uid: result.user,
                }.into())
        )
            .collect(),
        auth
    )
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePasswordForMeRequest {
    #[validate]
    password: Password,
    #[validate]
    old_password: Password
}

async fn update_password_for_me(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    request: ValidatedJson<UpdatePasswordForMeRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-password", "update-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    update_password_impl(database, subscriber, &auth, uid,
                         request.password.clone().into(),
                         Some(request.old_password.clone().into())).await
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UpdatePasswordRequest {
    #[validate]
    password: Password,
}

async fn update_password(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    uid_path: ValidatedPath<UidPath>,
    request: ValidatedJson<UpdatePasswordRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-password", "update")?;
    let uid = uid_path.uid.clone().into();
    update_password_impl(database, subscriber, &auth, uid, request.password.clone().into(), None).await
}

lazy_static! {
    static ref LIST_USER_GENERATOR: QueryConfig = QueryConfig::new()
        .field(FieldConfig::new_number_field::<i32>("id", Some("\"user\".id".into())))
        .field(FieldConfig::new_string_field("username", None))
        .field(FieldConfig::new_string_field("email", None))
        .field(FieldConfig::new_string_field("nickname", None))
        .field(FieldConfig::new("avatar")
            .partial_equal()
            .use_like())
        .field(FieldConfig::new("avatar128")
            .partial_equal()
            .use_like())
        .field(FieldConfig::new_number_field::<bool>("blocked", None))
        .field(FieldConfig::new_date_time_field("createdAt", Some("\"user\".created_at".into())))
        .field(FieldConfig::new_date_time_field("updatedAt", Some("\"user\".updated_at".into())))
        .field(FieldConfig::new("role")
            .partial_equal()
            .escape_handler(escape_unquoted::<i32>()));
}

#[derive(Debug, Validate, Deserialize)]
struct ListUserRequest {
    #[validate]
    before: Option<CursorField>,
    #[validate]
    after: Option<CursorField>,
    #[validate]
    #[serde(default)]
    size: PaginationSize,
    sort: Option<String>,
    #[serde(default)]
    desc: bool,
    #[serde(default)]
    query: String,
}

#[derive(Debug, Serialize)]
struct ListUserResponse {
    results: Vec<UserCursor>,
}

async fn list_user(
    database: web::Data<AppDatabase>,
    request: ValidatedQuery<ListUserRequest>,
    auth: Auth,
) -> ApiResult<ListUserResponse> {
    auth.try_permission("user", "list")?;
    let size = usize::from(request.size.clone());
    let users = process_query(
        &LIST_USER_GENERATOR, &request.before, &request.after, &request.sort,
        request.desc, &request.query,
        Box::new(move |condition, order_by, ordered_columns| async move {
            let statement = format!(
            "SELECT \"user\".id, username, email, nickname, avatar, avatar128, \
                     blocked, \"user\".created_at, \"user\".updated_at, ARRAY_AGG(role.id) as roles \
            FROM ( \
                SELECT DISTINCT {} FROM \"user\", user_role, role \
                WHERE {} AND (NOT \"user\".deleted AND user_role.user = \"user\".id AND \
                    user_role.role = role.id AND NOT role.deleted) \
                ORDER BY {} LIMIT {} \
            ) AS temp, \"user\", user_role, role \
            WHERE \"user\".id = temp.id AND NOT \"user\".deleted AND user_role.user = \"user\".id \
                AND user_role.role = role.id AND NOT role.deleted \
            GROUP BY \"user\".id \
            ORDER BY {}", ordered_columns, condition, order_by, size, order_by);
            Ok(database.db.read().await
                .query(&statement[..], &[])
                .await
                .map_err(|e| internal_server_error!(e))?)
        }.boxed_local())
    ).await?.iter()
        .map(UserAll::from)
        .collect::<Vec<_>>();
    let results = users.into_iter()
        .map(|user| { UserCursor::try_from_user(User::All(user), &request.sort) })
        .collect::<Result<Vec<_>, _>>()?;
    respond(ListUserResponse { results })
}

pub fn users_api(
    config: &web::Data<AppConfig>,
    database: &web::Data<AppDatabase>,
    subscriber: &web::Data<AppSubscriber>,
    smtp: &web::Data<AppSmtp>,
) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    if let Err(e) = std::fs::create_dir_all(Path::new(&config.config.media.root)
        .join(crate::constants::AVATAR_FOLDER))  {
        error!("failed to create directory {}", e);
    }
    let config = config.clone();
    let database = database.clone();
    let subscriber = subscriber.clone();
    let smtp = smtp.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("registrations")
                .service(
                    web::scope("/{reg_id}/confirm")
                        .wrap(default_confirm_rate_limit(database.clone()))
                        .route("", web::post().to(confirm_registration))
                )
                .route("/{reg_id}/resend", web::post().to(resend_registration_email))
                .route("/{reg_id}", web::get().to(query_registration))
                .route("", web::post().to(register_user))
        ).service(
            web::scope("registrations-others")
                .route("/{reg_id}/confirm", web::post().to(confirm_registration_for_others))
        ).service(
            web::scope("email-updating")
                .service(
                    web::scope("/{update_id}/confirm")
                        .wrap(default_confirm_rate_limit(database.clone()))
                        .route("", web::post().to(confirm_email_updating))
                )
                .route("/{update_id}/resend", web::post().to(resend_email_updating_email))
                .route("/{update_id}", web::get().to(query_email_updating))
                .route("", web::post().to(update_user_email))
        ).service(
            web::scope("email-updating-others")
                .route("/{update_id}/confirm", web::post().to(confirm_email_updating_for_others))
                .route("/{update_id}/resend", web::post().to(resend_email_updating_email_for_others))
                .route("/{update_id}", web::get().to(query_email_updating_for_others))
        ).service(
            web::scope("users")
                .route("/check-username-existence", web::get().to(check_username_existence))
                .route("/check-email-existence", web::get().to(check_email_existence))
                .service(
                    web::scope("/me/avatar")
                        .app_data(config.clone())
                        .app_data(database.clone())
                        .app_data(subscriber.clone())
                        .app_data(smtp.clone())
                        .app_data(default_json_config())
                        .app_data(default_path_config())
                        .app_data(default_query_config())
                        .app_data(avatar_multer_config())
                        .route("", web::post().to(upload_avatar_for_me))
                        .route("", web::delete().to(delete_avatar_for_me))
                )
                .route("/me/password", web::post().to(update_password_for_me))
                .route("/me", web::get().to(read_user_for_me))
                .route("/me", web::patch().to(update_user_for_me))
                // .route("/me", web::delete().to(index))
                .service(
                    web::scope("/{uid}/avatar")
                        .app_data(config.clone())
                        .app_data(database.clone())
                        .app_data(subscriber.clone())
                        .app_data(smtp)
                        .app_data(default_json_config())
                        .app_data(default_path_config())
                        .app_data(default_query_config())
                        .app_data(default_path_config())
                        .app_data(avatar_multer_config())
                        .route("", web::post().to(upload_avatar))
                        .route("", web::delete().to(delete_avatar))
                )
                .route("/{uid}/password", web::post().to(update_password))
                // .route("/{uid}/roles", web::post().to(index))
                .route("/{uid}", web::get().to(read_user))
                .route("/{uid}", web::patch().to(update_user))
                // .route("/{uid}", web::delete().to(index))
                .route("", web::post().to(create_user))
                .route("", web::get().to(list_user))
        ).service(
            web::scope("public-users")
                .route("/{uid}", web::get().to(read_user_public))
                // .route("", web::get().to(index))
        );
    })
}