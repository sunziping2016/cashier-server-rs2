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
        app_state::AppState,
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
use crate::queries::users::{UserCursor, UserWithoutRoles};
use crate::api::cursor::process_query;

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
    app_data: web::Data<AppState>,
    data: ValidatedJson<CreateUserRequest>,
    auth: Auth,
) -> ApiResult<CreateUserResponse> {
    auth.try_permission("user", "create")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let mut roles = data.roles.iter()
        .map(|x| x.clone().into())
        .collect::<Vec<_>>();
    roles.dedup();
    let extra_roles = app_data.query.user
        .check_extra_roles(&*app_data.db.read().await, uid, &roles[..])
        .await
        .map_err(|e| internal_server_error!(e))?;
    if !extra_roles.is_empty() {
        return Err(ApiError::AttemptToElevateRole { roles: extra_roles });
    }
    let email = data.email.as_ref().map(|x| x.clone().into());
    let nickname = data.nickname.as_ref().map(|x| x.clone().into());
    let user = app_data.query.user
        .insert_one(&mut *app_data.db.write().await,
                    &data.username[..], &data.password[..], &roles[..],
                    &email, &nickname)
        .await
        .map_err(|err| match err {
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    app_data.send(UserCreated {
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
    app_data: web::Data<AppState>,
    uid: i32,
    data: Multer,
    auth: Auth,
) -> ApiResult<UploadAvatarResponse> {
    // Fetch old avatars
    let old_avatars = app_data.query.user
        .fetch_avatars(&*app_data.db.read().await, uid)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    // Crop and resize new avatars
    let root = app_data.config.media.root.clone();
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
    let updated_at = match app_data.query.user
        .update_avatars(&*app_data.db.read().await, uid, &Some(avatar.clone()), &avatar128)
        .await {
        Ok(v) => v,
        Err(e) => {
            let avatar = avatar.clone();
            let avatar128 = avatar128.clone();
            let root = app_data.config.media.root.clone();
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
    let root = &app_data.config.media.root;
    // Remove old avatars
    if let Some(old_avatar) = old_avatars.avatar.as_ref() {
        remove_avatar_file(root, old_avatar);
    }
    if let Some(old_avatar128) = old_avatars.avatar128.as_ref() {
        remove_avatar_file(root, old_avatar128);
    }
    let url = &app_data.config.media.url;
    let avatar = join_avatar_url(url, &avatar);
    let avatar128 = avatar128.map(|x| join_avatar_url(url, &x));
    app_data.send(UserUpdated {
        id: uid,
        username: None,
        email: None,
        password: None,
        nickname: None,
        avatar: Some(Some(avatar.clone())),
        avatar128: Some(avatar128.clone()),
        blocked: None,
        updated_at,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(UploadAvatarResponse {
        avatar,
        avatar128,
    })
}

async fn upload_avatar_for_me(
    app_data: web::Data<AppState>,
    data: Multer,
    auth: Auth,
) -> ApiResult<UploadAvatarResponse> {
    auth.try_permission("user-avatar", "update-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    upload_avatar_impl(app_data, uid, data, auth).await
}

async fn upload_avatar(
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    data: Multer,
    auth: Auth,
) -> ApiResult<UploadAvatarResponse> {
    auth.try_permission("user-avatar", "update")?;
    let uid = uid_path.uid.clone().into();
    upload_avatar_impl(app_data, uid, data, auth).await
}

async fn delete_avatar_impl(
    app_data: web::Data<AppState>,
    uid: i32,
    auth: Auth,
) -> ApiResult<()> {
    // Fetch old avatars
    let old_avatars = app_data.query.user
        .fetch_avatars(&*app_data.db.read().await, uid)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    // Save new avatars to database
    let updated_at = app_data.query.user
        .update_avatars(&*app_data.db.read().await, uid, &None, &None)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    let root = &app_data.config.media.root;
    // Remove old avatars
    if let Some(old_avatar) = old_avatars.avatar.as_ref() {
        remove_avatar_file(root, old_avatar);
    }
    if let Some(old_avatar128) = old_avatars.avatar128.as_ref() {
        remove_avatar_file(root, old_avatar128);
    }
    app_data.send(UserUpdated {
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
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-avatar", "delete-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    delete_avatar_impl(app_data, uid, auth).await
}

async fn delete_avatar(
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-avatar", "update")?;
    let uid = uid_path.uid.clone().into();
    delete_avatar_impl(app_data, uid, auth).await
}

#[derive(Serialize, Debug)]
struct ReadUserResponse {
    user: User,
}

async fn read_user_impl(
    app_data: web::Data<AppState>,
    uid: i32,
) -> ApiResult<ReadUserResponse> {
    let mut user = User::All(app_data.query.user
        .find_one_all(
            &mut *app_data.db.write().await, uid
        )
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?);
    let media_url = &app_data.config.media.url;
    user.map_avatars(|x| join_avatar_url(media_url, x));
    respond(ReadUserResponse {
        user
    })
}

async fn read_user_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    auth.try_permission("user", "read-self")?;
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    read_user_impl(app_data, uid).await
}

async fn read_user(
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    auth.try_permission("user", "read")?;
    let uid = uid_path.uid.clone().into();
    read_user_impl(app_data, uid).await
}

async fn read_user_public(
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    auth.try_permission("user-public", "read")?;
    let uid = uid_path.uid.clone().into();
    let mut user = User::Public(app_data.query.user
        .find_one_public(
            &mut *app_data.db.write().await, uid
        )
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?);
    let media_url = &app_data.config.media.url;
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
    app_data: web::Data<AppState>,
    request: ValidatedJson<RegisterUserRequest>,
    auth: Auth,
) -> ApiResult<RegisterUserResponse> {
    auth.try_permission("registration", "create")?;
    let result = app_data.query.user
        .register_user(
            &*app_data.db.read().await, app_data.clone(),
            &app_data.config.smtp.sender, &app_data.config.site,
            &request.username[..], &request.email[..], &request.password[..],
        )
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

async fn confirm_registration(
    app_data: web::Data<AppState>,
    request: ValidatedJson<ConfirmRegistrationRequest>,
    path: ValidatedPath<RegIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("registration", "confirm")?;
    let result = app_data.query.user
        .confirm_registration(&mut *app_data.db.write().await,
                              &path.reg_id[..], &request.code[..])
        .await
        .map_err(|err| match err {
            QueryError::UserRegistrationNotFound => ApiError::UserRegistration { reason: "NotFound".into() },
            QueryError::UserRegistrationExpired => ApiError::UserRegistration { reason: "Expired".into() },
            QueryError::UserRegistrationWrongCode => ApiError::UserRegistration { reason: "WrongCode".into() },
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    app_data.send(UserCreated {
        id: result.id,
        username: result.username,
        roles: result.roles,
        email: result.email,
        created_at: result.created_at,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
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
    app_data: web::Data<AppState>,
    request: ValidatedQuery<CheckUsernameExistenceRequest>,
    auth: Auth,
) -> ApiResult<CheckExistenceResponse> {
    auth.try_permission("user-username", "check-existence")?;
    let exists = app_data.query.user
        .check_username_existence(&*app_data.db.read().await, &request.username[..])
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(CheckExistenceResponse {
        exists
    })
}

async fn check_email_existence(
    app_data: web::Data<AppState>,
    request: ValidatedQuery<CheckEmailExistenceRequest>,
    auth: Auth,
) -> ApiResult<CheckExistenceResponse> {
    auth.try_permission("user-username", "check-existence")?;
    let exists = app_data.query.user
        .check_email_existence(&*app_data.db.read().await, &request.email[..])
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
    app_data: web::Data<AppState>,
    path: ValidatedPath<RegIdPath>,
    auth: Auth,
) -> ApiResult<QueryRegistrationResponse> {
    auth.try_permission("registration", "read")?;
    let result = match app_data.query.user
        .query_registration(&*app_data.db.read().await, &path.reg_id[..])
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
    app_data: web::Data<AppState>,
    path: ValidatedPath<RegIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("registration", "resend")?;
    app_data.query.user
        .resend_registration_email(
            &*app_data.db.read().await, app_data.clone(),
            &app_data.config.smtp.sender, &app_data.config.site,
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

async fn update_user_impl(
    app_data: web::Data<AppState>,
    auth: Auth,
    uid: i32,
    username: Option<Username>,
    email: Option<Option<Email>>,
    nickname: Option<Option<Nickname>>,
    blocked: Option<Option<bool>>,
) -> ApiResult<()> {
    let username = username.map(|x| x.into());
    let email = email.map(|x| x.map(|x| x.into()));
    let nickname = nickname.map(|x| x.map(|x| x.into()));
    let updated_at = app_data.query.user
        .update_user(&mut *app_data.db.write().await, uid, &username,
                     &email, &nickname, &blocked)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    app_data.send(UserUpdated {
        id: uid,
        username,
        email,
        password: None,
        nickname,
        avatar: None,
        avatar128: None,
        blocked,
        updated_at,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn update_user_for_me(
    app_data: web::Data<AppState>,
    request: ValidatedJson<UpdateSelfRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user", "update-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    update_user_impl(app_data, auth, uid, request.username.clone(), None,
                     request.nickname.clone(), None).await
}

async fn update_user(
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    request: ValidatedJson<UpdateUserRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user", "update")?;
    let uid = uid_path.uid.clone().into();
    update_user_impl(app_data, auth, uid, request.username.clone(), request.email.clone(),
                     request.nickname.clone(), request.blocked.clone()).await
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
    app_data: web::Data<AppState>,
    request: ValidatedJson<UpdateEmailRequest>,
    auth: Auth,
) -> ApiResult<UpdateEmailResponse> {
    auth.try_permission("user-email-updating", "create-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let result = app_data.query.user
        .update_email(
            &*app_data.db.read().await, app_data.clone(),
            &app_data.config.smtp.sender, &app_data.config.site,
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
    app_data: web::Data<AppState>,
    updated_id: &str,
    uid: Option<i32>
) -> ApiResult<QueryEmailUpdatingResponse> {
    let result = match app_data.query.user
        .query_email_updating(&*app_data.db.read().await, updated_id, uid)
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
    app_data: web::Data<AppState>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<QueryEmailUpdatingResponse> {
    auth.try_permission("user-email-updating", "read-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    query_email_updating_impl(app_data, &path.update_id[..], Some(uid)).await
}

async fn query_email_updating_for_others(
    app_data: web::Data<AppState>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<QueryEmailUpdatingResponse> {
    auth.try_permission("user-email-updating", "read")?;
    query_email_updating_impl(app_data, &path.update_id[..], None).await
}

#[derive(Debug, Validate, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfirmEmailUpdatingRequest {
    #[validate]
    code: Any6,
}

async fn confirm_email_updating_impl(
    app_data: web::Data<AppState>,
    auth: Auth,
    update_id: &str,
    code: &str,
    uid: Option<i32>
) -> ApiResult<()> {
    let result = app_data.query.user
        .confirm_email_updating(&mut *app_data.db.write().await,
                                update_id, code, uid)
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
    app_data.send(UserUpdated {
        id: result.id,
        username: None,
        email: Some(Some(result.email)),
        password: None,
        nickname: None,
        avatar: None,
        avatar128: None,
        blocked: None,
        updated_at: result.updated_at,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn confirm_email_updating(
    app_data: web::Data<AppState>,
    request: ValidatedJson<ConfirmEmailUpdatingRequest>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "confirm-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    confirm_email_updating_impl(app_data, auth, &path.update_id[..], &request.code[..], Some(uid)).await
}

async fn confirm_email_updating_for_others(
    app_data: web::Data<AppState>,
    request: ValidatedJson<ConfirmEmailUpdatingRequest>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "confirm")?;
    confirm_email_updating_impl(app_data, auth, &path.update_id[..], &request.code[..], None).await
}

async fn resend_email_updating_email_impl(
    app_data: web::Data<AppState>,
    update_id: &str,
    uid: Option<i32>,
) -> ApiResult<()> {
    app_data.query.user
        .resend_email_updating_email(
            &*app_data.db.read().await, app_data.clone(),
            &app_data.config.smtp.sender, &app_data.config.site,
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
    app_data: web::Data<AppState>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "resend-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    resend_email_updating_email_impl(app_data, &path.update_id[..], Some(uid)).await
}

async fn resend_email_updating_email_for_others(
    app_data: web::Data<AppState>,
    path: ValidatedPath<UpdateIdPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-email-updating", "resend")?;
    resend_email_updating_email_impl(app_data, &path.update_id[..], None).await
}

async fn update_password_impl(
    app_data: web::Data<AppState>,
    auth: Auth,
    uid: i32,
    password: String,
    old_password: Option<String>,
) -> ApiResult<()> {
    let updated_at = app_data.query.user
        .update_password(&mut *app_data.db.write().await, uid,
                         password, old_password)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            QueryError::WrongPassword => ApiError::WrongUserOrPassword,
            e => internal_server_error!(e),
        })?;
    app_data.send(UserUpdated {
        id: uid,
        username: None,
        email: None,
        password: Some(()),
        nickname: None,
        avatar: None,
        avatar128: None,
        blocked: None,
        updated_at,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    let results = app_data.query.token
        .revoke_tokens_from_user(&*app_data.db.read().await, uid)
        .await
        .map_err(|e| internal_server_error!(e))?;
    app_data.send_all(
        results.into_iter()
            .map(|result| TokenRevoked {
                jti: result.id,
                uid: result.user,
            }.into())
            .collect(),
        &auth
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
    app_data: web::Data<AppState>,
    request: ValidatedJson<UpdatePasswordForMeRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-password", "update-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    update_password_impl(app_data, auth, uid,
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
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    request: ValidatedJson<UpdatePasswordRequest>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("user-password", "update")?;
    let uid = uid_path.uid.clone().into();
    update_password_impl(app_data, auth, uid, request.password.clone().into(), None).await
}

lazy_static! {
    static ref LIST_USER_GENERATOR: QueryConfig = QueryConfig::new()
        .field(FieldConfig::new_number_field::<i32>("id", None))
        .field(FieldConfig::new_string_field("username", None))
        .field(FieldConfig::new_string_field("email", None))
        .field(FieldConfig::new_string_field("nickname", None))
        .field(FieldConfig::new_number_field::<bool>("blocked", None))
        .field(FieldConfig::new_date_time_field("created_at", None))
        .field(FieldConfig::new_date_time_field("updated_at", None))
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
    app_data: web::Data<AppState>,
    request: ValidatedQuery<ListUserRequest>,
    auth: Auth,
) -> ApiResult<ListUserResponse> {
    auth.try_permission("user", "list")?;
    let users = process_query(&LIST_USER_GENERATOR,
                              &request.before, &request.after, &request.size,
                              &request.sort, request.desc, &request.query,
                              vec!["(NOT \"user\".deleted AND user_role.user = \"user\".id AND \
                                  user_role.role = role.id AND NOT role.deleted)".into()],
                              "\"user\".id, username, email, nickname, avatar, avatar128, \
                                  blocked, \"user\".created_at, \"user\".updated_at",
                              "\"user\", user_role, role", app_data.clone()).await?.iter()
        .map(UserWithoutRoles::from)
        .collect::<Vec<_>>();
    let users = app_data.query.user
        .add_roles(&*app_data.db.read().await, users)
        .await
        .map_err(|e| internal_server_error!(e))?;
    let results = users.into_iter()
        .map(|user| { UserCursor::try_from_user(User::All(user), &request.sort) })
        .collect::<Result<Vec<_>, _>>()?;
    respond(ListUserResponse { results })
}

pub fn users_api(state: &web::Data<AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    if let Err(e) = std::fs::create_dir_all(Path::new(&state.config.media.root)
        .join(crate::constants::AVATAR_FOLDER))  {
        error!("failed to create directory {}", e);
    }
    let state = state.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("registrations")
                .app_data(state.clone())
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
                .route("/{reg_id}/confirm", web::post().to(confirm_registration))
                .route("/{reg_id}/resend", web::post().to(resend_registration_email))
                .route("/{reg_id}", web::get().to(query_registration))
                .route("", web::post().to(register_user))
        ).service(
            web::scope("email-updating")
                .app_data(state.clone())
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
                .route("/{update_id}/confirm", web::post().to(confirm_email_updating))
                .route("/{update_id}/resend", web::post().to(resend_email_updating_email))
                .route("/{update_id}", web::get().to(query_email_updating))
                .route("", web::post().to(update_user_email))
        ).service(
            web::scope("email-updating-others")
                .app_data(state.clone())
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
                .route("/{update_id}/confirm", web::post().to(confirm_email_updating_for_others))
                .route("/{update_id}/resend", web::post().to(resend_email_updating_email_for_others))
                .route("/{update_id}", web::get().to(query_email_updating_for_others))
        ).service(
            web::scope("users")
                .app_data(state.clone())
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
                .route("/check-username-existence", web::get().to(check_username_existence))
                .route("/check-email-existence", web::get().to(check_email_existence))
                .service(
                    web::scope("/me/avatar")
                        .app_data(state.clone())
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
                        .app_data(state.clone())
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
                .app_data(state.clone())
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
                .route("/{uid}", web::get().to(read_user_public))
                // .route("", web::get().to(index))
        );
    })
}