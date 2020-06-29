use crate::{
    api::{
        extractors::{
            auth::Auth,
            multer::Multer,
            config::{
                default_json_config,
                default_path_config,
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
            PopulateUser,
            PopulateRole,
            PopulatePermission,
        },
    },
    queries::{
        errors::Error as QueryError,
        users::{
            UserAccessLevel, RoleAccessLevel, PermissionAccessLevel,
            User, Role, Permission,
        },
    },
    websocket::push_messages::{UserCreated, UserUpdated},
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
        let origin_filename = filename.clone() + ".png";
        cropped_avatar.save_with_format(join_avatar_file(&root, &origin_filename),
                                        image::ImageFormat::Png)?;
        let thumbnail_filename = if size <= 128 { None } else {
            let thumbnail = cropped_avatar.resize(128, 128,image::imageops::FilterType::Triangle);
            let thumbnail_filename = filename + ".thumb.png";
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
        updated_at: Some(updated_at),
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

#[derive(Deserialize, Validate, Debug)]
struct ReadUserQuery {
    #[serde(flatten, default)]
    populate_user: Option<PopulateUser>,
    #[serde(flatten, default)]
    populate_role: Option<PopulateRole>,
    #[serde(flatten, default)]
    populate_permission: Option<PopulatePermission>,
}

struct ReadUserQueryDecoded {
    populate_user: UserAccessLevel,
    populate_role: Option<RoleAccessLevel>,
    populate_permission: Option<PermissionAccessLevel>,
}

impl From<ReadUserQuery> for ReadUserQueryDecoded {
    fn from(request: ReadUserQuery) -> Self {
        Self {
            populate_user: request.populate_user.clone()
                .map(UserAccessLevel::from)
                .unwrap_or(UserAccessLevel::WithoutRoles),
            populate_role: request.populate_role.clone()
                .map(RoleAccessLevel::from),
            populate_permission: request.populate_permission
                .map(PermissionAccessLevel::from),
        }
    }
}

#[derive(Serialize, Debug)]
struct ReadUserResponse {
    user: User,
    roles: Vec<Role>,
    permissions: Vec<Permission>,
}

async fn read_user_impl(
    app_data: web::Data<AppState>,
    request: ReadUserQueryDecoded,
    uid: i32,
) -> ApiResult<ReadUserResponse> {
    let (mut user, roles, permissions) = app_data.query.user
        .find_one_with_permissions_and_roles(
            &mut *app_data.db.write().await, uid, request.populate_user,
            request.populate_role, request.populate_permission,
        )
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    let media_url = &app_data.config.media.url;
    user.map_avatars(|x| join_avatar_url(media_url, x));
    respond(ReadUserResponse {
        user,
        roles,
        permissions,
    })
}

async fn read_user_for_me(
    app_data: web::Data<AppState>,
    request: ValidatedQuery<ReadUserQuery>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    let request: ReadUserQueryDecoded = request.into_inner().into();
    match request.populate_user {
        UserAccessLevel::All => auth.try_permission("user", "read")?,
        UserAccessLevel::WithoutRoles | UserAccessLevel::Public =>
            if !auth.has_permission("user", "read") {
                auth.try_permission("user", "read-self")?;
            },
    }
    if request.populate_role.is_some() {
        auth.try_permission("role", "read")?;
    }
    if request.populate_permission.is_some() {
        auth.try_permission("permission", "read")?;
    }
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    read_user_impl(app_data, request, uid).await
}

async fn read_user(
    app_data: web::Data<AppState>,
    request: ValidatedQuery<ReadUserQuery>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<ReadUserResponse> {
    let request: ReadUserQueryDecoded = request.into_inner().into();
    match request.populate_user {
        UserAccessLevel::All | UserAccessLevel::WithoutRoles =>
            auth.try_permission("user", "read")?,
        UserAccessLevel::Public =>
            if !auth.has_permission("user", "read") {
                auth.try_permission("user-public", "read")?;
            }
    }
    if request.populate_role.is_some() {
        auth.try_permission("role", "read")?;
    }
    if request.populate_permission.is_some() {
        auth.try_permission("permission", "read")?;
    }
    let uid = uid_path.uid.clone().into();
    read_user_impl(app_data, request, uid).await
}

pub fn users_api(state: &web::Data<AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    if let Err(e) = std::fs::create_dir_all(Path::new(&state.config.media.root)
        .join(crate::constants::AVATAR_FOLDER))  {
        error!("failed to create directory {}", e);
    }
    let state = state.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("users")
                .app_data(state.clone())
                .app_data(default_json_config())
                // .route("/public", web::get().to(index))
                // .route("/me/password", web::post().to(index))
                .service(
                    web::scope("/me/avatar")
                        .app_data(state.clone())
                        .app_data(default_path_config())
                        .app_data(avatar_multer_config())
                        .route("", web::post().to(upload_avatar_for_me))
                )
                // .route("/me/roles", web::get().to(index))
                .route("/me", web::get().to(read_user_for_me))
                // .route("/me", web::patch().to(index))
                // .route("/me", web::delete().to(index))
                // .route("/{uid}/password", web::post().to(index))
                .service(
                    web::scope("/{uid}/avatar")
                        .app_data(state)
                        .app_data(default_path_config())
                        .app_data(avatar_multer_config())
                        .route("", web::post().to(upload_avatar))
                )
                // .route("/{uid}/roles", web::get().to(index))
                .route("/{uid}", web::get().to(read_user))
                // .route("/{uid}", web::patch().to(index))
                // .route("/{uid}", web::delete().to(index))
                .route("", web::post().to(create_user))
                // .route("", web::get().to(index))
        );
    })
}