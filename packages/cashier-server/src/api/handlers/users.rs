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
        },
    },
    queries::{
        errors::Error as QueryError,
        users::User,
    },
    internal_server_error,
};
use actix_web::{
    web::{self, block},
    error::BlockingError,
};
use actix_web_validator::{ValidatedJson, ValidatedPath};
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
}

async fn create_user(
    app_data: web::Data<AppState>,
    data: ValidatedJson<CreateUserRequest>,
    auth: Auth,
) -> ApiResult<CreateUserResponse> {
    auth.try_permission("user", "create")?;
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
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
    let id = app_data.query.user
        .insert_one(&mut *app_data.db.write().await,
                    &data.username[..], &data.password[..], &roles[..],
                    &email, &nickname)
        .await
        .map_err(|err| match err {
            QueryError::DuplicatedUser { field } => ApiError::DuplicatedUser { field },
            e => internal_server_error!(e),
        })?;
    respond(CreateUserResponse {
        id,
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
        let cropped_avatar = if width < height {
            avatar.crop_imm(0, (height - size) / 2, size, size)
        } else if height < width {
            avatar.crop_imm((width - size) / 2, 0, size, size)
        } else {
            avatar
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
            let thumbnail_filename = filename.clone() + ".thumb.png";
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
    if let Err(e) = app_data.query.user
        .update_avatars(&*app_data.db.read().await, uid, &Some(avatar.clone()), &avatar128)
        .await {
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
        return Err(internal_server_error!(e));
    }
    let root = &app_data.config.media.root;
    // Remove old avatars
    if let Some(old_avatar) = old_avatars.avatar.as_ref() {
        remove_avatar_file(root, old_avatar);
    }
    if let Some(old_avatar128) = old_avatars.avatar128.as_ref() {
        remove_avatar_file(root, old_avatar128);
    }
    let url = &app_data.config.media.url;
    respond(UploadAvatarResponse {
        avatar: join_avatar_url(url, &avatar),
        avatar128: avatar128.map(|x| join_avatar_url(url, &x)),
    })
}

async fn upload_avatar_for_me(
    app_data: web::Data<AppState>,
    data: Multer,
    auth: Auth,
) -> ApiResult<UploadAvatarResponse> {
    auth.try_permission("user-avatar", "update-self")?;
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    upload_avatar_impl(app_data, uid, data).await
}

async fn upload_avatar(
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    data: Multer,
    auth: Auth,
) -> ApiResult<UploadAvatarResponse> {
    auth.try_permission("user-avatar", "update")?;
    let uid = uid_path.uid.clone().into();
    upload_avatar_impl(app_data, uid, data).await
}

async fn read_user_impl(
    app_data: web::Data<AppState>,
    uid: i32,
) -> ApiResult<User> {
    let mut user = app_data.query.user
        .find_one(&*app_data.db.read().await, uid)
        .await
        .map_err(|err| match err {
            QueryError::UserNotFound => ApiError::UserNotFound,
            e => internal_server_error!(e),
        })?;
    let media_url = &app_data.config.media.url;
    user.avatar = user.avatar.as_ref().map(|x| join_avatar_url(media_url, x));
    user.avatar128 = user.avatar128.as_ref().map(|x| join_avatar_url(media_url, x));
    respond(user)
}

async fn read_user_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<User> {
    auth.try_permission("user", "read-self")?;
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    read_user_impl(app_data, uid).await
}

async fn read_user(
    app_data: web::Data<AppState>,
    uid_path: ValidatedPath<UidPath>,
    auth: Auth,
) -> ApiResult<User> {
    auth.try_permission("user", "read")?;
    let uid = uid_path.uid.clone().into();
    read_user_impl(app_data, uid).await
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
                // .route("/default/permissions", web::get().to(index))
                // .route("/public/{uid}", web::get().to(index))
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
                // .route("/me/permissions", web::get().to(index))
                .route("/me", web::get().to(read_user_for_me))
                // .route("/me", web::patch().to(index))
                // .route("/me", web::delete().to(index))
                // .route("/{uid}/password", web::post().to(index))
                .service(
                    web::scope("/{uid}/avatar")
                        .app_data(state.clone())
                        .app_data(default_path_config())
                        .app_data(avatar_multer_config())
                        .route("", web::post().to(upload_avatar))
                )
                // .route("/{uid}/roles", web::get().to(index))
                // .route("/{uid}/permissions", web::get().to(index))
                .route("/{uid}", web::get().to(read_user))
                // .route("/{uid}", web::patch().to(index))
                // .route("/{uid}", web::delete().to(index))
                .route("", web::post().to(create_user))
                // .route("", web::get().to(index))
        );
    })
}