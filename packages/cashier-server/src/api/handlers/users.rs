use crate::{
    api::{
        extractors::{
            auth::Auth,
            config::default_json_config,
        },
        errors::{ApiError, ApiResult, respond},
        app_state::AppState,
        fields::{
            Username,
            Password,
            Email,
            RoleName,
            Nickname,
        },
    },
    queries::{
        errors::Error as QueryError,
    },
    internal_server_error,
};
use actix_web::web;
use actix_web_validator::{ValidatedJson, JsonConfig};
use serde::{Serialize, Deserialize};
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

pub fn users_api(state: &web::Data<AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let state = state.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("users")
                .app_data(state)
                .app_data(default_json_config(JsonConfig::default()))
                // .route("/default/permissions", web::get().to(index))
                // .route("/public/{id}", web::get().to(index))
                // .route("/public", web::get().to(index))
                // .route("/me/password", web::post().to(index))
                // .route("/me/avatar", web::post().to(index))
                // .route("/me/permissions", web::get().to(index))
                // .route("/me", web::get().to(index))
                // .route("/me", web::patch().to(index))
                // .route("/me", web::delete().to(index))
                // .route("/{id}/password", web::post().to(index))
                // .route("/{id}/avatar", web::post().to(index))
                // .route("/{id}/permissions", web::get().to(index))
                // .route("/{id}", web::get().to(index))
                // .route("/{id}", web::patch().to(index))
                // .route("/{id}", web::delete().to(index))
                .route("", web::post().to(create_user))
                // .route("", web::get().to(index))
        );
    })
}