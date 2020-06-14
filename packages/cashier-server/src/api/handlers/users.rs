use crate::{
    api::{
        extractors::{
            auth::Auth,
            json::Json,
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
    data: Json<CreateUserRequest>,
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

pub fn users_api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("users")
            // .route("/default/permissions", web::get().to(index))
            .service(
                web::scope("/public")
                    // .route("/{id}", web::get().to(index))
                    // .route("/", web::get().to(index))
            )
            .service(
                web::scope("/me")
                    // .route("/password", web::post().to(index))
                    // .route("/avatar", web::post().to(index))
                    // .route("/permissions", web::get().to(index))
                    // .route("", web::get().to(index))
                    // .route("", web::patch().to(index))
                    // .route("", web::delete().to(index))
            )
            .service(
                web::scope("/{id}")
                    // .route("/password", web::post().to(index))
                    // .route("/avatar", web::post().to(index))
                    // .route("/permissions", web::get().to(index))
                    // .route("", web::get().to(index))
                    // .route("", web::patch().to(index))
                    // .route("", web::delete().to(index))
            )
            .route("", web::post().to(create_user))
            // .route("", web::get().to(index))
    );
}