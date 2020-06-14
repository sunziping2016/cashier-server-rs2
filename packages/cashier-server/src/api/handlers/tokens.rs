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
        },
    },
    queries::{
        tokens::Token,
        errors::Error as QueryError,
        users::EitherUsernameOrEmail,
    },
    internal_server_error,
};
use actix_web::{
    web,
    http::HeaderValue,
};
use serde::{Serialize, Deserialize};
use validator::Validate;
use validator_derive::Validate;

#[derive(Debug, Serialize)]
struct AcquireTokenResponse {
    jwt: String,
}

#[derive(Debug, Validate, Deserialize)]
struct AcquireTokenByUsernameRequest {
    #[validate]
    username: Username,
    #[validate]
    password: Password,
}

//noinspection RsTypeCheck,RsTypeCheck,RsTypeCheck
async fn acquire_token_by_username(
    app_data: web::Data<AppState>,
    data: Json<AcquireTokenByUsernameRequest>,
    auth: Auth,
    req: web::HttpRequest,
) -> ApiResult<AcquireTokenResponse> {
    auth.try_permission("token", "acquire-by-username")?;
    let uid = app_data.query.user
        .check_user_valid(&*app_data.db.read().await,
                          &EitherUsernameOrEmail::Username(data.username.clone().into()),
                          &data.password)
        .await
        .map_err(|e| match e {
            QueryError::UserNotFound | QueryError::WrongPassword => ApiError::WrongUserOrPassword,
            QueryError::UserBlocked => ApiError::UserBlocked,
            _ => { internal_server_error!(e) }
        })?;
    let connection_info = req.connection_info();
    let (jwt, _) = app_data.query.token
        .create_token(&*app_data.db.read().await, uid, "username",
                      connection_info.host(), connection_info.remote(),
                      req.headers().get("User-Agent")
                          .map(HeaderValue::to_str)
                          .map(std::result::Result::ok)
                          .flatten())
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(AcquireTokenResponse {
        jwt,
    })
}

#[derive(Debug, Validate, Deserialize)]
struct AcquireTokenByEmailRequest {
    #[validate]
    email: Email,
    #[validate]
    password: Password,
}

//noinspection ALL
async fn acquire_token_by_email(
    app_data: web::Data<AppState>,
    data: Json<AcquireTokenByEmailRequest>,
    auth: Auth,
    req: web::HttpRequest,
) -> ApiResult<AcquireTokenResponse> {
    auth.try_permission("token", "acquire-by-email")?;
    let uid = app_data.query.user
        .check_user_valid(&*app_data.db.read().await,
                          &EitherUsernameOrEmail::Email(data.email.clone().into()),
                          &data.password)
        .await
        .map_err(|e| match e {
            QueryError::UserNotFound | QueryError::WrongPassword => ApiError::WrongUserOrPassword,
            QueryError::UserBlocked => ApiError::UserBlocked,
            _ => { internal_server_error!(e) }
        })?;
    let connection_info = req.connection_info();
    let (jwt, _) = app_data.query.token
        .create_token(&*app_data.db.read().await, uid, "email",
                      connection_info.host(), connection_info.remote(),
                      req.headers().get("User-Agent")
                          .map(HeaderValue::to_str)
                          .map(std::result::Result::ok)
                          .flatten())
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(AcquireTokenResponse {
        jwt,
    })
}

async fn resume_token(
    app_data: web::Data<AppState>,
    auth: Auth,
    req: web::HttpRequest,
) -> ApiResult<AcquireTokenResponse> {
    auth.try_permission("token", "resume")?;
    let claims = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?;
    let connection_info = req.connection_info();
    app_data.query.token
        .revoke_token(&*app_data.db.read().await, claims.jti)
        .await
        .map_err(|e| internal_server_error!(e))?;
    let (jwt, _) = app_data.query.token
        .create_token(&*app_data.db.read().await, claims.uid, "resume",
                      connection_info.host(), connection_info.remote(),
                      req.headers().get("User-Agent")
                          .map(HeaderValue::to_str)
                          .map(std::result::Result::ok)
                          .flatten())
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(AcquireTokenResponse {
        jwt,
    })
}

#[derive(Debug, Serialize)]
struct ListTokenResponse {
    tokens: Vec<Token>,
}

async fn list_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<ListTokenResponse> {
    auth.try_permission("token", "list-self")?;
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let tokens = app_data.query.token
        .find_tokens_from_user(&*app_data.db.read().await, uid)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(ListTokenResponse {
        tokens,
    })
}

#[derive(Debug, Serialize)]
struct RevokeTokenResponse {
    count: u64,
}

async fn revoke_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke-self")?;
    let uid = auth.claims.ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let count = app_data.query.token
        .revoke_tokens_from_user(&*app_data.db.read().await, uid)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(RevokeTokenResponse {
        count
    })
}


pub fn tokens_api(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/tokens")
            .route("/acquire-by-username", web::post().to(acquire_token_by_username))
            .route("/acquire-by-email", web::post().to(acquire_token_by_email))
            .route("/resume", web::post().to(resume_token))
            .service(
                web::scope("/users")
                    .route("/me", web::get().to(list_token_for_me))
                    .route("/me", web::delete().to(revoke_token_for_me))
                    // .route("/{uid}", web::get().to(list_token_by_uid))
                    // .route("/{uid}", web::delete().to(revoke_token_by_uid))
            )
            .service(
                web::scope("/jwt")
                    // .route("/{jti}", web::get().to(read_token_by_jti))
                    // .route("/{jti}", web::delete().to(revoke_token_by_jti))
            )
            .service(
                web::scope("/my-jwt")
                    // .route("/{jti}", web::get().to(read_token_for_me_by_jti))
                    // .route("/{jti}", web::delete().to(revoke_token_for_me_by_jti))
            )
    );
}