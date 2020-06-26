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
        },
    },
    queries::{
        tokens::Token,
        errors::Error as QueryError,
        users::EitherUsernameOrEmail,
    },
    websocket::push_messages::{TokenAcquired, TokenRevoked},
    internal_server_error,
};
use actix_web::{
    web,
    http::HeaderValue,
};
use actix_web_validator::ValidatedJson;
use serde::{Serialize, Deserialize};
use validator::Validate;
use validator_derive::Validate;
use chrono::{DateTime, NaiveDateTime, Utc};

#[derive(Debug, Serialize)]
struct AcquireTokenResponse {
    jwt: String,
}

#[derive(Debug, Validate, Deserialize)]
pub struct AcquireTokenByUsernameRequest {
    #[validate]
    username: Username,
    #[validate]
    password: Password,
}

async fn acquire_token_impl_impl(
    app_data: &web::Data<AppState>,
    req: &web::HttpRequest,
    uid: i32,
    method: &str,
) -> std::result::Result<(AcquireTokenResponse, TokenAcquired), ApiError> {
    let connection_info = req.connection_info();
    let user_agent = req.headers().get("User-Agent")
        .map(HeaderValue::to_str)
        .map(std::result::Result::ok)
        .flatten();
    let (jwt, claims) = app_data.query.token
        .create_token(&*app_data.db.read().await, uid, method,
                      connection_info.host(), connection_info.remote(),
                      user_agent)
        .await
        .map_err(|e| internal_server_error!(e))?;
    Ok((AcquireTokenResponse {
        jwt,
    }, TokenAcquired(Token {
        id: claims.jti,
        user: uid,
        issued_at: DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(claims.iat, 0), Utc),
        expires_at: DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(claims.exp, 0), Utc),
        acquire_method: "username".into(),
        acquire_host: connection_info.host().into(),
        acquire_remote: connection_info.remote().map(String::from),
        acquire_user_agent: user_agent.map(String::from),
    })))
}

async fn acquire_token_impl(
    app_data: &web::Data<AppState>,
    req: &web::HttpRequest,
    auth: &Auth,
    uid: i32,
    method: &str,
) -> ApiResult<AcquireTokenResponse> {
    let (response, msg) = acquire_token_impl_impl(
        app_data, req, uid, method).await?;
    app_data.send(msg, auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(response)
}

async fn acquire_token_by_username(
    app_data: web::Data<AppState>,
    data: ValidatedJson<AcquireTokenByUsernameRequest>,
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
    acquire_token_impl(&app_data, &req, &auth, uid, "username")
        .await
}

#[derive(Debug, Validate, Deserialize)]
pub struct AcquireTokenByEmailRequest {
    #[validate]
    email: Email,
    #[validate]
    password: Password,
}

async fn acquire_token_by_email(
    app_data: web::Data<AppState>,
    data: ValidatedJson<AcquireTokenByEmailRequest>,
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
    acquire_token_impl(&app_data, &req, &auth, uid, "email").await
}

async fn resume_token(
    app_data: web::Data<AppState>,
    auth: Auth,
    req: web::HttpRequest,
) -> ApiResult<AcquireTokenResponse> {
    auth.try_permission("token", "resume")?;
    let claims = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?;
    app_data.query.token
        .revoke_token(&*app_data.db.read().await, claims.jti)
        .await
        .map_err(|e| internal_server_error!(e))?;
    let (response, msg) = acquire_token_impl_impl(
        &app_data, &req, claims.uid, "resume").await?;
    app_data.send_all(vec![
        TokenRevoked {
            jti: claims.jti,
            uid: claims.uid,
        }.into(),
        msg.into(),
    ], &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(response)
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
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
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
    count: usize,
}

async fn revoke_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let results = app_data.query.token
        .revoke_tokens_from_user(&*app_data.db.read().await, uid)
        .await
        .map_err(|e| internal_server_error!(e))?;
    let count = results.len();
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
    respond(RevokeTokenResponse {
        count
    })
}


pub fn tokens_api(state: &web::Data<AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let state = state.clone();
    Box::new(move |cfg| {
        cfg.service(
            web::scope("/tokens")
                .app_data(state)
                .app_data(default_json_config())
                .route("/acquire-by-username", web::post().to(acquire_token_by_username))
                .route("/acquire-by-email", web::post().to(acquire_token_by_email))
                .route("/resume", web::post().to(resume_token))
                .route("/users/me", web::get().to(list_token_for_me))
                .route("/users/me", web::delete().to(revoke_token_for_me))
                // .route("/users/{uid}", web::get().to(list_token_by_uid))
                // .route("/users/{uid}", web::delete().to(revoke_token_by_uid))
                // .route("/jwt/{jti}", web::get().to(read_token_by_jti))
                // .route("/jwt/{jti}", web::delete().to(revoke_token_by_jti))
                // .route("/my-jwt/{jti}", web::get().to(read_token_for_me_by_jti))
                // .route("/my-jwt/{jti}", web::delete().to(revoke_token_for_me_by_jti))
        );
    })
}
