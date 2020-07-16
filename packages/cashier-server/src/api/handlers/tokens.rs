use crate::{
    api::{
        extractors::{
            auth::Auth,
            config::{
                default_json_config,
                default_path_config,
                default_query_config,
            },
        },
        errors::{ApiError, ApiResult, respond},
        app_state::AppState,
        fields::{
            Username,
            Password,
            Email,
            Cursor as CursorField,
            Id,
            PaginationSize,
        },
    },
    queries::{
        tokens::{Token, TokenCursor},
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
use actix_web_validator::{ValidatedJson, ValidatedPath, ValidatedQuery};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use validator::Validate;
use validator_derive::Validate;
use cashier_query::generator::{QueryConfig, FieldConfig};
use chrono::{DateTime, NaiveDateTime, Utc};
use crate::api::cursor::process_query;
use crate::queries::tokens::TokenIdUser;

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
                          &data.password[..])
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
                          &data.password[..])
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
        .revoke_token(&*app_data.db.read().await, claims.jti, None)
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

#[derive(Debug, Validate, Deserialize)]
struct ListTokenRequest {
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
struct ListTokenResponse {
    results: Vec<TokenCursor>,
}

lazy_static! {
    static ref LIST_TOKEN_FOR_ME_GENERATOR: QueryConfig = QueryConfig::new()
        .field(FieldConfig::new_number_field::<i32>("id", None))
        .field(FieldConfig::new_date_time_field("issued_at", None))
        .field(FieldConfig::new_date_time_field("expires_at", None))
        .field(FieldConfig::new_string_field("acquire_method", None))
        .field(FieldConfig::new_string_field("acquire_host", None))
        .field(FieldConfig::new_string_field("acquire_remote", None))
        .field(FieldConfig::new_string_field("acquire_user_agent", None));
    static ref LIST_TOKEN_GENERATOR: QueryConfig = QueryConfig::new()
        .field(FieldConfig::new_number_field::<i32>("id", None))
        .field(FieldConfig::new_number_field::<i32>("user", Some("\"user\"".into())))
        .field(FieldConfig::new_date_time_field("issued_at", None))
        .field(FieldConfig::new_date_time_field("expires_at", None))
        .field(FieldConfig::new_string_field("acquire_method", None))
        .field(FieldConfig::new_string_field("acquire_host", None))
        .field(FieldConfig::new_string_field("acquire_remote", None))
        .field(FieldConfig::new_string_field("acquire_user_agent", None));
}

async fn list_token_for_me(
    app_data: web::Data<AppState>,
    request: ValidatedQuery<ListTokenRequest>,
    auth: Auth,
) -> ApiResult<ListTokenResponse> {
    auth.try_permission("token", "list-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let results = process_query(&LIST_TOKEN_FOR_ME_GENERATOR,
                                &request.before, &request.after, &request.size,
                                &request.sort, request.desc, &request.query,
                                vec!["NOT revoked".into(), format!("\"user\" = {}", uid)],
                                "id, \"user\", issued_at, expires_at, acquire_method, \
                                    acquire_host, acquire_remote, acquire_user_agent",
                                "token", app_data).await?.iter()
        .map(|row| {
            TokenCursor::try_from_token(Token::from(row), &request.sort)
        })
        .collect::<Result<Vec<_>, _>>()?;
    respond(ListTokenResponse { results })
}

async fn list_token(
    app_data: web::Data<AppState>,
    request: ValidatedQuery<ListTokenRequest>,
    auth: Auth,
) -> ApiResult<ListTokenResponse> {
    auth.try_permission("token", "list")?;
    let results = process_query(&LIST_TOKEN_GENERATOR,
                                &request.before, &request.after, &request.size,
                                &request.sort, request.desc, &request.query,
                                vec!["NOT revoked".into()],
                                "id, \"user\", issued_at, expires_at, acquire_method, \
                                    acquire_host, acquire_remote, acquire_user_agent",
                                "token", app_data).await?.iter()
        .map(|row| {
            TokenCursor::try_from_token(Token::from(row), &request.sort)
        })
        .collect::<Result<Vec<_>, _>>()?;
    respond(ListTokenResponse { results })
}

#[derive(Debug, Deserialize, Validate)]
struct RevokeTokenRequest {
    #[serde(default)]
    query: String,
}

#[derive(Debug, Serialize)]
struct RevokeTokenResponse {
    count: usize,
}

async fn revoke_token_impl(
    app_data: web::Data<AppState>,
    auth: Auth,
    query: &str,
    uid: Option<i32>,
) -> ApiResult<RevokeTokenResponse> {
    let mut conditions = vec![
        "NOT revoked".into(),
    ];
    match uid.as_ref() {
        Some(uid) => {
            conditions.push(LIST_TOKEN_FOR_ME_GENERATOR.parse_to_postgres(&query)?);
            conditions.push(format!("\"user\" = {}", uid));
        },
        None => {
            conditions.push(LIST_TOKEN_GENERATOR.parse_to_postgres(&query)?);
        }
    }
    let condition = conditions.join(" AND ");
    let statement = format!("UPDATE token SET revoked = true \
                                   WHERE {} \
                                   RETURNING id, \"user\"", condition);
    let rows = app_data.db.read().await
        .query(&statement[..], &[])
        .await
        .map_err(|e| internal_server_error!(e))?;
    let results = rows.iter()
        .map(|row| TokenIdUser {
            id: row.get("id"),
            user: row.get("user"),
        })
        .collect::<Vec<_>>();
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

async fn revoke_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
    request: ValidatedQuery<RevokeTokenRequest>,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    revoke_token_impl(app_data, auth, &request.query, Some(uid)).await
}

async fn revoke_token(
    app_data: web::Data<AppState>,
    auth: Auth,
    request: ValidatedQuery<RevokeTokenRequest>,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke")?;
    revoke_token_impl(app_data, auth, &request.query, None).await
}

#[derive(Debug, Validate, Deserialize)]
struct JtiPath {
    #[validate]
    jti: Id,
}

async fn revoke_single_token_impl(
    app_data: web::Data<AppState>,
    auth: Auth,
    jti: i32,
    uid: Option<i32>,
) -> ApiResult<()> {
    let result = app_data.query.token
        .revoke_token(&*app_data.db.read().await, jti, uid)
        .await
        .map_err(|err| match err {
            QueryError::TokenNotFound => ApiError::TokenNotFound,
            e => internal_server_error!(e),
        })?;
    app_data.send(TokenRevoked {
        jti: result.id,
        uid: result.user,
    }, &auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn revoke_single_token(
    app_data: web::Data<AppState>,
    jti_path: ValidatedPath<JtiPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("token", "revoke-single")?;
    revoke_single_token_impl(app_data, auth, jti_path.jti.clone().into(), None).await
}

async fn revoke_single_token_for_me(
    app_data: web::Data<AppState>,
    jti_path: ValidatedPath<JtiPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("token", "revoke-single")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    revoke_single_token_impl(app_data, auth, jti_path.jti.clone().into(), Some(uid)).await
}

async fn revoke_this_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("token", "revoke-single")?;
    let claims = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?;
    let jti = claims.jti;
    let uid = claims.uid;
    revoke_single_token_impl(app_data, auth, jti, Some(uid)).await
}

pub fn tokens_api(state: &web::Data<AppState>) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let state = state.clone();
    Box::new(move |cfg| {
        cfg
            .service(
                web::scope("tokens")
                    .app_data(state.clone())
                    .app_data(default_json_config())
                    .app_data(default_path_config())
                    .app_data(default_query_config())
                    .route("/acquire-by-username", web::post().to(acquire_token_by_username))
                    .route("/acquire-by-email", web::post().to(acquire_token_by_email))
                    .route("/resume", web::post().to(resume_token))
                    // .route("/{jti}", web::get().to(read_token_by_jti))
                    .route("/{jti}", web::delete().to(revoke_single_token))
                    .route("", web::get().to(list_token))
                    .route("", web::delete().to(revoke_token))
            )
            .service(
                web::scope("my-tokens")
                    .app_data(state.clone())
                    .app_data(default_json_config())
                    .app_data(default_path_config())
                    .app_data(default_query_config())
                    // .route("/this", web::get().to(read_token_by_jti))
                    .route("/this", web::delete().to(revoke_this_token_for_me))
                    // .route("/{jti}", web::get().to(read_token_for_me_by_jti))
                    .route("/{jti}", web::delete().to(revoke_single_token_for_me))
                    .route("", web::get().to(list_token_for_me))
                    .route("", web::delete().to(revoke_token_for_me))
            );
    })
}
