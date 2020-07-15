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
        cursor::Cursor,
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
use actix_web_validator::{ValidatedJson, ValidatedPath, ValidatedQuery};
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use validator::Validate;
use validator_derive::Validate;
use cashier_query::generator::{QueryConfig, FieldConfig};
use chrono::{DateTime, NaiveDateTime, Utc};
use crate::api::cursor::PrimaryCursor;

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
struct ListTokenForMeRequest {
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
struct TokenCursor {
    token: Token,
    cursor: String,
}

#[derive(Debug, Serialize)]
struct ListTokenResponse {
    results: Vec<TokenCursor>,
}

lazy_static! {
    pub static ref LIST_TOKEN_FOR_ME_GENERATOR: QueryConfig = QueryConfig::new()
        .field(FieldConfig::new_number_field::<i32>("id", None))
        .field(FieldConfig::new_date_time_field("issued_at", None))
        .field(FieldConfig::new_date_time_field("expires_at", None))
        .field(FieldConfig::new_string_field("acquire_method", None))
        .field(FieldConfig::new_string_field("acquire_host", None))
        .field(FieldConfig::new_string_field("acquire_remote", None))
        .field(FieldConfig::new_string_field("acquire_user_agent", None));
}

async fn list_token_for_me(
    app_data: web::Data<AppState>,
    request: ValidatedQuery<ListTokenForMeRequest>,
    auth: Auth,
) -> ApiResult<ListTokenResponse> {
    auth.try_permission("token", "list-self")?;
    let _uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    if request.before.is_some() && request.after.is_some() {
        return Err(ApiError::QueryError {
            error: "".into(),
        });
    }
    let direction = if request.before.is_some() == request.desc { "ASC" } else { "DESC" };
    let order_by = match request.sort.clone() {
        Some(sort) => format!("{} {}, id {}",
                              LIST_TOKEN_FOR_ME_GENERATOR.check_sortable(&sort)?,
                              direction, direction),
        None => format!("id {}", direction),
    };
    let mut condition = vec![
        "NOT revoked".into(),
        LIST_TOKEN_FOR_ME_GENERATOR.parse_to_postgres(&request.query)?,
    ];
    if let Some(before) = request.before.clone() {
        let before = Cursor::try_from_str(&before[..])?;
        before.check_key(&request.sort)?;
        condition.push(before.to_sql(&LIST_TOKEN_FOR_ME_GENERATOR, request.desc)?)
    }
    if let Some(after) = request.after.clone() {
        let after = Cursor::try_from_str(&after[..])?;
        after.check_key(&request.sort)?;
        condition.push(after.to_sql(&LIST_TOKEN_FOR_ME_GENERATOR, !request.desc)?)
    }
    let condition = condition.join(" AND ");
    let statement = format!(
        "SELECT id, \"user\", issued_at, expires_at, acquire_method, \
                acquire_host, acquire_remote, acquire_user_agent FROM token \
        WHERE {} ORDER BY {} LIMIT {}", condition, order_by, usize::from(request.size.clone()));
    println!("{}", statement);
    let rows = app_data.db.read().await
        .query(&statement[..], &[])
        .await
        .map_err(|e| internal_server_error!(e))?;
    let mut results = rows.iter()
        .map(|row| {
            let token = Token::from(row);
            let cursor = Cursor::new(token.id.to_string(), match request.sort.as_ref().map(|x| &x[..]) {
                Some(field) => match field {
                    "id" => Some(PrimaryCursor { k: "id".into(), v: Some(token.id.to_string()) }),
                    "issued_at" => Some(PrimaryCursor { k: "issued_at".into(),
                        v: Some(token.issued_at.to_rfc3339()) }),
                    "expires_at" => Some(PrimaryCursor { k: "expires_at".into(),
                        v: Some(token.expires_at.to_rfc3339()) }),
                    "acquire_method" => Some(PrimaryCursor { k: "acquire_method".into(),
                        v: Some(token.acquire_method.clone()) }),
                    "acquire_host" => Some(PrimaryCursor { k: "acquire_host".into(),
                        v: Some(token.acquire_host.clone()) }),
                    "acquire_remote" => Some(PrimaryCursor { k: "acquire_remote".into(),
                        v: token.acquire_remote.clone() }),
                    "acquire_user_agent" => Some(PrimaryCursor { k: "acquire_user_agent".into(),
                        v: token.acquire_user_agent.clone() }),
                    _ => None
                },
                _ => None,
            });
            cursor.try_to_str()
                .map(|cursor| TokenCursor {
                    token,
                    cursor,
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if request.before.is_some() {
        results.reverse();
    }
    respond(ListTokenResponse { results })
}

#[derive(Debug, Serialize)]
struct RevokeTokenResponse {
    count: usize,
}

async fn revoke_token_by_user_impl(
    app_data: web::Data<AppState>,
    auth: Auth,
    uid: i32,
) -> ApiResult<RevokeTokenResponse> {
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

async fn revoke_token_for_me(
    app_data: web::Data<AppState>,
    auth: Auth,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    revoke_token_by_user_impl(app_data, auth, uid).await
}

#[derive(Debug, Validate, Deserialize)]
struct UidPath {
    #[validate]
    uid: Id,
}

async fn revoke_token_for_someone(
    app_data: web::Data<AppState>,
    auth: Auth,
    uid_path: ValidatedPath<UidPath>,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke")?;
    let uid = uid_path.uid.clone().into();
    revoke_token_by_user_impl(app_data, auth, uid).await
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
        cfg.service(
            web::scope("/tokens")
                .app_data(state)
                .app_data(default_json_config())
                .app_data(default_path_config())
                .app_data(default_query_config())
                .route("/acquire-by-username", web::post().to(acquire_token_by_username))
                .route("/acquire-by-email", web::post().to(acquire_token_by_email))
                .route("/resume", web::post().to(resume_token))
                .route("/users/me", web::get().to(list_token_for_me))
                .route("/users/me", web::delete().to(revoke_token_for_me))
                // .route("/users/{uid}", web::get().to(list_token_by_uid))
                .route("/users/{uid}", web::delete().to(revoke_token_for_someone))
                // .route("/jwt/{jti}", web::get().to(read_token_by_jti))
                .route("/jwt/{jti}", web::delete().to(revoke_single_token))
                // .route("/my-jwt/this", web::get().to(read_token_by_jti))
                .route("/my-jwt/this", web::delete().to(revoke_this_token_for_me))
                // .route("/my-jwt/{jti}", web::get().to(read_token_for_me_by_jti))
                .route("/my-jwt/{jti}", web::delete().to(revoke_single_token_for_me))
        );
    })
}
