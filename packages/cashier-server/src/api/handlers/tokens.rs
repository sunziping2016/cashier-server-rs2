use crate::{
    api::{
        extractors::{
            auth::Auth,
        },
        errors::{ApiError, ApiResult, respond},
        app_state::AppDatabase,
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
use crate::api::cursor::{process_query, default_process};
use crate::queries::tokens::TokenIdUser;
use crate::api::extractors::config::default_password_rate_limit;
use crate::api::app_state::{AppSubscriber, AppConfig};
use std::net::{Ipv4Addr, Ipv6Addr};
use geoip::{IpAddr, GeoIp, Options};
use std::path::Path;

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
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    req: &web::HttpRequest,
    uid: i32,
    method: &str,
) -> std::result::Result<(AcquireTokenResponse, TokenAcquired), ApiError> {
    let connection_info = req.connection_info();
    let user_agent = req.headers().get("User-Agent")
        .map(HeaderValue::to_str)
        .map(std::result::Result::ok)
        .flatten();
    let (city_info, as_info) = if let Some(remote) = connection_info.remote() {
        if let Ok(ip) = remote.parse::<Ipv4Addr>() {
            let ip = IpAddr::V4(ip);
            let city_info = config.config.geoip.city.as_ref()
                .map(|x| GeoIp::open(&Path::new(x), Options::MemoryCache).ok())
                .flatten()
                .map(|x| x.city_info_by_ip(ip.clone()))
                .flatten();
            let as_info = config.config.geoip.asn.as_ref()
                .map(|x| GeoIp::open(&Path::new(x), Options::MemoryCache).ok())
                .flatten()
                .map(|x| x.as_info_by_ip(ip.clone()))
                .flatten();
            (city_info, as_info)
        } else if let Ok(ip) = remote.parse::<Ipv6Addr>() {
            let ip = IpAddr::V6(ip);
            let city_info = config.config.geoip.city_v6.as_ref()
                .map(|x| GeoIp::open(&Path::new(x), Options::MemoryCache).ok())
                .flatten()
                .map(|x| x.city_info_by_ip(ip.clone()))
                .flatten();
            let as_info = config.config.geoip.asn_v6.as_ref()
                .map(|x| GeoIp::open(&Path::new(x), Options::MemoryCache).ok())
                .flatten()
                .map(|x| x.as_info_by_ip(ip.clone()))
                .flatten();
            (city_info, as_info)
        } else {
            (None, None)
        }
    } else { (None, None) };
    let (jwt, claims) = database.query.token
        .create_token(&*database.db.read().await, uid, method,
                      connection_info.host(), connection_info.remote(),
                      user_agent, &city_info, &as_info)
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
        acquire_remote_country: city_info.as_ref().map(|x| x.country_code.clone()).flatten(),
        acquire_remote_country_name: city_info.as_ref().map(|x| x.country_name.clone()).flatten(),
        acquire_remote_region: city_info.as_ref().map(|x| x.region.clone()).flatten(),
        acquire_remote_region_name: city_info.as_ref().map(|x| x.city.clone()).flatten(),
        acquire_remote_as_number: as_info.as_ref().map(|x| x.asn),
        acquire_remote_as_name: as_info.as_ref().map(|x| x.name.clone()),
        acquire_user_agent: user_agent.map(String::from),
    })))
}

async fn acquire_token_impl(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    req: &web::HttpRequest,
    auth: &Auth,
    uid: i32,
    method: &str,
) -> ApiResult<AcquireTokenResponse> {
    let (response, msg) = acquire_token_impl_impl(
        config, database, req, uid, method).await?;
    subscriber.send(msg, auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(response)
}

async fn acquire_token_by_username(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    data: ValidatedJson<AcquireTokenByUsernameRequest>,
    auth: Auth,
    req: web::HttpRequest,
) -> ApiResult<AcquireTokenResponse> {
    auth.try_permission("token", "acquire-by-username")?;
    let uid = database.query.user
        .check_user_valid(&*database.db.read().await,
                          &EitherUsernameOrEmail::Username(data.username.clone().into()),
                          &data.password[..])
        .await
        .map_err(|e| match e {
            QueryError::UserNotFound | QueryError::WrongPassword => ApiError::WrongUserOrPassword,
            QueryError::UserBlocked => ApiError::UserBlocked,
            _ => { internal_server_error!(e) }
        })?;
    acquire_token_impl(config, database, subscriber, &req, &auth, uid, "username")
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
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    data: ValidatedJson<AcquireTokenByEmailRequest>,
    auth: Auth,
    req: web::HttpRequest,
) -> ApiResult<AcquireTokenResponse> {
    auth.try_permission("token", "acquire-by-email")?;
    let uid = database.query.user
        .check_user_valid(&*database.db.read().await,
                          &EitherUsernameOrEmail::Email(data.email.clone().into()),
                          &data.password[..])
        .await
        .map_err(|e| match e {
            QueryError::UserNotFound | QueryError::WrongPassword => ApiError::WrongUserOrPassword,
            QueryError::UserBlocked => ApiError::UserBlocked,
            _ => { internal_server_error!(e) }
        })?;
    acquire_token_impl(config, database, subscriber, &req, &auth, uid, "email").await
}

async fn resume_token(
    config: web::Data<AppConfig>,
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: Auth,
    req: web::HttpRequest,
) -> ApiResult<AcquireTokenResponse> {
    auth.try_permission("token", "resume")?;
    let claims = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?;
    database.query.token
        .revoke_token(&*database.db.read().await, claims.jti, None)
        .await
        .map_err(|e| internal_server_error!(e))?;
    let (response, msg) = acquire_token_impl_impl(
        config, database, &req, claims.uid, "resume").await?;
    subscriber.send_all(vec![
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
        .field(FieldConfig::new_date_time_field("issuedAt", Some("issued_at".into())))
        .field(FieldConfig::new_date_time_field("expiresAt", Some("expires_at".into())))
        .field(FieldConfig::new_string_field("acquireMethod", Some("acquire_method".into())))
        .field(FieldConfig::new("acquireHost")
            .rename("acquire_host")
            .partial_equal()
            .partial_order()
            .use_like())
        .field(FieldConfig::new_string_field("acquireRemote", Some("acquire_remote".into())))
        .field(FieldConfig::new_string_field("acquireRemoteCountry", Some("acquire_remote_country".into())))
        .field(FieldConfig::new_string_field("acquireRemoteCountryName", Some("acquire_remote_country_name".into())))
        .field(FieldConfig::new_string_field("acquireRemoteRegion", Some("acquire_remote_region".into())))
        .field(FieldConfig::new_string_field("acquireRemoteRegionName", Some("acquire_remote_region_name".into())))
        .field(FieldConfig::new_number_field::<i32>("acquireRemoteAsNumber", Some("acquire_remote_as_number".into())))
        .field(FieldConfig::new_string_field("acquireRemoteAsName", Some("acquire_remote_as_name".into())))
        .field(FieldConfig::new_string_field("acquireUserAgent", Some("acquire_user_agent".into())));
    static ref LIST_TOKEN_GENERATOR: QueryConfig = QueryConfig::new()
        .field(FieldConfig::new_number_field::<i32>("id", None))
        .field(FieldConfig::new_number_field::<i32>("user", Some("\"user\"".into())))
        .field(FieldConfig::new_date_time_field("issuedAt", Some("issued_at".into())))
        .field(FieldConfig::new_date_time_field("expiresAt", Some("expires_at".into())))
        .field(FieldConfig::new_string_field("acquireMethod", Some("acquire_method".into())))
        .field(FieldConfig::new_string_field("acquireHost", Some("acquire_host".into())))
        .field(FieldConfig::new_string_field("acquireRemote", Some("acquire_remote".into())))
        .field(FieldConfig::new_string_field("acquireRemoteCountry", Some("acquire_remote_country".into())))
        .field(FieldConfig::new_string_field("acquireRemoteCountryName", Some("acquire_remote_country_name".into())))
        .field(FieldConfig::new_string_field("acquireRemoteRegion", Some("acquire_remote_region".into())))
        .field(FieldConfig::new_string_field("acquireRemoteRegionName", Some("acquire_remote_region_name".into())))
        .field(FieldConfig::new_number_field::<i32>("acquireRemoteAsNumber", Some("acquire_remote_as_number".into())))
        .field(FieldConfig::new_string_field("acquireRemoteAsName", Some("acquire_remote_as_name".into())))
        .field(FieldConfig::new_string_field("acquireUserAgent", Some("acquire_user_agent".into())));
}

async fn list_token_for_me(
    database: web::Data<AppDatabase>,
    request: ValidatedQuery<ListTokenRequest>,
    auth: Auth,
) -> ApiResult<ListTokenResponse> {
    auth.try_permission("token", "list-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    let results = process_query(
        &LIST_TOKEN_FOR_ME_GENERATOR, &request.before, &request.after, &request.sort,
        request.desc, &request.query,
        default_process(
            &format!("NOT REVOKED AND \"user\" = {}", uid),
            "id, \"user\", issued_at, expires_at, acquire_method, \
                 acquire_host, acquire_remote, \
                 acquire_remote_country, acquire_remote_country_name, \
                 acquire_remote_region, acquire_remote_region_name, \
                 acquire_remote_as_number, acquire_remote_as_name, \
                acquire_user_agent",
            "token", &request.size, database.clone())
    ).await?.iter()
        .map(|row| {
            TokenCursor::try_from_token(Token::from(row), &request.sort)
        })
        .collect::<Result<Vec<_>, _>>()?;
    respond(ListTokenResponse { results })
}

async fn list_token(
    database: web::Data<AppDatabase>,
    request: ValidatedQuery<ListTokenRequest>,
    auth: Auth,
) -> ApiResult<ListTokenResponse> {
    auth.try_permission("token", "list")?;
    let results = process_query(
        &LIST_TOKEN_GENERATOR, &request.before, &request.after, &request.sort,
        request.desc, &request.query,
        default_process(
            "NOT REVOKED",
            "id, \"user\", issued_at, expires_at, acquire_method, \
                 acquire_host, acquire_remote, \
                 acquire_remote_country, acquire_remote_country_name, \
                 acquire_remote_region, acquire_remote_region_name, \
                 acquire_remote_as_number, acquire_remote_as_name, \
                acquire_user_agent",
            "token", &request.size, database.clone())
    ).await?.iter()
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
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: &Auth,
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
    let rows = database.db.read().await
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
    subscriber.send_all(
        results.into_iter()
            .map(|result| TokenRevoked {
                jti: result.id,
                uid: result.user,
            }.into())
            .collect(),
        auth
    )
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(RevokeTokenResponse {
        count
    })
}

async fn revoke_token_for_me(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: Auth,
    request: ValidatedQuery<RevokeTokenRequest>,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    revoke_token_impl(database, subscriber, &auth, &request.query, Some(uid)).await
}

async fn revoke_token(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: Auth,
    request: ValidatedQuery<RevokeTokenRequest>,
) -> ApiResult<RevokeTokenResponse> {
    auth.try_permission("token", "revoke")?;
    revoke_token_impl(database, subscriber, &auth, &request.query, None).await
}

#[derive(Debug, Validate, Deserialize)]
struct JtiPath {
    #[validate]
    jti: Id,
}

async fn revoke_single_token_impl(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: &Auth,
    jti: i32,
    uid: Option<i32>,
) -> ApiResult<()> {
    let result = database.query.token
        .revoke_token(&*database.db.read().await, jti, uid)
        .await
        .map_err(|err| match err {
            QueryError::TokenNotFound => ApiError::TokenNotFound,
            e => internal_server_error!(e),
        })?;
    subscriber.send(TokenRevoked {
        jti: result.id,
        uid: result.user,
    }, auth)
        .await
        .map_err(|e| internal_server_error!(e))?;
    respond(())
}

async fn revoke_single_token(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    jti_path: ValidatedPath<JtiPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("token", "revoke-single")?;
    revoke_single_token_impl(database, subscriber, &auth, jti_path.jti.clone().into(), None).await
}

async fn revoke_single_token_for_me(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    jti_path: ValidatedPath<JtiPath>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("token", "revoke-single")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    revoke_single_token_impl(database, subscriber, &auth, jti_path.jti.clone().into(), Some(uid)).await
}

async fn revoke_this_token_for_me(
    database: web::Data<AppDatabase>,
    subscriber: web::Data<AppSubscriber>,
    auth: Auth,
) -> ApiResult<()> {
    auth.try_permission("token", "revoke-single-self")?;
    let claims = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?;
    let jti = claims.jti;
    let uid = claims.uid;
    revoke_single_token_impl(database, subscriber, &auth, jti, Some(uid)).await
}

#[derive(Debug, Serialize)]
struct ReadTokenResponse {
    token: Token,
}

async fn read_token_impl(
    database: web::Data<AppDatabase>,
    jti: i32,
    uid: Option<i32>,
) -> ApiResult<ReadTokenResponse> {
    let token = database.query.token
        .read_token(&*database.db.read().await, jti, uid)
        .await
        .map_err(|err| match err {
            QueryError::TokenNotFound => ApiError::TokenNotFound,
            e => internal_server_error!(e),
        })?;
    respond(ReadTokenResponse {
        token
    })
}

async fn read_single_token(
    database: web::Data<AppDatabase>,
    auth: Auth,
    jti_path: ValidatedPath<JtiPath>,
) -> ApiResult<ReadTokenResponse> {
    auth.try_permission("token", "read-single")?;
    read_token_impl(database, jti_path.jti.clone().into(), None).await
}

async fn read_single_token_for_me(
    database: web::Data<AppDatabase>,
    auth: Auth,
    jti_path: ValidatedPath<JtiPath>,
) -> ApiResult<ReadTokenResponse> {
    auth.try_permission("token", "read-single-self")?;
    let uid = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.uid;
    read_token_impl(database, jti_path.jti.clone().into(), Some(uid)).await
}

async fn read_this_token_for_me(
    database: web::Data<AppDatabase>,
    auth: Auth,
) -> ApiResult<ReadTokenResponse> {
    auth.try_permission("token", "read-single-self")?;
    let jti = auth.claims.as_ref().ok_or_else(|| ApiError::MissingAuthorizationHeader)?.jti;
    read_token_impl(database, jti, None).await
}

pub fn tokens_api(
    database: &web::Data<AppDatabase>,
) -> Box<dyn FnOnce(&mut web::ServiceConfig)> {
    let database = database.clone();
    Box::new(move |cfg| {
        cfg
            .service(
                web::scope("tokens")
                    .service(
                        web::scope("acquire-by-username")
                            .wrap(default_password_rate_limit(database.clone()))
                            .route("", web::post().to(acquire_token_by_username))
                    )
                    .service(
                        web::scope("acquire-by-email")
                            .wrap(default_password_rate_limit(database.clone()))
                            .route("", web::post().to(acquire_token_by_email))
                    )
                    .route("/resume", web::post().to(resume_token))
                    .route("/{jti}", web::get().to(read_single_token))
                    .route("/{jti}", web::delete().to(revoke_single_token))
                    .route("", web::get().to(list_token))
                    .route("", web::delete().to(revoke_token))
            )
            .service(
                web::scope("my-tokens")
                    .route("/this", web::get().to(read_this_token_for_me))
                    .route("/this", web::delete().to(revoke_this_token_for_me))
                    .route("/{jti}", web::get().to(read_single_token_for_me))
                    .route("/{jti}", web::delete().to(revoke_single_token_for_me))
                    .route("", web::get().to(list_token_for_me))
                    .route("", web::delete().to(revoke_token_for_me))
            );
    })
}
