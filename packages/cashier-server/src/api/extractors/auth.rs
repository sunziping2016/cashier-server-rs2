use crate::{
    internal_server_error,
    api::{
        errors::ApiError,
    },
    queries::{
        tokens::JwtClaims,
        users::PermissionSubjectAction,
        errors::Error as QueryError,
    },
};
use actix_web::{
    web, FromRequest,
};
use futures::future::{LocalBoxFuture, FutureExt};
use crate::api::app_state::AppDatabase;

#[derive(Debug)]
pub struct Auth {
    pub claims: Option<JwtClaims>,
    pub permissions: Vec<PermissionSubjectAction>,
}

impl Auth {
    pub fn has_permission(&self, subject: &str, action: &str) -> bool {
        self.permissions.iter()
            .any(|permission| permission.subject == subject && permission.action == action)
    }

    pub fn try_permission(&self, subject: &str, action: &str) -> std::result::Result<(), ApiError> {
        if self.has_permission(subject, action) { Ok(()) } else {
            Err(ApiError::PermissionDenied {
                subject: subject.into(),
                action: action.into(),
            })
        }
    }
}

impl FromRequest for Auth {
    type Error = ApiError;
    type Future = LocalBoxFuture<'static, Result<Self, ApiError>>;
    type Config = ();

    fn from_request(req: &web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let database = match req.app_data::<web::Data<AppDatabase>>() {
            Some(st) => st.clone(),
            None => return futures::future::err(internal_server_error!()).boxed(),
        };
        let auth = match req.headers().get("Authorization")
            .map(|x| x.to_str()
                .ok()
                .map(|header| header.split_ascii_whitespace().collect::<Vec<_>>())
                .map(|fragments|
                    if fragments.len() == 2 && fragments[0] == "Bearer" {
                        Some(String::from(fragments[1]))
                    } else { None }
                )
                .flatten()
                .ok_or_else(|| ApiError::InvalidAuthorizationHeader)
            )
            .transpose() {
            Ok(v) => v,
            Err(e) => return futures::future::err(e).boxed(),
        };
        async move {
            let (claims, permissions) = match auth {
                Some(token) => {
                    let claims = database.query.token
                        .verify_token(&*database.db.read().await, &token)
                        .await
                        .map_err(|e| match e {
                            QueryError::InvalidToken { error } => ApiError::InvalidToken { error },
                            e => internal_server_error!(e),
                        })?;
                    database.query.token
                        .check_token_revoked(&*database.db.read().await, claims.jti)
                        .await
                        .map_err(|e| match e {
                            QueryError::TokenNotFound => ApiError::InvalidToken { error: "TokenRevoked".into() },
                            e => internal_server_error!(e),
                        })?;
                    database.query.user
                        .check_user_valid_by_id(&*database.db.read().await, claims.uid)
                        .await
                        .map_err(|e| match e {
                            QueryError::UserNotFound => ApiError::InvalidToken { error: "InvalidUser".into() },
                            QueryError::UserBlocked => ApiError::InvalidToken { error: "UserBlocked".into() },
                            e => internal_server_error!(e),
                        })?;
                    let permissions = database.query.user
                        .fetch_permission(&*database.db.read().await, claims.uid)
                        .await
                        .map_err(|e| internal_server_error!(e))?;
                    (Some(claims), permissions)
                }
                None => (
                    None,
                    database.query.user
                        .fetch_default_permission(&*database.db.read().await)
                        .await
                        .map_err(|e| internal_server_error!(e))?,
                )
            };
            Ok(Auth {
                claims,
                permissions,
            })
        }.boxed_local()
    }
}

