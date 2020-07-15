use actix_web::{
    web,
    error::ResponseError,
    HttpResponse,
};
use cashier_query::generator::Error as QueryError;
use err_derive::Error;
use serde::{Serialize};
use validator::{ValidationErrors, ValidationErrorsKind};
use crate::api::cursor::CursorError;

#[derive(Debug, Serialize, Clone)]
pub struct ValidationError {
    field: String,
    code: String,
    message: Option<String>,
}

#[derive(Debug, Error, Serialize, Clone)]
#[serde(tag = "type")]
pub enum ApiError {
    #[error(display = "{} not implemented", _0)]
    NotImplemented {
        api: String,
    },
    #[error(display = "internal server error")]
    InternalServerError {
        #[serde(skip_serializing)]
        file: &'static str,
        #[serde(skip_serializing)]
        line: u32,
        #[serde(skip_serializing)]
        message: Option<String>,
    },
    #[error(display = "user does not exist or wrong password")]
    WrongUserOrPassword,
    #[error(display = "user is blocked")]
    UserBlocked,
    #[error(display = "invalid authorization header")]
    InvalidAuthorizationHeader,
    #[error(display = "{}", error)]
    InvalidToken {
        error: String,
    },
    #[error(display = "permission denied, requires {} {} permission", action, subject)]
    PermissionDenied {
        subject: String,
        action: String,
    },
    #[error(display = "{}", error)]
    JsonPayloadError {
        error: String,
    },
    #[error(display = "validation failed")]
    ValidationError {
        errors: Vec<ValidationError>,
    },
    #[error(display = "missing authorization header")]
    MissingAuthorizationHeader,
    #[error(display = "attempt to create a user with more roles than creator's")]
    AttemptToElevateRole {
        roles: Vec<String>,
    },
    #[error(display = "duplicated user with same {} field", field)]
    DuplicatedUser {
        field: String,
    },
    #[error(display = "{}", error)]
    MultipartPayloadError {
        error: String,
    },
    #[error(display = "{}", error)]
    AvatarError {
        error: String,
    },
    #[error(display = "cannot find the user")]
    UserNotFound,
    #[error(display = "{}", reason)]
    UserRegistration {
        reason: String,
    },
    #[error(display = "{}", reason)]
    UserEmailUpdating {
        reason: String,
    },
    #[error(display = "cannot find the token")]
    TokenNotFound,
    #[error(display = "{}", error)]
    QueryError {
        error: String,
    },
}

#[derive(Debug, Serialize, Clone)]
pub struct PathValidationError {
    fields: Vec<String>,
    code: String,
    message: Option<String>,
}

fn flatten_validation_errors(errors: &ValidationErrors) -> Vec<PathValidationError> {
    errors.errors()
        .iter()
        .map(|(field, error_kind)| match error_kind {
            ValidationErrorsKind::Field(errors) => errors.iter()
                .map(move |error| PathValidationError {
                    fields: vec![(*field).into()],
                    code: error.code.to_owned().into(),
                    message: error.message.as_ref().map(|msg| msg.to_owned().into()),
                })
                .collect::<Vec<_>>(),
            ValidationErrorsKind::Struct(errors) =>
                flatten_validation_errors(errors).into_iter()
                    .map(|error| PathValidationError {
                        fields: {
                            let mut fields = error.fields;
                            fields.push((*field).into());
                            fields
                        },
                        code: error.code,
                        message: error.message,
                    })
                    .collect::<Vec<_>>(),
            ValidationErrorsKind::List(errors) => errors.iter()
                .flat_map(move |(index, errors)|
                    flatten_validation_errors(errors).into_iter()
                        .map(move |error| PathValidationError {
                            fields: {
                                let mut fields = error.fields;
                                fields.push(index.to_string());
                                fields.push((*field).into());
                                fields
                            },
                            code: error.code,
                            message: error.message,
                        })
                )
                .collect::<Vec<_>>(),
        })
        .flatten()
        .collect()
}

impl From<ValidationErrors> for ApiError {
    fn from(errors: ValidationErrors) -> Self {
        ApiError::ValidationError {
            errors: flatten_validation_errors(&errors).into_iter()
                .map(|error| ValidationError {
                    field: {
                        let mut fields = error.fields;
                        fields.retain(|x| x != "inner");
                        fields.reverse();
                        fields.join(".")
                    },
                    code: error.code,
                    message: error.message,
                })
                .collect(),
        }
    }
}

impl From<QueryError> for ApiError {
    fn from(err: QueryError) -> Self {
        ApiError::QueryError {
            error: format!("{}", err),
        }
    }
}

impl From<CursorError> for ApiError {
    fn from(_err: CursorError) -> Self {
        ApiError::QueryError {
            error: "invalid cursor".into(),
        }
    }
}

#[macro_export]
macro_rules! internal_server_error {
    () => {
        crate::api::errors::ApiError::InternalServerError {
            file: file!(),
            line: line!(),
            message: None,
        }
    };
    ( &str: tt ) => {
        crate::api::errors::ApiError::InternalServerError {
            file: file!(),
            line: line!(),
            message: Some($str.into()),
        }
    };
    ( $e: expr ) => {
        crate::api::errors::ApiError::InternalServerError {
            file: file!(),
            line: line!(),
            message: Some(format!("{:?}", $e)),
        }
    };
}

#[derive(Debug, Serialize)]
struct ApiErrorWrapper {
    code: u32,
    message: String,
    data: ApiError,
}

impl From<ApiError> for ApiErrorWrapper {
    fn from(error: ApiError) -> Self {
        let code = match &error {
            ApiError::NotImplemented { .. } => 501,
            ApiError::InternalServerError { .. } => 500,
            ApiError::WrongUserOrPassword
            | ApiError::UserBlocked
            | ApiError::InvalidAuthorizationHeader
            | ApiError::InvalidToken { .. } => 401,
            ApiError::PermissionDenied { .. }
            | ApiError::AttemptToElevateRole { .. } => 403,
            ApiError::JsonPayloadError { .. }
            | ApiError::MultipartPayloadError { .. }
            | ApiError::ValidationError { .. }
            | ApiError::MissingAuthorizationHeader
            | ApiError::AvatarError{ .. }
            | ApiError::UserRegistration { .. }
            | ApiError:: UserEmailUpdating { .. }
            | ApiError::QueryError { .. } => 400,
            ApiError::DuplicatedUser { .. } => 409,
            ApiError::UserNotFound
            | ApiError::TokenNotFound => 404,
        };
        ApiErrorWrapper {
            code,
            message: format!("{}", error),
            data: error,
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::NotImplemented { .. } =>
                HttpResponse::NotImplemented().json(ApiErrorWrapper::from(self.clone())),
            ApiError::InternalServerError { .. } =>
                HttpResponse::InternalServerError().json(ApiErrorWrapper::from(self.clone())),
            ApiError::WrongUserOrPassword
            | ApiError::UserBlocked
            | ApiError::InvalidAuthorizationHeader
            | ApiError::InvalidToken { .. }=>
                HttpResponse::Unauthorized().json(ApiErrorWrapper::from(self.clone())),
            ApiError::PermissionDenied { .. }
            | ApiError::AttemptToElevateRole { .. } =>
                HttpResponse::Forbidden().json(ApiErrorWrapper::from(self.clone())),
            ApiError::JsonPayloadError { .. }
            | ApiError::MultipartPayloadError { .. }
            | ApiError::ValidationError { .. }
            | ApiError::MissingAuthorizationHeader
            | ApiError::AvatarError { .. }
            | ApiError::UserRegistration { .. }
            | ApiError::UserEmailUpdating { .. }
            | ApiError::QueryError { .. } =>
                HttpResponse::BadRequest().json(ApiErrorWrapper::from(self.clone())),
            ApiError::DuplicatedUser { .. } =>
                HttpResponse::Conflict().json(ApiErrorWrapper::from(self.clone())),
            ApiError::UserNotFound
            | ApiError::TokenNotFound =>
                HttpResponse::NotFound().json(ApiErrorWrapper::from(self.clone())),
        }
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;
pub type ApiResult<T> = Result<web::Json<ApiResultWrapper<T>>>;

#[derive(Debug, Serialize)]
pub struct ApiResultWrapper<T: Serialize> {
    code: u32,
    message: String,
    data: T,
}

impl<T: Serialize> From<T> for ApiResultWrapper<T> {
    fn from(data: T) -> Self {
        ApiResultWrapper {
            code: 200,
            message: "okay".into(),
            data,
        }
    }
}

pub fn respond<T: Serialize>(data: T) -> ApiResult<T> {
    Ok(web::Json(data.into()))
}
