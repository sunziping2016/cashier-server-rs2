use actix_web::error::BlockingError;
use bcrypt::BcryptError;
use err_derive::Error;
use jsonwebtoken::errors::Error as JsonWebTokenError;
use tokio_postgres::error::Error as PostgresError;
use lettre::address::AddressError;
use lettre::error::Error as EmailError;
use lettre::transport::smtp::error::Error as SmtpError;

#[derive(Debug, Error)]
pub enum Error {
    #[error(display = "{}", _0)]
    Db(#[error(source)]#[error(from)] PostgresError),
    #[error(display = "{}", _0)]
    JsonWebToken(#[error(source)]#[error(from)] JsonWebTokenError),
    #[error(display = "user not found")]
    UserNotFound,
    #[error(display = "wrong password")]
    WrongPassword,
    #[error(display = "user blocked")]
    UserBlocked,
    #[error(display = "token not found")]
    TokenNotFound,
    #[error(display = "invalid token causing by {}", error)]
    InvalidToken {
        error: String,
    },
    #[error(display = "duplicated user with same {} field", field)]
    DuplicatedUser {
        field: String,
    },
    #[error(display = "{}", _0)]
    Bcrypt(#[error(source)]#[error(from)] BlockingError<BcryptError>),
    #[error(display = "{}", _0)]
    Address(#[error(source)]#[error(from)] AddressError),
    #[error(display = "{}", _0)]
    Email(#[error(source)]#[error(from)] EmailError),
    #[error(display = "{}", _0)]
    Smtp(#[error(source)]#[error(from)] BlockingError<SmtpError>),
    #[error(display = "user registration not found")]
    UserRegistrationNotFound,
    #[error(display = "user registration expired")]
    UserRegistrationExpired,
    #[error(display = "user registration wrong code")]
    UserRegistrationWrongCode,
}

pub type Result<T> = std::result::Result<T, Error>;
