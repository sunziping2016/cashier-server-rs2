use actix_web::error::BlockingError;
use bcrypt::BcryptError;
use err_derive::Error;
use jsonwebtoken::errors::Error as JsonWebTokenError;
use tokio_postgres::error::Error as PostgresError;

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
    Bcrypt(#[error(source)]#[error(from)] BlockingError<BcryptError>)
}

pub type Result<T> = std::result::Result<T, Error>;
