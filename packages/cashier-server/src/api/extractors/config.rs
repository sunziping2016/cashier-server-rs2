use actix_web_validator::{
    JsonConfig,
    Error,
};
use crate::api::errors::ApiError;

pub fn default_json_config(cfg: JsonConfig) -> JsonConfig {
    cfg.error_handler(|err, _req| match err {
        Error::Validate(e) => ApiError::from(e),
        e => ApiError::JsonPayloadError { error: format!("{}", e) },
    }.into())
}