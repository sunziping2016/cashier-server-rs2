use actix_web_validator::{
    JsonConfig,
    PathConfig,
    QueryConfig,
    Error,
};
use crate::api::errors::ApiError;
use std::sync::Arc;
use multer::{
    FieldConfig, MulterConfig,
    memory_storage::MemoryStorageBuilder,
};
use crate::api::extractors::limit::RateLimit;
use actix_web::web;
use crate::api::app_state::AppDatabase;

pub fn default_json_config() -> JsonConfig {
    JsonConfig::default()
        .error_handler(|err, _req| match err {
            Error::Validate(e) => ApiError::from(e),
            e => ApiError::JsonPayloadError { error: format!("{}", e) },
        }.into())
}

pub fn default_path_config() -> PathConfig {
    PathConfig::default()
        .error_handler(|err, _req| match err {
            Error::Validate(e) => ApiError::from(e),
            e => ApiError::JsonPayloadError { error: format!("{}", e) },
        }.into())
}

pub fn default_query_config() -> QueryConfig {
    QueryConfig::default()
        .error_handler(|err, _req| match err {
            Error::Validate(e) => ApiError::from(e),
            e => ApiError::JsonPayloadError { error: format!("{}", e) },
        }.into())
}

pub fn avatar_multer_config() -> Arc<MulterConfig> {
    Arc::new(MulterConfig::new()
        .field("avatar", FieldConfig::default()
            .single()
            .accept_file(true)
            .accept_content_type(vec![mime::IMAGE_PNG, mime::IMAGE_JPEG])
            .handler(MemoryStorageBuilder::new()
                .max_size(1024 * 1024)
                .build()
            )
        )
    )
}

pub fn default_global_rate_limit(database: web::Data<AppDatabase>) -> RateLimit {
    RateLimit {
        subject: "global".into(),
        burst: 20.0,
        rate: 1.0,
        reset_on_fail: false,
        database,
    }
}

pub fn default_password_rate_limit(database: web::Data<AppDatabase>) -> RateLimit {
    RateLimit {
        subject: "password".into(),
        burst: 5.0,
        rate: 0.05, // 3/min
        reset_on_fail: false,
        database,
    }
}

pub fn default_confirm_rate_limit(database: web::Data<AppDatabase>) -> RateLimit {
    RateLimit {
        subject: "password".into(),
        burst: 5.0,
        rate: 0.05, // 3/min
        reset_on_fail: false,
        database,
    }
}