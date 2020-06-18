use actix_web_validator::{
    JsonConfig,
    PathConfig,
    Error,
};
use crate::api::errors::ApiError;
use std::sync::Arc;
use multer::{
    FieldConfig, MulterConfig,
    memory_storage::MemoryStorageBuilder,
};

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

pub fn avatar_multer_config() -> Arc<MulterConfig> {
    Arc::new(MulterConfig::new()
        .field("avatar", FieldConfig::new()
            .single()
            .accept_file(true)
            .accept_content_type(vec![mime::IMAGE_PNG, mime::IMAGE_JPEG])
            .handler(MemoryStorageBuilder::new()
                .max_size(1 * 1024 * 1024)
                .build()
            )
        )
    )
}
