use actix_web_validator::{
    JsonConfig,
    Error,
};
use crate::api::errors::ApiError;
use std::rc::Rc;
use multer::{
    FieldConfig, MulterConfig,
    file_storage::FileStorageBuilder,
};

pub fn default_json_config() -> JsonConfig {
    JsonConfig::default()
        .error_handler(|err, _req| match err {
            Error::Validate(e) => ApiError::from(e),
            e => ApiError::JsonPayloadError { error: format!("{}", e) },
        }.into())
}

pub fn avatar_multer_config() -> Rc<MulterConfig> {
    Rc::new(MulterConfig::new()
        .field("avatar", FieldConfig::new()
            .single()
            .accept_file(true)
            .accept_content_type(vec![mime::IMAGE_PNG, mime::IMAGE_JPEG])
            .handler(FileStorageBuilder::new()
                .max_size(8 * 1024 * 1024)
                .constant_destination("media/avatar".into())
                .random_filename(24)
                .make_dirs()
                .build()
            ),
        )
    )
}
