use std::collections::HashMap;
use actix_multipart::Multipart;

pub trait Storage {
    type File;
}

pub struct FieldConfig {
    min_count: usize,
    max_count: usize,
}

pub struct MulterConfig {
    fields: HashMap<String, FieldConfig>,
}

pub async fn multipart(_payload: Multipart) {

}
