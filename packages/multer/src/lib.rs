pub mod memory_storage;
pub mod file_storage;

use actix_multipart::{Multipart, Field, MultipartError};
use actix_web::{http::HeaderMap, error::BlockingError};
use err_derive::Error;
use futures::future::LocalBoxFuture;
use mime::Mime;
use std::{
    collections::{
        HashSet,
        HashMap,
    },
    iter::FromIterator,
    ffi::OsString,
    fmt,
};
use tokio::stream::StreamExt;

#[derive(Debug)]
pub struct FieldName(Option<String>);

impl fmt::Display for FieldName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Some(x) => write!(f, "\"{}\"", x),
            None => write!(f, "UNKNOWN"),
        }
    }
}

impl From<Option<String>> for FieldName {
    fn from(field: Option<String>) -> Self {
        Self(field)
    }
}

#[derive(Debug, Error)]
pub enum MulterError {
    #[error(display = "{}", _0)]
    PayloadError(#[error(from)] MultipartError),
    #[error(display = "max field count reached")]
    MaxFieldCountReached,
    #[error(display = "max field name length reached")]
    MaxFieldNameLengthReached,
    #[error(display = "unexpected field {}", field)]
    UnexpectedField {
        field: FieldName,
    },
    #[error(display = "unexpected content type \"{}\" for {}", content_type, field)]
    UnexpectedContentType {
        content_type: Mime,
        field: FieldName,
    },
    #[error(display = "expected file field for {}", field)]
    ExpectedFileField {
        field: FieldName,
    },
    #[error(display = "expected non-file field for {}", field)]
    ExpectedNonFileField {
        field: FieldName,
    },
    #[error(display = "too many field {}", field)]
    MaxSameFieldCountReached {
        field: FieldName,
    },
    #[error(display = "missing field {}", field)]
    MinSameFieldCountNotReached {
        field: FieldName,
    },
    #[error(display = "missing content disposition header")]
    MissingContentDisposition,
    #[error(display = "invalid encoding for {}", field)]
    InvalidEncoding {
        field: FieldName,
    },
    #[error(display = "content too large for {}", field)]
    MaxFieldContentLengthReached {
        field: FieldName,
    },
    #[error(display = "{}", _0)]
    BlockingIoError(#[error(source)] #[error(from)] BlockingError<std::io::Error>),
}

pub type Result<T> = std::result::Result<T, MulterError>;

pub struct FieldInfo<'a> {
    pub index: usize,
    pub name: &'a Option<String>,
    pub config: &'a FieldConfig,
}

pub struct FileInfo {
    pub destination: OsString,
    pub filename: OsString,
    pub path: OsString,
    pub size: usize,
}

pub trait FieldResultExtra {
    fn content(&self) -> Option<&[u8]>;
    fn file(&self) -> Option<&FileInfo>;
    fn size(&self) -> usize;
    fn accept(&mut self);
}

pub type Handler = Box<dyn for<'a> Fn(&'a FieldInfo, &'a mut Field)
    -> LocalBoxFuture<'a, Result<Box<dyn FieldResultExtra + std::marker::Send>>>>;

pub struct FieldConfig {
    accept_content_type: Option<HashSet<Mime>>,
    accept_file: Option<bool>,
    min_count: Option<usize>,
    max_count: Option<usize>,
    handler: Option<Handler>,
}

impl FieldConfig {
    pub fn new() -> Self {
        Self {
            accept_content_type: None,
            accept_file: None,
            min_count: None,
            max_count: None,
            handler: None,
        }
    }
    pub fn handler(mut self, handler: Handler) -> Self {
        self.handler = Some(handler);
        self
    }
    pub fn accept_content_type(mut self, types: Vec<Mime>) -> Self {
        self.accept_content_type = Some(HashSet::from_iter(types.into_iter()));
        self
    }
    pub fn accept_file(mut self, value: bool) -> Self {
        self.accept_file = Some(value);
        self
    }
    pub fn single(mut self) -> Self {
        self.min_count = Some(1);
        self.max_count = Some(1);
        self
    }
    pub fn min_count(mut self, count: usize) -> Self {
        self.min_count = Some(count);
        self
    }
    pub fn max_count(mut self, count: usize) -> Self {
        self.max_count = Some(count);
        self
    }
}

pub struct MulterConfig {
    fields: HashMap<Option<String>, FieldConfig>,
    max_field_count: Option<usize>,
    max_field_name_length: Option<usize>,
}

impl MulterConfig {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
            max_field_count: None,
            max_field_name_length: None,
        }
    }
    pub fn field(mut self, key: &str, config: FieldConfig) -> Self {
        config.handler.as_ref().expect("must provide a handler");
        self.fields.insert(Some(String::from(key)), config);
        self
    }
    pub fn default_field(mut self, config: FieldConfig) -> Self {
        self.fields.insert(None, config);
        self
    }
    pub fn max_field_count(mut self, max_field_count: usize) -> Self {
        self.max_field_count = Some(max_field_count);
        self
    }
    pub fn max_field_name_length(mut self, max_field_name_length: usize) -> Self {
        self.max_field_name_length = Some(max_field_name_length);
        self
    }
}

impl Default for MulterConfig {
    fn default() -> Self {
        MulterConfig::new()
    }
}

pub struct FieldResult {
    headers: HeaderMap,
    content_type: Mime,
    filename: Option<String>,
    extra: Box<dyn FieldResultExtra + std::marker::Send>,
}

impl FieldResult {
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }
    pub fn content_type(&self) -> &Mime {
        &self.content_type
    }
    pub fn filename(&self) -> &Option<String> {
        &self.filename
    }
    pub fn extra(&self) -> &Box<dyn FieldResultExtra + std::marker::Send> {
        &self.extra
    }
    pub fn extra_mut(&mut self) -> &mut Box<dyn FieldResultExtra + std::marker::Send> {
        &mut self.extra
    }
}

pub struct MulterResults {
    fields: HashMap<Option<String>, Vec<FieldResult>>,
}

impl MulterResults {
    pub fn fields(&self) -> &HashMap<Option<String>, Vec<FieldResult>> {
        &self.fields
    }
    pub fn get(&self, index: &str) -> Option<&Vec<FieldResult>> {
        self.fields.get(&Some(index.into()))
    }
    pub fn get_default(&self) -> Option<&Vec<FieldResult>> {
        self.fields.get(&None)
    }
    pub fn get_single(&self, index: &str) -> &FieldResult {
        self.get(index).unwrap().get(0).unwrap()
    }
    pub fn get_mut(&mut self, index: &str) -> Option<&mut Vec<FieldResult>> {
        self.fields.get_mut(&Some(index.into()))
    }
    pub fn get_mut_default(&mut self) -> Option<&mut Vec<FieldResult>> {
        self.fields.get_mut(&None)
    }
    pub fn get_mut_single(&mut self, index: &str) -> &mut FieldResult {
        self.get_mut(index).unwrap().get_mut(0).unwrap()
    }
}

pub async fn multer(mut payload: Multipart, config: &MulterConfig) -> Result<MulterResults> {
    let mut field_count = 0;
    let mut results = MulterResults {
        fields: HashMap::new(),
    };
    while let Some(mut field) = payload.try_next().await
        .map_err(MulterError::from)? {
        field_count += 1;
        // Check max_field_count
        if let Some(max_field_count) = config.max_field_count {
            if field_count > max_field_count {
                return Err(MulterError::MaxFieldCountReached);
            }
        }
        if let Some(content_disposition) = field.content_disposition() {
            // Check max_field_name_length
            let name = content_disposition.get_name().map(String::from);
            if let Some(ref name) = name {
                if let Some(max_field_name_length) = config.max_field_name_length {
                    if name.len() > max_field_name_length {
                        return Err(MulterError::MaxFieldNameLengthReached);
                    }
                }
            }
            let (matched_config, matched_index) = config.fields.get(&name)
                .map(|config| (config, name.clone()))
                .or_else(|| config.fields.get(&None)
                    .map(|config| (config, None)))
                .ok_or_else(|| MulterError::UnexpectedField {
                    field: name.clone().into(),
                })?;
            let matched_result = results.fields.entry(matched_index).or_insert_with(Vec::new);
            // Check accept_content_type
            if let Some(accept_content_type) = matched_config.accept_content_type.as_ref() {
                if !accept_content_type.contains(field.content_type()) {
                    return Err(MulterError::UnexpectedContentType {
                        content_type: field.content_type().clone(),
                        field: name.into(),
                    });
                }
            }
            // Check accept_file
            let filename = content_disposition.get_filename();
            if let Some(accept_file) = matched_config.accept_file {
                if filename.is_some() != accept_file {
                    return Err(if accept_file {
                        MulterError::ExpectedFileField { field: name.into() }
                    } else {
                        MulterError::ExpectedNonFileField { field: name.into() }
                    });
                }
            }
            // Check max_count
            if let Some(max_count) = matched_config.max_count {
                if matched_result.len() >= max_count {
                    return Err(MulterError::MaxSameFieldCountReached {
                        field: name.into(),
                    });
                }
            }
            matched_result.push(FieldResult {
                headers: field.headers().clone(),
                content_type: field.content_type().clone(),
                filename: filename.map(String::from),
                extra: (matched_config.handler.as_ref().unwrap())(&FieldInfo {
                    index: matched_result.len(),
                    name: &name,
                    config: &matched_config,
                }, &mut field).await?,
            });
        } else {
            return Err(MulterError::MissingContentDisposition);
        }
    }
    // Check min_count
    for (name, result) in &results.fields {
        let config = config.fields.get(name)
            .or_else(|| config.fields.get(&None)).unwrap();
        if let Some(min_count) = config.min_count {
            if result.len() < min_count {
                return Err(MulterError::MinSameFieldCountNotReached {
                    field: name.clone().into(),
                });
            }
        }
    }
    Ok(results)
}
