use serde::{Deserialize, Serialize};
use err_derive::Error;
use cashier_query::generator::{QueryConfig, Error as QueryError};

#[derive(Debug, Error)]
pub enum CursorError {
    #[error(display = "{}", _0)]
    Base64(#[error(source)] #[error(from)] base64::DecodeError),
    #[error(display = "{}", _0)]
    Json(#[error(source)] #[error(from)] serde_json::Error),
    #[error(display = "invalid key field")]
    InvalidKey,
    #[error(display = "{}", _0)]
    Query(#[error(source)] #[error(from)] QueryError),
}

pub type Result<T> = std::result::Result<T, CursorError>;

#[derive(Debug, Deserialize, Serialize)]
pub struct PrimaryCursor {
    pub k: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Cursor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub p: Option<PrimaryCursor>,
    pub id: String,
}

impl Cursor {
    pub fn new(id: String, p: Option<PrimaryCursor>) -> Self {
        Self { p, id }
    }
    pub fn try_from_str(input: &str) -> Result<Cursor> {
        Ok(serde_json::from_slice(&base64::decode(input)?)?)
    }
    pub fn try_to_str(&self) -> Result<String> {
        Ok(base64::encode(serde_json::to_string(self)?))
    }
    pub fn check_key(&self, key: &Option<String>) -> Result<()> {
        if self.p.as_ref().map(|x| x.k.clone()) != *key {
            Err(CursorError::InvalidKey) } else { Ok(()) }
    }
    pub fn to_sql(&self, config: &QueryConfig, gt: bool) -> Result<String> {
        let (id_field, id_value) = config.map_field_value("id", &self.id)?;
        Ok(match self.p.as_ref() {
            Some(PrimaryCursor{ k, v }) => {
                match v {
                    // null value is large than any other value
                    Some(v) => {
                        let (primary_field, primary_value) = config.map_field_value(k, &v)?;
                        if gt {
                            format!("({} IS NULL OR {} > {} OR {} = {} AND {} > {})",
                                    primary_field, primary_field, primary_value,
                                    primary_field, primary_value, id_field, id_value)
                        } else {
                            format!("({} IS NOT NULL AND ({} < {} OR {} = {} AND {} < {}))",
                                    primary_field, primary_field, primary_value,
                                    primary_field, primary_value, id_field, id_value)
                        }
                    },
                    None => {
                        let primary_field = config.map_field(k)?;
                        if gt {
                            format!("({} IS NULL AND {} > {})", primary_field, id_field, id_value)
                        } else {
                            format!("({} IS NOT NULL OR {} IS NULL AND {} < {})",
                                    primary_field, primary_field, id_field, id_value)
                        }
                    }
                }
            }
            None => format!("{} {} {}", id_field, if gt { ">" } else { "<" }, id_value),
        })
    }
}