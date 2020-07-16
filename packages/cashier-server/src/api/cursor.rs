use serde::{Deserialize, Serialize};
use err_derive::Error;
use cashier_query::generator::{QueryConfig, Error as QueryError};
use crate::api::fields::{PaginationSize, Cursor as CursorField};
use crate::api::errors::{Result as ApiResult, ApiError};
use crate::internal_server_error;
use tokio_postgres::Row;
use actix_web::web;
use crate::api::app_state::AppState;

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
    pub fn try_from_str(input: &str, key: &Option<String>) -> Result<Cursor> {
        println!("{}", input);
        let cursor: Self = serde_json::from_slice(&base64::decode(input)?)?;
        if cursor.p.as_ref().map(|x| x.k.clone()) != *key {
            return Err(CursorError::InvalidKey);
        }
        Ok(cursor)
    }
    pub fn try_to_str(&self) -> Result<String> {
        Ok(base64::encode(serde_json::to_string(self)?))
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

pub async fn process_query(
    generator: &QueryConfig,
    before: &Option<CursorField>,
    after: &Option<CursorField>,
    size: &PaginationSize,
    sort: &Option<String>,
    desc: bool,
    query: &str,
    mut conditions: Vec<String>,
    projection: &str,
    table: &str,
    app_data: web::Data<AppState>,
) -> ApiResult<Vec<Row>> {
    if before.is_some() && after.is_some() {
        return Err(ApiError::QueryError {
            error: "".into(),
        });
    }
    let direction = if before.is_some() == desc { "ASC" } else { "DESC" };
    let order_by = match sort.as_ref() {
        Some(sort) => format!("{} {}, id {}",
                              generator.check_sortable(sort)?,
                              direction, direction),
        None => format!("id {}", direction),
    };
    conditions.push(generator.parse_to_postgres(&query)?);
    if let Some(before) = before.as_ref() {
        conditions.push(Cursor::try_from_str(&before[..], &sort)?.to_sql(generator, desc)?)
    }
    if let Some(after) = after.as_ref() {
        conditions.push(Cursor::try_from_str(&after[..], &sort)?.to_sql(generator, !desc)?)
    }
    let condition = conditions.join(" AND ");
    let statement = format!("SELECT DISTINCT {} FROM {} WHERE {} ORDER BY {} LIMIT {}",
                            projection, table, condition, order_by, usize::from(size.clone()));
    let mut rows = app_data.db.read().await
        .query(&statement[..], &[])
        .await
        .map_err(|e| internal_server_error!(e))?;
    if before.is_some() {
        rows.reverse();
    }
    Ok(rows)
}
