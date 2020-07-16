use serde::{Deserialize, Serialize};
use err_derive::Error;
use cashier_query::generator::{QueryConfig, Error as QueryError};
use crate::api::fields::{PaginationSize, Cursor as CursorField};
use crate::api::errors::{Result as ApiResult, ApiError};
use crate::internal_server_error;
use tokio_postgres::Row;
use actix_web::web;
use crate::api::app_state::AppState;
use futures::FutureExt;
use futures::future::LocalBoxFuture;

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
    pub fn convert_to_sql(input: &str, key: &Option<String>, config: &QueryConfig, gt: bool) -> Result<String> {
        Ok(Cursor::try_from_str(input, key)?.to_sql(config, gt)?)
    }
    pub fn try_from_str(input: &str, key: &Option<String>) -> Result<Cursor> {
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

pub type Handler = Box<dyn FnOnce(String/*condition*/, String/*order_by*/, String/*ordered_columns*/)
    -> LocalBoxFuture<'static, ApiResult<Vec<Row>>>>;

pub fn default_process(
    extra_condition: &str,
    projection: &str,
    table: &str,
    size: &PaginationSize,
    app_data: web::Data<AppState>,
) -> Handler {
    let extra_condition = extra_condition.to_owned();
    let projection = projection.to_owned();
    let table = table.to_owned();
    let size = usize::from(size.clone());
    Box::new(move |condition, order_by, _| async move {
        let statement = format!("SELECT {} FROM {} WHERE {} AND ({}) ORDER BY {} LIMIT {}",
                                projection, table, condition, extra_condition, order_by, size);
        Ok(app_data.db.read().await
            .query(&statement[..], &[])
            .await
            .map_err(|e| internal_server_error!(e))?)
    }.boxed_local())
}

pub fn process_query(
    generator: &QueryConfig,
    before: &Option<CursorField>,
    after: &Option<CursorField>,
    sort: &Option<String>,
    desc: bool,
    query: &str,
    process: Handler,
) -> LocalBoxFuture<'static, ApiResult<Vec<Row>>> {
    if before.is_some() && after.is_some() {
        return futures::future::ready(Err(ApiError::QueryError {
            error: "".into(),
        })).boxed_local();
    }
    let direction = if before.is_some() == desc { "ASC" } else { "DESC" };
    let id = generator.check_sortable("id").unwrap();
    let (order_by, ordered_columns) = match sort.as_ref() {
        Some(sort) => match generator.check_sortable(sort) {
            Ok(result) => (
                format!("{} {}, {} {}", result, direction, id, direction),
                format!("{}, {}", id, result),
            ),
            Err(e) => return futures::future::ready(Err(e.into())).boxed_local(),
        }
        None => (
            format!("{} {}", id, direction),
            format!("{}", id),
        )
    };
    let mut conditions: Vec<String> = Vec::new();
    match generator.parse_to_postgres(&query) {
        Ok(result) => conditions.push(result),
        Err(e) => return futures::future::ready(Err(e.into())).boxed_local(),
    }
    if let Some(before) = before.as_ref() {
        match Cursor::convert_to_sql(&before[..], &sort, generator, desc) {
            Ok(result) => conditions.push(result),
            Err(e) => return futures::future::ready(Err(e.into())).boxed_local(),
        }
    }
    if let Some(after) = after.as_ref() {
        match Cursor::convert_to_sql(&after[..], &sort, generator, !desc) {
            Ok(result) => conditions.push(result),
            Err(e) => return futures::future::ready(Err(e.into())).boxed_local(),
        }
    }
    let condition = conditions.join(" AND ");
    let has_before = before.is_some();
    process(condition, order_by, ordered_columns)
        .map(move |results| results.map(|mut rows| {
            if has_before {
                rows.reverse();
            }
            rows
        }))
        .boxed_local()
}
