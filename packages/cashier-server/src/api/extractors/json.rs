//! Json extractor.
use core::fmt::Debug;
use std::ops::Deref;

use actix_web::dev::JsonBody;
use actix_web::FromRequest;
use actix_web::HttpRequest;
use futures::future::{FutureExt, LocalBoxFuture};
// use futures_util::future::{LocalBoxFuture, Try};
use serde::de::DeserializeOwned;
use validator::Validate;

use crate::api::errors::ApiError;

#[derive(Debug)]
pub struct Json<T>(pub T);

impl<T> Json<T> {
    /// Deconstruct to an inner value
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> AsRef<T> for Json<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> Deref for Json<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> FromRequest for Json<T>
    where
        T: DeserializeOwned + Validate + 'static,
{
    type Error = ApiError;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;
    type Config = JsonConfig;

    #[inline]
    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {
        let req2 = req.clone();
        let (limit,) = req
            .app_data::<Self::Config>()
            .map(|c| (c.limit,))
            .unwrap_or((32768,));

        JsonBody::new(req, payload, None)
            .limit(limit)
            .map(|res: Result<T, _>| match res {
                Ok(data) => data
                    .validate()
                    .map(|_| Json(data))
                    .map_err(ApiError::from),
                Err(e) => Err(ApiError::JsonPayloadError { error: format!("{}", e)}),
            })
            .map(move |res| match res {
                Ok(data) => Ok(data),
                Err(e) => {
                    log::debug!(
                        "Failed to deserialize Json from payload. \
                         Request path: {}",
                        req2.path()
                    );
                    Err(e.into())
                }
            })
            .boxed_local()
    }
}

#[derive(Clone)]
pub struct JsonConfig {
    limit: usize
}

impl JsonConfig {
    /// Change max size of payload. By default max size is 32Kb
    pub fn limit(mut self, limit: usize) -> Self {
        self.limit = limit;
        self
    }
}

impl Default for JsonConfig {
    fn default() -> Self {
        JsonConfig {
            limit: 32768,
        }
    }
}