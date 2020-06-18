use crate::{
    api::errors::ApiError,
    internal_server_error,
};
use actix_multipart::Multipart;
use actix_web::{
    FromRequest, HttpRequest,
    dev::{PayloadStream, Payload},
};
use derive_more::{Deref, DerefMut, From};
use futures::future::{LocalBoxFuture, FutureExt};
use multer::{MulterResults, MulterConfig, MulterError, multer};
use std::sync::Arc;

#[derive(Deref, DerefMut, From)]
pub struct Multer(MulterResults);

impl FromRequest for Multer {
    type Error = ApiError;
    type Future = LocalBoxFuture<'static, Result<Self, ApiError>>;
    type Config = Arc<MulterConfig>;

    fn from_request(req: &HttpRequest, payload: &mut Payload<PayloadStream>) -> Self::Future {
        let multer_config = req
            .app_data::<Self::Config>()
            .expect("must provide a configuration")
            .clone();
        let multipart = Multipart::new(req.headers(), payload.take());
        async move {
            let result = multer(multipart, &multer_config)
                .await
                .map_err(|err| match err {
                    MulterError::BlockingIoError(e) => internal_server_error!(e),
                    e => ApiError::MultipartPayloadError {
                        error: format!("{}", e),
                    },
                })?;
            Ok(result.into())
        }.boxed_local()
    }
}