use std::pin::Pin;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, ResponseError, web};
use futures::future::{ok, Ready};
use futures::Future;
use crate::api::errors::ApiError;
use crate::api::app_state::AppDatabase;
use crate::internal_server_error;
use log::warn;
use std::sync::{Arc, RwLock};

pub struct RateLimit {
    pub subject: String,
    pub burst: f64,
    pub rate: f64, // token per second
    pub reset_on_fail: bool,
    pub database: web::Data<AppDatabase>,
}

impl<S, B> Transform<S> for RateLimit
    where
        S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SayHiMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(SayHiMiddleware {
            subject: self.subject.clone(),
            burst: self.burst,
            rate: self.rate,
            reset_on_fail: self.reset_on_fail,
            database: self.database.clone(),
            service: Arc::new(RwLock::new(service)),
        })
    }
}

pub struct SayHiMiddleware<S> {
    subject: String,
    burst: f64,
    rate: f64, // token per second
    reset_on_fail: bool,
    database: web::Data<AppDatabase>,
    service: Arc<RwLock<S>>,
}

impl<S, B> Service for SayHiMiddleware<S>
    where
        S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.write().unwrap().poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let database = self.database.clone();
        let subject = self.subject.clone();
        let remote = req.connection_info().remote().map(str::to_owned);
        let burst = self.burst;
        let rate = self.rate;
        let reset_on_fail = self.reset_on_fail;
        let service = self.service.clone();
        Box::pin(async move {
            match remote {
                Some(remote) => {
                    match database.query.limit
                        .try_acquire_token(&mut *database.db.write().await, &subject, &remote,
                                           burst, rate, reset_on_fail)
                        .await {
                        Ok(success) => if !success {
                            return Ok(req.into_response(ApiError::TooManyRequests {
                                subject,
                            }.error_response().into_body()))
                        },
                        Err(e) => return Ok(req.into_response(
                            internal_server_error!(e).error_response().into_body())),
                    }
                },
                None => warn!("don't know the remote address")
            }
            Ok(service.write().unwrap().call(req).await?)
        })
    }
}
