#![allow(clippy::type_complexity)]

use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::{ok, LocalBoxFuture, Ready};
use futures::FutureExt;

use actix_service::{Service, Transform};
use actix_web::{
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    Error, HttpMessage, HttpResponse, Result,
};

use casbin::prelude::{TryIntoAdapter, TryIntoModel};
use casbin::{CachedEnforcer, CoreApi, Result as CasbinResult};

#[cfg(feature = "runtime-tokio")]
use tokio::sync::RwLock;

#[cfg(feature = "runtime-async-std")]
use async_std::sync::RwLock;

#[derive(Clone)]
pub struct CasbinVals {
    pub subject: String,
    pub domain: Option<String>,
}

type ErrorHandler = Arc<dyn Fn() -> HttpResponse + Send + Sync>;

#[derive(Clone)]
pub struct CasbinService {
    enforcer: Arc<RwLock<CachedEnforcer>>,
    unauthorized_handler: Option<ErrorHandler>,
    forbidden_handler: Option<ErrorHandler>,
    error_handler: Option<ErrorHandler>,
}

impl CasbinService {
    pub async fn new<M: TryIntoModel, A: TryIntoAdapter>(m: M, a: A) -> CasbinResult<Self> {
        let enforcer: CachedEnforcer = CachedEnforcer::new(m, a).await?;
        Ok(CasbinService {
            enforcer: Arc::new(RwLock::new(enforcer)),
            unauthorized_handler: None,
            forbidden_handler: None,
            error_handler: None,
        })
    }

    pub fn get_enforcer(&mut self) -> Arc<RwLock<CachedEnforcer>> {
        self.enforcer.clone()
    }

    pub fn set_enforcer(e: Arc<RwLock<CachedEnforcer>>) -> CasbinService {
        CasbinService {
            enforcer: e,
            unauthorized_handler: None,
            forbidden_handler: None,
            error_handler: None,
        }
    }

    pub fn set_unauthorized_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn() -> HttpResponse + Send + Sync + 'static,
    {
        self.unauthorized_handler = Some(Arc::new(handler));
        self
    }

    pub fn set_forbidden_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn() -> HttpResponse + Send + Sync + 'static,
    {
        self.forbidden_handler = Some(Arc::new(handler));
        self
    }

    pub fn set_error_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn() -> HttpResponse + Send + Sync + 'static,
    {
        self.error_handler = Some(Arc::new(handler));
        self
    }
}

impl<S, B> Transform<S, ServiceRequest> for CasbinService
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = CasbinMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(CasbinMiddleware {
            enforcer: self.enforcer.clone(),
            service: Rc::new(RefCell::new(service)),
            unauthorized_handler: self.unauthorized_handler.clone(),
            forbidden_handler: self.forbidden_handler.clone(),
            error_handler: self.error_handler.clone(),
        })
    }
}

impl Deref for CasbinService {
    type Target = Arc<RwLock<CachedEnforcer>>;

    fn deref(&self) -> &Self::Target {
        &self.enforcer
    }
}

impl DerefMut for CasbinService {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.enforcer
    }
}

pub struct CasbinMiddleware<S> {
    service: Rc<RefCell<S>>,
    enforcer: Arc<RwLock<CachedEnforcer>>,
    unauthorized_handler: Option<ErrorHandler>,
    forbidden_handler: Option<ErrorHandler>,
    error_handler: Option<ErrorHandler>,
}

impl<S, B> Service<ServiceRequest> for CasbinMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let cloned_enforcer = self.enforcer.clone();
        let srv = self.service.clone();
        let unauthorized_handler = self.unauthorized_handler.clone();
        let forbidden_handler = self.forbidden_handler.clone();
        let error_handler = self.error_handler.clone();

        async move {
            let path = req.path().to_string();
            let action = req.method().as_str().to_string();
            let option_vals = req.extensions().get::<CasbinVals>().map(|x| x.to_owned());
            let vals = match option_vals {
                Some(value) => value,
                None => {
                    let response = unauthorized_handler
                        .map(|h| h())
                        .unwrap_or_else(|| HttpResponse::Unauthorized().finish());
                    return Ok(req.into_response(response.map_into_right_body()));
                }
            };
            let subject = vals.subject.clone();

            if !vals.subject.is_empty() {
                if let Some(domain) = vals.domain {
                    let mut lock = cloned_enforcer.write().await;
                    match lock.enforce_mut(vec![subject, domain, path, action]) {
                        Ok(true) => {
                            drop(lock);
                            srv.call(req).await.map(|res| res.map_into_left_body())
                        }
                        Ok(false) => {
                            drop(lock);
                            let response = forbidden_handler
                                .map(|h| h())
                                .unwrap_or_else(|| HttpResponse::Forbidden().finish());
                            Ok(req.into_response(response.map_into_right_body()))
                        }
                        Err(_) => {
                            drop(lock);
                            let response = error_handler
                                .map(|h| h())
                                .unwrap_or_else(|| HttpResponse::BadGateway().finish());
                            Ok(req.into_response(response.map_into_right_body()))
                        }
                    }
                } else {
                    let mut lock = cloned_enforcer.write().await;
                    match lock.enforce_mut(vec![subject, path, action]) {
                        Ok(true) => {
                            drop(lock);
                            srv.call(req).await.map(|res| res.map_into_left_body())
                        }
                        Ok(false) => {
                            drop(lock);
                            let response = forbidden_handler
                                .map(|h| h())
                                .unwrap_or_else(|| HttpResponse::Forbidden().finish());
                            Ok(req.into_response(response.map_into_right_body()))
                        }
                        Err(_) => {
                            drop(lock);
                            let response = error_handler
                                .map(|h| h())
                                .unwrap_or_else(|| HttpResponse::BadGateway().finish());
                            Ok(req.into_response(response.map_into_right_body()))
                        }
                    }
                }
            } else {
                let response = unauthorized_handler
                    .map(|h| h())
                    .unwrap_or_else(|| HttpResponse::Unauthorized().finish());
                Ok(req.into_response(response.map_into_right_body()))
            }
        }
        .boxed_local()
    }
}
