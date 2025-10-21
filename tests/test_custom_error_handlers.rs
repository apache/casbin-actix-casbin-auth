use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{
    body::MessageBody, dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage, HttpResponse,
};
use futures::future::{ok, Future, Ready};
use serde_json::json;

use actix_casbin_auth::{CasbinService, CasbinVals};

use actix_web::{test, web, App};
use casbin::{CoreApi, DefaultModel, FileAdapter};

pub struct FakeAuth;

impl<S, B> Transform<S, ServiceRequest> for FakeAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = FakeAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(FakeAuthMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct FakeAuthMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S, B> Service<ServiceRequest> for FakeAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            let vals = CasbinVals {
                subject: String::from("alice"),
                domain: None,
            };
            req.extensions_mut().insert(vals);
            svc.call(req).await
        })
    }
}

pub struct NoAuth;

impl<S, B> Transform<S, ServiceRequest> for NoAuth
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = NoAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(NoAuthMiddleware {
            service: Rc::new(RefCell::new(service)),
        })
    }
}

pub struct NoAuthMiddleware<S> {
    service: Rc<RefCell<S>>,
}

impl<S, B> Service<ServiceRequest> for NoAuthMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();

        Box::pin(async move {
            // Don't insert CasbinVals - this will trigger unauthorized error
            svc.call(req).await
        })
    }
}

#[actix_rt::test]
async fn test_custom_forbidden_handler() {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinService::new(m, a)
        .await
        .unwrap()
        .set_forbidden_handler(|| {
            HttpResponse::Forbidden()
                .json(json!({
                    "error": "Access forbidden",
                    "code": 403
                }))
        });

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(casbin::function_map::key_match2), None);

    let mut app = test::init_service(
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(FakeAuth)
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/data/1", web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    // alice can access /pen/1 - should succeed
    let req_pen = test::TestRequest::get().uri("/pen/1").to_request();
    let resp_pen = test::call_service(&mut app, req_pen).await;
    assert!(resp_pen.status().is_success());

    // alice cannot access /data/1 (no permission) - should trigger custom forbidden handler
    let req_data = test::TestRequest::get().uri("/data/1").to_request();
    let resp_data = test::call_service(&mut app, req_data).await;
    assert_eq!(resp_data.status().as_u16(), 403);
}

#[actix_rt::test]
async fn test_custom_unauthorized_handler() {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinService::new(m, a)
        .await
        .unwrap()
        .set_unauthorized_handler(|| {
            HttpResponse::Unauthorized()
                .json(json!({
                    "error": "Authentication required",
                    "code": 401
                }))
        });

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(casbin::function_map::key_match2), None);

    let mut app = test::init_service(
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(NoAuth)
            .route("/pen/1", web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    // No CasbinVals provided - should trigger custom unauthorized handler
    let req_pen = test::TestRequest::get().uri("/pen/1").to_request();
    let resp_pen = test::call_service(&mut app, req_pen).await;
    assert_eq!(resp_pen.status().as_u16(), 401);
}

#[actix_rt::test]
async fn test_all_custom_handlers() {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinService::new(m, a)
        .await
        .unwrap()
        .set_unauthorized_handler(|| {
            HttpResponse::Unauthorized()
                .json(json!({
                    "error": "Authentication required",
                    "code": 401
                }))
        })
        .set_forbidden_handler(|| {
            HttpResponse::Forbidden()
                .json(json!({
                    "error": "Access forbidden",
                    "code": 403
                }))
        })
        .set_error_handler(|| {
            HttpResponse::InternalServerError()
                .json(json!({
                    "error": "Internal server error",
                    "code": 500
                }))
        });

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(casbin::function_map::key_match2), None);

    let mut app = test::init_service(
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(FakeAuth)
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/data/1", web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    // alice can access /pen/1 - should succeed
    let req_pen = test::TestRequest::get().uri("/pen/1").to_request();
    let resp_pen = test::call_service(&mut app, req_pen).await;
    assert!(resp_pen.status().is_success());

    // alice cannot access /data/1 - should trigger custom forbidden handler
    let req_data = test::TestRequest::get().uri("/data/1").to_request();
    let resp_data = test::call_service(&mut app, req_data).await;
    assert_eq!(resp_data.status().as_u16(), 403);
}

#[actix_rt::test]
async fn test_default_handlers_still_work() {
    // Test that when no custom handlers are set, the default behavior is preserved
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinService::new(m, a).await.unwrap();

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .matching_fn(Some(casbin::function_map::key_match2), None);

    let mut app = test::init_service(
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(FakeAuth)
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/data/1", web::get().to(|| HttpResponse::Ok())),
    )
    .await;

    // alice can access /pen/1 - should succeed
    let req_pen = test::TestRequest::get().uri("/pen/1").to_request();
    let resp_pen = test::call_service(&mut app, req_pen).await;
    assert!(resp_pen.status().is_success());

    // alice cannot access /data/1 - should return default 403 Forbidden
    let req_data = test::TestRequest::get().uri("/data/1").to_request();
    let resp_data = test::call_service(&mut app, req_data).await;
    assert_eq!(resp_data.status().as_u16(), 403);
}
