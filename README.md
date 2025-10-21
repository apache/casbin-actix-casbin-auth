# Actix Casbin Middleware

[![Crates.io](https://img.shields.io/crates/d/actix-casbin-auth)](https://crates.io/crates/actix-casbin-auth)
[![Docs](https://docs.rs/actix-casbin-auth/badge.svg)](https://docs.rs/actix-casbin-auth)
[![CI](https://github.com/casbin-rs/actix-casbin-auth/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin-rs/actix-casbin-auth/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/casbin-rs/actix-casbin-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/casbin-rs/actix-casbin-auth)

[Casbin](https://github.com/casbin/casbin-rs) access control middleware for [actix-web](https://github.com/actix/actix-web) framework

## Install

Add dependencies

```bash
cargo add actix-rt
cargo add actix-web
cargo add actix-casbin --no-default-features --features runtime-async-std
cargo add actix-casbin-auth --no-default-features --features runtime-async-std
```

## Requirement

**Casbin only takes charge of permission control**, so you need to implement an `Authentication Middleware` to identify user.

You should put `actix_casbin_auth::CasbinVals` which contains `subject`(username) and `domain`(optional) into [Extension](https://docs.rs/actix-web/2.0.0/actix_web/dev/struct.Extensions.html).

For example:

```rust
use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::{dev::ServiceRequest, dev::ServiceResponse, Error, HttpMessage};
use futures::future::{ok, Future, Ready};

use actix_casbin_auth::CasbinVals;


pub struct FakeAuth;

impl<S: 'static, B> Transform<S> for FakeAuth
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
        S::Future: 'static,
        B: 'static,
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

impl<S, B> Service for FakeAuthMiddleware<S>
    where
        S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
        S::Future: 'static,
        B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        let mut svc = self.service.clone();

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
````


## Example

```rust
use actix_casbin_auth::casbin::{DefaultModel, FileAdapter, Result};
use actix_casbin_auth::CasbinService;
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_casbin_auth::casbin::function_map::key_match2;

#[allow(dead_code)]
mod fake_auth;

#[actix_rt::main]
async fn main() -> Result<()> {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");  //You can also use diesel-adapter or sqlx-adapter

    let casbin_middleware = CasbinService::new(m, a).await?;

    casbin_middleware
        .write()
        .await
        .get_role_manager()
        .write()
        .unwrap()
        .matching_fn(Some(key_match2), None);

    HttpServer::new(move || {
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(FakeAuth)          
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/book/{id}", web::get().to(|| HttpResponse::Ok()))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;

    Ok(())
}
```

## Customizing Error Responses

By default, the middleware returns the following HTTP status codes:
- `401 Unauthorized` - when no `CasbinVals` are found in request extensions
- `403 Forbidden` - when access is denied by Casbin enforcer
- `502 Bad Gateway` - when the Casbin enforcer returns an error

You can customize these error responses to return structured JSON or any other format:

```rust
use actix_casbin_auth::casbin::{DefaultModel, FileAdapter, Result};
use actix_casbin_auth::CasbinService;
use actix_web::{web, App, HttpResponse, HttpServer};
use serde_json::json;

#[actix_rt::main]
async fn main() -> Result<()> {
    let m = DefaultModel::from_file("examples/rbac_with_pattern_model.conf")
        .await
        .unwrap();
    let a = FileAdapter::new("examples/rbac_with_pattern_policy.csv");

    let casbin_middleware = CasbinService::new(m, a)
        .await?
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

    HttpServer::new(move || {
        App::new()
            .wrap(casbin_middleware.clone())
            .wrap(FakeAuth)
            .route("/pen/1", web::get().to(|| HttpResponse::Ok()))
            .route("/book/{id}", web::get().to(|| HttpResponse::Ok()))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await?;

    Ok(())
}
```

## License

This project is licensed under

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0))
