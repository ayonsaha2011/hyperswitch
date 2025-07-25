use actix_web::web;
use router_env::{instrument, tracing};

use super::app;
use crate::{
    core::api_locking,
    services::{api, authentication as auth},
};

mod consts;
mod core;
mod errors;
pub mod types;
mod utils;

#[cfg(all(feature = "dummy_connector", feature = "v1"))]
#[instrument(skip_all, fields(flow = ?types::Flow::DummyPaymentCreate))]
pub async fn dummy_connector_authorize_payment(
    state: web::Data<app::AppState>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
) -> impl actix_web::Responder {
    let flow = types::Flow::DummyPaymentAuthorize;
    let attempt_id = path.into_inner();
    let payload = types::DummyConnectorPaymentConfirmRequest { attempt_id };
    api::server_wrap(
        flow,
        state,
        &req,
        payload,
        |state, _: (), req, _| core::payment_authorize(state, req),
        &auth::NoAuth,
        api_locking::LockAction::NotApplicable,
    )
    .await
}

#[cfg(all(feature = "dummy_connector", feature = "v1"))]
#[instrument(skip_all, fields(flow = ?types::Flow::DummyPaymentCreate))]
pub async fn dummy_connector_complete_payment(
    state: web::Data<app::AppState>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
    json_payload: web::Query<types::DummyConnectorPaymentCompleteBody>,
) -> impl actix_web::Responder {
    let flow = types::Flow::DummyPaymentComplete;
    let attempt_id = path.into_inner();
    let payload = types::DummyConnectorPaymentCompleteRequest {
        attempt_id,
        confirm: json_payload.confirm,
    };
    Box::pin(api::server_wrap(
        flow,
        state,
        &req,
        payload,
        |state, _: (), req, _| core::payment_complete(state, req),
        &auth::NoAuth,
        api_locking::LockAction::NotApplicable,
    ))
    .await
}

#[cfg(feature = "dummy_connector")]
#[instrument(skip_all, fields(flow = ?types::Flow::DummyPaymentCreate))]
pub async fn dummy_connector_payment(
    state: web::Data<app::AppState>,
    req: actix_web::HttpRequest,
    json_payload: web::Json<types::DummyConnectorPaymentRequest>,
) -> impl actix_web::Responder {
    let payload = json_payload.into_inner();
    let flow = types::Flow::DummyPaymentCreate;
    Box::pin(api::server_wrap(
        flow,
        state,
        &req,
        payload,
        |state, _: (), req, _| core::payment(state, req),
        &auth::NoAuth,
        api_locking::LockAction::NotApplicable,
    ))
    .await
}

#[cfg(feature = "dummy_connector")]
#[instrument(skip_all, fields(flow = ?types::Flow::DummyPaymentRetrieve))]
pub async fn dummy_connector_payment_data(
    state: web::Data<app::AppState>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
) -> impl actix_web::Responder {
    let flow = types::Flow::DummyPaymentRetrieve;
    let payment_id = path.into_inner();
    let payload = types::DummyConnectorPaymentRetrieveRequest { payment_id };
    api::server_wrap(
        flow,
        state,
        &req,
        payload,
        |state, _: (), req, _| core::payment_data(state, req),
        &auth::NoAuth,
        api_locking::LockAction::NotApplicable,
    )
    .await
}

#[cfg(all(feature = "dummy_connector", feature = "v1"))]
#[instrument(skip_all, fields(flow = ?types::Flow::DummyRefundCreate))]
pub async fn dummy_connector_refund(
    state: web::Data<app::AppState>,
    req: actix_web::HttpRequest,
    json_payload: web::Json<types::DummyConnectorRefundRequest>,
    path: web::Path<common_utils::id_type::PaymentId>,
) -> impl actix_web::Responder {
    let flow = types::Flow::DummyRefundCreate;
    let mut payload = json_payload.into_inner();
    payload.payment_id = Some(path.into_inner());
    Box::pin(api::server_wrap(
        flow,
        state,
        &req,
        payload,
        |state, _: (), req, _| core::refund_payment(state, req),
        &auth::NoAuth,
        api_locking::LockAction::NotApplicable,
    ))
    .await
}

#[cfg(all(feature = "dummy_connector", feature = "v1"))]
#[instrument(skip_all, fields(flow = ?types::Flow::DummyRefundRetrieve))]
pub async fn dummy_connector_refund_data(
    state: web::Data<app::AppState>,
    req: actix_web::HttpRequest,
    path: web::Path<String>,
) -> impl actix_web::Responder {
    let flow = types::Flow::DummyRefundRetrieve;
    let refund_id = path.into_inner();
    let payload = types::DummyConnectorRefundRetrieveRequest { refund_id };
    api::server_wrap(
        flow,
        state,
        &req,
        payload,
        |state, _: (), req, _| core::refund_data(state, req),
        &auth::NoAuth,
        api_locking::LockAction::NotApplicable,
    )
    .await
}
