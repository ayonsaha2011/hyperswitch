use hyperswitch_domain_models::payment_method_data::{Card, PaymentMethodData, WalletData};
use masking::Secret;
use router::types::{self, api, storage::enums};
use test_utils::connector_auth;

use crate::utils::{self, ConnectorActions};

#[derive(Clone, Copy)]
struct DemopayTest;
impl ConnectorActions for DemopayTest {}
impl utils::Connector for DemopayTest {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Demopay;
        utils::construct_connector_data_old(
            Box::new(Demopay::new()),
            types::Connector::Demopay,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        utils::to_connector_auth_type(
            connector_auth::ConnectorAuthentication::new()
                .demopay
                .expect("Missing connector authentication configuration")
                .into(),
        )
    }

    fn get_name(&self) -> String {
        "demopay".to_string()
    }
}

static CONNECTOR: DemopayTest = DemopayTest {};

fn get_default_payment_info() -> Option<utils::PaymentInfo> {
    None
}

fn payment_method_details(wallet_id: &str) -> Option<types::PaymentsAuthorizeData> {
    Some(types::PaymentsAuthorizeData {
        payment_method_data: PaymentMethodData::Wallet(WalletData {
            wallet_token: Secret::new(wallet_id.to_string()),
        }),
        ..Default::default()
    })
}

// Test wallet_id "abc" - Authorize fail and capture fail
#[actix_web::test]
async fn should_fail_authorize_for_wallet_abc() {
    let response = CONNECTOR
        .authorize_payment(payment_method_details("abc"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    assert_eq!(response.status, enums::AttemptStatus::Failure);
}

#[actix_web::test]
async fn should_fail_capture_for_wallet_abc() {
    // First authorize with a different wallet_id to get a successful authorization
    let auth_response = CONNECTOR
        .authorize_payment(payment_method_details("xyz"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
    
    // Then try to capture with wallet_id "abc" which should fail
    let txn_id = utils::get_connector_transaction_id(auth_response.response).unwrap();
    let response = CONNECTOR
        .capture_payment(
            Some(types::PaymentsCaptureData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(txn_id),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Capture payment response");
    assert_eq!(response.status, enums::AttemptStatus::Failure);
}

// Test wallet_id "def" - Authorize pass and capture fail
#[actix_web::test]
async fn should_pass_authorize_for_wallet_def() {
    let response = CONNECTOR
        .authorize_payment(payment_method_details("def"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    assert_eq!(response.status, enums::AttemptStatus::Authorized);
}

#[actix_web::test]
async fn should_fail_capture_for_wallet_def() {
    let auth_response = CONNECTOR
        .authorize_payment(payment_method_details("def"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
    
    let txn_id = utils::get_connector_transaction_id(auth_response.response).unwrap();
    let response = CONNECTOR
        .capture_payment(
            Some(types::PaymentsCaptureData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(txn_id),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Capture payment response");
    assert_eq!(response.status, enums::AttemptStatus::Failure);
}

// Test wallet_id "xyz" - Authorize pass and capture success
#[actix_web::test]
async fn should_pass_authorize_for_wallet_xyz() {
    let response = CONNECTOR
        .authorize_payment(payment_method_details("xyz"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    assert_eq!(response.status, enums::AttemptStatus::Authorized);
}

#[actix_web::test]
async fn should_pass_capture_for_wallet_xyz() {
    let auth_response = CONNECTOR
        .authorize_payment(payment_method_details("xyz"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
    
    let txn_id = utils::get_connector_transaction_id(auth_response.response).unwrap();
    let response = CONNECTOR
        .capture_payment(
            Some(types::PaymentsCaptureData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(txn_id),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Capture payment response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

// Test complete flow for wallet_id "xyz"
#[actix_web::test]
async fn should_complete_payment_flow_for_wallet_xyz() {
    let response = CONNECTOR
        .authorize_and_capture_payment(payment_method_details("xyz"), None, get_default_payment_info())
        .await
        .expect("Payment response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

// Test refund functionality
#[actix_web::test]
async fn should_refund_payment() {
    let response = CONNECTOR
        .capture_payment_and_refund(
            payment_method_details("xyz"),
            None,
            None,
            get_default_payment_info(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}

// Test payment status check
#[actix_web::test]
async fn should_sync_payment_status() {
    let authorize_response = CONNECTOR
        .authorize_payment(payment_method_details("xyz"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    let txn_id = utils::get_connector_transaction_id(authorize_response.response);
    let response = CONNECTOR
        .psync_retry_till_status_matches(
            enums::AttemptStatus::Authorized,
            Some(types::PaymentsSyncData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(
                    txn_id.unwrap(),
                ),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("PSync response");
    assert_eq!(response.status, enums::AttemptStatus::Authorized,);
}

// Test void functionality
#[actix_web::test]
async fn should_void_authorized_payment() {
    let response = CONNECTOR
        .authorize_and_void_payment(
            payment_method_details("xyz"),
            Some(types::PaymentsCancelData {
                connector_transaction_id: String::from(""),
                cancellation_reason: Some("requested_by_customer".to_string()),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Void payment response");
    assert_eq!(response.status, enums::AttemptStatus::Voided);
}

// Test partial capture
#[actix_web::test]
async fn should_partially_capture_authorized_payment() {
    let response = CONNECTOR
        .authorize_and_capture_payment(
            payment_method_details("xyz"),
            Some(types::PaymentsCaptureData {
                amount_to_capture: 50,
                ..utils::PaymentCaptureType::default().0
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Capture payment response");
    assert_eq!(response.status, enums::AttemptStatus::Charged);
}

// Test partial refund
#[actix_web::test]
async fn should_partially_refund_manually_captured_payment() {
    let response = CONNECTOR
        .capture_payment_and_refund(
            payment_method_details("xyz"),
            None,
            Some(types::RefundsData {
                refund_amount: 50,
                ..utils::PaymentRefundType::default().0
            }),
            get_default_payment_info(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}

// Test automatic capture flow
#[actix_web::test]
async fn should_make_payment_with_auto_capture() {
    let authorize_response = CONNECTOR
        .make_payment(payment_method_details("xyz"), get_default_payment_info())
        .await
        .unwrap();
    assert_eq!(authorize_response.status, enums::AttemptStatus::Charged);
}

// Test refund sync
#[actix_web::test]
async fn should_sync_refund() {
    let refund_response = CONNECTOR
        .capture_payment_and_refund(
            payment_method_details("xyz"),
            None,
            None,
            get_default_payment_info(),
        )
        .await
        .unwrap();
    let response = CONNECTOR
        .rsync_retry_till_status_matches(
            enums::RefundStatus::Success,
            refund_response.response.unwrap().connector_refund_id,
            None,
            get_default_payment_info(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}
