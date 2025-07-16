use hyperswitch_domain_models::payment_method_data::{PaymentMethodData, WalletData};
use masking::Secret;
use router::types::{self, api, storage::enums};
use test_utils::connector_auth;
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

use crate::utils::{self, ConnectorActions};

#[derive(Clone, Copy)]
struct DemopayIntegrationTest;
impl ConnectorActions for DemopayIntegrationTest {}
impl utils::Connector for DemopayIntegrationTest {
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

static CONNECTOR: DemopayIntegrationTest = DemopayIntegrationTest {};

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

// Helper function to wait for the mock server to be ready
async fn wait_for_server() {
    let client = Client::new();
    let mut retries = 0;
    while retries < 30 {
        match client.get("http://localhost:3005/health").send().await {
            Ok(response) => {
                if response.status().is_success() {
                    println!("Mock server is ready");
                    return;
                }
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        retries += 1;
    }
    panic!("Mock server did not start within 3 seconds");
}

// Test the complete flow with the mock server
#[actix_web::test]
async fn test_complete_payment_flow_with_mock_server() {
    // Wait for the mock server to be ready
    wait_for_server().await;

    // Test wallet_id "xyz" - should succeed
    let response = CONNECTOR
        .authorize_and_capture_payment(payment_method_details("xyz"), None, get_default_payment_info())
        .await
        .expect("Payment response");
    
    assert_eq!(response.status, enums::AttemptStatus::Charged);
    
    // Verify the transaction was created in the mock server
    let client = Client::new();
    let txn_id = utils::get_connector_transaction_id(response.response).unwrap();
    
    let status_response = client
        .get(&format!("http://localhost:3005/status/{}", txn_id))
        .header("Authorization", "Bearer test_token")
        .send()
        .await
        .expect("Status request failed");
    
    assert!(status_response.status().is_success());
}

#[actix_web::test]
async fn test_wallet_abc_authorize_failure() {
    wait_for_server().await;

    let response = CONNECTOR
        .authorize_payment(payment_method_details("abc"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    
    assert_eq!(response.status, enums::AttemptStatus::Failure);
}

#[actix_web::test]
async fn test_wallet_def_authorize_success_capture_failure() {
    wait_for_server().await;

    // Authorize should succeed
    let auth_response = CONNECTOR
        .authorize_payment(payment_method_details("def"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    
    assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
    
    // Capture should fail
    let txn_id = utils::get_connector_transaction_id(auth_response.response).unwrap();
    let capture_response = CONNECTOR
        .capture_payment(
            Some(types::PaymentsCaptureData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(txn_id),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Capture payment response");
    
    assert_eq!(capture_response.status, enums::AttemptStatus::Failure);
}

#[actix_web::test]
async fn test_wallet_xyz_full_success() {
    wait_for_server().await;

    // Authorize should succeed
    let auth_response = CONNECTOR
        .authorize_payment(payment_method_details("xyz"), get_default_payment_info())
        .await
        .expect("Authorize payment response");
    
    assert_eq!(auth_response.status, enums::AttemptStatus::Authorized);
    
    // Capture should succeed
    let txn_id = utils::get_connector_transaction_id(auth_response.response).unwrap();
    let capture_response = CONNECTOR
        .capture_payment(
            Some(types::PaymentsCaptureData {
                connector_transaction_id: types::ResponseId::ConnectorTransactionId(txn_id),
                ..Default::default()
            }),
            get_default_payment_info(),
        )
        .await
        .expect("Capture payment response");
    
    assert_eq!(capture_response.status, enums::AttemptStatus::Charged);
}

#[actix_web::test]
async fn test_refund_flow() {
    wait_for_server().await;

    // First capture a payment
    let capture_response = CONNECTOR
        .authorize_and_capture_payment(payment_method_details("xyz"), None, get_default_payment_info())
        .await
        .expect("Capture payment response");
    
    assert_eq!(capture_response.status, enums::AttemptStatus::Charged);
    
    // Then refund it
    let refund_response = CONNECTOR
        .capture_payment_and_refund(
            payment_method_details("xyz"),
            None,
            None,
            get_default_payment_info(),
        )
        .await
        .unwrap();
    
    assert_eq!(
        refund_response.response.unwrap().refund_status,
        enums::RefundStatus::Success,
    );
}

#[actix_web::test]
async fn test_payment_status_sync() {
    wait_for_server().await;

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
    
    assert_eq!(response.status, enums::AttemptStatus::Authorized);
}

#[actix_web::test]
async fn test_void_payment() {
    wait_for_server().await;

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

#[actix_web::test]
async fn test_partial_capture() {
    wait_for_server().await;

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

#[actix_web::test]
async fn test_partial_refund() {
    wait_for_server().await;

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

// Test direct API calls to verify mock server behavior
#[actix_web::test]
async fn test_mock_server_direct_api_calls() {
    wait_for_server().await;
    
    let client = Client::new();
    let base_url = "http://localhost:3005";
    
    // Test authorize with wallet_id "abc" (should fail)
    let auth_response = client
        .post(&format!("{}/pay", base_url))
        .header("Authorization", "Bearer test_token")
        .header("Content-Type", "application/json")
        .json(&json!({
            "amount": 1000,
            "currency": "USD",
            "wallet_id": "abc",
            "reference": "test_order_abc"
        }))
        .send()
        .await
        .expect("Authorize request failed");
    
    assert_eq!(auth_response.status().as_u16(), 400);
    
    // Test authorize with wallet_id "xyz" (should succeed)
    let auth_response = client
        .post(&format!("{}/pay", base_url))
        .header("Authorization", "Bearer test_token")
        .header("Content-Type", "application/json")
        .json(&json!({
            "amount": 1000,
            "currency": "USD",
            "wallet_id": "xyz",
            "reference": "test_order_xyz"
        }))
        .send()
        .await
        .expect("Authorize request failed");
    
    assert_eq!(auth_response.status().as_u16(), 200);
    
    let auth_data: serde_json::Value = auth_response.json().await.expect("Failed to parse response");
    let transaction_id = auth_data["data"]["id"].as_str().unwrap();
    
    // Test capture (should succeed for wallet_id "xyz")
    let capture_response = client
        .post(&format!("{}/capture/{}", base_url, transaction_id))
        .header("Authorization", "Bearer test_token")
        .header("Content-Type", "application/json")
        .json(&json!({
            "amount": 1000
        }))
        .send()
        .await
        .expect("Capture request failed");
    
    assert_eq!(capture_response.status().as_u16(), 200);
    
    // Test status check
    let status_response = client
        .get(&format!("{}/status/{}", base_url, transaction_id))
        .header("Authorization", "Bearer test_token")
        .send()
        .await
        .expect("Status request failed");
    
    assert_eq!(status_response.status().as_u16(), 200);
    
    // Test refund
    let refund_response = client
        .post(&format!("{}/refund/{}", base_url, transaction_id))
        .header("Authorization", "Bearer test_token")
        .header("Content-Type", "application/json")
        .json(&json!({
            "amount": 1000
        }))
        .send()
        .await
        .expect("Refund request failed");
    
    assert_eq!(refund_response.status().as_u16(), 200);
} 