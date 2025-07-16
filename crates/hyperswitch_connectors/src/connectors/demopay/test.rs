#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::connectors::demopay::transformers::{DemopayPaymentsRequest, DemopayPaymentsResponse, DemopayPaymentStatus, DemopayRouterData};
    use common_enums::Currency;
    use common_utils::types::StringMinorUnit;
    use hyperswitch_domain_models::router_request_types::PaymentsAuthorizeData;
    use hyperswitch_domain_models::types::PaymentsAuthorizeRouterData;
    use hyperswitch_domain_models::payment_method_data::PaymentMethodData;
    use masking::Secret;

    fn make_wallet_data(wallet_id: &str) -> PaymentMethodData {
        PaymentMethodData::Wallet(api_models::payment_methods::WalletData {
            wallet_token: Secret::new(wallet_id.to_string()),
            wallet_type: None,
        })
    }

    fn make_auth_data(wallet_id: &str) -> PaymentsAuthorizeRouterData {
        PaymentsAuthorizeRouterData {
            flow: hyperswitch_domain_models::router_flow_types::payments::Authorize,
            merchant_id: "test_merchant".to_string(),
            connector_request_reference_id: "test_ref".to_string(),
            request: PaymentsAuthorizeData {
                amount: 1000,
                minor_amount: StringMinorUnit::from(1000),
                currency: Currency::USD,
                payment_method_data: make_wallet_data(wallet_id),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_authorize_wallet_id_abc() {
        let data = make_auth_data("abc");
        let wallet_id = "abc";
        let resp = super::create_mock_response(wallet_id, "authorize");
        assert_eq!(resp.status, DemopayPaymentStatus::Failed);
        assert!(resp.message.unwrap().contains("failed"));
    }

    #[test]
    fn test_authorize_wallet_id_def() {
        let data = make_auth_data("def");
        let wallet_id = "def";
        let resp = super::create_mock_response(wallet_id, "authorize");
        assert_eq!(resp.status, DemopayPaymentStatus::Succeeded);
        assert!(resp.message.unwrap().contains("succeeded"));
    }

    #[test]
    fn test_authorize_wallet_id_xyz() {
        let data = make_auth_data("xyz");
        let wallet_id = "xyz";
        let resp = super::create_mock_response(wallet_id, "authorize");
        assert_eq!(resp.status, DemopayPaymentStatus::Succeeded);
        assert!(resp.message.unwrap().contains("succeeded"));
    }

    #[test]
    fn test_capture_wallet_id_abc() {
        let wallet_id = "abc";
        let resp = super::create_mock_response(wallet_id, "capture");
        assert_eq!(resp.status, DemopayPaymentStatus::Failed);
        assert!(resp.message.unwrap().contains("failed"));
    }

    #[test]
    fn test_capture_wallet_id_def() {
        let wallet_id = "def";
        let resp = super::create_mock_response(wallet_id, "capture");
        assert_eq!(resp.status, DemopayPaymentStatus::Failed);
        assert!(resp.message.unwrap().contains("failed"));
    }

    #[test]
    fn test_capture_wallet_id_xyz() {
        let wallet_id = "xyz";
        let resp = super::create_mock_response(wallet_id, "capture");
        assert_eq!(resp.status, DemopayPaymentStatus::Succeeded);
        assert!(resp.message.unwrap().contains("succeeded"));
    }
} 