pub mod transformers;

use error_stack::ResultExt;
use masking::{ExposeInterface, Mask};


use common_utils::{
    errors::CustomResult,
    ext_traits::BytesExt,
    types::{AmountConvertor, StringMinorUnit, StringMinorUnitForConnector, MinorUnit},
    request::{Method, Request, RequestBuilder, RequestContent},
};

use hyperswitch_domain_models::{
    router_data::{AccessToken, ConnectorAuthType, ErrorResponse, RouterData},
    router_flow_types::{
        access_token_auth::AccessTokenAuth,
        payments::{
            Authorize, Capture, PSync, PaymentMethodToken, Session,
            SetupMandate, Void,
        },
        refunds::{Execute, RSync},
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData,
        PaymentsAuthorizeData, PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData,
        PaymentsSyncData, RefundsData, SetupMandateRequestData, ResponseId,
    },
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{
        PaymentsAuthorizeRouterData,
        PaymentsCaptureRouterData, PaymentsSyncRouterData, RefundSyncRouterData, RefundsRouterData,
    },
};
use hyperswitch_interfaces::{
    api::{self, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration, ConnectorValidation, ConnectorSpecifications},
    configs::Connectors,
    errors,
    events::connector_api_logs::ConnectorEvent,
    types::{self, Response},
    webhooks,
};


use common_enums::enums;
use hyperswitch_domain_models::router_response_types::{ConnectorInfo, SupportedPaymentMethods};
use crate::{
    constants::headers,
    types::ResponseRouterData,
    utils::{self, WalletData},
};
use hyperswitch_domain_models::payment_method_data::PaymentMethodData;

use transformers as demopay;

#[derive(Clone)]
pub struct Demopay {
    amount_converter: &'static (dyn AmountConvertor<Output = StringMinorUnit> + Sync)
}

impl Demopay {
    pub fn new() -> &'static Self {
        &Self {
            amount_converter: &StringMinorUnitForConnector
        }
    }
}

// Helper function to determine payment behavior based on wallet_id
fn get_payment_behavior(wallet_id: &str) -> demopay::DemopayPaymentBehavior {
    match wallet_id {
        "abc" => demopay::DemopayPaymentBehavior::AuthorizeFailCaptureFail,
        "def" => demopay::DemopayPaymentBehavior::AuthorizePassCaptureFail,
        "xyz" => demopay::DemopayPaymentBehavior::AuthorizePassCapturePass,
        _ => demopay::DemopayPaymentBehavior::AuthorizePassCapturePass, // Default behavior
    }
}

// Helper function to create mock response based on wallet_id and operation
fn create_mock_response(wallet_id: &str, operation: &str) -> demopay::DemopayPaymentsResponse {
    let behavior = get_payment_behavior(wallet_id);
    
    match (operation, behavior) {
        ("authorize", demopay::DemopayPaymentBehavior::AuthorizeFailCaptureFail) => {
            router_env::logger::warn!(wallet_id = %wallet_id, "Authorize failed for wallet_id: abc");
            demopay::DemopayPaymentsResponse {
                status: demopay::DemopayPaymentStatus::Failed,
                id: format!("txn_fail_{}", uuid::Uuid::new_v4()),
                message: Some("Authorization failed for wallet_id: abc".to_string()),
            }
        },
        ("authorize", demopay::DemopayPaymentBehavior::AuthorizePassCaptureFail) => {
            router_env::logger::info!(wallet_id = %wallet_id, "Authorize succeeded for wallet_id: def");
            demopay::DemopayPaymentsResponse {
                status: demopay::DemopayPaymentStatus::Succeeded,
                id: format!("txn_success_{}", uuid::Uuid::new_v4()),
                message: Some("Authorization succeeded for wallet_id: def".to_string()),
            }
        },
        ("authorize", demopay::DemopayPaymentBehavior::AuthorizePassCapturePass) => {
            router_env::logger::info!(wallet_id = %wallet_id, "Authorize succeeded for wallet_id: xyz");
            demopay::DemopayPaymentsResponse {
                status: demopay::DemopayPaymentStatus::Succeeded,
                id: format!("txn_success_{}", uuid::Uuid::new_v4()),
                message: Some("Authorization succeeded for wallet_id: xyz".to_string()),
            }
        },
        ("capture", demopay::DemopayPaymentBehavior::AuthorizeFailCaptureFail) => {
            router_env::logger::warn!(wallet_id = %wallet_id, "Capture failed for wallet_id: abc");
            demopay::DemopayPaymentsResponse {
                status: demopay::DemopayPaymentStatus::Failed,
                id: format!("capture_fail_{}", uuid::Uuid::new_v4()),
                message: Some("Capture failed for wallet_id: abc".to_string()),
            }
        },
        ("capture", demopay::DemopayPaymentBehavior::AuthorizePassCaptureFail) => {
            router_env::logger::warn!(wallet_id = %wallet_id, "Capture failed for wallet_id: def");
            demopay::DemopayPaymentsResponse {
                status: demopay::DemopayPaymentStatus::Failed,
                id: format!("capture_fail_{}", uuid::Uuid::new_v4()),
                message: Some("Capture failed for wallet_id: def".to_string()),
            }
        },
        ("capture", demopay::DemopayPaymentBehavior::AuthorizePassCapturePass) => {
            router_env::logger::info!(wallet_id = %wallet_id, "Capture succeeded for wallet_id: xyz");
            demopay::DemopayPaymentsResponse {
                status: demopay::DemopayPaymentStatus::Succeeded,
                id: format!("capture_success_{}", uuid::Uuid::new_v4()),
                message: Some("Capture succeeded for wallet_id: xyz".to_string()),
            }
        },
        _ => {
            router_env::logger::info!(wallet_id = %wallet_id, operation = %operation, "Default success response");
            demopay::DemopayPaymentsResponse {
                status: demopay::DemopayPaymentStatus::Succeeded,
                id: format!("txn_default_{}", uuid::Uuid::new_v4()),
                message: Some("Operation completed successfully".to_string()),
            }
        }
    }
}

impl api::Payment for Demopay {}
impl api::PaymentSession for Demopay {}
impl api::ConnectorAccessToken for Demopay {}
impl api::MandateSetup for Demopay {}
impl api::PaymentAuthorize for Demopay {}
impl api::PaymentSync for Demopay {}
impl api::PaymentCapture for Demopay {}
impl api::PaymentVoid for Demopay {}
impl api::Refund for Demopay {}
impl api::RefundExecute for Demopay {}
impl api::RefundSync for Demopay {}
impl api::PaymentToken for Demopay {}

impl
    ConnectorIntegration<
        PaymentMethodToken,
        PaymentMethodTokenizationData,
        PaymentsResponseData,
    > for Demopay
{
    // Not Implemented (R)
}

impl<Flow, Request, Response> ConnectorCommonExt<Flow, Request, Response> for Demopay
where
    Self: ConnectorIntegration<Flow, Request, Response>,{
    fn build_headers(
        &self,
        req: &RouterData<Flow, Request, Response>,
        _connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        let mut header = vec![(
            headers::CONTENT_TYPE.to_string(),
            self.get_content_type().to_string().into(),
        )];
        let mut api_key = self.get_auth_header(&req.connector_auth_type)?;
        header.append(&mut api_key);
        Ok(header)
    }
}

impl ConnectorCommon for Demopay {
    fn id(&self) -> &'static str {
        "demopay"
    }

    fn get_currency_unit(&self) -> api::CurrencyUnit {
        api::CurrencyUnit::Minor
    }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.demopay.base_url.as_ref()
    }

    fn get_auth_header(&self, auth_type:&ConnectorAuthType)-> CustomResult<Vec<(String,masking::Maskable<String>)>,errors::ConnectorError> {
        let auth =  demopay::DemopayAuthType::try_from(auth_type)
            .change_context(errors::ConnectorError::FailedToObtainAuthType)?;
        Ok(vec![(
            headers::AUTHORIZATION.to_string(),
            format!("Bearer {}", auth.api_key.expose()).into_masked(),
        )])
    }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        let response: demopay::DemopayErrorResponse = res
            .response
            .parse_struct("DemopayErrorResponse")
            .change_context(errors::ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::error!(connector_response=?response, "Demopay error response received");

        Ok(ErrorResponse {
            status_code: res.status_code,
            code: response.code,
            message: response.message,
            reason: response.reason,
            attempt_status: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
        })
    }
}

impl ConnectorValidation for Demopay {
    fn validate_mandate_payment(
        &self,
        _pm_type: Option<enums::PaymentMethodType>,
        pm_data: PaymentMethodData,
    ) -> CustomResult<(), errors::ConnectorError> {
        match pm_data {
            PaymentMethodData::Wallet(_) => Ok(()),
            _ => Err(errors::ConnectorError::NotImplemented(
                "Only wallet payment method is supported".to_string(),
            )
            .into()),
        }
    }

    fn validate_psync_reference_id(
        &self,
        _data: &PaymentsSyncData,
        _is_three_ds: bool,
        _status: enums::AttemptStatus,
        _connector_meta_data: Option<common_utils::pii::SecretSerdeValue>,
    ) -> CustomResult<(), errors::ConnectorError> {
        Ok(())
    }
}

impl
    ConnectorIntegration<
        Session,
        PaymentsSessionData,
        PaymentsResponseData,
    > for Demopay
{
    //TODO: implement sessions flow
}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Demopay {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData> for Demopay {}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Demopay {
    fn get_headers(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/pay", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsAuthorizeRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            req.request.minor_amount,
            req.request.currency,
        )?;

        let connector_router_data = demopay::DemopayRouterData::from((amount, req));
        let connector_req = demopay::DemopayPaymentsRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsAuthorizeRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsAuthorizeType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsAuthorizeType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsAuthorizeType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsAuthorizeRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsAuthorizeRouterData, errors::ConnectorError> {
        // Extract wallet_id for mock response logic
        let wallet_id = if let PaymentMethodData::Wallet(ref wallet_data) = &data.request.payment_method_data {
            wallet_data.get_wallet_token()
                .map(|s| s.expose())
                .unwrap_or_else(|_| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        // For demo purposes, create mock response based on wallet_id
        let mock_response = create_mock_response(&wallet_id, "authorize");
        
        event_builder.map(|i| i.set_response_body(&mock_response));
        router_env::logger::info!(connector_response=?mock_response, "Demopay authorize response created");
        
        RouterData::try_from(ResponseRouterData {
            response: mock_response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Demopay {
    fn get_headers(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let transaction_id = match &req.request.connector_transaction_id {
            ResponseId::ConnectorTransactionId(id) => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };
        Ok(format!("{}/status/{}", self.base_url(connectors), transaction_id))
    }

    fn build_request(
        &self,
        req: &PaymentsSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::PaymentsSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::PaymentsSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsSyncRouterData, errors::ConnectorError> {
        // For sync, return the same status as the original transaction
        let wallet_id = if let Some(meta) = &data.request.connector_meta {
            meta.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("unknown")
        } else {
            "unknown"
        };

        let mock_response = create_mock_response(wallet_id, "sync");
        
        event_builder.map(|i| i.set_response_body(&mock_response));
        router_env::logger::info!(connector_response=?mock_response, "Demopay sync response created");
        
        RouterData::try_from(ResponseRouterData {
            response: mock_response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Demopay {
    fn get_headers(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let _transaction_id = match &req.request.connector_transaction_id {
            id if !id.is_empty() => id.clone(),
            _ => return Err(errors::ConnectorError::MissingConnectorTransactionID.into()),
        };
        Ok(format!("{}/capture", self.base_url(connectors)))
    }

    fn get_request_body(
        &self,
        req: &PaymentsCaptureRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            MinorUnit::new(req.request.amount_to_capture),
            req.request.currency,
        )?;

        let connector_router_data = demopay::DemopayRouterData::from((amount, req));
        let connector_req = demopay::DemopayPaymentsRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(
        &self,
        req: &PaymentsCaptureRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::PaymentsCaptureType::get_url(
                    self, req, connectors,
                )?)
                .attach_default_headers()
                .headers(types::PaymentsCaptureType::get_headers(
                    self, req, connectors,
                )?)
                .set_body(types::PaymentsCaptureType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &PaymentsCaptureRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<PaymentsCaptureRouterData, errors::ConnectorError> {
        // Extract wallet_id from connector metadata
        let wallet_id = if let Some(meta) = &data.request.connector_meta {
            meta.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("unknown")
        } else {
            "unknown"
        };

        // Create mock response based on wallet_id
        let mock_response = create_mock_response(wallet_id, "capture");
        
        event_builder.map(|i| i.set_response_body(&mock_response));
        router_env::logger::info!(connector_response=?mock_response, "Demopay capture response created");
        
        RouterData::try_from(ResponseRouterData {
            response: mock_response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Demopay {}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Demopay {
    fn get_headers(&self, req: &RefundsRouterData<Execute>, connectors: &Connectors,) -> CustomResult<Vec<(String,masking::Maskable<String>)>,errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &RefundsRouterData<Execute>,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        Ok(format!("{}/refund", self.base_url(connectors)))
    }

    fn get_request_body(&self, req: &RefundsRouterData<Execute>, _connectors: &Connectors,) -> CustomResult<RequestContent, errors::ConnectorError> {
        let amount = utils::convert_amount(
            self.amount_converter,
            MinorUnit::new(req.request.refund_amount),
            req.request.currency,
        )?;

        let connector_router_data = demopay::DemopayRouterData::from((amount, req));
        let connector_req = demopay::DemopayRefundRequest::try_from(&connector_router_data)?;
        Ok(RequestContent::Json(Box::new(connector_req)))
    }

    fn build_request(&self, req: &RefundsRouterData<Execute>, connectors: &Connectors,) -> CustomResult<Option<Request>,errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&types::RefundExecuteType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundExecuteType::get_headers(self, req, connectors)?)
                .set_body(types::RefundExecuteType::get_request_body(
                    self, req, connectors,
                )?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundsRouterData<Execute>,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundsRouterData<Execute>, errors::ConnectorError> {
        // Create mock refund response
        let mock_response = demopay::RefundResponse {
            id: format!("refund_{}", uuid::Uuid::new_v4()),
            status: demopay::RefundStatus::Succeeded,
            message: Some("Refund processed successfully".to_string()),
        };
        
        event_builder.map(|i| i.set_response_body(&mock_response));
        router_env::logger::info!(connector_response=?mock_response, "Demopay refund response created");
        
        RouterData::try_from(ResponseRouterData {
            response: mock_response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse,errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Demopay {
    fn get_headers(&self, req: &RefundSyncRouterData,connectors: &Connectors,) -> CustomResult<Vec<(String, masking::Maskable<String>)>, errors::ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, errors::ConnectorError> {
        let refund_id = req.request.connector_refund_id.as_ref().ok_or(errors::ConnectorError::MissingConnectorTransactionID)?.clone();
        Ok(format!("{}/refund/{}", self.base_url(connectors), refund_id))
    }

    fn build_request(
        &self,
        req: &RefundSyncRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, errors::ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Get)
                .url(&types::RefundSyncType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(types::RefundSyncType::get_headers(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &RefundSyncRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<RefundSyncRouterData, errors::ConnectorError> {
        // Create mock refund sync response
        let mock_response = demopay::RefundResponse {
            id: data.request.connector_refund_id.clone().unwrap_or_else(|| format!("refund_sync_{}", uuid::Uuid::new_v4())),
            status: demopay::RefundStatus::Succeeded,
            message: Some("Refund sync completed successfully".to_string()),
        };
        
        event_builder.map(|i| i.set_response_body(&mock_response));
        router_env::logger::info!(connector_response=?mock_response, "Demopay refund sync response created");
        
        RouterData::try_from(ResponseRouterData {
            response: mock_response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(&self, res: Response, event_builder: Option<&mut ConnectorEvent>) -> CustomResult<ErrorResponse,errors::ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl webhooks::IncomingWebhook for Demopay {
    fn get_webhook_object_reference_id(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::ObjectReferenceId, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Webhooks not implemented".to_string()).into())
    }

    fn get_webhook_event_type(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<api_models::webhooks::IncomingWebhookEvent, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Webhooks not implemented".to_string()).into())
    }

    fn get_webhook_resource_object(
        &self,
        _request: &webhooks::IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, errors::ConnectorError> {
        Err(errors::ConnectorError::NotImplemented("Webhooks not implemented".to_string()).into())
    }
}

impl ConnectorSpecifications for Demopay {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        None
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        None
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [enums::EventClass]> {
        None
    }
}
