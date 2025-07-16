use common_enums::enums;
use serde::{Deserialize, Serialize};
use masking::{Secret, ExposeInterface, PeekInterface};
use common_utils::types::{StringMinorUnit};
use router_env;
use hyperswitch_domain_models::{
    payment_method_data::PaymentMethodData,
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::{payments::{Capture, PSync}, refunds::{Execute, RSync}},
    router_request_types::{PaymentsCaptureData, PaymentsSyncData, ResponseId},
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use crate::types::{RefundsResponseRouterData, ResponseRouterData};
use crate::utils::{WalletData, PaymentsAuthorizeRequestData};

pub struct DemopayRouterData<T> {
    pub amount: StringMinorUnit,
    pub router_data: T,
}

impl<T>
    From<(
        StringMinorUnit,
        T,
    )> for DemopayRouterData<T>
{
    fn from(
        (amount, item): (
            StringMinorUnit,
            T,
        ),
    ) -> Self {
        Self {
            amount,
            router_data: item,
        }
    }
}

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct DemopayPaymentsRequest {
    amount: StringMinorUnit,
    wallet_id: String,
    currency: common_enums::Currency,
    reference: String,
}

// Helper function to determine payment behavior based on wallet_id
fn get_payment_behavior(wallet_id: &str) -> DemopayPaymentBehavior {
    match wallet_id {
        "abc" => DemopayPaymentBehavior::AuthorizeFailCaptureFail,
        "def" => DemopayPaymentBehavior::AuthorizePassCaptureFail,
        "xyz" => DemopayPaymentBehavior::AuthorizePassCapturePass,
        _ => DemopayPaymentBehavior::AuthorizePassCapturePass, // Default behavior
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum DemopayPaymentBehavior {
    AuthorizeFailCaptureFail,
    AuthorizePassCaptureFail,
    AuthorizePassCapturePass,
}

impl TryFrom<&DemopayRouterData<&PaymentsAuthorizeRouterData>> for DemopayPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &DemopayRouterData<&PaymentsAuthorizeRouterData>) -> Result<Self, Self::Error> {
        match item.router_data.request.payment_method_data.clone() {
            PaymentMethodData::Wallet(ref wallet_data) => {
                // Extract wallet_id from wallet data
                let wallet_id = wallet_data.get_wallet_token()
                    .map(|s| s.expose())
                    .map_err(|_| errors::ConnectorError::MissingRequiredField { field_name: "wallet_id" })?;
                
                // Log the wallet_id for debugging
                router_env::logger::info!(wallet_id = %wallet_id, "Processing payment with wallet_id");
                
                Ok(Self {
                    amount: item.amount.to_owned(),
                    wallet_id,
                    currency: item.router_data.request.currency,
                    reference: item.router_data.connector_request_reference_id.clone(),
                })
            },
            _ => Err(errors::ConnectorError::NotImplemented("Only wallet payment method is supported".to_string()).into()),
        }
    }
}

// Implement TryFrom for PaymentsCaptureRouterData
impl TryFrom<&DemopayRouterData<&PaymentsCaptureRouterData>> for DemopayPaymentsRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &DemopayRouterData<&PaymentsCaptureRouterData>) -> Result<Self, Self::Error> {
        let wallet_id = item.router_data.request.connector_meta.as_ref()
            .and_then(|meta| meta.get("wallet_id").and_then(|v| v.as_str().map(|s| s.to_string())))
            .unwrap_or_else(|| "demo_wallet_id".to_string());
        
        // Log the wallet_id for debugging
        router_env::logger::info!(wallet_id = %wallet_id, "Processing capture with wallet_id");
        
        Ok(Self {
            amount: item.amount.to_owned(),
            wallet_id,
            currency: item.router_data.request.currency,
            reference: item.router_data.connector_request_reference_id.clone(),
        })
    }
}

// Auth Struct
pub struct DemopayAuthType {
    pub(super) api_key: Secret<String>
}

impl TryFrom<&ConnectorAuthType> for DemopayAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}

// PaymentsResponse
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DemopayPaymentStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<DemopayPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: DemopayPaymentStatus) -> Self {
        match item {
            DemopayPaymentStatus::Succeeded => Self::Charged,
            DemopayPaymentStatus::Failed => Self::Failure,
            DemopayPaymentStatus::Processing => Self::Authorizing,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DemopayPaymentsResponse {
    pub status: DemopayPaymentStatus,
    pub id: String,
    pub message: Option<String>,
}

impl<F,T: PaymentsAuthorizeRequestData> TryFrom<ResponseRouterData<F, DemopayPaymentsResponse, T, PaymentsResponseData>> for RouterData<F, T, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<F, DemopayPaymentsResponse, T, PaymentsResponseData>) -> Result<Self,Self::Error> {
        // Extract wallet_id from the request for logging
        let meta_binding = item.data.request.get_metadata_as_object();
        let wallet_id = if let Some(meta) = &meta_binding {
            meta.peek().get("wallet_id").and_then(|v| v.as_str()).unwrap_or("unknown")
        } else {
            "unknown"
        };
        
        // Log the response status
        router_env::logger::info!(
            wallet_id = %wallet_id,
            status = ?item.response.status,
            transaction_id = %item.response.id,
            "Payment response received"
        );
        
        Ok(Self {
            status: common_enums::AttemptStatus::from(item.response.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: Some(serde_json::json!({
                    "wallet_id": wallet_id,
                    "demopay_transaction_id": item.response.id
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// TryFrom implementation for PSync flow
impl TryFrom<ResponseRouterData<PSync, DemopayPaymentsResponse, PaymentsSyncData, PaymentsResponseData>> for RouterData<PSync, PaymentsSyncData, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<PSync, DemopayPaymentsResponse, PaymentsSyncData, PaymentsResponseData>) -> Result<Self,Self::Error> {
        // Extract wallet_id from the request for logging
        let wallet_id = if let Some(meta) = &item.data.request.connector_meta {
            meta.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("unknown")
        } else {
            "unknown"
        };
        
        // Log the response status
        router_env::logger::info!(
            wallet_id = %wallet_id,
            status = ?item.response.status,
            transaction_id = %item.response.id,
            "Payment sync response received"
        );
        
        Ok(Self {
            status: common_enums::AttemptStatus::from(item.response.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: Some(serde_json::json!({
                    "wallet_id": wallet_id,
                    "demopay_transaction_id": item.response.id
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// TryFrom implementation for Capture flow
impl TryFrom<ResponseRouterData<Capture, DemopayPaymentsResponse, PaymentsCaptureData, PaymentsResponseData>> for RouterData<Capture, PaymentsCaptureData, PaymentsResponseData> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: ResponseRouterData<Capture, DemopayPaymentsResponse, PaymentsCaptureData, PaymentsResponseData>) -> Result<Self,Self::Error> {
        // Extract wallet_id from the request for logging
        let wallet_id = if let Some(meta) = &item.data.request.connector_meta {
            meta.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("unknown")
        } else {
            "unknown"
        };
        
        // Log the response status
        router_env::logger::info!(
            wallet_id = %wallet_id,
            status = ?item.response.status,
            transaction_id = %item.response.id,
            "Payment capture response received"
        );
        
        Ok(Self {
            status: common_enums::AttemptStatus::from(item.response.status),
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(item.response.id.clone()),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: Some(serde_json::json!({
                    "wallet_id": wallet_id,
                    "demopay_transaction_id": item.response.id
                })),
                network_txn_id: None,
                connector_response_reference_id: Some(item.response.id),
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

// REFUND :
// Type definition for RefundRequest
#[derive(Default, Debug, Serialize)]
pub struct DemopayRefundRequest {
    pub amount: StringMinorUnit,
    pub transaction_id: String,
}

impl<F> TryFrom<&DemopayRouterData<&RefundsRouterData<F>>> for DemopayRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &DemopayRouterData<&RefundsRouterData<F>>) -> Result<Self,Self::Error> {
        let transaction_id = item.router_data.request.connector_transaction_id.clone();
        
        // Log refund request
        router_env::logger::info!(
            transaction_id = %transaction_id,
            amount = %item.amount,
            "Processing refund request"
        );
        
        Ok(Self {
            amount: item.amount.to_owned(),
            transaction_id,
        })
    }
}

// Type definition for Refund Response
#[allow(dead_code)]
#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
pub enum RefundStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
        }
    }
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    pub id: String,
    pub status: RefundStatus,
    pub message: Option<String>,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>>
    for RefundsRouterData<Execute>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        // Log refund response
        router_env::logger::info!(
            refund_id = %item.response.id,
            status = ?item.response.status,
            "Refund response received"
        );
        
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: RefundsResponseRouterData<RSync, RefundResponse>) -> Result<Self,Self::Error> {
        // Log refund sync response
        router_env::logger::info!(
            refund_id = %item.response.id,
            status = ?item.response.status,
            "Refund sync response received"
        );
        
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

// Error Response
#[derive(Debug, Serialize, Deserialize)]
pub struct DemopayErrorResponse {
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
}
