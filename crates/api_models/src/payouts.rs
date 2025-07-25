use std::collections::HashMap;

use cards::CardNumber;
use common_utils::{
    consts::default_payouts_list_limit,
    crypto, id_type, link_utils, payout_method_utils,
    pii::{self, Email},
    transformers::ForeignFrom,
    types::{UnifiedCode, UnifiedMessage},
};
use masking::Secret;
use router_derive::FlatStruct;
use serde::{Deserialize, Serialize};
use time::PrimitiveDateTime;
use utoipa::ToSchema;

use crate::{enums as api_enums, payment_methods::RequiredFieldInfo, payments};

#[derive(Debug, Serialize, Clone, ToSchema)]
pub enum PayoutRequest {
    PayoutActionRequest(PayoutActionRequest),
    PayoutCreateRequest(Box<PayoutCreateRequest>),
    PayoutRetrieveRequest(PayoutRetrieveRequest),
}

#[derive(
    Default, Debug, Deserialize, Serialize, Clone, ToSchema, router_derive::PolymorphicSchema,
)]
#[generate_schemas(PayoutsCreateRequest, PayoutUpdateRequest, PayoutConfirmRequest)]
#[serde(deny_unknown_fields)]
pub struct PayoutCreateRequest {
    /// Unique identifier for the payout. This ensures idempotency for multiple payouts that have been done by a single merchant. This field is auto generated and is returned in the API response, **not required to be included in the Payout Create/Update Request.**
    #[schema(
        value_type = Option<String>,
        min_length = 30,
        max_length = 30,
        example = "187282ab-40ef-47a9-9206-5099ba31e432"
    )]
    #[remove_in(PayoutsCreateRequest, PayoutUpdateRequest, PayoutConfirmRequest)]
    pub payout_id: Option<id_type::PayoutId>,

    /// This is an identifier for the merchant account. This is inferred from the API key provided during the request, **not required to be included in the Payout Create/Update Request.**
    #[schema(max_length = 255, value_type = Option<String>, example = "merchant_1668273825")]
    #[remove_in(PayoutsCreateRequest, PayoutUpdateRequest, PayoutConfirmRequest)]
    pub merchant_id: Option<id_type::MerchantId>,

    /// Your unique identifier for this payout or order. This ID helps you reconcile payouts on your system. If provided, it is passed to the connector if supported.
    #[schema(value_type = Option<String>, max_length = 255, example = "merchant_order_ref_123")]
    pub merchant_order_reference_id: Option<String>,

    /// The payout amount. Amount for the payout in lowest denomination of the currency. (i.e) in cents for USD denomination, in paisa for INR denomination etc.,
    #[schema(value_type = Option<u64>, example = 1000)]
    #[mandatory_in(PayoutsCreateRequest = u64)]
    #[remove_in(PayoutsConfirmRequest)]
    #[serde(default, deserialize_with = "payments::amount::deserialize_option")]
    pub amount: Option<payments::Amount>,

    /// The currency of the payout request can be specified here
    #[schema(value_type = Option<Currency>, example = "USD")]
    #[mandatory_in(PayoutsCreateRequest = Currency)]
    #[remove_in(PayoutsConfirmRequest)]
    pub currency: Option<api_enums::Currency>,

    /// Specifies routing algorithm for selecting a connector
    #[schema(value_type = Option<StaticRoutingAlgorithm>, example = json!({
        "type": "single",
        "data": "adyen"
    }))]
    pub routing: Option<serde_json::Value>,

    /// This field allows the merchant to manually select a connector with which the payout can go through.
    #[schema(value_type = Option<Vec<PayoutConnectors>>, max_length = 255, example = json!(["wise", "adyen"]))]
    pub connector: Option<Vec<api_enums::PayoutConnectors>>,

    /// This field is used when merchant wants to confirm the payout, thus useful for the payout _Confirm_ request. Ideally merchants should _Create_ a payout, _Update_ it (if required), then _Confirm_ it.
    #[schema(value_type = Option<bool>, example = true, default = false)]
    #[remove_in(PayoutConfirmRequest)]
    pub confirm: Option<bool>,

    /// The payout_type of the payout request can be specified here, this is a mandatory field to _Confirm_ the payout, i.e., should be passed in _Create_ request, if not then should be updated in the payout _Update_ request, then only it can be confirmed.
    #[schema(value_type = Option<PayoutType>, example = "card")]
    pub payout_type: Option<api_enums::PayoutType>,

    /// The payout method information required for carrying out a payout
    #[schema(value_type = Option<PayoutMethodData>)]
    pub payout_method_data: Option<PayoutMethodData>,

    /// The billing address for the payout
    #[schema(value_type = Option<Address>, example = json!(r#"{
        "address": {
            "line1": "1467",
            "line2": "Harrison Street",
            "line3": "Harrison Street",
            "city": "San Francisco",
            "state": "CA",
            "zip": "94122",
            "country": "US",
            "first_name": "John",
            "last_name": "Doe"
        },
        "phone": { "number": "9123456789", "country_code": "+1" }
    }"#))]
    pub billing: Option<payments::Address>,

    /// Set to true to confirm the payout without review, no further action required
    #[schema(value_type = Option<bool>, example = true, default = false)]
    pub auto_fulfill: Option<bool>,

    /// The identifier for the customer object. If not provided the customer ID will be autogenerated. _Deprecated: Use customer_id instead._
    #[schema(deprecated, value_type = Option<String>, max_length = 255, example = "cus_y3oqhf46pyzuxjbcn2giaqnb44")]
    pub customer_id: Option<id_type::CustomerId>,

    /// Passing this object creates a new customer or attaches an existing customer to the payout
    #[schema(value_type = Option<CustomerDetails>)]
    pub customer: Option<payments::CustomerDetails>,

    /// It's a token used for client side verification.
    #[schema(value_type = Option<String>, example = "pay_U42c409qyHwOkWo3vK60_secret_el9ksDkiB8hi6j9N78yo")]
    #[remove_in(PayoutsCreateRequest)]
    #[mandatory_in(PayoutConfirmRequest = String)]
    pub client_secret: Option<String>,

    /// The URL to redirect after the completion of the operation
    #[schema(value_type = Option<String>, example = "https://hyperswitch.io")]
    pub return_url: Option<String>,

    /// Business country of the merchant for this payout. _Deprecated: Use profile_id instead._
    #[schema(deprecated, example = "US", value_type = Option<CountryAlpha2>)]
    pub business_country: Option<api_enums::CountryAlpha2>,

    /// Business label of the merchant for this payout. _Deprecated: Use profile_id instead._
    #[schema(deprecated, example = "food", value_type = Option<String>)]
    pub business_label: Option<String>,

    /// A description of the payout
    #[schema(example = "It's my first payout request", value_type = Option<String>)]
    pub description: Option<String>,

    /// Type of entity to whom the payout is being carried out to, select from the given list of options
    #[schema(value_type = Option<PayoutEntityType>, example = "Individual")]
    pub entity_type: Option<api_enums::PayoutEntityType>,

    /// Specifies whether or not the payout request is recurring
    #[schema(value_type = Option<bool>, default = false)]
    pub recurring: Option<bool>,

    /// You can specify up to 50 keys, with key names up to 40 characters long and values up to 500 characters long. Metadata is useful for storing additional, structured information on an object.
    #[schema(value_type = Option<Object>, example = r#"{ "udf1": "some-value", "udf2": "some-value" }"#)]
    pub metadata: Option<pii::SecretSerdeValue>,

    /// Provide a reference to a stored payout method, used to process the payout.
    #[schema(example = "187282ab-40ef-47a9-9206-5099ba31e432", value_type = Option<String>)]
    pub payout_token: Option<String>,

    /// The business profile to use for this payout, especially if there are multiple business profiles associated with the account, otherwise default business profile associated with the merchant account will be used.
    #[schema(value_type = Option<String>)]
    pub profile_id: Option<id_type::ProfileId>,

    /// The send method which will be required for processing payouts, check options for better understanding.
    #[schema(value_type = Option<PayoutSendPriority>, example = "instant")]
    pub priority: Option<api_enums::PayoutSendPriority>,

    /// Whether to get the payout link (if applicable). Merchant need to specify this during the Payout _Create_, this field can not be updated during Payout _Update_.
    #[schema(default = false, example = true, value_type = Option<bool>)]
    pub payout_link: Option<bool>,

    /// Custom payout link config for the particular payout, if payout link is to be generated.
    #[schema(value_type = Option<PayoutCreatePayoutLinkConfig>)]
    pub payout_link_config: Option<PayoutCreatePayoutLinkConfig>,

    /// Will be used to expire client secret after certain amount of time to be supplied in seconds
    /// (900) for 15 mins
    #[schema(value_type = Option<u32>, example = 900)]
    pub session_expiry: Option<u32>,

    /// Customer's email. _Deprecated: Use customer object instead._
    #[schema(deprecated, max_length = 255, value_type = Option<String>, example = "johntest@test.com")]
    pub email: Option<Email>,

    /// Customer's name. _Deprecated: Use customer object instead._
    #[schema(deprecated, value_type = Option<String>, max_length = 255, example = "John Test")]
    pub name: Option<Secret<String>>,

    /// Customer's phone. _Deprecated: Use customer object instead._
    #[schema(deprecated, value_type = Option<String>, max_length = 255, example = "9123456789")]
    pub phone: Option<Secret<String>>,

    /// Customer's phone country code. _Deprecated: Use customer object instead._
    #[schema(deprecated, max_length = 255, example = "+1")]
    pub phone_country_code: Option<String>,

    /// Identifier for payout method
    pub payout_method_id: Option<String>,
}

impl PayoutCreateRequest {
    pub fn get_customer_id(&self) -> Option<&id_type::CustomerId> {
        self.customer_id
            .as_ref()
            .or(self.customer.as_ref().map(|customer| &customer.id))
    }
}

/// Custom payout link config for the particular payout, if payout link is to be generated.
#[derive(Default, Debug, Deserialize, Serialize, Clone, ToSchema)]
pub struct PayoutCreatePayoutLinkConfig {
    /// The unique identifier for the collect link.
    #[schema(value_type = Option<String>, example = "pm_collect_link_2bdacf398vwzq5n422S1")]
    pub payout_link_id: Option<String>,

    #[serde(flatten)]
    #[schema(value_type = Option<GenericLinkUiConfig>)]
    pub ui_config: Option<link_utils::GenericLinkUiConfig>,

    /// List of payout methods shown on collect UI
    #[schema(value_type = Option<Vec<EnabledPaymentMethod>>, example = r#"[{"payment_method": "bank_transfer", "payment_method_types": ["ach", "bacs"]}]"#)]
    pub enabled_payment_methods: Option<Vec<link_utils::EnabledPaymentMethod>>,

    /// Form layout of the payout link
    #[schema(value_type = Option<UIWidgetFormLayout>, max_length = 255, example = "tabs")]
    pub form_layout: Option<api_enums::UIWidgetFormLayout>,

    /// `test_mode` allows for opening payout links without any restrictions. This removes
    /// - domain name validations
    /// - check for making sure link is accessed within an iframe
    #[schema(value_type = Option<bool>, example = false)]
    pub test_mode: Option<bool>,
}

/// The payout method information required for carrying out a payout
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayoutMethodData {
    Card(CardPayout),
    Bank(Bank),
    Wallet(Wallet),
}

impl Default for PayoutMethodData {
    fn default() -> Self {
        Self::Card(CardPayout::default())
    }
}

#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct CardPayout {
    /// The card number
    #[schema(value_type = String, example = "4242424242424242")]
    pub card_number: CardNumber,

    /// The card's expiry month
    #[schema(value_type = String)]
    pub expiry_month: Secret<String>,

    /// The card's expiry year
    #[schema(value_type = String)]
    pub expiry_year: Secret<String>,

    /// The card holder's name
    #[schema(value_type = String, example = "John Doe")]
    pub card_holder_name: Option<Secret<String>>,
}

#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(untagged)]
pub enum Bank {
    Ach(AchBankTransfer),
    Bacs(BacsBankTransfer),
    Sepa(SepaBankTransfer),
    Pix(PixBankTransfer),
}

#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct AchBankTransfer {
    /// Bank name
    #[schema(value_type = Option<String>, example = "Deutsche Bank")]
    pub bank_name: Option<String>,

    /// Bank country code
    #[schema(value_type = Option<CountryAlpha2>, example = "US")]
    pub bank_country_code: Option<api_enums::CountryAlpha2>,

    /// Bank city
    #[schema(value_type = Option<String>, example = "California")]
    pub bank_city: Option<String>,

    /// Bank account number is an unique identifier assigned by a bank to a customer.
    #[schema(value_type = String, example = "000123456")]
    pub bank_account_number: Secret<String>,

    /// [9 digits] Routing number - used in USA for identifying a specific bank.
    #[schema(value_type = String, example = "110000000")]
    pub bank_routing_number: Secret<String>,
}

#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct BacsBankTransfer {
    /// Bank name
    #[schema(value_type = Option<String>, example = "Deutsche Bank")]
    pub bank_name: Option<String>,

    /// Bank country code
    #[schema(value_type = Option<CountryAlpha2>, example = "US")]
    pub bank_country_code: Option<api_enums::CountryAlpha2>,

    /// Bank city
    #[schema(value_type = Option<String>, example = "California")]
    pub bank_city: Option<String>,

    /// Bank account number is an unique identifier assigned by a bank to a customer.
    #[schema(value_type = String, example = "000123456")]
    pub bank_account_number: Secret<String>,

    /// [6 digits] Sort Code - used in UK and Ireland for identifying a bank and it's branches.
    #[schema(value_type = String, example = "98-76-54")]
    pub bank_sort_code: Secret<String>,
}

#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
// The SEPA (Single Euro Payments Area) is a pan-European network that allows you to send and receive payments in euros between two cross-border bank accounts in the eurozone.
pub struct SepaBankTransfer {
    /// Bank name
    #[schema(value_type = Option<String>, example = "Deutsche Bank")]
    pub bank_name: Option<String>,

    /// Bank country code
    #[schema(value_type = Option<CountryAlpha2>, example = "US")]
    pub bank_country_code: Option<api_enums::CountryAlpha2>,

    /// Bank city
    #[schema(value_type = Option<String>, example = "California")]
    pub bank_city: Option<String>,

    /// International Bank Account Number (iban) - used in many countries for identifying a bank along with it's customer.
    #[schema(value_type = String, example = "DE89370400440532013000")]
    pub iban: Secret<String>,

    /// [8 / 11 digits] Bank Identifier Code (bic) / Swift Code - used in many countries for identifying a bank and it's branches
    #[schema(value_type = String, example = "HSBCGB2LXXX")]
    pub bic: Option<Secret<String>>,
}

#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct PixBankTransfer {
    /// Bank name
    #[schema(value_type = Option<String>, example = "Deutsche Bank")]
    pub bank_name: Option<String>,

    /// Bank branch
    #[schema(value_type = Option<String>, example = "3707")]
    pub bank_branch: Option<String>,

    /// Bank account number is an unique identifier assigned by a bank to a customer.
    #[schema(value_type = String, example = "000123456")]
    pub bank_account_number: Secret<String>,

    /// Unique key for pix customer
    #[schema(value_type = String, example = "000123456")]
    pub pix_key: Secret<String>,

    /// Individual taxpayer identification number
    #[schema(value_type = Option<String>, example = "000123456")]
    pub tax_id: Option<Secret<String>>,
}

#[derive(Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Wallet {
    Paypal(Paypal),
    Venmo(Venmo),
}

#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Paypal {
    /// Email linked with paypal account
    #[schema(value_type = String, example = "john.doe@example.com")]
    pub email: Option<Email>,

    /// mobile number linked to paypal account
    #[schema(value_type = String, example = "16608213349")]
    pub telephone_number: Option<Secret<String>>,

    /// id of the paypal account
    #[schema(value_type = String, example = "G83KXTJ5EHCQ2")]
    pub paypal_id: Option<Secret<String>>,
}

#[derive(Default, Eq, PartialEq, Clone, Debug, Deserialize, Serialize, ToSchema)]
pub struct Venmo {
    /// mobile number linked to venmo account
    #[schema(value_type = String, example = "16608213349")]
    pub telephone_number: Option<Secret<String>>,
}

#[derive(Debug, ToSchema, Clone, Serialize, router_derive::PolymorphicSchema)]
#[serde(deny_unknown_fields)]
pub struct PayoutCreateResponse {
    /// Unique identifier for the payout. This ensures idempotency for multiple payouts
    /// that have been done by a single merchant. This field is auto generated and is returned in the API response.
    #[schema(
        value_type = String,
        min_length = 30,
        max_length = 30,
        example = "187282ab-40ef-47a9-9206-5099ba31e432"
    )]
    pub payout_id: id_type::PayoutId,

    /// This is an identifier for the merchant account. This is inferred from the API key
    /// provided during the request
    #[schema(max_length = 255, value_type = String, example = "merchant_1668273825")]
    pub merchant_id: id_type::MerchantId,

    /// Your unique identifier for this payout or order. This ID helps you reconcile payouts on your system. If provided, it is passed to the connector if supported.
    #[schema(value_type = Option<String>, max_length = 255, example = "merchant_order_ref_123")]
    pub merchant_order_reference_id: Option<String>,

    /// The payout amount. Amount for the payout in lowest denomination of the currency. (i.e) in cents for USD denomination, in paisa for INR denomination etc.,
    #[schema(value_type = i64, example = 1000)]
    pub amount: common_utils::types::MinorUnit,

    /// Recipient's currency for the payout request
    #[schema(value_type = Currency, example = "USD")]
    pub currency: api_enums::Currency,

    /// The connector used for the payout
    #[schema(example = "wise")]
    pub connector: Option<String>,

    /// The payout method that is to be used
    #[schema(value_type = Option<PayoutType>, example = "bank")]
    pub payout_type: Option<api_enums::PayoutType>,

    /// The payout method details for the payout
    #[schema(value_type = Option<PayoutMethodDataResponse>, example = json!(r#"{
        "card": {
            "last4": "2503",
            "card_type": null,
            "card_network": null,
            "card_issuer": null,
            "card_issuing_country": null,
            "card_isin": "400000",
            "card_extended_bin": null,
            "card_exp_month": "08",
            "card_exp_year": "25",
            "card_holder_name": null,
            "payment_checks": null,
            "authentication_data": null
        }
    }"#))]
    pub payout_method_data: Option<PayoutMethodDataResponse>,

    /// The billing address for the payout
    #[schema(value_type = Option<Address>, example = json!(r#"{
        "address": {
            "line1": "1467",
            "line2": "Harrison Street",
            "line3": "Harrison Street",
            "city": "San Francisco",
            "state": "CA",
            "zip": "94122",
            "country": "US",
            "first_name": "John",
            "last_name": "Doe"
        },
        "phone": { "number": "9123456789", "country_code": "+1" }
    }"#))]
    pub billing: Option<payments::Address>,

    /// Set to true to confirm the payout without review, no further action required
    #[schema(value_type = bool, example = true, default = false)]
    pub auto_fulfill: bool,

    /// The identifier for the customer object. If not provided the customer ID will be autogenerated.
    #[schema(value_type = String, max_length = 255, example = "cus_y3oqhf46pyzuxjbcn2giaqnb44")]
    pub customer_id: Option<id_type::CustomerId>,

    /// Passing this object creates a new customer or attaches an existing customer to the payout
    #[schema(value_type = Option<CustomerDetailsResponse>)]
    pub customer: Option<payments::CustomerDetailsResponse>,

    /// It's a token used for client side verification.
    #[schema(value_type = String, example = "pay_U42c409qyHwOkWo3vK60_secret_el9ksDkiB8hi6j9N78yo")]
    pub client_secret: Option<String>,

    /// The URL to redirect after the completion of the operation
    #[schema(value_type = String, example = "https://hyperswitch.io")]
    pub return_url: Option<String>,

    /// Business country of the merchant for this payout
    #[schema(example = "US", value_type = CountryAlpha2)]
    pub business_country: Option<api_enums::CountryAlpha2>,

    /// Business label of the merchant for this payout
    #[schema(example = "food", value_type = Option<String>)]
    pub business_label: Option<String>,

    /// A description of the payout
    #[schema(example = "It's my first payout request", value_type = Option<String>)]
    pub description: Option<String>,

    /// Type of entity to whom the payout is being carried out to
    #[schema(value_type = PayoutEntityType, example = "Individual")]
    pub entity_type: api_enums::PayoutEntityType,

    /// Specifies whether or not the payout request is recurring
    #[schema(value_type = bool, default = false)]
    pub recurring: bool,

    /// You can specify up to 50 keys, with key names up to 40 characters long and values up to 500 characters long. Metadata is useful for storing additional, structured information on an object.
    #[schema(value_type = Option<Object>, example = r#"{ "udf1": "some-value", "udf2": "some-value" }"#)]
    pub metadata: Option<pii::SecretSerdeValue>,

    /// Unique identifier of the merchant connector account
    #[schema(value_type = Option<String>, example = "mca_sAD3OZLATetvjLOYhUSy")]
    pub merchant_connector_id: Option<id_type::MerchantConnectorAccountId>,

    /// Current status of the Payout
    #[schema(value_type = PayoutStatus, example = RequiresConfirmation)]
    pub status: api_enums::PayoutStatus,

    /// If there was an error while calling the connector the error message is received here
    #[schema(value_type = Option<String>, example = "Failed while verifying the card")]
    pub error_message: Option<String>,

    /// If there was an error while calling the connectors the code is received here
    #[schema(value_type = Option<String>, example = "E0001")]
    pub error_code: Option<String>,

    /// The business profile that is associated with this payout
    #[schema(value_type = String)]
    pub profile_id: id_type::ProfileId,

    /// Time when the payout was created
    #[schema(example = "2022-09-10T10:11:12Z")]
    #[serde(with = "common_utils::custom_serde::iso8601::option")]
    pub created: Option<PrimitiveDateTime>,

    /// Underlying processor's payout resource ID
    #[schema(value_type = Option<String>, example = "S3FC9G9M2MVFDXT5")]
    pub connector_transaction_id: Option<String>,

    /// Payout's send priority (if applicable)
    #[schema(value_type = Option<PayoutSendPriority>, example = "instant")]
    pub priority: Option<api_enums::PayoutSendPriority>,

    /// List of attempts
    #[schema(value_type = Option<Vec<PayoutAttemptResponse>>)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<Vec<PayoutAttemptResponse>>,

    /// If payout link was requested, this contains the link's ID and the URL to render the payout widget
    #[schema(value_type = Option<PayoutLinkResponse>)]
    pub payout_link: Option<PayoutLinkResponse>,

    /// Customer's email. _Deprecated: Use customer object instead._
    #[schema(deprecated, max_length = 255, value_type = Option<String>, example = "johntest@test.com")]
    pub email: crypto::OptionalEncryptableEmail,

    /// Customer's name. _Deprecated: Use customer object instead._
    #[schema(deprecated, value_type = Option<String>, max_length = 255, example = "John Test")]
    pub name: crypto::OptionalEncryptableName,

    /// Customer's phone. _Deprecated: Use customer object instead._
    #[schema(deprecated, value_type = Option<String>, max_length = 255, example = "9123456789")]
    pub phone: crypto::OptionalEncryptablePhone,

    /// Customer's phone country code. _Deprecated: Use customer object instead._
    #[schema(deprecated, max_length = 255, example = "+1")]
    pub phone_country_code: Option<String>,

    /// (This field is not live yet)
    /// Error code unified across the connectors is received here in case of errors while calling the underlying connector
    #[remove_in(PayoutCreateResponse)]
    #[schema(value_type = Option<String>, max_length = 255, example = "UE_000")]
    pub unified_code: Option<UnifiedCode>,

    /// (This field is not live yet)
    /// Error message unified across the connectors is received here in case of errors while calling the underlying connector
    #[remove_in(PayoutCreateResponse)]
    #[schema(value_type = Option<String>, max_length = 1024, example = "Invalid card details")]
    pub unified_message: Option<UnifiedMessage>,

    /// Identifier for payout method
    pub payout_method_id: Option<String>,
}

/// The payout method information for response
#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum PayoutMethodDataResponse {
    #[schema(value_type = CardAdditionalData)]
    Card(Box<payout_method_utils::CardAdditionalData>),
    #[schema(value_type = BankAdditionalData)]
    Bank(Box<payout_method_utils::BankAdditionalData>),
    #[schema(value_type = WalletAdditionalData)]
    Wallet(Box<payout_method_utils::WalletAdditionalData>),
}

#[derive(
    Default, Debug, serde::Serialize, Clone, PartialEq, ToSchema, router_derive::PolymorphicSchema,
)]
pub struct PayoutAttemptResponse {
    /// Unique identifier for the attempt
    pub attempt_id: String,
    /// The status of the attempt
    #[schema(value_type = PayoutStatus, example = "failed")]
    pub status: api_enums::PayoutStatus,
    /// The payout attempt amount. Amount for the payout in lowest denomination of the currency. (i.e) in cents for USD denomination, in paisa for INR denomination etc.,
    #[schema(value_type = i64, example = 6583)]
    pub amount: common_utils::types::MinorUnit,
    /// The currency of the amount of the payout attempt
    #[schema(value_type = Option<Currency>, example = "USD")]
    pub currency: Option<api_enums::Currency>,
    /// The connector used for the payout
    pub connector: Option<String>,
    /// Connector's error code in case of failures
    pub error_code: Option<String>,
    /// Connector's error message in case of failures
    pub error_message: Option<String>,
    /// The payout method that was used
    #[schema(value_type = Option<PayoutType>, example = "bank")]
    pub payment_method: Option<api_enums::PayoutType>,
    /// Payment Method Type
    #[schema(value_type = Option<PaymentMethodType>, example = "bacs")]
    pub payout_method_type: Option<api_enums::PaymentMethodType>,
    /// A unique identifier for a payout provided by the connector
    pub connector_transaction_id: Option<String>,
    /// If the payout was cancelled the reason provided here
    pub cancellation_reason: Option<String>,
    /// (This field is not live yet)
    /// Error code unified across the connectors is received here in case of errors while calling the underlying connector
    #[remove_in(PayoutAttemptResponse)]
    #[schema(value_type = Option<String>, max_length = 255, example = "UE_000")]
    pub unified_code: Option<UnifiedCode>,
    /// (This field is not live yet)
    /// Error message unified across the connectors is received here in case of errors while calling the underlying connector
    #[remove_in(PayoutAttemptResponse)]
    #[schema(value_type = Option<String>, max_length = 1024, example = "Invalid card details")]
    pub unified_message: Option<UnifiedMessage>,
}

#[derive(Default, Debug, Clone, Deserialize, ToSchema)]
pub struct PayoutRetrieveBody {
    pub force_sync: Option<bool>,
    #[schema(value_type = Option<String>)]
    pub merchant_id: Option<id_type::MerchantId>,
}

#[derive(Debug, Serialize, ToSchema, Clone, Deserialize)]
pub struct PayoutRetrieveRequest {
    /// Unique identifier for the payout. This ensures idempotency for multiple payouts
    /// that have been done by a single merchant. This field is auto generated and is returned in the API response.
    #[schema(
        value_type = String,
        min_length = 30,
        max_length = 30,
        example = "187282ab-40ef-47a9-9206-5099ba31e432"
    )]
    pub payout_id: id_type::PayoutId,

    /// `force_sync` with the connector to get payout details
    /// (defaults to false)
    #[schema(value_type = Option<bool>, default = false, example = true)]
    pub force_sync: Option<bool>,

    /// The identifier for the Merchant Account.
    #[schema(value_type = Option<String>)]
    pub merchant_id: Option<id_type::MerchantId>,
}

#[derive(Debug, Serialize, Clone, ToSchema, router_derive::PolymorphicSchema)]
#[generate_schemas(PayoutCancelRequest, PayoutFulfillRequest)]
pub struct PayoutActionRequest {
    /// Unique identifier for the payout. This ensures idempotency for multiple payouts
    /// that have been done by a single merchant. This field is auto generated and is returned in the API response.
    #[schema(
        value_type = String,
        min_length = 30,
        max_length = 30,
        example = "187282ab-40ef-47a9-9206-5099ba31e432"
    )]
    pub payout_id: id_type::PayoutId,
}

#[derive(Default, Debug, ToSchema, Clone, Deserialize)]
pub struct PayoutVendorAccountDetails {
    pub vendor_details: PayoutVendorDetails,
    pub individual_details: PayoutIndividualDetails,
}

#[derive(Default, Debug, Serialize, ToSchema, Clone, Deserialize)]
pub struct PayoutVendorDetails {
    pub account_type: String,
    pub business_type: String,
    pub business_profile_mcc: Option<i32>,
    pub business_profile_url: Option<String>,
    pub business_profile_name: Option<Secret<String>>,
    pub company_address_line1: Option<Secret<String>>,
    pub company_address_line2: Option<Secret<String>>,
    pub company_address_postal_code: Option<Secret<String>>,
    pub company_address_city: Option<Secret<String>>,
    pub company_address_state: Option<Secret<String>>,
    pub company_phone: Option<Secret<String>>,
    pub company_tax_id: Option<Secret<String>>,
    pub company_owners_provided: Option<bool>,
    pub capabilities_card_payments: Option<bool>,
    pub capabilities_transfers: Option<bool>,
}

#[derive(Default, Debug, Serialize, ToSchema, Clone, Deserialize)]
pub struct PayoutIndividualDetails {
    pub tos_acceptance_date: Option<i64>,
    pub tos_acceptance_ip: Option<Secret<String>>,
    pub individual_dob_day: Option<Secret<String>>,
    pub individual_dob_month: Option<Secret<String>>,
    pub individual_dob_year: Option<Secret<String>>,
    pub individual_id_number: Option<Secret<String>>,
    pub individual_ssn_last_4: Option<Secret<String>>,
    pub external_account_account_holder_type: Option<String>,
}

#[derive(Clone, Debug, serde::Deserialize, ToSchema, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutListConstraints {
    /// The identifier for customer
    #[schema(value_type = Option<String>, example = "cus_y3oqhf46pyzuxjbcn2giaqnb44")]
    pub customer_id: Option<id_type::CustomerId>,

    /// A cursor for use in pagination, fetch the next list after some object
    #[schema(example = "payout_fafa124123", value_type = Option<String>,)]
    pub starting_after: Option<id_type::PayoutId>,

    /// A cursor for use in pagination, fetch the previous list before some object
    #[schema(example = "payout_fafa124123", value_type = Option<String>,)]
    pub ending_before: Option<id_type::PayoutId>,

    /// limit on the number of objects to return
    #[schema(default = 10, maximum = 100)]
    #[serde(default = "default_payouts_list_limit")]
    pub limit: u32,

    /// The time at which payout is created
    #[schema(example = "2022-09-10T10:11:12Z")]
    #[serde(default, with = "common_utils::custom_serde::iso8601::option")]
    pub created: Option<PrimitiveDateTime>,

    /// The time range for which objects are needed. TimeRange has two fields start_time and end_time from which objects can be filtered as per required scenarios (created_at, time less than, greater than etc).
    #[serde(flatten)]
    #[schema(value_type = Option<TimeRange>)]
    pub time_range: Option<common_utils::types::TimeRange>,
}

#[derive(Clone, Debug, serde::Deserialize, ToSchema, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct PayoutListFilterConstraints {
    /// The identifier for payout
    #[schema(
    value_type = Option<String>,
    min_length = 30,
    max_length = 30,
    example = "187282ab-40ef-47a9-9206-5099ba31e432"
)]
    pub payout_id: Option<id_type::PayoutId>,
    /// The merchant order reference ID for payout
    #[schema(value_type = Option<String>, max_length = 255, example = "merchant_order_ref_123")]
    pub merchant_order_reference_id: Option<String>,
    /// The identifier for business profile
    #[schema(value_type = Option<String>)]
    pub profile_id: Option<id_type::ProfileId>,
    /// The identifier for customer
    #[schema(value_type = Option<String>,example = "cus_y3oqhf46pyzuxjbcn2giaqnb44")]
    pub customer_id: Option<id_type::CustomerId>,
    /// The limit on the number of objects. The default limit is 10 and max limit is 20
    #[serde(default = "default_payouts_list_limit")]
    pub limit: u32,
    /// The starting point within a list of objects
    pub offset: Option<u32>,
    /// The time range for which objects are needed. TimeRange has two fields start_time and end_time from which objects can be filtered as per required scenarios (created_at, time less than, greater than etc).
    #[serde(flatten)]
    #[schema(value_type = Option<TimeRange>)]
    pub time_range: Option<common_utils::types::TimeRange>,
    /// The list of connectors to filter payouts list
    #[schema(value_type = Option<Vec<PayoutConnectors>>, max_length = 255, example = json!(["wise", "adyen"]))]
    pub connector: Option<Vec<api_enums::PayoutConnectors>>,
    /// The list of currencies to filter payouts list
    #[schema(value_type = Currency, example = "USD")]
    pub currency: Option<Vec<api_enums::Currency>>,
    /// The list of payout status to filter payouts list
    #[schema(value_type = Option<Vec<PayoutStatus>>, example = json!(["pending", "failed"]))]
    pub status: Option<Vec<api_enums::PayoutStatus>>,
    /// The list of payout methods to filter payouts list
    #[schema(value_type = Option<Vec<PayoutType>>, example = json!(["bank", "card"]))]
    pub payout_method: Option<Vec<common_enums::PayoutType>>,
    /// Type of recipient
    #[schema(value_type = PayoutEntityType, example = "Individual")]
    pub entity_type: Option<common_enums::PayoutEntityType>,
}

#[derive(Clone, Debug, serde::Serialize, ToSchema)]
pub struct PayoutListResponse {
    /// The number of payouts included in the list
    pub size: usize,
    /// The list of payouts response objects
    pub data: Vec<PayoutCreateResponse>,
    /// The total number of available payouts for given constraints
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,
}

#[derive(Clone, Debug, serde::Serialize, ToSchema)]
pub struct PayoutListFilters {
    /// The list of available connector filters
    #[schema(value_type = Vec<PayoutConnectors>)]
    pub connector: Vec<api_enums::PayoutConnectors>,
    /// The list of available currency filters
    #[schema(value_type = Vec<Currency>)]
    pub currency: Vec<common_enums::Currency>,
    /// The list of available payout status filters
    #[schema(value_type = Vec<PayoutStatus>)]
    pub status: Vec<common_enums::PayoutStatus>,
    /// The list of available payout method filters
    #[schema(value_type = Vec<PayoutType>)]
    pub payout_method: Vec<common_enums::PayoutType>,
}

#[derive(Clone, Debug, serde::Serialize, ToSchema)]
pub struct PayoutLinkResponse {
    pub payout_link_id: String,
    #[schema(value_type = String)]
    pub link: Secret<url::Url>,
}

#[derive(Clone, Debug, serde::Deserialize, ToSchema, serde::Serialize)]
pub struct PayoutLinkInitiateRequest {
    #[schema(value_type = String)]
    pub merchant_id: id_type::MerchantId,
    #[schema(value_type = String)]
    pub payout_id: id_type::PayoutId,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PayoutLinkDetails {
    pub publishable_key: Secret<String>,
    pub client_secret: Secret<String>,
    pub payout_link_id: String,
    pub payout_id: id_type::PayoutId,
    pub customer_id: id_type::CustomerId,
    #[serde(with = "common_utils::custom_serde::iso8601")]
    pub session_expiry: PrimitiveDateTime,
    pub return_url: Option<url::Url>,
    #[serde(flatten)]
    pub ui_config: link_utils::GenericLinkUiConfigFormData,
    pub enabled_payment_methods: Vec<link_utils::EnabledPaymentMethod>,
    pub enabled_payment_methods_with_required_fields: Vec<PayoutEnabledPaymentMethodsInfo>,
    pub amount: common_utils::types::StringMajorUnit,
    pub currency: common_enums::Currency,
    pub locale: String,
    pub form_layout: Option<common_enums::UIWidgetFormLayout>,
    pub test_mode: bool,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PayoutEnabledPaymentMethodsInfo {
    pub payment_method: common_enums::PaymentMethod,
    pub payment_method_types_info: Vec<PaymentMethodTypeInfo>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PaymentMethodTypeInfo {
    pub payment_method_type: common_enums::PaymentMethodType,
    pub required_fields: Option<HashMap<String, RequiredFieldInfo>>,
}

#[derive(Clone, Debug, serde::Serialize, FlatStruct)]
pub struct RequiredFieldsOverrideRequest {
    pub billing: Option<payments::Address>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct PayoutLinkStatusDetails {
    pub payout_link_id: String,
    pub payout_id: id_type::PayoutId,
    pub customer_id: id_type::CustomerId,
    #[serde(with = "common_utils::custom_serde::iso8601")]
    pub session_expiry: PrimitiveDateTime,
    pub return_url: Option<url::Url>,
    pub status: api_enums::PayoutStatus,
    pub error_code: Option<UnifiedCode>,
    pub error_message: Option<UnifiedMessage>,
    #[serde(flatten)]
    pub ui_config: link_utils::GenericLinkUiConfigFormData,
    pub test_mode: bool,
}

impl From<Bank> for payout_method_utils::BankAdditionalData {
    fn from(bank_data: Bank) -> Self {
        match bank_data {
            Bank::Ach(AchBankTransfer {
                bank_name,
                bank_country_code,
                bank_city,
                bank_account_number,
                bank_routing_number,
            }) => Self::Ach(Box::new(
                payout_method_utils::AchBankTransferAdditionalData {
                    bank_name,
                    bank_country_code,
                    bank_city,
                    bank_account_number: bank_account_number.into(),
                    bank_routing_number: bank_routing_number.into(),
                },
            )),
            Bank::Bacs(BacsBankTransfer {
                bank_name,
                bank_country_code,
                bank_city,
                bank_account_number,
                bank_sort_code,
            }) => Self::Bacs(Box::new(
                payout_method_utils::BacsBankTransferAdditionalData {
                    bank_name,
                    bank_country_code,
                    bank_city,
                    bank_account_number: bank_account_number.into(),
                    bank_sort_code: bank_sort_code.into(),
                },
            )),
            Bank::Sepa(SepaBankTransfer {
                bank_name,
                bank_country_code,
                bank_city,
                iban,
                bic,
            }) => Self::Sepa(Box::new(
                payout_method_utils::SepaBankTransferAdditionalData {
                    bank_name,
                    bank_country_code,
                    bank_city,
                    iban: iban.into(),
                    bic: bic.map(From::from),
                },
            )),
            Bank::Pix(PixBankTransfer {
                bank_name,
                bank_branch,
                bank_account_number,
                pix_key,
                tax_id,
            }) => Self::Pix(Box::new(
                payout_method_utils::PixBankTransferAdditionalData {
                    bank_name,
                    bank_branch,
                    bank_account_number: bank_account_number.into(),
                    pix_key: pix_key.into(),
                    tax_id: tax_id.map(From::from),
                },
            )),
        }
    }
}

impl From<Wallet> for payout_method_utils::WalletAdditionalData {
    fn from(wallet_data: Wallet) -> Self {
        match wallet_data {
            Wallet::Paypal(Paypal {
                email,
                telephone_number,
                paypal_id,
            }) => Self::Paypal(Box::new(payout_method_utils::PaypalAdditionalData {
                email: email.map(ForeignFrom::foreign_from),
                telephone_number: telephone_number.map(From::from),
                paypal_id: paypal_id.map(From::from),
            })),
            Wallet::Venmo(Venmo { telephone_number }) => {
                Self::Venmo(Box::new(payout_method_utils::VenmoAdditionalData {
                    telephone_number: telephone_number.map(From::from),
                }))
            }
        }
    }
}

impl From<payout_method_utils::AdditionalPayoutMethodData> for PayoutMethodDataResponse {
    fn from(additional_data: payout_method_utils::AdditionalPayoutMethodData) -> Self {
        match additional_data {
            payout_method_utils::AdditionalPayoutMethodData::Card(card_data) => {
                Self::Card(card_data)
            }
            payout_method_utils::AdditionalPayoutMethodData::Bank(bank_data) => {
                Self::Bank(bank_data)
            }
            payout_method_utils::AdditionalPayoutMethodData::Wallet(wallet_data) => {
                Self::Wallet(wallet_data)
            }
        }
    }
}
