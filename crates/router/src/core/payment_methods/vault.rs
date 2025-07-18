use common_enums::PaymentMethodType;
#[cfg(feature = "v2")]
use common_utils::request;
use common_utils::{
    crypto::{DecodeMessage, EncodeMessage, GcmAes256},
    ext_traits::{BytesExt, Encode},
    generate_id_with_default_len, id_type,
    pii::Email,
};
use error_stack::{report, ResultExt};
#[cfg(feature = "v2")]
use hyperswitch_domain_models::{
    router_data_v2::flow_common_types::VaultConnectorFlowData,
    router_flow_types::{ExternalVaultDeleteFlow, ExternalVaultRetrieveFlow},
    types::VaultRouterData,
};
use masking::PeekInterface;
use router_env::{instrument, tracing};
use scheduler::{types::process_data, utils as process_tracker_utils};

#[cfg(feature = "payouts")]
use crate::types::api::payouts;
use crate::{
    consts,
    core::errors::{self, CustomResult, RouterResult},
    db, logger,
    routes::{self, metrics},
    types::{
        api, domain,
        storage::{self, enums},
    },
    utils::StringExt,
};
#[cfg(feature = "v2")]
use crate::{
    core::{
        errors::ConnectorErrorExt,
        errors::StorageErrorExt,
        payment_methods::{transformers as pm_transforms, utils},
        payments::{self as payments_core, helpers as payment_helpers},
        utils as core_utils,
    },
    headers,
    services::{self, connector_integration_interface::RouterDataConversion},
    settings,
    types::{self, payment_methods as pm_types},
    utils::{ext_traits::OptionExt, ConnectorResponseExt},
};

const VAULT_SERVICE_NAME: &str = "CARD";

pub struct SupplementaryVaultData {
    pub customer_id: Option<id_type::CustomerId>,
    pub payment_method_id: Option<String>,
}

pub trait Vaultable: Sized {
    fn get_value1(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError>;
    fn get_value2(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        Ok(String::new())
    }
    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError>;
}

impl Vaultable for domain::Card {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = domain::TokenizedCardValue1 {
            card_number: self.card_number.peek().clone(),
            exp_year: self.card_exp_year.peek().clone(),
            exp_month: self.card_exp_month.peek().clone(),
            nickname: self.nick_name.as_ref().map(|name| name.peek().clone()),
            card_last_four: None,
            card_token: None,
            card_holder_name: self.card_holder_name.clone(),
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode card value1")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = domain::TokenizedCardValue2 {
            card_security_code: Some(self.card_cvc.peek().clone()),
            card_fingerprint: None,
            external_id: None,
            customer_id,
            payment_method_id: None,
        };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode card value2")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: domain::TokenizedCardValue1 = value1
            .parse_struct("TokenizedCardValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into card value1")?;

        let value2: domain::TokenizedCardValue2 = value2
            .parse_struct("TokenizedCardValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into card value2")?;

        let card = Self {
            card_number: cards::CardNumber::try_from(value1.card_number)
                .change_context(errors::VaultError::ResponseDeserializationFailed)
                .attach_printable("Invalid card number format from the mock locker")?,
            card_exp_month: value1.exp_month.into(),
            card_exp_year: value1.exp_year.into(),
            card_cvc: value2.card_security_code.unwrap_or_default().into(),
            card_issuer: None,
            card_network: None,
            bank_code: None,
            card_issuing_country: None,
            card_type: None,
            nick_name: value1.nickname.map(masking::Secret::new),
            card_holder_name: value1.card_holder_name,
            co_badged_card_data: None,
        };

        let supp_data = SupplementaryVaultData {
            customer_id: value2.customer_id,
            payment_method_id: value2.payment_method_id,
        };

        Ok((card, supp_data))
    }
}

impl Vaultable for domain::BankTransferData {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = domain::TokenizedBankTransferValue1 {
            data: self.to_owned(),
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode bank transfer data")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = domain::TokenizedBankTransferValue2 { customer_id };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode bank transfer supplementary data")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: domain::TokenizedBankTransferValue1 = value1
            .parse_struct("TokenizedBankTransferValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into bank transfer data")?;

        let value2: domain::TokenizedBankTransferValue2 = value2
            .parse_struct("TokenizedBankTransferValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into supplementary bank transfer data")?;

        let bank_transfer_data = value1.data;

        let supp_data = SupplementaryVaultData {
            customer_id: value2.customer_id,
            payment_method_id: None,
        };

        Ok((bank_transfer_data, supp_data))
    }
}

impl Vaultable for domain::WalletData {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = domain::TokenizedWalletValue1 {
            data: self.to_owned(),
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode wallet data value1")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = domain::TokenizedWalletValue2 { customer_id };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode wallet data value2")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: domain::TokenizedWalletValue1 = value1
            .parse_struct("TokenizedWalletValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into wallet data value1")?;

        let value2: domain::TokenizedWalletValue2 = value2
            .parse_struct("TokenizedWalletValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into wallet data value2")?;

        let wallet = value1.data;

        let supp_data = SupplementaryVaultData {
            customer_id: value2.customer_id,
            payment_method_id: None,
        };

        Ok((wallet, supp_data))
    }
}

impl Vaultable for domain::BankRedirectData {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = domain::TokenizedBankRedirectValue1 {
            data: self.to_owned(),
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode bank redirect data")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = domain::TokenizedBankRedirectValue2 { customer_id };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode bank redirect supplementary data")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: domain::TokenizedBankRedirectValue1 = value1
            .parse_struct("TokenizedBankRedirectValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into bank redirect data")?;

        let value2: domain::TokenizedBankRedirectValue2 = value2
            .parse_struct("TokenizedBankRedirectValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into supplementary bank redirect data")?;

        let bank_transfer_data = value1.data;

        let supp_data = SupplementaryVaultData {
            customer_id: value2.customer_id,
            payment_method_id: None,
        };

        Ok((bank_transfer_data, supp_data))
    }
}

impl Vaultable for domain::BankDebitData {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = domain::TokenizedBankDebitValue1 {
            data: self.to_owned(),
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode bank debit data")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = domain::TokenizedBankDebitValue2 { customer_id };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode bank debit supplementary data")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: domain::TokenizedBankDebitValue1 = value1
            .parse_struct("TokenizedBankDebitValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into bank debit data")?;

        let value2: domain::TokenizedBankDebitValue2 = value2
            .parse_struct("TokenizedBankDebitValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into supplementary bank debit data")?;

        let bank_transfer_data = value1.data;

        let supp_data = SupplementaryVaultData {
            customer_id: value2.customer_id,
            payment_method_id: None,
        };

        Ok((bank_transfer_data, supp_data))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum VaultPaymentMethod {
    Card(String),
    Wallet(String),
    BankTransfer(String),
    BankRedirect(String),
    BankDebit(String),
}

impl Vaultable for domain::PaymentMethodData {
    fn get_value1(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = match self {
            Self::Card(card) => VaultPaymentMethod::Card(card.get_value1(customer_id)?),
            Self::Wallet(wallet) => VaultPaymentMethod::Wallet(wallet.get_value1(customer_id)?),
            Self::BankTransfer(bank_transfer) => {
                VaultPaymentMethod::BankTransfer(bank_transfer.get_value1(customer_id)?)
            }
            Self::BankRedirect(bank_redirect) => {
                VaultPaymentMethod::BankRedirect(bank_redirect.get_value1(customer_id)?)
            }
            Self::BankDebit(bank_debit) => {
                VaultPaymentMethod::BankDebit(bank_debit.get_value1(customer_id)?)
            }
            _ => Err(errors::VaultError::PaymentMethodNotSupported)
                .attach_printable("Payment method not supported")?,
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode payment method value1")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = match self {
            Self::Card(card) => VaultPaymentMethod::Card(card.get_value2(customer_id)?),
            Self::Wallet(wallet) => VaultPaymentMethod::Wallet(wallet.get_value2(customer_id)?),
            Self::BankTransfer(bank_transfer) => {
                VaultPaymentMethod::BankTransfer(bank_transfer.get_value2(customer_id)?)
            }
            Self::BankRedirect(bank_redirect) => {
                VaultPaymentMethod::BankRedirect(bank_redirect.get_value2(customer_id)?)
            }
            Self::BankDebit(bank_debit) => {
                VaultPaymentMethod::BankDebit(bank_debit.get_value2(customer_id)?)
            }
            _ => Err(errors::VaultError::PaymentMethodNotSupported)
                .attach_printable("Payment method not supported")?,
        };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode payment method value2")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: VaultPaymentMethod = value1
            .parse_struct("PaymentMethodValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into payment method value 1")?;

        let value2: VaultPaymentMethod = value2
            .parse_struct("PaymentMethodValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into payment method value 2")?;

        match (value1, value2) {
            (VaultPaymentMethod::Card(mvalue1), VaultPaymentMethod::Card(mvalue2)) => {
                let (card, supp_data) = domain::Card::from_values(mvalue1, mvalue2)?;
                Ok((Self::Card(card), supp_data))
            }
            (VaultPaymentMethod::Wallet(mvalue1), VaultPaymentMethod::Wallet(mvalue2)) => {
                let (wallet, supp_data) = domain::WalletData::from_values(mvalue1, mvalue2)?;
                Ok((Self::Wallet(wallet), supp_data))
            }
            (
                VaultPaymentMethod::BankTransfer(mvalue1),
                VaultPaymentMethod::BankTransfer(mvalue2),
            ) => {
                let (bank_transfer, supp_data) =
                    domain::BankTransferData::from_values(mvalue1, mvalue2)?;
                Ok((Self::BankTransfer(Box::new(bank_transfer)), supp_data))
            }
            (
                VaultPaymentMethod::BankRedirect(mvalue1),
                VaultPaymentMethod::BankRedirect(mvalue2),
            ) => {
                let (bank_redirect, supp_data) =
                    domain::BankRedirectData::from_values(mvalue1, mvalue2)?;
                Ok((Self::BankRedirect(bank_redirect), supp_data))
            }
            (VaultPaymentMethod::BankDebit(mvalue1), VaultPaymentMethod::BankDebit(mvalue2)) => {
                let (bank_debit, supp_data) = domain::BankDebitData::from_values(mvalue1, mvalue2)?;
                Ok((Self::BankDebit(bank_debit), supp_data))
            }

            _ => Err(errors::VaultError::PaymentMethodNotSupported)
                .attach_printable("Payment method not supported"),
        }
    }
}

#[cfg(feature = "payouts")]
impl Vaultable for api::CardPayout {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = api::TokenizedCardValue1 {
            card_number: self.card_number.peek().clone(),
            exp_year: self.expiry_year.peek().clone(),
            exp_month: self.expiry_month.peek().clone(),
            name_on_card: self.card_holder_name.clone().map(|n| n.peek().to_string()),
            nickname: None,
            card_last_four: None,
            card_token: None,
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode card value1")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = api::TokenizedCardValue2 {
            card_security_code: None,
            card_fingerprint: None,
            external_id: None,
            customer_id,
            payment_method_id: None,
        };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode card value2")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: api::TokenizedCardValue1 = value1
            .parse_struct("TokenizedCardValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into card value1")?;

        let value2: api::TokenizedCardValue2 = value2
            .parse_struct("TokenizedCardValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into card value2")?;

        let card = Self {
            card_number: value1
                .card_number
                .parse()
                .map_err(|_| errors::VaultError::FetchCardFailed)?,
            expiry_month: value1.exp_month.into(),
            expiry_year: value1.exp_year.into(),
            card_holder_name: value1.name_on_card.map(masking::Secret::new),
        };

        let supp_data = SupplementaryVaultData {
            customer_id: value2.customer_id,
            payment_method_id: value2.payment_method_id,
        };

        Ok((card, supp_data))
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenizedWalletSensitiveValues {
    pub email: Option<Email>,
    pub telephone_number: Option<masking::Secret<String>>,
    pub wallet_id: Option<masking::Secret<String>>,
    pub wallet_type: PaymentMethodType,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenizedWalletInsensitiveValues {
    pub customer_id: Option<id_type::CustomerId>,
}

#[cfg(feature = "payouts")]
impl Vaultable for api::WalletPayout {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = match self {
            Self::Paypal(paypal_data) => TokenizedWalletSensitiveValues {
                email: paypal_data.email.clone(),
                telephone_number: paypal_data.telephone_number.clone(),
                wallet_id: paypal_data.paypal_id.clone(),
                wallet_type: PaymentMethodType::Paypal,
            },
            Self::Venmo(venmo_data) => TokenizedWalletSensitiveValues {
                email: None,
                telephone_number: venmo_data.telephone_number.clone(),
                wallet_id: None,
                wallet_type: PaymentMethodType::Venmo,
            },
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode wallet data - TokenizedWalletSensitiveValues")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = TokenizedWalletInsensitiveValues { customer_id };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode data - TokenizedWalletInsensitiveValues")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: TokenizedWalletSensitiveValues = value1
            .parse_struct("TokenizedWalletSensitiveValues")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into wallet data wallet_sensitive_data")?;

        let value2: TokenizedWalletInsensitiveValues = value2
            .parse_struct("TokenizedWalletInsensitiveValues")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into wallet data wallet_insensitive_data")?;

        let wallet = match value1.wallet_type {
            PaymentMethodType::Paypal => Self::Paypal(api_models::payouts::Paypal {
                email: value1.email,
                telephone_number: value1.telephone_number,
                paypal_id: value1.wallet_id,
            }),
            PaymentMethodType::Venmo => Self::Venmo(api_models::payouts::Venmo {
                telephone_number: value1.telephone_number,
            }),
            _ => Err(errors::VaultError::PayoutMethodNotSupported)?,
        };
        let supp_data = SupplementaryVaultData {
            customer_id: value2.customer_id,
            payment_method_id: None,
        };

        Ok((wallet, supp_data))
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenizedBankSensitiveValues {
    pub bank_account_number: Option<masking::Secret<String>>,
    pub bank_routing_number: Option<masking::Secret<String>>,
    pub bic: Option<masking::Secret<String>>,
    pub bank_sort_code: Option<masking::Secret<String>>,
    pub iban: Option<masking::Secret<String>>,
    pub pix_key: Option<masking::Secret<String>>,
    pub tax_id: Option<masking::Secret<String>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenizedBankInsensitiveValues {
    pub customer_id: Option<id_type::CustomerId>,
    pub bank_name: Option<String>,
    pub bank_country_code: Option<api::enums::CountryAlpha2>,
    pub bank_city: Option<String>,
    pub bank_branch: Option<String>,
}

#[cfg(feature = "payouts")]
impl Vaultable for api::BankPayout {
    fn get_value1(
        &self,
        _customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let bank_sensitive_data = match self {
            Self::Ach(b) => TokenizedBankSensitiveValues {
                bank_account_number: Some(b.bank_account_number.clone()),
                bank_routing_number: Some(b.bank_routing_number.to_owned()),
                bic: None,
                bank_sort_code: None,
                iban: None,
                pix_key: None,
                tax_id: None,
            },
            Self::Bacs(b) => TokenizedBankSensitiveValues {
                bank_account_number: Some(b.bank_account_number.to_owned()),
                bank_routing_number: None,
                bic: None,
                bank_sort_code: Some(b.bank_sort_code.to_owned()),
                iban: None,
                pix_key: None,
                tax_id: None,
            },
            Self::Sepa(b) => TokenizedBankSensitiveValues {
                bank_account_number: None,
                bank_routing_number: None,
                bic: b.bic.to_owned(),
                bank_sort_code: None,
                iban: Some(b.iban.to_owned()),
                pix_key: None,
                tax_id: None,
            },
            Self::Pix(bank_details) => TokenizedBankSensitiveValues {
                bank_account_number: Some(bank_details.bank_account_number.to_owned()),
                bank_routing_number: None,
                bic: None,
                bank_sort_code: None,
                iban: None,
                pix_key: Some(bank_details.pix_key.to_owned()),
                tax_id: bank_details.tax_id.to_owned(),
            },
        };

        bank_sensitive_data
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode data - bank_sensitive_data")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let bank_insensitive_data = match self {
            Self::Ach(b) => TokenizedBankInsensitiveValues {
                customer_id,
                bank_name: b.bank_name.to_owned(),
                bank_country_code: b.bank_country_code.to_owned(),
                bank_city: b.bank_city.to_owned(),
                bank_branch: None,
            },
            Self::Bacs(b) => TokenizedBankInsensitiveValues {
                customer_id,
                bank_name: b.bank_name.to_owned(),
                bank_country_code: b.bank_country_code.to_owned(),
                bank_city: b.bank_city.to_owned(),
                bank_branch: None,
            },
            Self::Sepa(bank_details) => TokenizedBankInsensitiveValues {
                customer_id,
                bank_name: bank_details.bank_name.to_owned(),
                bank_country_code: bank_details.bank_country_code.to_owned(),
                bank_city: bank_details.bank_city.to_owned(),
                bank_branch: None,
            },
            Self::Pix(bank_details) => TokenizedBankInsensitiveValues {
                customer_id,
                bank_name: bank_details.bank_name.to_owned(),
                bank_country_code: None,
                bank_city: None,
                bank_branch: bank_details.bank_branch.to_owned(),
            },
        };

        bank_insensitive_data
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode wallet data bank_insensitive_data")
    }

    fn from_values(
        bank_sensitive_data: String,
        bank_insensitive_data: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let bank_sensitive_data: TokenizedBankSensitiveValues = bank_sensitive_data
            .parse_struct("TokenizedBankValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into bank data bank_sensitive_data")?;

        let bank_insensitive_data: TokenizedBankInsensitiveValues = bank_insensitive_data
            .parse_struct("TokenizedBankValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into wallet data bank_insensitive_data")?;

        let bank = match (
            // ACH + BACS + PIX
            bank_sensitive_data.bank_account_number.to_owned(),
            bank_sensitive_data.bank_routing_number.to_owned(), // ACH
            bank_sensitive_data.bank_sort_code.to_owned(),      // BACS
            // SEPA
            bank_sensitive_data.iban.to_owned(),
            bank_sensitive_data.bic,
            // PIX
            bank_sensitive_data.pix_key,
            bank_sensitive_data.tax_id,
        ) {
            (Some(ban), Some(brn), None, None, None, None, None) => {
                Self::Ach(payouts::AchBankTransfer {
                    bank_account_number: ban,
                    bank_routing_number: brn,
                    bank_name: bank_insensitive_data.bank_name,
                    bank_country_code: bank_insensitive_data.bank_country_code,
                    bank_city: bank_insensitive_data.bank_city,
                })
            }
            (Some(ban), None, Some(bsc), None, None, None, None) => {
                Self::Bacs(payouts::BacsBankTransfer {
                    bank_account_number: ban,
                    bank_sort_code: bsc,
                    bank_name: bank_insensitive_data.bank_name,
                    bank_country_code: bank_insensitive_data.bank_country_code,
                    bank_city: bank_insensitive_data.bank_city,
                })
            }
            (None, None, None, Some(iban), bic, None, None) => {
                Self::Sepa(payouts::SepaBankTransfer {
                    iban,
                    bic,
                    bank_name: bank_insensitive_data.bank_name,
                    bank_country_code: bank_insensitive_data.bank_country_code,
                    bank_city: bank_insensitive_data.bank_city,
                })
            }
            (Some(ban), None, None, None, None, Some(pix_key), tax_id) => {
                Self::Pix(payouts::PixBankTransfer {
                    bank_account_number: ban,
                    bank_branch: bank_insensitive_data.bank_branch,
                    bank_name: bank_insensitive_data.bank_name,
                    pix_key,
                    tax_id,
                })
            }
            _ => Err(errors::VaultError::ResponseDeserializationFailed)?,
        };

        let supp_data = SupplementaryVaultData {
            customer_id: bank_insensitive_data.customer_id,
            payment_method_id: None,
        };

        Ok((bank, supp_data))
    }
}

#[cfg(feature = "payouts")]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum VaultPayoutMethod {
    Card(String),
    Bank(String),
    Wallet(String),
}

#[cfg(feature = "payouts")]
impl Vaultable for api::PayoutMethodData {
    fn get_value1(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value1 = match self {
            Self::Card(card) => VaultPayoutMethod::Card(card.get_value1(customer_id)?),
            Self::Bank(bank) => VaultPayoutMethod::Bank(bank.get_value1(customer_id)?),
            Self::Wallet(wallet) => VaultPayoutMethod::Wallet(wallet.get_value1(customer_id)?),
        };

        value1
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode payout method value1")
    }

    fn get_value2(
        &self,
        customer_id: Option<id_type::CustomerId>,
    ) -> CustomResult<String, errors::VaultError> {
        let value2 = match self {
            Self::Card(card) => VaultPayoutMethod::Card(card.get_value2(customer_id)?),
            Self::Bank(bank) => VaultPayoutMethod::Bank(bank.get_value2(customer_id)?),
            Self::Wallet(wallet) => VaultPayoutMethod::Wallet(wallet.get_value2(customer_id)?),
        };

        value2
            .encode_to_string_of_json()
            .change_context(errors::VaultError::RequestEncodingFailed)
            .attach_printable("Failed to encode payout method value2")
    }

    fn from_values(
        value1: String,
        value2: String,
    ) -> CustomResult<(Self, SupplementaryVaultData), errors::VaultError> {
        let value1: VaultPayoutMethod = value1
            .parse_struct("VaultMethodValue1")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into vault method value 1")?;

        let value2: VaultPayoutMethod = value2
            .parse_struct("VaultMethodValue2")
            .change_context(errors::VaultError::ResponseDeserializationFailed)
            .attach_printable("Could not deserialize into vault method value 2")?;

        match (value1, value2) {
            (VaultPayoutMethod::Card(mvalue1), VaultPayoutMethod::Card(mvalue2)) => {
                let (card, supp_data) = api::CardPayout::from_values(mvalue1, mvalue2)?;
                Ok((Self::Card(card), supp_data))
            }
            (VaultPayoutMethod::Bank(mvalue1), VaultPayoutMethod::Bank(mvalue2)) => {
                let (bank, supp_data) = api::BankPayout::from_values(mvalue1, mvalue2)?;
                Ok((Self::Bank(bank), supp_data))
            }
            (VaultPayoutMethod::Wallet(mvalue1), VaultPayoutMethod::Wallet(mvalue2)) => {
                let (wallet, supp_data) = api::WalletPayout::from_values(mvalue1, mvalue2)?;
                Ok((Self::Wallet(wallet), supp_data))
            }
            _ => Err(errors::VaultError::PayoutMethodNotSupported)
                .attach_printable("Payout method not supported"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MockTokenizeDBValue {
    pub value1: String,
    pub value2: String,
}

pub struct Vault;

impl Vault {
    #[instrument(skip_all)]
    pub async fn get_payment_method_data_from_locker(
        state: &routes::SessionState,
        lookup_key: &str,
        merchant_key_store: &domain::MerchantKeyStore,
    ) -> RouterResult<(Option<domain::PaymentMethodData>, SupplementaryVaultData)> {
        let de_tokenize =
            get_tokenized_data(state, lookup_key, true, merchant_key_store.key.get_inner()).await?;
        let (payment_method, customer_id) =
            domain::PaymentMethodData::from_values(de_tokenize.value1, de_tokenize.value2)
                .change_context(errors::ApiErrorResponse::InternalServerError)
                .attach_printable("Error parsing Payment Method from Values")?;

        Ok((Some(payment_method), customer_id))
    }

    #[instrument(skip_all)]
    pub async fn store_payment_method_data_in_locker(
        state: &routes::SessionState,
        token_id: Option<String>,
        payment_method: &domain::PaymentMethodData,
        customer_id: Option<id_type::CustomerId>,
        pm: enums::PaymentMethod,
        merchant_key_store: &domain::MerchantKeyStore,
    ) -> RouterResult<String> {
        let value1 = payment_method
            .get_value1(customer_id.clone())
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Error getting Value1 for locker")?;

        let value2 = payment_method
            .get_value2(customer_id)
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Error getting Value12 for locker")?;

        let lookup_key = token_id.unwrap_or_else(|| generate_id_with_default_len("token"));

        let lookup_key = create_tokenize(
            state,
            value1,
            Some(value2),
            lookup_key,
            merchant_key_store.key.get_inner(),
        )
        .await?;
        add_delete_tokenized_data_task(&*state.store, &lookup_key, pm).await?;
        metrics::TOKENIZED_DATA_COUNT.add(1, &[]);
        Ok(lookup_key)
    }

    #[cfg(feature = "payouts")]
    #[instrument(skip_all)]
    pub async fn get_payout_method_data_from_temporary_locker(
        state: &routes::SessionState,
        lookup_key: &str,
        merchant_key_store: &domain::MerchantKeyStore,
    ) -> RouterResult<(Option<api::PayoutMethodData>, SupplementaryVaultData)> {
        let de_tokenize =
            get_tokenized_data(state, lookup_key, true, merchant_key_store.key.get_inner()).await?;
        let (payout_method, supp_data) =
            api::PayoutMethodData::from_values(de_tokenize.value1, de_tokenize.value2)
                .change_context(errors::ApiErrorResponse::InternalServerError)
                .attach_printable("Error parsing Payout Method from Values")?;

        Ok((Some(payout_method), supp_data))
    }

    #[cfg(feature = "payouts")]
    #[instrument(skip_all)]
    pub async fn store_payout_method_data_in_locker(
        state: &routes::SessionState,
        token_id: Option<String>,
        payout_method: &api::PayoutMethodData,
        customer_id: Option<id_type::CustomerId>,
        merchant_key_store: &domain::MerchantKeyStore,
    ) -> RouterResult<String> {
        let value1 = payout_method
            .get_value1(customer_id.clone())
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Error getting Value1 for locker")?;

        let value2 = payout_method
            .get_value2(customer_id)
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Error getting Value2 for locker")?;

        let lookup_key =
            token_id.unwrap_or_else(|| generate_id_with_default_len("temporary_token"));

        let lookup_key = create_tokenize(
            state,
            value1,
            Some(value2),
            lookup_key,
            merchant_key_store.key.get_inner(),
        )
        .await?;
        // add_delete_tokenized_data_task(&*state.store, &lookup_key, pm).await?;
        // scheduler_metrics::TOKENIZED_DATA_COUNT.add(1, &[]);
        Ok(lookup_key)
    }

    #[instrument(skip_all)]
    pub async fn delete_locker_payment_method_by_lookup_key(
        state: &routes::SessionState,
        lookup_key: &Option<String>,
    ) {
        if let Some(lookup_key) = lookup_key {
            delete_tokenized_data(state, lookup_key)
                .await
                .map(|_| logger::info!("Card From locker deleted Successfully"))
                .map_err(|err| logger::error!("Error: Deleting Card From Redis Locker : {:?}", err))
                .ok();
        }
    }
}

//------------------------------------------------TokenizeService------------------------------------------------

#[inline(always)]
fn get_redis_locker_key(lookup_key: &str) -> String {
    format!("{}_{}", consts::LOCKER_REDIS_PREFIX, lookup_key)
}

#[instrument(skip(state, value1, value2))]
pub async fn create_tokenize(
    state: &routes::SessionState,
    value1: String,
    value2: Option<String>,
    lookup_key: String,
    encryption_key: &masking::Secret<Vec<u8>>,
) -> RouterResult<String> {
    let redis_key = get_redis_locker_key(lookup_key.as_str());
    let func = || async {
        metrics::CREATED_TOKENIZED_CARD.add(1, &[]);

        let payload_to_be_encrypted = api::TokenizePayloadRequest {
            value1: value1.clone(),
            value2: value2.clone().unwrap_or_default(),
            lookup_key: lookup_key.clone(),
            service_name: VAULT_SERVICE_NAME.to_string(),
        };

        let payload = payload_to_be_encrypted
            .encode_to_string_of_json()
            .change_context(errors::ApiErrorResponse::InternalServerError)?;

        let encrypted_payload = GcmAes256
            .encode_message(encryption_key.peek().as_ref(), payload.as_bytes())
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to encode redis temp locker data")?;

        let redis_conn = state
            .store
            .get_redis_conn()
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to get redis connection")?;

        redis_conn
            .set_key_if_not_exists_with_expiry(
                &redis_key.as_str().into(),
                bytes::Bytes::from(encrypted_payload),
                Some(i64::from(consts::LOCKER_REDIS_EXPIRY_SECONDS)),
            )
            .await
            .map(|_| lookup_key.clone())
            .inspect_err(|error| {
                metrics::TEMP_LOCKER_FAILURES.add(1, &[]);
                logger::error!(?error, "Failed to store tokenized data in Redis");
            })
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Error from redis locker")
    };

    match func().await {
        Ok(s) => {
            logger::info!(
                "Insert payload in redis locker successful with lookup key: {:?}",
                redis_key
            );
            Ok(s)
        }
        Err(err) => {
            logger::error!("Redis Temp locker Failed: {:?}", err);
            Err(err)
        }
    }
}

#[instrument(skip(state))]
pub async fn get_tokenized_data(
    state: &routes::SessionState,
    lookup_key: &str,
    _should_get_value2: bool,
    encryption_key: &masking::Secret<Vec<u8>>,
) -> RouterResult<api::TokenizePayloadRequest> {
    let redis_key = get_redis_locker_key(lookup_key);
    let func = || async {
        metrics::GET_TOKENIZED_CARD.add(1, &[]);

        let redis_conn = state
            .store
            .get_redis_conn()
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to get redis connection")?;

        let response = redis_conn
            .get_key::<bytes::Bytes>(&redis_key.as_str().into())
            .await;

        match response {
            Ok(resp) => {
                let decrypted_payload = GcmAes256
                    .decode_message(
                        encryption_key.peek().as_ref(),
                        masking::Secret::new(resp.into()),
                    )
                    .change_context(errors::ApiErrorResponse::InternalServerError)
                    .attach_printable("Failed to decode redis temp locker data")?;

                let get_response: api::TokenizePayloadRequest =
                    bytes::Bytes::from(decrypted_payload)
                        .parse_struct("TokenizePayloadRequest")
                        .change_context(errors::ApiErrorResponse::InternalServerError)
                        .attach_printable(
                            "Error getting TokenizePayloadRequest from tokenize response",
                        )?;

                Ok(get_response)
            }
            Err(err) => {
                metrics::TEMP_LOCKER_FAILURES.add(1, &[]);
                Err(err).change_context(errors::ApiErrorResponse::UnprocessableEntity {
                    message: "Token is invalid or expired".into(),
                })
            }
        }
    };

    match func().await {
        Ok(s) => {
            logger::info!(
                "Fetch payload in redis locker successful with lookup key: {:?}",
                redis_key
            );
            Ok(s)
        }
        Err(err) => {
            logger::error!("Redis Temp locker Failed: {:?}", err);
            Err(err)
        }
    }
}

#[instrument(skip(state))]
pub async fn delete_tokenized_data(
    state: &routes::SessionState,
    lookup_key: &str,
) -> RouterResult<()> {
    let redis_key = get_redis_locker_key(lookup_key);
    let func = || async {
        metrics::DELETED_TOKENIZED_CARD.add(1, &[]);

        let redis_conn = state
            .store
            .get_redis_conn()
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to get redis connection")?;

        let response = redis_conn.delete_key(&redis_key.as_str().into()).await;

        match response {
            Ok(redis_interface::DelReply::KeyDeleted) => Ok(()),
            Ok(redis_interface::DelReply::KeyNotDeleted) => {
                Err(errors::ApiErrorResponse::InternalServerError)
                    .attach_printable("Token invalid or expired")
            }
            Err(err) => {
                metrics::TEMP_LOCKER_FAILURES.add(1, &[]);
                Err(errors::ApiErrorResponse::InternalServerError).attach_printable_lazy(|| {
                    format!("Failed to delete from redis locker: {err:?}")
                })
            }
        }
    };
    match func().await {
        Ok(s) => {
            logger::info!(
                "Delete payload in redis locker successful with lookup key: {:?}",
                redis_key
            );
            Ok(s)
        }
        Err(err) => {
            logger::error!("Redis Temp locker Failed: {:?}", err);
            Err(err)
        }
    }
}

#[cfg(feature = "v2")]
async fn create_vault_request<R: pm_types::VaultingInterface>(
    jwekey: &settings::Jwekey,
    locker: &settings::Locker,
    payload: Vec<u8>,
    tenant_id: id_type::TenantId,
) -> CustomResult<request::Request, errors::VaultError> {
    let private_key = jwekey.vault_private_key.peek().as_bytes();

    let jws = services::encryption::jws_sign_payload(
        &payload,
        &locker.locker_signing_key_id,
        private_key,
    )
    .await
    .change_context(errors::VaultError::RequestEncryptionFailed)?;

    let jwe_payload = pm_transforms::create_jwe_body_for_vault(jwekey, &jws).await?;

    let mut url = locker.host.to_owned();
    url.push_str(R::get_vaulting_request_url());
    let mut request = request::Request::new(services::Method::Post, &url);
    request.add_header(
        headers::CONTENT_TYPE,
        consts::VAULT_HEADER_CONTENT_TYPE.into(),
    );
    request.add_header(
        headers::X_TENANT_ID,
        tenant_id.get_string_repr().to_owned().into(),
    );
    request.set_body(request::RequestContent::Json(Box::new(jwe_payload)));
    Ok(request)
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn call_to_vault<V: pm_types::VaultingInterface>(
    state: &routes::SessionState,
    payload: Vec<u8>,
) -> CustomResult<String, errors::VaultError> {
    let locker = &state.conf.locker;
    let jwekey = state.conf.jwekey.get_inner();

    let request =
        create_vault_request::<V>(jwekey, locker, payload, state.tenant.tenant_id.to_owned())
            .await?;
    let response = services::call_connector_api(state, request, V::get_vaulting_flow_name())
        .await
        .change_context(errors::VaultError::VaultAPIError);

    let jwe_body: services::JweBody = response
        .get_response_inner("JweBody")
        .change_context(errors::VaultError::ResponseDeserializationFailed)
        .attach_printable("Failed to get JweBody from vault response")?;

    let decrypted_payload = pm_transforms::get_decrypted_vault_response_payload(
        jwekey,
        jwe_body,
        locker.decryption_scheme.clone(),
    )
    .await
    .change_context(errors::VaultError::ResponseDecryptionFailed)
    .attach_printable("Error getting decrypted vault response payload")?;

    Ok(decrypted_payload)
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn get_fingerprint_id_from_vault<D: domain::VaultingDataInterface + serde::Serialize>(
    state: &routes::SessionState,
    data: &D,
    key: String,
) -> CustomResult<String, errors::VaultError> {
    let data = serde_json::to_string(data)
        .change_context(errors::VaultError::RequestEncodingFailed)
        .attach_printable("Failed to encode Vaulting data to string")?;

    let payload = pm_types::VaultFingerprintRequest { key, data }
        .encode_to_vec()
        .change_context(errors::VaultError::RequestEncodingFailed)
        .attach_printable("Failed to encode VaultFingerprintRequest")?;

    let resp = call_to_vault::<pm_types::GetVaultFingerprint>(state, payload)
        .await
        .change_context(errors::VaultError::VaultAPIError)
        .attach_printable("Call to vault failed")?;

    let fingerprint_resp: pm_types::VaultFingerprintResponse = resp
        .parse_struct("VaultFingerprintResponse")
        .change_context(errors::VaultError::ResponseDeserializationFailed)
        .attach_printable("Failed to parse data into VaultFingerprintResponse")?;

    Ok(fingerprint_resp.fingerprint_id)
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn add_payment_method_to_vault(
    state: &routes::SessionState,
    merchant_context: &domain::MerchantContext,
    pmd: &domain::PaymentMethodVaultingData,
    existing_vault_id: Option<domain::VaultId>,
    customer_id: &id_type::GlobalCustomerId,
) -> CustomResult<pm_types::AddVaultResponse, errors::VaultError> {
    let payload = pm_types::AddVaultRequest {
        entity_id: customer_id.to_owned(),
        vault_id: existing_vault_id
            .unwrap_or(domain::VaultId::generate(uuid::Uuid::now_v7().to_string())),
        data: pmd,
        ttl: state.conf.locker.ttl_for_storage_in_secs,
    }
    .encode_to_vec()
    .change_context(errors::VaultError::RequestEncodingFailed)
    .attach_printable("Failed to encode AddVaultRequest")?;

    let resp = call_to_vault::<pm_types::AddVault>(state, payload)
        .await
        .change_context(errors::VaultError::VaultAPIError)
        .attach_printable("Call to vault failed")?;

    let stored_pm_resp: pm_types::AddVaultResponse = resp
        .parse_struct("AddVaultResponse")
        .change_context(errors::VaultError::ResponseDeserializationFailed)
        .attach_printable("Failed to parse data into AddVaultResponse")?;

    Ok(stored_pm_resp)
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn retrieve_payment_method_from_vault_internal(
    state: &routes::SessionState,
    merchant_context: &domain::MerchantContext,
    vault_id: &domain::VaultId,
    customer_id: &id_type::GlobalCustomerId,
) -> CustomResult<pm_types::VaultRetrieveResponse, errors::VaultError> {
    let payload = pm_types::VaultRetrieveRequest {
        entity_id: customer_id.to_owned(),
        vault_id: vault_id.to_owned(),
    }
    .encode_to_vec()
    .change_context(errors::VaultError::RequestEncodingFailed)
    .attach_printable("Failed to encode VaultRetrieveRequest")?;

    let resp = call_to_vault::<pm_types::VaultRetrieve>(state, payload)
        .await
        .change_context(errors::VaultError::VaultAPIError)
        .attach_printable("Call to vault failed")?;

    let stored_pm_resp: pm_types::VaultRetrieveResponse = resp
        .parse_struct("VaultRetrieveResponse")
        .change_context(errors::VaultError::ResponseDeserializationFailed)
        .attach_printable("Failed to parse data into VaultRetrieveResponse")?;

    Ok(stored_pm_resp)
}

#[cfg(all(feature = "v2", feature = "tokenization_v2"))]
#[instrument(skip_all)]
pub async fn retrieve_value_from_vault(
    state: &routes::SessionState,
    request: pm_types::VaultRetrieveRequest,
) -> CustomResult<serde_json::value::Value, errors::VaultError> {
    let payload = request
        .encode_to_vec()
        .change_context(errors::VaultError::RequestEncodingFailed)
        .attach_printable("Failed to encode VaultRetrieveRequest")?;

    let resp = call_to_vault::<pm_types::VaultRetrieve>(state, payload)
        .await
        .change_context(errors::VaultError::VaultAPIError)
        .attach_printable("Call to vault failed")?;

    let stored_resp: serde_json::Value = resp
        .parse_struct("VaultRetrieveResponse")
        .change_context(errors::VaultError::ResponseDeserializationFailed)
        .attach_printable("Failed to parse data into VaultRetrieveResponse")?;

    Ok(stored_resp)
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn retrieve_payment_method_from_vault_external(
    state: &routes::SessionState,
    merchant_account: &domain::MerchantAccount,
    pm: &domain::PaymentMethod,
    merchant_connector_account: domain::MerchantConnectorAccountTypeDetails,
) -> RouterResult<pm_types::VaultRetrieveResponse> {
    let connector_vault_id = pm
        .locker_id
        .clone()
        .map(|id| id.get_string_repr().to_owned());

    let router_data = core_utils::construct_vault_router_data(
        state,
        merchant_account,
        &merchant_connector_account,
        None,
        connector_vault_id,
        None,
    )
    .await?;

    let mut old_router_data = VaultConnectorFlowData::to_old_router_data(router_data)
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable(
            "Cannot construct router data for making the external vault retrieve api call",
        )?;

    let connector_name = merchant_connector_account
        .get_connector_name()
        .ok_or(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Connector name not present for external vault")?; // always get the connector name from this call

    let connector_data = api::ConnectorData::get_external_vault_connector_by_name(
        &state.conf.connectors,
        &connector_name,
        api::GetToken::Connector,
        merchant_connector_account.get_mca_id(),
    )
    .change_context(errors::ApiErrorResponse::InternalServerError)
    .attach_printable("Failed to get the connector data")?;

    let connector_integration: services::BoxedVaultConnectorIntegrationInterface<
        ExternalVaultRetrieveFlow,
        types::VaultRequestData,
        types::VaultResponseData,
    > = connector_data.connector.get_connector_integration();

    let router_data_resp = services::execute_connector_processing_step(
        state,
        connector_integration,
        &old_router_data,
        payments_core::CallConnectorAction::Trigger,
        None,
        None,
    )
    .await
    .to_vault_failed_response()?;

    get_vault_response_for_retrieve_payment_method_data::<ExternalVaultRetrieveFlow>(
        router_data_resp,
    )
}

#[cfg(feature = "v2")]
pub fn get_vault_response_for_retrieve_payment_method_data<F>(
    router_data: VaultRouterData<F>,
) -> RouterResult<pm_types::VaultRetrieveResponse> {
    match router_data.response {
        Ok(response) => match response {
            types::VaultResponseData::ExternalVaultRetrieveResponse { vault_data } => {
                Ok(pm_types::VaultRetrieveResponse { data: vault_data })
            }
            types::VaultResponseData::ExternalVaultInsertResponse { .. }
            | types::VaultResponseData::ExternalVaultDeleteResponse { .. }
            | types::VaultResponseData::ExternalVaultCreateResponse { .. } => {
                Err(report!(errors::ApiErrorResponse::InternalServerError)
                    .attach_printable("Invalid Vault Response"))
            }
        },
        Err(err) => Err(report!(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to retrieve payment method")),
    }
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn retrieve_payment_method_from_vault_using_payment_token(
    state: &routes::SessionState,
    merchant_context: &domain::MerchantContext,
    profile: &domain::Profile,
    payment_token: &String,
    payment_method_type: &common_enums::PaymentMethod,
) -> RouterResult<(domain::PaymentMethod, domain::PaymentMethodVaultingData)> {
    let pm_token_data = utils::retrieve_payment_token_data(
        state,
        payment_token.to_string(),
        Some(payment_method_type),
    )
    .await?;

    let payment_method_id = match pm_token_data {
        storage::PaymentTokenData::PermanentCard(card_token_data) => {
            card_token_data.payment_method_id
        }
        storage::PaymentTokenData::TemporaryGeneric(_) => {
            Err(errors::ApiErrorResponse::NotImplemented {
                message: errors::NotImplementedMessage::Reason(
                    "TemporaryGeneric Token not implemented".to_string(),
                ),
            })?
        }
        storage::PaymentTokenData::AuthBankDebit(_) => {
            Err(errors::ApiErrorResponse::NotImplemented {
                message: errors::NotImplementedMessage::Reason(
                    "AuthBankDebit Token not implemented".to_string(),
                ),
            })?
        }
    };
    let db = &*state.store;
    let key_manager_state = &state.into();

    let storage_scheme = merchant_context.get_merchant_account().storage_scheme;

    let payment_method = db
        .find_payment_method(
            key_manager_state,
            merchant_context.get_merchant_key_store(),
            &payment_method_id,
            storage_scheme,
        )
        .await
        .to_not_found_response(errors::ApiErrorResponse::PaymentNotFound)?;

    let vault_data =
        retrieve_payment_method_from_vault(state, merchant_context, profile, &payment_method)
            .await
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to retrieve payment method from vault")?
            .data;

    Ok((payment_method, vault_data))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TemporaryVaultCvc {
    card_cvc: masking::Secret<String>,
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn insert_cvc_using_payment_token(
    state: &routes::SessionState,
    payment_token: &String,
    payment_method_data: api_models::payment_methods::PaymentMethodCreateData,
    payment_method: common_enums::PaymentMethod,
    fullfillment_time: i64,
    encryption_key: &masking::Secret<Vec<u8>>,
) -> RouterResult<()> {
    let card_cvc = domain::PaymentMethodVaultingData::from(payment_method_data)
        .get_card()
        .and_then(|card| card.card_cvc.clone());

    if let Some(card_cvc) = card_cvc {
        let redis_conn = state
            .store
            .get_redis_conn()
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to get redis connection")?;

        let key = format!("pm_token_{payment_token}_{payment_method}_hyperswitch_cvc");

        let payload_to_be_encrypted = TemporaryVaultCvc { card_cvc };

        let payload = payload_to_be_encrypted
            .encode_to_string_of_json()
            .change_context(errors::ApiErrorResponse::InternalServerError)?;

        // Encrypt the CVC and store it in Redis
        let encrypted_payload = GcmAes256
            .encode_message(encryption_key.peek().as_ref(), payload.as_bytes())
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to encode TemporaryVaultCvc for vault")?;

        redis_conn
            .set_key_if_not_exists_with_expiry(
                &key.as_str().into(),
                bytes::Bytes::from(encrypted_payload),
                Some(fullfillment_time),
            )
            .await
            .change_context(errors::StorageError::KVError)
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to add token in redis")?;
    };

    Ok(())
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn retrieve_and_delete_cvc_from_payment_token(
    state: &routes::SessionState,
    payment_token: &String,
    payment_method: common_enums::PaymentMethod,
    encryption_key: &masking::Secret<Vec<u8>>,
) -> RouterResult<masking::Secret<String>> {
    let redis_conn = state
        .store
        .get_redis_conn()
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Failed to get redis connection")?;

    let key = format!("pm_token_{payment_token}_{payment_method}_hyperswitch_cvc",);

    let data = redis_conn
        .get_key::<bytes::Bytes>(&key.clone().into())
        .await
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Failed to fetch the token from redis")?;

    // decrypt the cvc data
    let decrypted_payload = GcmAes256
        .decode_message(
            encryption_key.peek().as_ref(),
            masking::Secret::new(data.into()),
        )
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Failed to decode TemporaryVaultCvc from vault")?;

    let cvc_data: TemporaryVaultCvc = bytes::Bytes::from(decrypted_payload)
        .parse_struct("TemporaryVaultCvc")
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Failed to deserialize TemporaryVaultCvc")?;

    // delete key after retrieving the cvc
    redis_conn.delete_key(&key.into()).await.map_err(|err| {
        logger::error!("Failed to delete token from redis: {:?}", err);
    });

    Ok(cvc_data.card_cvc)
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn delete_payment_token(
    state: &routes::SessionState,
    key_for_token: &str,
    intent_status: enums::IntentStatus,
) -> RouterResult<()> {
    if ![
        enums::IntentStatus::RequiresCustomerAction,
        enums::IntentStatus::RequiresMerchantAction,
    ]
    .contains(&intent_status)
    {
        utils::delete_payment_token_data(state, key_for_token)
            .await
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Unable to delete payment_token")?;
    }
    Ok(())
}

#[cfg(feature = "v2")]
#[instrument(skip_all)]
pub async fn retrieve_payment_method_from_vault(
    state: &routes::SessionState,
    merchant_context: &domain::MerchantContext,
    profile: &domain::Profile,
    pm: &domain::PaymentMethod,
) -> RouterResult<pm_types::VaultRetrieveResponse> {
    let is_external_vault_enabled = profile.is_external_vault_enabled();

    match is_external_vault_enabled {
        true => {
            let external_vault_source = pm.external_vault_source.as_ref();

            let merchant_connector_account =
                domain::MerchantConnectorAccountTypeDetails::MerchantConnectorAccount(Box::new(
                    payments_core::helpers::get_merchant_connector_account_v2(
                        state,
                        merchant_context.get_merchant_key_store(),
                        external_vault_source,
                    )
                    .await
                    .attach_printable(
                        "failed to fetch merchant connector account for external vault retrieve",
                    )?,
                ));

            retrieve_payment_method_from_vault_external(
                state,
                merchant_context.get_merchant_account(),
                pm,
                merchant_connector_account,
            )
            .await
        }
        false => {
            let vault_id = pm
                .locker_id
                .clone()
                .ok_or(errors::VaultError::MissingRequiredField {
                    field_name: "locker_id",
                })
                .change_context(errors::ApiErrorResponse::InternalServerError)
                .attach_printable("Missing locker_id for VaultRetrieveRequest")?;
            retrieve_payment_method_from_vault_internal(
                state,
                merchant_context,
                &vault_id,
                &pm.customer_id,
            )
            .await
            .change_context(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to retrieve payment method from vault")
        }
    }
}

#[cfg(feature = "v2")]
pub async fn delete_payment_method_data_from_vault_internal(
    state: &routes::SessionState,
    merchant_context: &domain::MerchantContext,
    vault_id: domain::VaultId,
    customer_id: &id_type::GlobalCustomerId,
) -> CustomResult<pm_types::VaultDeleteResponse, errors::VaultError> {
    let payload = pm_types::VaultDeleteRequest {
        entity_id: customer_id.to_owned(),
        vault_id,
    }
    .encode_to_vec()
    .change_context(errors::VaultError::RequestEncodingFailed)
    .attach_printable("Failed to encode VaultDeleteRequest")?;

    let resp = call_to_vault::<pm_types::VaultDelete>(state, payload)
        .await
        .change_context(errors::VaultError::VaultAPIError)
        .attach_printable("Call to vault failed")?;

    let stored_pm_resp: pm_types::VaultDeleteResponse = resp
        .parse_struct("VaultDeleteResponse")
        .change_context(errors::VaultError::ResponseDeserializationFailed)
        .attach_printable("Failed to parse data into VaultDeleteResponse")?;

    Ok(stored_pm_resp)
}

#[cfg(feature = "v2")]
pub async fn delete_payment_method_data_from_vault_external(
    state: &routes::SessionState,
    merchant_account: &domain::MerchantAccount,
    merchant_connector_account: domain::MerchantConnectorAccountTypeDetails,
    vault_id: domain::VaultId,
    customer_id: &id_type::GlobalCustomerId,
) -> RouterResult<pm_types::VaultDeleteResponse> {
    let connector_vault_id = vault_id.get_string_repr().to_owned();

    let router_data = core_utils::construct_vault_router_data(
        state,
        merchant_account,
        &merchant_connector_account,
        None,
        Some(connector_vault_id),
        None,
    )
    .await?;

    let mut old_router_data = VaultConnectorFlowData::to_old_router_data(router_data)
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable(
            "Cannot construct router data for making the external vault delete api call",
        )?;

    let connector_name = merchant_connector_account
        .get_connector_name()
        .ok_or(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Connector name not present for external vault")?; // always get the connector name from this call

    let connector_data = api::ConnectorData::get_external_vault_connector_by_name(
        &state.conf.connectors,
        &connector_name,
        api::GetToken::Connector,
        merchant_connector_account.get_mca_id(),
    )
    .change_context(errors::ApiErrorResponse::InternalServerError)
    .attach_printable("Failed to get the connector data")?;

    let connector_integration: services::BoxedVaultConnectorIntegrationInterface<
        ExternalVaultDeleteFlow,
        types::VaultRequestData,
        types::VaultResponseData,
    > = connector_data.connector.get_connector_integration();

    let router_data_resp = services::execute_connector_processing_step(
        state,
        connector_integration,
        &old_router_data,
        payments_core::CallConnectorAction::Trigger,
        None,
        None,
    )
    .await
    .to_vault_failed_response()?;

    get_vault_response_for_delete_payment_method_data::<ExternalVaultDeleteFlow>(
        router_data_resp,
        customer_id.to_owned(),
    )
}

#[cfg(feature = "v2")]
pub fn get_vault_response_for_delete_payment_method_data<F>(
    router_data: VaultRouterData<F>,
    customer_id: id_type::GlobalCustomerId,
) -> RouterResult<pm_types::VaultDeleteResponse> {
    match router_data.response {
        Ok(response) => match response {
            types::VaultResponseData::ExternalVaultDeleteResponse { connector_vault_id } => {
                Ok(pm_types::VaultDeleteResponse {
                    vault_id: domain::VaultId::generate(connector_vault_id), // converted to VaultId type
                    entity_id: customer_id,
                })
            }
            types::VaultResponseData::ExternalVaultInsertResponse { .. }
            | types::VaultResponseData::ExternalVaultRetrieveResponse { .. }
            | types::VaultResponseData::ExternalVaultCreateResponse { .. } => {
                Err(report!(errors::ApiErrorResponse::InternalServerError)
                    .attach_printable("Invalid Vault Response"))
            }
        },
        Err(err) => Err(report!(errors::ApiErrorResponse::InternalServerError)
            .attach_printable("Failed to retrieve payment method")),
    }
}

#[cfg(feature = "v2")]
pub async fn delete_payment_method_data_from_vault(
    state: &routes::SessionState,
    merchant_context: &domain::MerchantContext,
    profile: &domain::Profile,
    pm: &domain::PaymentMethod,
) -> RouterResult<pm_types::VaultDeleteResponse> {
    let is_external_vault_enabled = profile.is_external_vault_enabled();

    let vault_id = pm
        .locker_id
        .clone()
        .get_required_value("locker_id")
        .attach_printable("Missing locker_id in PaymentMethod")?;

    match is_external_vault_enabled {
        true => {
            let external_vault_source = pm.external_vault_source.as_ref();

            let merchant_connector_account =
                domain::MerchantConnectorAccountTypeDetails::MerchantConnectorAccount(Box::new(
                    payments_core::helpers::get_merchant_connector_account_v2(
                        state,
                        merchant_context.get_merchant_key_store(),
                        external_vault_source,
                    )
                    .await
                    .attach_printable(
                        "failed to fetch merchant connector account for external vault delete",
                    )?,
                ));

            delete_payment_method_data_from_vault_external(
                state,
                merchant_context.get_merchant_account(),
                merchant_connector_account,
                vault_id.clone(),
                &pm.customer_id,
            )
            .await
        }
        false => delete_payment_method_data_from_vault_internal(
            state,
            merchant_context,
            vault_id,
            &pm.customer_id,
        )
        .await
        .change_context(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Failed to delete payment method from vault"),
    }
}

// ********************************************** PROCESS TRACKER **********************************************

pub async fn add_delete_tokenized_data_task(
    db: &dyn db::StorageInterface,
    lookup_key: &str,
    pm: enums::PaymentMethod,
) -> RouterResult<()> {
    let runner = storage::ProcessTrackerRunner::DeleteTokenizeDataWorkflow;
    let process_tracker_id = format!("{runner}_{lookup_key}");
    let task = runner.to_string();
    let tag = ["BASILISK-V3"];
    let tracking_data = storage::TokenizeCoreWorkflow {
        lookup_key: lookup_key.to_owned(),
        pm,
    };
    let schedule_time = get_delete_tokenize_schedule_time(db, pm, 0)
        .await
        .ok_or(errors::ApiErrorResponse::InternalServerError)
        .attach_printable("Failed to obtain initial process tracker schedule time")?;

    let process_tracker_entry = storage::ProcessTrackerNew::new(
        process_tracker_id,
        &task,
        runner,
        tag,
        tracking_data,
        None,
        schedule_time,
        common_types::consts::API_VERSION,
    )
    .change_context(errors::ApiErrorResponse::InternalServerError)
    .attach_printable("Failed to construct delete tokenized data process tracker task")?;

    let response = db.insert_process(process_tracker_entry).await;
    response.map(|_| ()).or_else(|err| {
        if err.current_context().is_db_unique_violation() {
            Ok(())
        } else {
            Err(report!(errors::ApiErrorResponse::InternalServerError))
        }
    })
}

pub async fn start_tokenize_data_workflow(
    state: &routes::SessionState,
    tokenize_tracker: &storage::ProcessTracker,
) -> Result<(), errors::ProcessTrackerError> {
    let db = &*state.store;
    let delete_tokenize_data = serde_json::from_value::<storage::TokenizeCoreWorkflow>(
        tokenize_tracker.tracking_data.clone(),
    )
    .change_context(errors::ApiErrorResponse::InternalServerError)
    .attach_printable_lazy(|| {
        format!(
            "unable to convert into DeleteTokenizeByTokenRequest {:?}",
            tokenize_tracker.tracking_data
        )
    })?;

    match delete_tokenized_data(state, &delete_tokenize_data.lookup_key).await {
        Ok(()) => {
            logger::info!("Card From locker deleted Successfully");
            //mark task as finished
            db.as_scheduler()
                .finish_process_with_business_status(
                    tokenize_tracker.clone(),
                    diesel_models::process_tracker::business_status::COMPLETED_BY_PT,
                )
                .await?;
        }
        Err(err) => {
            logger::error!("Err: Deleting Card From Locker : {:?}", err);
            retry_delete_tokenize(db, delete_tokenize_data.pm, tokenize_tracker.to_owned()).await?;
            metrics::RETRIED_DELETE_DATA_COUNT.add(1, &[]);
        }
    }
    Ok(())
}

pub async fn get_delete_tokenize_schedule_time(
    db: &dyn db::StorageInterface,
    pm: enums::PaymentMethod,
    retry_count: i32,
) -> Option<time::PrimitiveDateTime> {
    let redis_mapping = db::get_and_deserialize_key(
        db,
        &format!("pt_mapping_delete_{pm}_tokenize_data"),
        "PaymentMethodsPTMapping",
    )
    .await;
    let mapping = match redis_mapping {
        Ok(x) => x,
        Err(error) => {
            logger::info!(?error, "Redis Mapping Error");
            process_data::PaymentMethodsPTMapping::default()
        }
    };
    let time_delta = process_tracker_utils::get_pm_schedule_time(mapping, pm, retry_count + 1);

    process_tracker_utils::get_time_from_delta(time_delta)
}

pub async fn retry_delete_tokenize(
    db: &dyn db::StorageInterface,
    pm: enums::PaymentMethod,
    pt: storage::ProcessTracker,
) -> Result<(), errors::ProcessTrackerError> {
    let schedule_time = get_delete_tokenize_schedule_time(db, pm, pt.retry_count).await;

    match schedule_time {
        Some(s_time) => {
            let retry_schedule = db
                .as_scheduler()
                .retry_process(pt, s_time)
                .await
                .map_err(Into::into);
            metrics::TASKS_RESET_COUNT.add(
                1,
                router_env::metric_attributes!(("flow", "DeleteTokenizeData")),
            );
            retry_schedule
        }
        None => db
            .as_scheduler()
            .finish_process_with_business_status(
                pt,
                diesel_models::process_tracker::business_status::RETRIES_EXCEEDED,
            )
            .await
            .map_err(Into::into),
    }
}

// Fallback logic of old temp locker needs to be removed later
