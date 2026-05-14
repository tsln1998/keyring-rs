//! Bitwarden identity authentication primitives used by the local provider integration.
//!
//! The provider only needs the API-key client-credentials exchange and a small subset of the
//! identity response payload, so this module keeps a deliberately narrow surface.

use anyhow::anyhow;
use bitwarden_api_api::models::MasterPasswordUnlockResponseModel;
use bitwarden_api_identity::apis::configuration::Configuration as IdentityConfiguration;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::fmt::Write as _;
use tracing::{debug, error};

const DEVICE_TYPE: u8 = 10;
const DEVICE_IDENTIFIER: &str = "b86dd6ab-4265-4ddf-a7f1-eb28d5677f33";
const DEVICE_NAME: &str = "firefox";

/// Form payload expected by Bitwarden's API-key token endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct BitwardenApiTokenRequest {
    scope: String,
    client_id: String,
    client_secret: String,
    #[serde(rename = "deviceType")]
    device_type: u8,
    #[serde(rename = "deviceIdentifier")]
    device_identifier: String,
    #[serde(rename = "deviceName")]
    device_name: String,
    grant_type: String,
}

impl BitwardenApiTokenRequest {
    fn new(client_id: &str, client_secret: &str) -> Self {
        Self {
            scope: "api".to_owned(),
            client_id: client_id.to_owned(),
            client_secret: client_secret.to_owned(),
            device_type: DEVICE_TYPE,
            device_identifier: DEVICE_IDENTIFIER.to_owned(),
            device_name: DEVICE_NAME.to_owned(),
            grant_type: "client_credentials".to_owned(),
        }
    }

    fn pairs(&self) -> [(&'static str, &str); 7] {
        [
            ("scope", self.scope.as_str()),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("deviceType", "10"),
            ("deviceIdentifier", self.device_identifier.as_str()),
            ("deviceName", self.device_name.as_str()),
            ("grant_type", self.grant_type.as_str()),
        ]
    }

    fn to_form_body(&self) -> String {
        // Field names are fixed ASCII literals, so only the runtime values need encoding here.
        self.pairs()
            .into_iter()
            .map(|(key, value)| format!("{key}={}", percent_encode(value)))
            .collect::<Vec<_>>()
            .join("&")
    }
}

/// Minimal successful token payload required to bootstrap local Bitwarden crypto.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct BitwardenTokenSuccessResponse {
    pub(crate) access_token: String,
    pub(crate) expires_in: u64,
    #[serde(rename = "privateKey", alias = "PrivateKey")]
    pub(crate) private_key: Option<String>,
    #[serde(
        rename = "userDecryptionOptions",
        alias = "UserDecryptionOptions",
        default
    )]
    pub(crate) user_decryption_options: Option<BitwardenUserDecryptionOptionsResponseModel>,
}

/// User-decryption options subset needed for master-password unlock.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct BitwardenUserDecryptionOptionsResponseModel {
    #[serde(
        rename = "masterPasswordUnlock",
        alias = "MasterPasswordUnlock",
        default
    )]
    pub(crate) master_password_unlock: Option<Box<MasterPasswordUnlockResponseModel>>,
}

/// Normalized identity error payload returned by `/connect/token`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct BitwardenIdentityTokenFailResponse {
    pub(crate) error: String,
    pub(crate) error_description: String,
    #[serde(alias = "ErrorModel")]
    pub(crate) error_model: BitwardenIdentityErrorModel,
}

impl fmt::Display for BitwardenIdentityTokenFailResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.error_model.message.trim().is_empty() {
            write!(formatter, "{}: {}", self.error, self.error_description)
        } else {
            formatter.write_str(&self.error_model.message)
        }
    }
}

/// Nested identity error object used by the Bitwarden API.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct BitwardenIdentityErrorModel {
    #[serde(alias = "Message")]
    pub(crate) message: String,
    #[serde(alias = "Object")]
    pub(crate) object: String,
}

/// Shape used by Bitwarden to signal that two-factor auth is required.
#[derive(Clone, Debug, Deserialize, PartialEq)]
struct BitwardenTwoFactorResponse {
    pub(crate) error: String,
    pub(crate) error_description: String,
    #[serde(rename = "twoFactorProviders2", alias = "TwoFactorProviders2")]
    pub(crate) two_factor_providers: BTreeMap<String, Value>,
}

/// Local authentication error variants surfaced to the provider boundary.
#[derive(Debug)]
pub(crate) enum BitwardenAuthError {
    TokenRequest(anyhow::Error),
    IdentityFail(BitwardenIdentityTokenFailResponse),
    TwoFactorRequired,
    InvalidResponse(String),
    CryptoBootstrap(anyhow::Error),
}

impl BitwardenAuthError {
    pub(crate) fn token_request(error: anyhow::Error) -> Self {
        Self::TokenRequest(error)
    }

    pub(crate) fn crypto_bootstrap(error: anyhow::Error) -> Self {
        Self::CryptoBootstrap(error)
    }
}

impl fmt::Display for BitwardenAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TokenRequest(_) => formatter.write_str("failed to request bitwarden token"),
            Self::IdentityFail(error) => fmt::Display::fmt(error, formatter),
            Self::TwoFactorRequired => {
                formatter.write_str("bitwarden requires two-factor authentication")
            }
            Self::InvalidResponse(body) => {
                write!(
                    formatter,
                    "bitwarden identity response could not be parsed: {body}"
                )
            }
            Self::CryptoBootstrap(_) => {
                formatter.write_str("failed to initialize bitwarden crypto")
            }
        }
    }
}

impl std::error::Error for BitwardenAuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::TokenRequest(error) | Self::CryptoBootstrap(error) => Some(error.as_ref()),
            Self::IdentityFail(_) | Self::TwoFactorRequired | Self::InvalidResponse(_) => None,
        }
    }
}

/// Performs the API-key token exchange against Bitwarden identity.
pub(crate) async fn request_api_key_token(
    config: &IdentityConfiguration,
    client_id: &str,
    client_secret: &str,
) -> Result<BitwardenTokenSuccessResponse, BitwardenAuthError> {
    debug!(identity_url = %config.base_path, client_id, "requesting bitwarden api-key token");

    let request = BitwardenApiTokenRequest::new(client_id, client_secret);

    // Bitwarden expects a classic form post for API-key login rather than a JSON payload.
    let mut builder = config
        .client
        .post(format!("{}/connect/token", config.base_path))
        .header(
            "content-type",
            "application/x-www-form-urlencoded; charset=utf-8",
        )
        .header("accept", "application/json")
        .header("Device-Type", DEVICE_TYPE.to_string())
        .body(request.to_form_body());

    if let Some(user_agent) = &config.user_agent {
        builder = builder.header("user-agent", user_agent.clone());
    }

    // Transport failures are mapped first so callers can distinguish them from identity errors
    // reported by Bitwarden itself.
    let response = builder
        .send()
        .await
        .map_err(|error| BitwardenAuthError::token_request(anyhow!(error)))?;

    // Read the full body before branching because the same payload may need to be interpreted as
    // success, two-factor-required, or a structured identity error.
    let body = response
        .text()
        .await
        .map_err(|error| BitwardenAuthError::token_request(anyhow!(error)))?;

    debug!(
        body_len = body.len(),
        "received bitwarden identity response"
    );
    parse_token_response(&body)
}

fn parse_token_response(body: &str) -> Result<BitwardenTokenSuccessResponse, BitwardenAuthError> {
    // Success is checked first because Bitwarden uses overlapping field names across multiple
    // response shapes, and the provider only cares about the authenticated path here.
    if let Ok(response) = serde_json::from_str::<BitwardenTokenSuccessResponse>(body) {
        debug!(
            expires_in = response.expires_in,
            "parsed successful bitwarden token response"
        );
        return Ok(response);
    }

    // Bitwarden uses a distinct response shape when the account requires an interactive second
    // factor, which this headless provider intentionally does not support.
    if serde_json::from_str::<BitwardenTwoFactorResponse>(body).is_ok() {
        error!("bitwarden identity response requires two-factor authentication");
        return Err(BitwardenAuthError::TwoFactorRequired);
    }

    // Structured identity failures are still useful to bubble up because they often contain the
    // real configuration or credential problem.
    if let Ok(response) = serde_json::from_str::<BitwardenIdentityTokenFailResponse>(body) {
        error!(message = %response, "bitwarden identity response returned an error");
        return Err(BitwardenAuthError::IdentityFail(response));
    }

    // Anything else is treated as an unexpected payload so the caller can log the raw response.
    error!(body, "bitwarden identity response could not be parsed");
    Err(BitwardenAuthError::InvalidResponse(body.to_owned()))
}

fn percent_encode(value: &str) -> String {
    // This is intentionally tiny because the Bitwarden login request only needs value escaping for
    // `application/x-www-form-urlencoded`.
    let mut encoded = String::with_capacity(value.len());

    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }

    encoded
}
