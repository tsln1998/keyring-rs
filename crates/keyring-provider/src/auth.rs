//! Bitwarden identity authentication primitives used by the local provider integration.
//!
//! The provider only needs the API-key client-credentials exchange and a small subset of the
//! identity response payload, so this module keeps a deliberately narrow surface.

use crate::models::MasterPasswordUnlockResponseModel;
use anyhow::anyhow;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use tracing::{debug, error};
use zeroize::{Zeroize, Zeroizing};

const DEVICE_TYPE: u8 = 10;
// Keep the identity request's device metadata consistent across API-key exchanges.
// These values describe the client to the server; they are not vault decryption inputs.
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
    /// Builds the API-key grant without including the locally supplied master password.
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
}

/// Classifies token bodies by their fields rather than relying on a server-provided type tag.
///
/// HTTP status is checked separately: a success-shaped body on a failed request is not a login.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BitwardenTokenResponse {
    Success(BitwardenTokenSuccessResponse),
    TwoFactor(BitwardenTwoFactorResponse),
    IdentityFail(BitwardenIdentityTokenFailResponse),
}

/// Minimal successful token payload required to bootstrap local Bitwarden crypto.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct BitwardenTokenSuccessResponse {
    /// Bearer credential used only for requests in the current explicit load.
    pub(crate) access_token: String,
    /// Server-reported lifetime for diagnostics; this loader does not schedule renewal from it.
    pub(crate) expires_in: u64,
    /// Encrypted account asymmetric key needed to unwrap organization shared keys.
    #[serde(rename = "privateKey", alias = "PrivateKey")]
    pub(crate) private_key: Option<String>,
    /// KDF parameters and the wrapped user key used for local master-password unlock.
    #[serde(rename = "userDecryptionOptions", alias = "UserDecryptionOptions", default)]
    pub(crate) user_decryption_options: Option<BitwardenUserDecryptionOptionsResponseModel>,
}

impl Drop for BitwardenTokenSuccessResponse {
    /// Wipes the access-token string still owned by this response.
    fn drop(&mut self) {
        self.access_token.zeroize();
    }
}

/// User-decryption options subset needed for master-password unlock.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct BitwardenUserDecryptionOptionsResponseModel {
    /// May be absent for accounts or responses that do not support this password-unlock flow.
    #[serde(rename = "masterPasswordUnlock", alias = "MasterPasswordUnlock", default)]
    pub(crate) master_password_unlock: Option<Box<MasterPasswordUnlockResponseModel>>,
}

/// Normalized identity error payload returned by `/connect/token`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub(crate) struct BitwardenIdentityTokenFailResponse {
    /// Identity service error code, used when no more specific message is provided.
    pub(crate) error: String,
    /// Fallback human-readable description supplied by the identity service.
    pub(crate) error_description: String,
    /// Structured API error details preferred for display when their message is nonblank.
    #[serde(alias = "ErrorModel")]
    pub(crate) error_model: BitwardenIdentityErrorModel,
}

impl fmt::Display for BitwardenIdentityTokenFailResponse {
    /// Uses the server's specific message when available, otherwise its code and description.
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
    /// Human-readable explanation returned by the identity service.
    #[serde(alias = "Message")]
    pub(crate) message: String,
}

/// Shape used by Bitwarden to signal that two-factor auth is required.
#[derive(Clone, Debug, Deserialize, PartialEq)]
struct BitwardenTwoFactorResponse {
    #[serde(rename = "twoFactorProviders2", alias = "TwoFactorProviders2")]
    pub(crate) two_factor_providers: BTreeMap<String, Value>,
}

/// Local authentication error variants surfaced to the provider boundary.
#[derive(Debug, thiserror::Error)]
pub(crate) enum BitwardenAuthError {
    /// Transport, body-read, or HTTP-status failure during the token exchange.
    #[error("failed to request bitwarden token")]
    TokenRequest(#[source] anyhow::Error),
    /// A recognized structured error from the identity service.
    #[error("{0}")]
    IdentityFail(BitwardenIdentityTokenFailResponse),
    /// The server requested an interactive flow this API-key loader does not perform.
    #[error("bitwarden requires two-factor authentication")]
    TwoFactorRequired,
    /// No supported token-response shape could be decoded.
    #[error("bitwarden identity response could not be parsed")]
    InvalidResponse,
    /// Token acquisition succeeded, but local account-key initialization failed.
    #[error("failed to initialize bitwarden crypto")]
    CryptoBootstrap(#[source] anyhow::Error),
}

/// Performs the API-key token exchange against Bitwarden identity.
///
/// A token requires both a successful HTTP status and a valid success payload. Structured identity
/// and two-factor errors are preserved even when the endpoint returns a non-success status.
/// Only API credentials are sent; master-password processing belongs to local crypto bootstrap.
pub(crate) async fn request_api_key_token(
    client: &Client,
    identity_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<BitwardenTokenSuccessResponse, BitwardenAuthError> {
    let identity_url = identity_url.trim_end_matches('/');
    debug!(url = %identity_url, client = client_id, "requesting bitwarden api-key token");

    let form = BitwardenApiTokenRequest::new(client_id, client_secret);

    // Bitwarden expects a classic form post for API-key login rather than a JSON payload.
    let req = client
        .post(format!("{identity_url}/connect/token"))
        .header("content-type", "application/x-www-form-urlencoded; charset=utf-8")
        .header("accept", "application/json")
        .header("Device-Type", DEVICE_TYPE.to_string())
        .form(&form);

    // Transport failures are mapped first so callers can distinguish them from identity errors
    // reported by Bitwarden itself.
    let response = req
        .send()
        .await
        .map_err(|error| BitwardenAuthError::TokenRequest(anyhow!(error)))?;
    let status = response.status();
    // Error responses carry structured identity details too; read them within the client timeout
    // before deciding whether to return a domain error or a generic HTTP failure.
    // Wipe this owned body buffer on drop. Deserialized fields have their own ownership and lifetimes.
    let body = Zeroizing::new(
        response
            .text()
            .await
            .map_err(|error| BitwardenAuthError::TokenRequest(anyhow!(error)))?,
    );

    debug!(%status, "received bitwarden identity response");
    // Payload shape alone must never make a non-success HTTP response a successful login.
    match parse_token(body.as_bytes()) {
        result if status.is_success() => result,
        Err(error @ (BitwardenAuthError::IdentityFail(_) | BitwardenAuthError::TwoFactorRequired)) => Err(error),
        _ => Err(BitwardenAuthError::TokenRequest(anyhow!(
            "bitwarden identity request failed with status {status}"
        ))),
    }
}

/// Decodes a token body independently of HTTP status so structured failures keep their meaning.
fn parse_token(body: &[u8]) -> Result<BitwardenTokenSuccessResponse, BitwardenAuthError> {
    // One response model centralizes shape selection; untagged deserialization tries its variants.
    let response: BitwardenTokenResponse = serde_json::from_slice(body).map_err(|_| {
        error!("bitwarden identity response could not be parsed");
        BitwardenAuthError::InvalidResponse
    })?;

    match response {
        BitwardenTokenResponse::Success(response) => {
            debug!(ttl = response.expires_in, "parsed successful bitwarden token response");
            Ok(response)
        }
        BitwardenTokenResponse::TwoFactor(_response) => {
            error!("bitwarden identity response requires two-factor authentication");
            Err(BitwardenAuthError::TwoFactorRequired)
        }
        BitwardenTokenResponse::IdentityFail(response) => {
            error!(message = %response, "bitwarden identity response returned an error");
            Err(BitwardenAuthError::IdentityFail(response))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BitwardenTokenResponse;

    #[test]
    fn token_error_shapes_require_their_distinguishing_fields() -> Result<(), serde_json::Error> {
        for json in [r#"{"twoFactorProviders2":{}}"#, r#"{"TwoFactorProviders2":{}}"#] {
            assert!(matches!(
                serde_json::from_str(json)?,
                BitwardenTokenResponse::TwoFactor(_)
            ));
        }

        for json in [
            r#"{}"#,
            r#"{"error":"invalid_grant","error_description":"Invalid login"}"#,
            r#"{"twoFactorProviders2":null}"#,
        ] {
            assert!(serde_json::from_str::<BitwardenTokenResponse>(json).is_err());
        }

        for json in [
            r#"{"error":"invalid_grant","error_description":"Invalid login","error_model":{"message":"Invalid login"}}"#,
            r#"{"error":"invalid_grant","error_description":"Invalid login","ErrorModel":{"Message":"Invalid login"}}"#,
        ] {
            assert!(matches!(
                serde_json::from_str(json)?,
                BitwardenTokenResponse::IdentityFail(_)
            ));
        }

        Ok(())
    }
}
