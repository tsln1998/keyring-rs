//! Minimal `/sync` response models used by the local Bitwarden integration.
//!
//! The generated upstream models do not match the payload shape returned by the deployed API for
//! SSH-key ciphers, so the provider keeps a small hand-written subset here.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Bitwarden cipher type identifier for SSH keys.
pub(crate) const CIPHER_TYPE_SSH_KEY: i64 = 5;

/// Top-level subset of the `/sync` response consumed by the provider.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct BitwardenSyncResponse {
    #[serde(
        rename = "profile",
        alias = "Profile",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) profile: Option<Box<BitwardenProfile>>,
    #[serde(
        rename = "ciphers",
        alias = "Ciphers",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) ciphers: Option<Vec<BitwardenCipher>>,
}

/// Profile subset used to import organization shared keys.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct BitwardenProfile {
    #[serde(
        rename = "organizations",
        alias = "Organizations",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) organizations: Option<Vec<BitwardenProfileOrganization>>,
}

/// Organization entry carrying the encrypted shared key.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct BitwardenProfileOrganization {
    #[serde(rename = "id", alias = "Id", skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<Uuid>,
    #[serde(rename = "key", alias = "Key", skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<String>,
}

/// Cipher subset needed for SSH-key discovery and decryption.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct BitwardenCipher {
    #[serde(rename = "id", alias = "Id", skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<Uuid>,
    #[serde(
        rename = "organizationId",
        alias = "OrganizationId",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) organization_id: Option<Uuid>,
    #[serde(
        rename = "type",
        alias = "Type",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) r#type: Option<i64>,
    #[serde(
        rename = "name",
        alias = "Name",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) name: Option<String>,
    #[serde(
        rename = "deletedDate",
        alias = "DeletedDate",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) deleted_date: Option<String>,
    #[serde(rename = "key", alias = "Key", skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<String>,
    #[serde(
        rename = "sshKey",
        alias = "SshKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) ssh_key: Option<Box<BitwardenCipherSshKey>>,
}

impl BitwardenCipher {
    /// Returns whether this cipher represents an SSH key item.
    pub(crate) fn is_ssh_key(&self) -> bool {
        self.r#type == Some(CIPHER_TYPE_SSH_KEY)
    }
}

/// SSH-key payload subset embedded inside a Bitwarden cipher.
#[derive(Clone, Default, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct BitwardenCipherSshKey {
    #[serde(
        rename = "privateKey",
        alias = "PrivateKey",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) private_key: Option<String>,
}
