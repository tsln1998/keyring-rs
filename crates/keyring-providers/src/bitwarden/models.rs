//! Minimal `/sync` response models used by the local Bitwarden integration.
//!
//! The generated upstream models do not match the payload shape returned by the deployed API for
//! SSH-key ciphers, so the provider keeps a small hand-written subset here.

use serde::Deserialize;
use uuid::Uuid;

/// Bitwarden cipher type identifier for SSH keys.
pub(crate) const CIPHER_TYPE_SSH_KEY: i64 = 5;

/// Top-level subset of the `/sync` response consumed by the provider.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenSyncResponse {
    #[serde(rename = "profile", alias = "Profile")]
    pub(crate) profile: Option<Box<BitwardenProfile>>,
    #[serde(rename = "ciphers", alias = "Ciphers")]
    pub(crate) ciphers: Option<Vec<BitwardenCipher>>,
}

/// Profile subset used to import organization shared keys.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenProfile {
    #[serde(rename = "organizations", alias = "Organizations")]
    pub(crate) organizations: Option<Vec<BitwardenProfileOrganization>>,
}

/// Organization entry carrying the encrypted shared key.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenProfileOrganization {
    #[serde(rename = "id", alias = "Id")]
    pub(crate) id: Option<Uuid>,
    #[serde(rename = "key", alias = "Key")]
    pub(crate) key: Option<String>,
}

/// Cipher subset needed for SSH-key discovery and decryption.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenCipher {
    #[serde(rename = "id", alias = "Id")]
    pub(crate) id: Option<Uuid>,
    #[serde(rename = "organizationId", alias = "OrganizationId")]
    pub(crate) organization_id: Option<Uuid>,
    #[serde(rename = "type", alias = "Type")]
    pub(crate) r#type: Option<i64>,
    #[serde(rename = "name", alias = "Name")]
    pub(crate) name: Option<String>,
    #[serde(rename = "deletedDate", alias = "DeletedDate")]
    pub(crate) deleted_date: Option<String>,
    #[serde(rename = "archivedDate", alias = "ArchivedDate")]
    pub(crate) archived_date: Option<String>,
    #[serde(rename = "key", alias = "Key")]
    pub(crate) key: Option<String>,
    #[serde(rename = "sshKey", alias = "SshKey")]
    pub(crate) ssh_key: Option<Box<BitwardenCipherSshKey>>,
}

impl BitwardenCipher {
    /// Returns whether this cipher represents an SSH key item.
    pub(crate) fn is_ssh_key(&self) -> bool {
        self.r#type == Some(CIPHER_TYPE_SSH_KEY)
    }

    /// Returns whether Bitwarden has moved this cipher to the trash.
    pub(crate) fn is_deleted(&self) -> bool {
        has_non_blank_value(self.deleted_date.as_deref())
    }

    /// Returns whether Bitwarden has archived this cipher.
    pub(crate) fn is_archived(&self) -> bool {
        has_non_blank_value(self.archived_date.as_deref())
    }
}

fn has_non_blank_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

/// SSH-key payload subset embedded inside a Bitwarden cipher.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenCipherSshKey {
    #[serde(rename = "privateKey", alias = "PrivateKey")]
    pub(crate) private_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::BitwardenCipher;

    #[test]
    fn deserializes_archived_date_field_spellings() -> Result<(), serde_json::Error> {
        for json in [
            r#"{"archivedDate":"2026-08-11T00:00:00Z"}"#,
            r#"{"ArchivedDate":"2026-08-11T00:00:00Z"}"#,
        ] {
            let cipher: BitwardenCipher = serde_json::from_str(json)?;
            assert_eq!(cipher.archived_date.as_deref(), Some("2026-08-11T00:00:00Z"));
        }

        Ok(())
    }

    #[test]
    fn archived_state_requires_a_non_blank_date() -> Result<(), serde_json::Error> {
        for json in [r#"{}"#, r#"{"archivedDate":null}"#, r#"{"archivedDate":"  "}"#] {
            let cipher: BitwardenCipher = serde_json::from_str(json)?;
            assert!(!cipher.is_archived());
        }

        let cipher: BitwardenCipher = serde_json::from_str(r#"{"archivedDate":"2026-08-11T00:00:00Z"}"#)?;
        assert!(cipher.is_archived());

        Ok(())
    }
}
