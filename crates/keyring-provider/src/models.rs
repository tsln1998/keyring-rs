//! Minimal unlock and `/sync` response models used by the local Bitwarden integration.
//!
//! The generated upstream models do not match the payload shape returned by the deployed API for
//! SSH-key ciphers, so the provider keeps a small hand-written subset here.
//!
//! Field aliases accept the lower-camel and Pascal spellings used by Bitwarden payloads. Optional
//! fields let callers distinguish an absent value from a malformed encrypted value at its use site;
//! an absent cipher list is treated as an empty snapshot.

use serde::{Deserialize, Deserializer, de::Visitor};
use uuid::Uuid;

/// Bitwarden cipher type identifier for SSH keys.
pub(crate) const CIPHER_TYPE_SSH_KEY: i64 = 5;

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub(crate) struct MasterPasswordUnlockResponseModel {
    #[serde(rename = "kdf", alias = "Kdf")]
    pub(crate) kdf: Box<MasterPasswordUnlockKdfResponseModel>,
    #[serde(rename = "masterKeyEncryptedUserKey", alias = "MasterKeyEncryptedUserKey")]
    pub(crate) master_key_encrypted_user_key: Option<String>,
    #[serde(rename = "salt", alias = "Salt")]
    pub(crate) salt: Option<String>,
    #[serde(rename = "containedKeyId", alias = "ContainedKeyId")]
    pub(crate) contained_key_id: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub(crate) struct MasterPasswordUnlockKdfResponseModel {
    #[serde(rename = "kdfType", alias = "KdfType", deserialize_with = "deserialize_kdf_type")]
    pub(crate) kdf_type: i64,
    #[serde(rename = "iterations", alias = "Iterations")]
    pub(crate) iterations: i32,
    #[serde(rename = "memory", alias = "Memory")]
    pub(crate) memory: Option<i32>,
    #[serde(rename = "parallelism", alias = "Parallelism")]
    pub(crate) parallelism: Option<i32>,
}

fn deserialize_kdf_type<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
    struct KdfTypeVisitor;

    impl Visitor<'_> for KdfTypeVisitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an integer")
        }

        fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
            Ok(value)
        }

        fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
            Ok(value as i64)
        }
    }

    deserializer.deserialize_i64(KdfTypeVisitor)
}

/// Top-level subset of the `/sync` response consumed by the provider.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenSyncResponse {
    /// Account and organization metadata needed before decrypting any organization-owned item.
    #[serde(rename = "profile", alias = "Profile")]
    pub(crate) profile: Option<Box<BitwardenProfile>>,
    /// Encrypted items; only active SSH-key ciphers are considered by the loader.
    #[serde(rename = "ciphers", alias = "Ciphers")]
    pub(crate) ciphers: Option<Vec<BitwardenCipher>>,
}

/// Profile subset used to import organization shared keys.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenProfile {
    /// Organization keys encrypted for the account's asymmetric private key.
    #[serde(rename = "organizations", alias = "Organizations")]
    pub(crate) organizations: Option<Vec<BitwardenProfileOrganization>>,
}

/// Organization entry carrying the encrypted shared key.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenProfileOrganization {
    /// Selects the organization-key slot used by ciphers with the same organization ID.
    #[serde(rename = "id", alias = "Id")]
    pub(crate) id: Option<Uuid>,
    /// Serialized encrypted shared key, not an already decrypted organization secret.
    #[serde(rename = "key", alias = "Key")]
    pub(crate) key: Option<String>,
}

/// Cipher subset needed for SSH-key discovery and decryption.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenCipher {
    /// Stable vault item identifier retained in the imported backend record.
    #[serde(rename = "id", alias = "Id")]
    pub(crate) id: Option<Uuid>,
    /// Chooses an organization key instead of the personal user key when present.
    #[serde(rename = "organizationId", alias = "OrganizationId")]
    pub(crate) organization_id: Option<Uuid>,
    /// Numeric item kind; only `CIPHER_TYPE_SSH_KEY` is eligible for import.
    #[serde(rename = "type", alias = "Type")]
    pub(crate) r#type: Option<i64>,
    /// Encrypted item name used as the SSH comment after decryption.
    #[serde(rename = "name", alias = "Name")]
    pub(crate) name: Option<String>,
    /// A nonblank timestamp excludes this item without requiring timestamp parsing.
    #[serde(rename = "deletedDate", alias = "DeletedDate")]
    pub(crate) deleted_date: Option<String>,
    /// A nonblank timestamp excludes archived keys from the active signing snapshot.
    #[serde(rename = "archivedDate", alias = "ArchivedDate")]
    pub(crate) archived_date: Option<String>,
    /// Optional item-specific key wrapped by the owning user or organization key.
    #[serde(rename = "key", alias = "Key")]
    pub(crate) key: Option<String>,
    /// SSH-specific encrypted fields, which may be absent even on an SSH-typed item.
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

/// Treats missing, null, and whitespace-only date fields as an unset lifecycle marker.
fn has_non_blank_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.trim().is_empty())
}

/// SSH-key payload subset embedded inside a Bitwarden cipher.
#[derive(Clone, Default, Debug, PartialEq, Deserialize)]
pub(crate) struct BitwardenCipherSshKey {
    /// Serialized encrypted OpenSSH private-key text, decrypted only for eligible items.
    #[serde(rename = "privateKey", alias = "PrivateKey")]
    pub(crate) private_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{BitwardenCipher, MasterPasswordUnlockResponseModel};

    #[test]
    fn unlock_field_aliases_and_optional_fields_match() -> Result<(), serde_json::Error> {
        let camel: MasterPasswordUnlockResponseModel = serde_json::from_str(
            r#"{"kdf":{"kdfType":1,"iterations":2,"memory":64,"parallelism":4},"masterKeyEncryptedUserKey":"wrapped","salt":"account","containedKeyId":"key-id"}"#,
        )?;
        let pascal: MasterPasswordUnlockResponseModel = serde_json::from_str(
            r#"{"Kdf":{"KdfType":1,"Iterations":2,"Memory":64,"Parallelism":4},"MasterKeyEncryptedUserKey":"wrapped","Salt":"account","ContainedKeyId":"key-id"}"#,
        )?;
        assert_eq!(camel, pascal);
        assert_eq!(camel.kdf.kdf_type, 1);
        assert_eq!(camel.master_key_encrypted_user_key.as_deref(), Some("wrapped"));
        assert_eq!(camel.salt.as_deref(), Some("account"));
        assert_eq!(camel.contained_key_id.as_deref(), Some("key-id"));

        for json in [
            r#"{"kdf":{"kdfType":0,"iterations":1}}"#,
            r#"{"kdf":{"kdfType":0,"iterations":1,"memory":null,"parallelism":null},"masterKeyEncryptedUserKey":null,"salt":null,"containedKeyId":null}"#,
        ] {
            let unlock: MasterPasswordUnlockResponseModel = serde_json::from_str(json)?;
            assert!(unlock.master_key_encrypted_user_key.is_none());
            assert!(unlock.salt.is_none());
            assert!(unlock.contained_key_id.is_none());
            assert!(unlock.kdf.memory.is_none());
            assert!(unlock.kdf.parallelism.is_none());
        }
        Ok(())
    }

    #[test]
    fn unlock_required_fields_and_known_field_types_are_enforced() {
        for json in [
            r#"{}"#,
            r#"{"kdf":null}"#,
            r#"{"kdf":{}}"#,
            r#"{"kdf":{"iterations":1}}"#,
            r#"{"kdf":{"kdfType":0}}"#,
            r#"{"kdf":{"kdfType":null,"iterations":1}}"#,
            r#"{"kdf":{"kdfType":0.0,"iterations":1}}"#,
            r#"{"kdf":{"kdfType":"0","iterations":1}}"#,
            r#"{"kdf":{"kdfType":true,"iterations":1}}"#,
            r#"{"kdf":{"kdfType":0,"iterations":null}}"#,
            r#"{"kdf":{"kdfType":0,"iterations":1},"salt":1}"#,
            r#"{"kdf":{"kdfType":0,"iterations":1},"masterKeyEncryptedUserKey":1}"#,
            r#"{"kdf":{"kdfType":0,"iterations":1},"containedKeyId":1}"#,
            r#"{"kdf":{"kdfType":0,"KdfType":0,"iterations":1}}"#,
        ] {
            assert!(
                serde_json::from_str::<MasterPasswordUnlockResponseModel>(json).is_err(),
                "{json}"
            );
        }
    }

    /// Both supported API field spellings must preserve the archive marker.
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

    /// Presence alone is insufficient: a blank archive field must not hide an active key.
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
