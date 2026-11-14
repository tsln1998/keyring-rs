/// Keeps serialized records independent of `ssh_key`'s internal key representation.
pub(crate) mod keydata {
    use ::serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};
    use ssh_key::{PublicKey, public::KeyData};

    /// Encodes only the public identity in the standard OpenSSH text format.
    pub fn serialize<S: Serializer>(key: &KeyData, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&PublicKey::from(key.clone()).to_openssh().map_err(S::Error::custom)?)
    }

    /// Parses the public key while leaving the record's separate comment untouched.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<KeyData, D::Error> {
        let text = String::deserialize(deserializer)?;
        PublicKey::from_openssh(&text)
            .map(KeyData::from)
            .map_err(D::Error::custom)
    }
}
