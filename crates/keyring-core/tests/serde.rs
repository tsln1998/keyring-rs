use anyhow::Result;
use keyring_core::keystore::{KeyInfo, KeySpec};
use serde_json::json;
use ssh_key::{
    HashAlg, Mpint, PublicKey,
    public::{Ed25519PublicKey, KeyData, RsaPublicKey},
};

#[test]
fn key_info_round_trips_openssh_identities_and_reads_legacy_spec() -> Result<()> {
    let rsa = RsaPublicKey::new(
        Mpint::from_positive_bytes(&[1, 0, 1]),
        Mpint::from_positive_bytes(&[0x81; 256]),
    )?;
    for identity in [KeyData::Ed25519(Ed25519PublicKey([42; 32])), KeyData::Rsa(rsa)] {
        let info = KeyInfo {
            fingerprint: identity.fingerprint(HashAlg::Sha256).to_string(),
            identity,
            comment: "separate public comment".into(),
        };
        let mut value = serde_json::to_value(&info)?;
        assert_eq!(value["identity"], PublicKey::from(info.identity.clone()).to_openssh()?);
        assert!(value.get("spec").is_none());
        assert_eq!(serde_json::from_value::<KeyInfo>(value.clone())?, info);
        value["spec"] = serde_json::to_value(KeySpec::try_from(&info.identity)?)?;
        assert_eq!(serde_json::from_value::<KeyInfo>(value)?, info);
    }
    Ok(())
}

#[test]
fn key_info_rejects_invalid_openssh_identity_text() {
    let value = json!({
        "identity": "invalid OpenSSH public key",
        "comment": "public comment",
        "fingerprint": "public fingerprint",
    });
    assert!(serde_json::from_value::<KeyInfo>(value).is_err());
}
