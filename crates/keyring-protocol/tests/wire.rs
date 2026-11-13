use keyring_protocol::{
    control,
    wire::{Extension, Identity, RSA_SHA2_512, Request, Response},
};
use ssh_encoding::{Decode, Encode};
use ssh_key::Signature;

#[test]
fn request_fixtures_preserve_binary_data_and_raw_extension_tails() -> anyhow::Result<()> {
    let signing = b"\x0d\0\0\0\x02\0\xff\0\0\0\x03\x01\0\xff\0\0\0\x04";
    let mut input = signing.as_slice();
    let Request::SignRequest(request) = Request::decode(&mut input)? else {
        anyhow::bail!("expected signing request");
    };
    assert!(input.is_empty());
    assert_eq!(request.key, [0, 255]);
    assert_eq!(request.data, [1, 0, 255]);
    assert_eq!(request.flags, RSA_SHA2_512);
    assert_eq!(Request::SignRequest(request).encode_vec()?, signing);
    for end in 0..signing.len() {
        assert!(Request::decode(&mut &signing[..end]).is_err());
    }
    let unlocking = b"\x1b\0\0\0\x0eunlock@keyringsecret\0\xff";
    let mut input = unlocking.as_slice();
    let Request::Extension(extension) = Request::decode(&mut input)? else {
        anyhow::bail!("expected extension");
    };
    assert!(input.is_empty());
    assert_eq!(extension.name, control::UNLOCK);
    assert_eq!(extension.details.as_slice(), b"secret\0\xff");
    assert_eq!(Request::Extension(extension).encode_vec()?, unlocking);
    let mut unsupported = b"\x11private material".as_slice();
    assert!(matches!(Request::decode(&mut unsupported)?, Request::Unsupported));
    assert!(unsupported.is_empty());
    Ok(())
}

#[test]
fn response_fixtures_match_agent_counts_and_nested_key_encodings() -> anyhow::Result<()> {
    let mut expected = b"\x0c\0\0\0\x01\0\0\0\x33\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    expected.extend_from_slice(&[9; 32]);
    expected.extend_from_slice(b"\0\0\0\x07fixture");
    let response = Response::IdentitiesAnswer(vec![Identity {
        key: ssh_key::public::Ed25519PublicKey([9; 32]).into(),
        comment: "fixture".into(),
    }]);
    assert_eq!(response.encoded_len()?, expected.len());
    assert_eq!(response.encode_vec()?, expected);
    let mut input = expected.as_slice();
    let Response::IdentitiesAnswer(identities) = Response::decode(&mut input)? else {
        anyhow::bail!("expected identities");
    };
    assert!(input.is_empty());
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].comment, "fixture");
    assert_eq!(identities[0].key, ssh_key::public::Ed25519PublicKey([9; 32]).into());
    assert!(Response::decode(&mut b"\x0c\xff\xff\xff\xff".as_slice()).is_err());
    expected[8] = 52;
    expected.insert(60, 0);
    assert!(Response::decode(&mut expected.as_slice()).is_err());
    Ok(())
}

#[test]
fn signature_and_control_response_fixtures_keep_their_message_ids() -> anyhow::Result<()> {
    let mut expected = b"\x0e\0\0\0\x53\0\0\0\x0bssh-ed25519\0\0\0\x40".to_vec();
    expected.extend_from_slice(&[7; 64]);
    let response = Response::SignResponse(Signature::new(ssh_key::Algorithm::Ed25519, vec![7; 64])?);
    assert_eq!(response.encode_vec()?, expected);
    let mut input = expected.as_slice();
    assert!(matches!(Response::decode(&mut input)?, Response::SignResponse(_)));
    assert!(input.is_empty());
    let response = Response::ExtensionResponse(Extension {
        name: control::STATUS.into(),
        details: b"{}".to_vec().into(),
    });
    let expected = b"\x1d\0\0\0\x0estatus@keyring{}";
    assert_eq!(response.encoded_len()?, expected.len());
    assert_eq!(response.encode_vec()?, expected);
    let mut input = expected.as_slice();
    let Response::ExtensionResponse(extension) = Response::decode(&mut input)? else {
        anyhow::bail!("expected extension response");
    };
    assert!(input.is_empty());
    assert_eq!(extension.name, control::STATUS);
    assert_eq!(extension.details.as_slice(), b"{}");
    assert_eq!(Response::Failure.encode_vec()?, [5]);
    assert_eq!(Response::Success.encode_vec()?, [6]);
    assert_eq!(Response::ExtensionFailure.encode_vec()?, [28]);
    Ok(())
}
