use keyring_protocol::{
    codec::{Request, Response},
    control,
};
use ssh_encoding::{Decode, Encode};
use ssh_key::Signature;

#[test]
fn request_fixtures_preserve_binary_data_and_raw_extension_tails() -> anyhow::Result<()> {
    assert_eq!(Request::Identities.encoded_len()?, 1);
    assert_eq!(Request::Identities.encode_vec()?, [11]);
    let mut input = b"\x0b".as_slice();
    assert!(matches!(Request::decode(&mut input)?, Request::Identities));
    assert!(input.is_empty());
    let signing = b"\x0d\0\0\0\x02\0\xff\0\0\0\x03\x01\0\xff\0\0\0\x04";
    let mut input = signing.as_slice();
    let Request::Signature { key, data, flags } = Request::decode(&mut input)? else {
        anyhow::bail!("expected signing request");
    };
    assert!(input.is_empty());
    assert_eq!(key, [0, 255]);
    assert_eq!(data, [1, 0, 255]);
    assert_eq!(flags, 4);
    let request = Request::Signature { key, data, flags };
    assert_eq!(request.encoded_len()?, signing.len());
    assert_eq!(request.encode_vec()?, signing);
    for end in 0..signing.len() {
        assert!(Request::decode(&mut &signing[..end]).is_err());
    }
    let unlocking = b"\x1b\0\0\0\x0eunlock@keyringsecret\0\xff";
    let mut input = unlocking.as_slice();
    let Request::Extension { name, details } = Request::decode(&mut input)? else {
        anyhow::bail!("expected extension");
    };
    assert!(input.is_empty());
    assert_eq!(name, control::UNLOCK);
    assert_eq!(details.as_slice(), b"secret\0\xff");
    let request = Request::Extension { name, details };
    assert_eq!(request.encoded_len()?, unlocking.len());
    assert_eq!(request.encode_vec()?, unlocking);
    for end in 0..5 + control::UNLOCK.len() {
        assert!(Request::decode(&mut &unlocking[..end]).is_err());
    }
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
    let response = Response::Identities(vec![(
        ssh_key::public::Ed25519PublicKey([9; 32]).into(),
        "fixture".into(),
    )]);
    assert_eq!(response.encoded_len()?, expected.len());
    assert_eq!(response.encode_vec()?, expected);
    let mut input = expected.as_slice();
    let Response::Identities(identities) = Response::decode(&mut input)? else {
        anyhow::bail!("expected identities");
    };
    assert!(input.is_empty());
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].1, "fixture");
    assert_eq!(identities[0].0, ssh_key::public::Ed25519PublicKey([9; 32]).into());
    for end in 0..expected.len() {
        assert!(Response::decode(&mut &expected[..end]).is_err());
    }
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
    let response = Response::Signature(Signature::new(ssh_key::Algorithm::Ed25519, vec![7; 64])?);
    assert_eq!(response.encoded_len()?, expected.len());
    assert_eq!(response.encode_vec()?, expected);
    let mut input = expected.as_slice();
    assert!(matches!(Response::decode(&mut input)?, Response::Signature(_)));
    assert!(input.is_empty());
    for end in 0..expected.len() {
        assert!(Response::decode(&mut &expected[..end]).is_err());
    }
    expected[4] += 1;
    expected.push(0);
    assert!(Response::decode(&mut expected.as_slice()).is_err());
    for (name, details, expected) in [
        (
            control::STATUS,
            b"{}".as_slice(),
            b"\x1d\0\0\0\x0estatus@keyring{}".as_slice(),
        ),
        (
            control::STATUS,
            b"\0\xff".as_slice(),
            b"\x1d\0\0\0\x0estatus@keyring\0\xff".as_slice(),
        ),
        ("", b"".as_slice(), b"\x1d\0\0\0\0".as_slice()),
    ] {
        let response = Response::Extension(Some((name.into(), details.to_vec().into())));
        assert_eq!(response.encoded_len()?, expected.len());
        assert_eq!(response.encode_vec()?, expected);
        let mut input = expected;
        let Response::Extension(Some((decoded_name, decoded_details))) = Response::decode(&mut input)? else {
            anyhow::bail!("expected extension response");
        };
        assert!(input.is_empty());
        assert_eq!(decoded_name, name);
        assert_eq!(decoded_details.as_slice(), details);
        for end in 0..5 + name.len() {
            assert!(Response::decode(&mut &expected[..end]).is_err());
        }
    }
    assert_eq!(Response::Failure.encode_vec()?, [5]);
    assert_eq!(Response::Success.encode_vec()?, [6]);
    assert_eq!(Response::Extension(None).encoded_len()?, 1);
    assert_eq!(Response::Extension(None).encode_vec()?, [28]);
    let mut input = b"\x1c".as_slice();
    assert!(matches!(Response::decode(&mut input)?, Response::Extension(None)));
    assert!(input.is_empty());
    Ok(())
}
