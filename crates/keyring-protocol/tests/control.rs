use anyhow::{Context, Result, bail};
use keyring_core::keystore::{Kind, SigningMode};
use keyring_protocol::{
    codec,
    control::{self, Key, Request, Response, Snapshot, State, Store},
};
use secrecy::{ExposeSecret, SecretBox};
use serde_json::json;

#[test]
fn requests_preserve_extension_names_and_raw_password_bytes() -> Result<()> {
    for password in [b"".as_slice(), b"password\0\xff"] {
        let request = Request::Unlock(SecretBox::from(password.to_vec().into_boxed_slice()));
        assert_eq!(request.name(), control::UNLOCK);
        let codec::Request::Extension { name, details } = request.into() else {
            bail!("missing extension request");
        };
        assert_eq!(name, control::UNLOCK);
        assert_eq!(details.as_slice(), password);
        let Request::Unlock(decoded) = Request::decode(&name, details)? else {
            bail!("missing unlock request");
        };
        assert_eq!(decoded.expose_secret(), password);
    }
    for (request, expected) in [(Request::Lock, control::LOCK), (Request::Status, control::STATUS)] {
        assert_eq!(request.name(), expected);
        let codec::Request::Extension { name, details } = request.into() else {
            bail!("missing extension request");
        };
        assert_eq!(name, expected);
        assert!(details.is_empty());
        assert_eq!(Request::decode(&name, details)?.name(), expected);
    }
    Ok(())
}

#[test]
fn requests_reject_invalid_payloads_and_unknown_extensions_without_exposing_secrets() -> Result<()> {
    for name in [control::LOCK, control::STATUS, "unknown", "refresh@keyring"] {
        let error = Request::decode(name, b"fixture-secret-password".to_vec().into())
            .err()
            .context("invalid request accepted")?;
        assert!(!error.to_string().contains("fixture-secret-password"));
        if matches!(name, control::LOCK | control::STATUS) {
            assert_eq!(error.to_string(), "extension payload must be empty");
        } else {
            assert_eq!(error.to_string(), "unsupported control extension");
        }
    }
    assert!(Request::decode("unknown", Vec::new().into()).is_err());
    Ok(())
}

#[test]
fn responses_serialize_tagged_variants_and_optional_fields() -> Result<()> {
    for (response, expected) in [
        (Response::Success, json!({"type": "success"})),
        (
            Response::failure("store", "agent locked, but cleanup failed"),
            json!({"type": "failure", "code": "store", "message": "agent locked, but cleanup failed"}),
        ),
        (
            Response::Status {
                state: State::Locked,
                snapshot: None,
                stores: Vec::new(),
                keys: Vec::new(),
            },
            json!({"type": "status", "state": "locked", "snapshot": null, "stores": [], "keys": []}),
        ),
        (
            Response::Status {
                state: State::Loading,
                snapshot: None,
                stores: Vec::new(),
                keys: Vec::new(),
            },
            json!({"type": "status", "state": "loading", "snapshot": null, "stores": [], "keys": []}),
        ),
        (
            Response::Status {
                state: State::Unlocked,
                snapshot: Some(Snapshot {
                    loaded_at: "2026-11-14T00:00:00Z".into(),
                }),
                stores: vec![
                    Store {
                        kind: Kind::Keychain,
                        available: false,
                        reason: Some("UNAVAILABLE".into()),
                    },
                    Store {
                        kind: Kind::Memory,
                        available: true,
                        reason: None,
                    },
                ],
                keys: vec![
                    Key {
                        fingerprint: "SHA256:rsa".into(),
                        comment: "rsa fixture".into(),
                        algorithm: "rsa".into(),
                        bits: Some(2048),
                        store: Kind::Memory,
                        signing: SigningMode::Software,
                    },
                    Key {
                        fingerprint: "SHA256:ed25519".into(),
                        comment: "ed25519 fixture".into(),
                        algorithm: "ed25519".into(),
                        bits: None,
                        store: Kind::Memory,
                        signing: SigningMode::Software,
                    },
                ],
            },
            json!({
                "type": "status",
                "state": "unlocked",
                "snapshot": {"loaded_at": "2026-11-14T00:00:00Z"},
                "stores": [
                    {"kind": "keychain", "available": false, "reason": "UNAVAILABLE"},
                    {"kind": "memory", "available": true, "reason": null}
                ],
                "keys": [
                    {
                        "fingerprint": "SHA256:rsa", "comment": "rsa fixture",
                        "algorithm": "rsa", "bits": 2048, "store": "memory", "signing": "software"
                    },
                    {
                        "fingerprint": "SHA256:ed25519", "comment": "ed25519 fixture",
                        "algorithm": "ed25519", "store": "memory", "signing": "software"
                    }
                ]
            }),
        ),
    ] {
        assert_eq!(serde_json::to_value(&response)?, expected);
        let decoded: Response = serde_json::from_value(expected.clone())?;
        assert_eq!(serde_json::to_value(decoded)?, expected);
    }
    assert!(matches!(
        serde_json::from_str(r#"{"type":"success"}"#)?,
        Response::Success
    ));
    assert!(matches!(
        serde_json::from_str(r#"{"type":"failure","code":"auth","message":"authentication failed"}"#)?,
        Response::Failure { code, message } if code == "auth" && message == "authentication failed"
    ));
    assert!(matches!(
        serde_json::from_str(r#"{"type":"status","state":"locked","stores":[],"keys":[]}"#)?,
        Response::Status {
            state: State::Locked,
            snapshot: None,
            ..
        }
    ));
    Ok(())
}

#[test]
fn responses_reject_unknown_tags_and_invalid_fields() {
    for invalid in [
        json!({}),
        json!({"type": true}),
        json!({"type": "unknown"}),
        json!({"type": "failure"}),
        json!({"type": "failure", "code": "auth"}),
        json!({"type": "failure", "message": "failure"}),
        json!({"type": "failure", "code": null, "message": "failure"}),
        json!({"type": "failure", "code": "auth", "message": null}),
        json!({"type": "status", "state": "locked"}),
        json!({"type": "status", "state": "locked", "stores": []}),
        json!({"type": "status", "state": "locked", "keys": []}),
        json!({"type": "status", "state": "unknown", "stores": [], "keys": []}),
        json!({"type": "status", "state": "locked", "stores": null, "keys": []}),
        json!({"type": "status", "state": "locked", "stores": [], "keys": "invalid"}),
    ] {
        assert!(
            serde_json::from_value::<Response>(invalid.clone()).is_err(),
            "{invalid}"
        );
    }
}
