use garde::Validate;
use keyring_provider::config::BitwardenConfig;

fn config() -> BitwardenConfig {
    BitwardenConfig {
        api_url: "https://api.example".into(),
        identity_url: "https://identity.example".into(),
        client_id: "fixture-client".into(),
        client_secret: "fixture-secret-never-in-errors".to_owned().into(),
    }
}

#[test]
fn accepts_http_endpoints_with_path_prefixes() {
    let mut config = config();
    config.api_url = "http://127.0.0.1:8080/bitwarden/api/".into();
    config.identity_url = "https://identity.example/bitwarden/identity/".into();
    config.client_id = " fixture-client ".into();
    config.client_secret = " fixture-secret ".to_owned().into();
    assert!(config.validate().is_ok());
}

#[test]
fn rejects_invalid_endpoints_without_exposing_values() {
    for field in ["api_url", "identity_url"] {
        for value in [
            "",
            "fixture-secret-never-in-errors",
            "file:///tmp/fixture-secret-never-in-errors",
            "ftp://fixture-secret-never-in-errors.example",
            "https://fixture-secret-never-in-errors@api.example",
            "https://user:fixture-secret-never-in-errors@api.example",
            "https://api.example?fixture-secret-never-in-errors",
            "https://api.example#fixture-secret-never-in-errors",
        ] {
            let mut config = config();
            match field {
                "api_url" => config.api_url = value.into(),
                _ => config.identity_url = value.into(),
            }
            let error = config.validate().expect_err("invalid endpoint must be rejected");
            assert!(error.to_string().contains(field));
            assert!(!format!("{error:#?}").contains("fixture-secret-never-in-errors"));
        }
    }
}

#[test]
fn rejects_blank_credentials_without_exposing_other_values() {
    for field in ["client_id", "client_secret"] {
        for value in ["", " \t\n", "\u{2003}"] {
            let mut config = config();
            match field {
                "client_id" => config.client_id = value.into(),
                _ => config.client_secret = value.to_owned().into(),
            }
            let error = config.validate().expect_err("blank credential must be rejected");
            assert!(error.to_string().contains(field));
            assert!(!format!("{error:#?}").contains("fixture-secret-never-in-errors"));
        }
    }
}
