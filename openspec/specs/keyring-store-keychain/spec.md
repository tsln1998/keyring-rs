# keyring-store-keychain

## Purpose

Provide macOS-only durable storage isolated from the rest of the workspace.

## Requirements

### Requirement: Keychain behavior

The cached probe SHALL inspect the existing default Keychain without changing it or
prompting. RSA SHALL import PKCS#1 material as a non-extractable SecKey and sign through
SecKeyCreateSignature. Ed25519 SHALL store a generic-password seed and retrieve it only
for software signing. Metadata SHALL survive process restart, and clear SHALL delete
only this application's namespace.
Unavailable reasons SHALL use NO_KEYCHAIN for a missing default Keychain, LOCKED for a
locked Keychain, and PROBE_FAILED when its status cannot be inspected.

#### Scenario: RSA status

- **WHEN** RSA is held in Keychain
- **THEN** status reports platform signing without guaranteeing hardware execution.

### Requirement: Honest platform acceptance

Real Keychain round trips, RSA verification, and non-extractability SHALL be tested manually
on macOS and SHALL NOT be described as verified by mocked CI tests.
