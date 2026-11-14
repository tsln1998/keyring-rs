# keyring-store-keychain

## Purpose

Provide macOS-only durable storage isolated from the rest of the workspace.

## Requirements

### Requirement: Keychain behavior

The probe SHALL inspect the existing default Keychain without unlocking it or prompting,
then create a temporary generic-password item, read and compare its bytes, and delete it.
Temporary items SHALL use the separate `keyring-rs.probe` service and a random account,
and creation SHALL NOT overwrite existing items. Only a successful write, read, comparison,
and deletion SHALL make the backend available. A created item SHALL still be deleted
after an ordinary read failure or mismatch.
The probe SHALL run once per instance through synchronized initialization and cache
both success and failure. Construction SHALL complete the probe; later availability,
capability, and storage calls SHALL reuse its result. Temporary user-interaction changes
SHALL be serialized across probes and restore the previous setting.
RSA SHALL import PKCS#1 material as a non-extractable SecKey and sign through
SecKeyCreateSignature. Ed25519 SHALL store a generic-password seed and retrieve it only
for software signing. Metadata SHALL survive process restart, and clear SHALL delete
only this application's namespace.
Unavailable reasons SHALL use NO_KEYCHAIN for a missing default Keychain, LOCKED for a
locked Keychain, and PROBE_FAILED when status inspection or the storage round trip fails.

#### Scenario: Keychain is unlocked but denies storage access

- **WHEN** inspection succeeds but a probe write, read, comparison, or deletion fails
- **THEN** availability reports PROBE_FAILED, capabilities report unsupported, and later
  calls reuse the failure without retrying.

#### Scenario: RSA status

- **WHEN** RSA is held in Keychain
- **THEN** status reports platform signing without guaranteeing hardware execution.

### Requirement: Honest platform acceptance

Real Keychain round trips, RSA verification, and non-extractability SHALL be tested manually
on macOS and SHALL NOT be described as verified by mocked CI tests.
