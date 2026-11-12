# keyring-store-memory

## Purpose

Provide the universal ephemeral store and a reusable store contract.

## Requirements

### Requirement: Universal software fallback

Memory SHALL always advertise support for RSA and Ed25519, use unique monotonic handles,
reject duplicate public identities, and delegate signing to core software. Valid keys
SHALL survive load/list and be unusable after delete/clear.

#### Scenario: Independent contract

- **WHEN** the shared contract exercises a supported key
- **THEN** all record fields match and its signatures verify with the public key.

### Requirement: Secret memory lifecycle

Secrets SHALL be zeroized on release. Unix storage SHALL use dedicated anonymous pages,
attempt mlock, apply Linux MADV_DONTDUMP, and zeroize before unmapping.
Capabilities SHALL report software signing.
