# keyring-store-memory

## Purpose

Provide the universal ephemeral store with software signing.

## Requirements

### Requirement: Universal software fallback

Memory SHALL always advertise support for RSA and Ed25519, use unique monotonic handles,
reject duplicate public identities, and delegate signing to core software. Valid keys
SHALL survive load/list and be unusable after delete/clear.

#### Scenario: Key lifecycle

- **WHEN** a supported key is imported
- **THEN** its public record matches, its signatures verify with the public key,
  and delete or clear makes its handle unusable.

### Requirement: Secret memory lifecycle

Secrets SHALL use dedicated pages managed by region on every supported platform,
attempt page locking, and apply Linux MADV_DONTDUMP. The entire allocation SHALL be
zeroized before its lock is released and its pages are freed.
Capabilities SHALL report software signing.
