# keyring-core

## Purpose

Define platform-independent storage contracts and the single software signing implementation.

## Requirements

### Requirement: Typed key and store contracts

The crate SHALL expose RSA key specifications including their actual bit size, Ed25519,
opaque store handles, public records, capabilities, and signing
mode. Secrets SHALL use zeroizing byte containers and SHALL NOT be serializable
or included in debug output.

#### Scenario: Record round trip

- **WHEN** a backend persists a record
- **THEN** every public field survives the round trip.

### Requirement: Synchronous store boundary

Every store SHALL implement kind, cached availability, capabilities, load, list, sign,
delete, and clear. Unavailable stores SHALL advertise no supported specifications.
Availability reasons SHALL use short uppercase codes with underscores between words,
defaulting to UNAVAILABLE; available stores SHALL return no reason.
Duplicate public-key import SHALL return Duplicate.

#### Scenario: Deleted handle

- **WHEN** a key is deleted or the store cleared
- **THEN** signing with its old handle fails.

### Requirement: Shared cryptographic implementation

Software signing SHALL support Ed25519 and RSA PKCS#1 v1.5 with SHA-256/SHA-512, enforce
2048-bit RSA minimums, reconstruct distinct RSA primes, reject unsupported algorithms,
and return SSH-compatible raw signature bytes. Import SHALL validate the secret against
its identity, fingerprint, and RSA size.

#### Scenario: Independent verification

- **WHEN** a supported key signs data
- **THEN** the signature verifies independently using its SSH public key.

### Requirement: Dependency isolation

Core SHALL NOT depend on Tokio, platform APIs, HTTP, concrete stores, or ssh-agent-lib.
Platform signing SHALL not imply guaranteed hardware execution.
