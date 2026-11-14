# keyring-core

## Purpose

Define platform-independent provider and storage contracts and the single software signing implementation.

## Requirements

### Requirement: Typed key and store contracts

The crate SHALL expose public crypto, keystore, and provider modules without root re-exports.
The keystore module SHALL expose RSA key specifications including their actual bit size, Ed25519,
backend-local KeyId values, KeyInfo public metadata, KeyRecord import material, Kind, capabilities,
and SigningMode. KeyInfo SHALL derive its specification from its public identity rather than store
a duplicate spec field. Secrets SHALL use SecretBox<[u8]> and SHALL NOT be serializable
or included in debug output.

#### Scenario: Record round trip

- **WHEN** a backend persists a record
- **THEN** every public field survives the round trip, with the identity encoded as an OpenSSH
  public-key string through the private serde::keydata adapter.

### Requirement: Synchronous store boundary

The KeyStore trait SHALL provide kind, cached availability, capabilities, load, list, sign,
delete, and clear. Listing SHALL return pairs of KeyId and KeyInfo.
Unavailable stores SHALL advertise no supported specifications.
The available operation SHALL return anyhow::Result<()>, with Ok(()) for an available store.
Unavailable stores SHALL return errors whose display messages are short uppercase codes with
underscores between words, using UNAVAILABLE when no more specific reason exists.
Store operation failures SHALL use keystore::Error; duplicate public-key import SHALL return Duplicate.

#### Scenario: Deleted handle

- **WHEN** a key is deleted or the store cleared
- **THEN** signing with its old handle fails.

### Requirement: Asynchronous provider boundary

The crate SHALL expose a Send + Sync Provider trait with an object-safe asynchronous load
operation. Each load SHALL consume a zeroizing password and return owned KeyRecord values.
Provider failures SHALL use provider::Error, distinguish authentication from snapshot-loading failures, and expose
safe display messages while retaining source context for diagnostics.

#### Scenario: Provider injection

- **WHEN** the application supplies a Provider implementation to the protocol
- **THEN** the protocol can load keys without depending on the concrete provider crate.

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
