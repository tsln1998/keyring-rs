# keyring-service Specification

## Purpose
Implement the SSH agent behavior on top of `ssh-agent-lib`, index provider-loaded private keys, and sign locally without introducing a cached runtime registry layer or extra exported identity wrapper types.

## Requirements
### Requirement: Provider-backed agent behavior
The `keyring-service` crate SHALL expose one `ssh-agent-lib` agent implementation that stores configured provider trait objects, creates per-connection sessions, and serves `request identities` plus `sign request` without introducing a separate protocol adapter layer or direct helper APIs for listing and signing outside a session.

#### Scenario: Construct the service agent
- **WHEN** the CLI assembles the service with one or more providers
- **THEN** `keyring-service` returns one agent object that can create sessions for the foreground Unix listener

#### Scenario: Reject an empty provider list
- **WHEN** the CLI tries to construct the service without any configured providers
- **THEN** `keyring-service` returns a stable startup error instead of creating a non-functional agent

### Requirement: Session-scoped provider loading
The `keyring-service` crate SHALL defer provider loading until a session first needs identities or signing data and SHALL reuse the successfully loaded private-key set for the rest of the same session. Failed loads SHALL fail the request without initializing the session cache.

#### Scenario: List identities twice in one session
- **WHEN** the same client session asks for identities twice
- **THEN** `keyring-service` triggers provider `load` only once and serves the second response from the same session-local private-key cache

#### Scenario: Sign after listing identities in one session
- **WHEN** the same client session lists identities and then asks to sign
- **THEN** `keyring-service` reuses the already loaded session-local private-key cache instead of calling provider `load` again

### Requirement: Stable identity listing
The `keyring-service` crate SHALL index the typed private keys returned by providers, SHALL derive each published display name from `private_key.comment()`, and SHALL return identities in ascending `KeyData` order independently of provider order. Listing SHALL NOT impose additional comment or signing-algorithm validation.

#### Scenario: List identities from an empty load result
- **WHEN** all configured providers load zero identities successfully
- **THEN** `keyring-service` returns an empty identity list without failing the running service

#### Scenario: Publish a key with an empty comment
- **WHEN** a provider returns a typed private key with an empty comment
- **THEN** `keyring-service` publishes its public key with that empty comment

### Requirement: Runtime-local signing
The `keyring-service` crate SHALL sign requests locally from the session-cached OpenSSH private key material and SHALL NOT delegate steady-state signing behavior back through provider trait objects.

#### Scenario: Sign with a known loaded identity
- **WHEN** a client requests a signature for a known public key blob
- **THEN** `keyring-service` resolves the indexed private key from the current session cache and returns a signature produced from runtime-local key material

#### Scenario: Reject an unsupported signing algorithm
- **WHEN** the requested key uses an algorithm that the signing implementation does not support
- **THEN** `keyring-service` fails the sign request without changing the session snapshot

### Requirement: Stable duplicate key handling
The `keyring-service` crate SHALL load providers sequentially in the order supplied by the CLI and iterate each returned snapshot in its supplied order. Later keys SHALL replace earlier keys with the same public `KeyData`, including their published comments.

#### Scenario: Encounter duplicate public keys
- **WHEN** multiple loaded identities publish the same OpenSSH public key blob
- **THEN** the last loaded occurrence supplies the single published identity and the private key used for signing

### Requirement: Supported signing algorithms
The `keyring-service` crate SHALL support `ssh-ed25519`, `rsa-sha2-256`, and `rsa-sha2-512`. RSA requests SHALL require at least one SHA-2 flag; the SHA-256 flag SHALL take precedence when both flags are present. Requests without either SHA-2 flag SHALL fail rather than selecting a default SHA-2 algorithm or producing a legacy `ssh-rsa` signature.

#### Scenario: Sign with a valid RSA identity
- **WHEN** a client requests an RSA SHA-2 signature using a valid RSA identity that meets the minimum key size
- **THEN** the service constructs the signing key from its modulus, exponents, and distinct `p` and `q` components and returns a signature verifiable with the published public key

#### Scenario: Reject an invalid or undersized RSA signing key
- **WHEN** an RSA identity has inconsistent private components or falls below the existing 2048-bit minimum key size
- **THEN** the service fails the sign request and remains available for subsequent requests

#### Scenario: Sign with an RSA identity without an explicit algorithm
- **WHEN** the service signs with an RSA identity and no signature algorithm preference is provided
- **THEN** it fails the request
