# keyring-service Specification

## Purpose
Implement the SSH agent behavior on top of `ssh-agent-lib`, validate provider-loaded private keys, and sign locally without introducing a cached runtime registry layer or extra exported identity wrapper types.

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
The `keyring-service` crate SHALL defer provider loading until a session first needs identities or signing data and SHALL reuse that loaded validated private-key set for the rest of the same session.

#### Scenario: List identities twice in one session
- **WHEN** the same client session asks for identities twice
- **THEN** `keyring-service` triggers provider `load` only once and serves the second response from the same session-local private-key cache

#### Scenario: Sign after listing identities in one session
- **WHEN** the same client session lists identities and then asks to sign
- **THEN** `keyring-service` reuses the already loaded session-local private-key cache instead of calling provider `load` again

### Requirement: Stable identity listing
The `keyring-service` crate SHALL validate loaded private keys before caching them for a session, SHALL derive each published display name from `private_key.comment()`, and SHALL return published identities in deterministic order using provider order first and per-provider ordering by name, algorithm, and public key blob.

#### Scenario: List identities from an empty load result
- **WHEN** all configured providers load zero identities successfully
- **THEN** `keyring-service` returns an empty identity list without failing the running service

#### Scenario: Reject invalid loaded private keys
- **WHEN** a loaded private key has an empty published comment, an unsupported algorithm, or an unencodable public key
- **THEN** `keyring-service` rejects the request with a stable invalid-identity error

### Requirement: Runtime-local signing
The `keyring-service` crate SHALL sign requests locally from the session-cached OpenSSH private key material and SHALL NOT delegate steady-state signing behavior back through provider trait objects.

#### Scenario: Sign with a known loaded identity
- **WHEN** a client requests a signature for a known public key blob
- **THEN** `keyring-service` resolves the first matching published private key from the current session cache and returns a signature produced from runtime-local key material

### Requirement: Stable duplicate key handling
The `keyring-service` crate SHALL resolve duplicate public key blobs deterministically by using the first published identity in stable order as the lookup winner.

#### Scenario: Encounter duplicate public keys
- **WHEN** multiple loaded identities publish the same OpenSSH public key blob
- **THEN** `keyring-service` signs with the first identity in deterministic runtime order instead of making lookup nondeterministic

### Requirement: Supported signing algorithms
The `keyring-service` crate SHALL support `ssh-ed25519`, `rsa-sha2-256`, and `rsa-sha2-512`, and SHALL default RSA requests without an explicit algorithm to `rsa-sha2-512`.

#### Scenario: Sign with an RSA identity without an explicit algorithm
- **WHEN** the service signs with an RSA identity and no signature algorithm preference is provided
- **THEN** it emits an `rsa-sha2-512` signature
