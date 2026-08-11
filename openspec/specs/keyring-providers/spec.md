# keyring-providers Specification

## Purpose
Bundle the workspace provider implementations in one crate while keeping the shared provider contract in `keyring-core` and preserving provider-specific behavior inside provider-owned modules.

## Requirements
### Requirement: Provider-owned config types
The `keyring-providers` crate SHALL define and expose each provider's config type from its own module so upper layers can deserialize provider-specific settings without re-declaring those schemas elsewhere.

#### Scenario: Build the startup config graph
- **WHEN** `keyring-cli` parses the top-level service config document
- **THEN** it references provider-owned config structs from `keyring_providers::dummy` and `keyring_providers::bitwarden` instead of duplicating those type definitions locally

### Requirement: Dummy provider behavior
The `keyring-providers` crate SHALL provide one dummy provider implementation that loads exactly one `ssh-ed25519` identity for each configured dummy provider instance.

#### Scenario: Initialize a dummy provider instance
- **WHEN** a configured dummy provider instance is created
- **THEN** the provider accepts its module-owned config struct and returns exactly one `ssh-ed25519` identity from its load path

### Requirement: Dummy identities stay provider-local
The `keyring-providers` crate SHALL expose dummy identities only as typed `ssh_key::PrivateKey` values through the shared core load contract and SHALL not implement provider-local refresh or signing operations for the dummy provider.

#### Scenario: Load dummy identities
- **WHEN** the runtime calls the dummy provider's load operation
- **THEN** it receives typed OpenSSH private keys without any provider-local wrapper model

### Requirement: Dummy provider stays fully local
The `keyring-providers` crate SHALL keep dummy private keys fully local to the process and SHALL not perform network or storage I/O while loading dummy identities.

#### Scenario: Start the service with only a dummy provider
- **WHEN** the runtime assembles a service using only the dummy provider
- **THEN** identity loading completes using only local in-memory key material

### Requirement: Bitwarden sync-based identity loading
The `keyring-providers` crate SHALL provide one Bitwarden provider implementation that uses its configured endpoints and credentials to authenticate, establish the account context required for vault access, call `GET /sync`, and return loaded private keys through the shared provider trait without owning a nested runtime.

#### Scenario: Start a Bitwarden provider with valid credentials
- **WHEN** a configured Bitwarden provider instance is initialized with valid service endpoints and credentials
- **THEN** the Bitwarden provider authenticates successfully, loads identities from `/sync`, and returns them through `KeyPairProvider::load`

### Requirement: Secret-safe provider config debug
The `keyring-providers` crate SHALL keep secret-bearing provider config fields redacted in `Debug` output.

#### Scenario: Render Bitwarden provider config for diagnostics
- **WHEN** a caller formats a Bitwarden provider config with `Debug`
- **THEN** passwords and client secrets stay redacted while non-secret fields remain visible

#### Scenario: Reject invalid credentials or unlock material
- **WHEN** a configured Bitwarden provider instance cannot authenticate or cannot establish the account state required to decrypt vault items
- **THEN** the Bitwarden provider fails provider startup instead of returning partial identities

### Requirement: Bitwarden SSH key discovery
The `keyring-providers` crate SHALL inspect `response.ciphers`, keep items whose type is `SshKey`, whose `deletedDate` and `archivedDate` values are absent or blank, and whose decrypted `sshKey.privateKey` payload is present, SHALL NOT discover identities by scanning custom fields, notes, or attachments, and SHALL retain only the sync fields needed for discovery.

#### Scenario: Discover an SSH key cipher from sync data
- **WHEN** the sync response contains a cipher item with `type == SshKey` and a populated `sshKey.privateKey`
- **THEN** the Bitwarden provider publishes that item as one loaded identity

#### Scenario: Skip an archived SSH key cipher
- **WHEN** the sync response contains an otherwise usable SSH key cipher with a non-empty `archivedDate`
- **THEN** the Bitwarden provider excludes that cipher from the published identities without attempting to decrypt it

### Requirement: Bitwarden identity material derives from private keys
The `keyring-providers` crate SHALL derive the published algorithm and public key from the decrypted private key and SHALL write the published identity comment onto that private key using decrypted `cipher.name` as the default value with a deterministic fallback when the name is empty.

#### Scenario: Publish a discovered identity with a missing name
- **WHEN** a discovered SSH key item has no usable decrypted `cipher.name`
- **THEN** the Bitwarden provider publishes the identity with a deterministic fallback comment while still deriving algorithm and public key from the private key

### Requirement: Bitwarden decryption chain
The `keyring-providers` crate SHALL unwrap `cipher.key` when it is present before decrypting item fields and SHALL decrypt only the fields required for identity loading with the resolved item key.

#### Scenario: Decrypt an item that carries its own cipher key
- **WHEN** an SSH key cipher includes a non-empty `cipher.key`
- **THEN** the Bitwarden provider unwraps the item key first and decrypts the SSH key fields with that key

### Requirement: Bitwarden empty discovery is not fatal
The `keyring-providers` crate SHALL allow Bitwarden provider startup to succeed with an empty identity set when sync completes successfully but no usable SSH keys are discovered.

#### Scenario: Start with no usable SSH keys
- **WHEN** the sync response contains no usable SSH key items after filtering and decryption
- **THEN** the Bitwarden provider returns an empty identity collection instead of failing startup

### Requirement: Bitwarden expired-token retry
The `keyring-providers` crate SHALL retry the Bitwarden sync load path once after refreshing the access token when the current token has expired.

#### Scenario: Recover from an expired token during sync
- **WHEN** Bitwarden rejects the startup sync operation because the current access token has expired
- **THEN** the Bitwarden provider refreshes the token once, retries the load operation, and only then returns a stable failure if the retry also fails

### Requirement: No websocket or signer cache layer
The `keyring-providers` crate SHALL not accept websocket refresh configuration and SHALL not keep a provider-local signer cache, sign facade, runtime refresh state, or extra provider-internal business layers after the load-only refactor; Bitwarden startup SHALL stay as one direct load path with only minimal crypto helpers and reusable cache primitives separated.

#### Scenario: Build the production provider
- **WHEN** startup constructs the production Bitwarden provider
- **THEN** the provider keeps only the direct SDK client plus the minimal discovery helpers required to return identities from startup load
