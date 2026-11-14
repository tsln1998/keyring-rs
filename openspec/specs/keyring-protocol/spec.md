# keyring-protocol

## Purpose

Own SSH agent behavior, transactional unlocking, storage orchestration, and control extensions.

## Requirements

### Requirement: Public module boundaries

The crate SHALL expose public agent, codec, and control modules without root re-exports.
The agent module SHALL expose Agent and Session, construct shared services as Arc<Agent>,
and keep lifecycle state, key routing, rollback, and request-handling helpers private.
The codec module SHALL own request and response types and their binary encoding.
The control module SHALL own control extension names and expose Request, Response,
State, Snapshot, Store, and Key. Request SHALL describe Unlock, Lock, and Status.
Response SHALL describe Success, Failure, and Status without separate outcome or status
wrapper types. Control message conversion and JSON encoding SHALL belong to these types.

### Requirement: Provider dependency isolation

The service SHALL accept a Provider instance through keyring-core's trait. The protocol
crate SHALL NOT depend on keyring-provider or interpret Bitwarden configuration or error
sources. The CLI SHALL construct the concrete provider before constructing the service.

### Requirement: Locked startup

Startup SHALL perform no Bitwarden login or sync and SHALL expose locked status. Identity
and signing requests SHALL fail while locked. Transitions SHALL serialize, while status
remains readable during loading. A second unlock SHALL report an already-unlocked conflict.

#### Scenario: Cancelled unlock

- **WHEN** unlock fails, times out, or its client disconnects
- **THEN** no partial binding table is published and stores are cleared before another transition.

### Requirement: Public-only binding table

Bindings and identity caches SHALL contain public records, references to selected stores,
and opaque key handles only. Private key bytes SHALL remain owned by stores.
Stores SHALL be called through spawn_blocking. Identity ordering SHALL use KeyData.
RSA flags SHALL require SHA-2, prefer SHA-256 when both flags are set, and reject unknown flags.

#### Scenario: Signing dispatch

- **WHEN** a client signs with a published key
- **THEN** the agent maps flags, calls its home store, and wraps the returned bytes as an SSH signature.

### Requirement: Fixed per-key selection and reconciliation

Selection SHALL try Keychain, FreeDesktop, then Memory according to availability,
capabilities, and successful import. Duplicate public keys SHALL use the last record.
Import SHALL clear this application's prior entries through each available store's clear
operation, including stale keys, rotations, duplicate homes, and entries with unreadable
public metadata. Cleanup errors SHALL fail closed rather than publish uncertain state.

#### Scenario: Import fallback

- **WHEN** a preferred store rejects an import
- **THEN** the next eligible store is tried and exactly one home is published.

### Requirement: Explicit loading and generation isolation

Only an explicit unlock SHALL authenticate, sync, decrypt, and import keys. The agent SHALL
retain only public snapshot metadata and backend bindings after loading, with no Bitwarden
session, access token, or account decryption keys. Snapshot metadata SHALL contain loaded_at
without an expiry. Idle time, identity listing, signing, and status SHALL NOT initiate
remote requests or refresh the loaded keys. Lock SHALL invalidate generations before
clearing stores, and an old generation SHALL never publish an in-flight signature after lock.

#### Scenario: Remote vault changes after unlock

- **WHEN** the remote vault changes while the agent remains unlocked
- **THEN** SSH operations continue to use the loaded backend keys until another explicit
  lock and unlock.

#### Scenario: Sign races lock

- **WHEN** lock occurs while a backend is signing
- **THEN** the computed signature is rejected.

### Requirement: Control extensions

unlock@keyring SHALL accept raw password bytes; lock@keyring and status@keyring SHALL accept
empty payloads. Known operations SHALL return same-name JSON extension responses, including
failures. Unknown extensions SHALL return extension failure. Query SHALL advertise only
query and OpenSSH session binding. Public status SHALL exclude cipher IDs and private data.
Refresh SHALL be composed by the client from lock and unlock; the service SHALL NOT provide
a refresh operation or extension.

Control responses SHALL use a lowercase type tag: success without additional fields,
failure with code and message, and status with state, snapshot, stores, and keys.
Response SHALL derive serialization and deserialization through Serde. Decoding SHALL
reject unknown tags, missing required fields, and invalid field types.
