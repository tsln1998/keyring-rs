# keyring-protocol

## Purpose

Own SSH agent behavior, transactional unlocking, storage orchestration, and control extensions.

## Requirements

### Requirement: Locked startup

Startup SHALL perform no Bitwarden login or sync and SHALL expose locked status. Identity
and signing requests SHALL fail while locked. Transitions SHALL serialize, while status
remains readable during loading. A second unlock SHALL report an already-unlocked conflict.

#### Scenario: Cancelled unlock

- **WHEN** unlock fails, times out, or its client disconnects
- **THEN** no partial binding table is published and stores are cleared before another transition.

### Requirement: Public-only binding table

Bindings and identity caches SHALL contain public records, store kinds, and opaque handles
only. Stores SHALL be called through spawn_blocking. Identity ordering SHALL use KeyData.
RSA flags SHALL require SHA-2, prefer SHA-256 when both flags are set, and reject unknown flags.

#### Scenario: Signing dispatch

- **WHEN** a client signs with a published key
- **THEN** the agent maps flags, calls its home store, and wraps the returned bytes as an SSH signature.

### Requirement: Fixed per-key selection and reconciliation

Selection SHALL try Keychain, FreeDesktop, then Memory according to availability,
capabilities, and successful import. Duplicate public keys SHALL use the last record.
Import SHALL remove this application's prior entries, including stale keys, rotations,
and duplicate homes. Cleanup errors SHALL fail closed rather than publish uncertain state.

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
