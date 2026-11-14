# keyring-store-freedesktop

## Purpose

Provide Linux-only durable Secret Service storage using pure Rust D-Bus.

## Requirements

### Requirement: Cached storage availability probe

The probe SHALL connect only to the local session bus, require an existing Secret Service
owner and an unlocked default collection, and never start a daemon or request an interactive
prompt. It SHALL then open a session, create a temporary item without replacing existing
items, retrieve and compare its Secret, and delete it. Probe items SHALL use a random
`user` attribute and `server=keyring-rs.probe`, outside normal key listing and cleanup.
Only a successful write, read, comparison, and deletion SHALL make the backend available.
The probe SHALL run once per instance through synchronized initialization and cache both
success and failure, retaining the successful connection and collection. Construction SHALL
complete the probe; later availability, capability, and storage calls SHALL reuse its result.
Discovery SHALL have a two-second timeout and the write/read stage an eight-second timeout.
A known probe item SHALL still receive a deletion attempt after read errors or timeout.
Deletion and session closing SHALL run outside the write/read deadline with separate
five-second timeouts. Session closing SHALL be attempted after success and ordinary
failure without replacing the storage result.
Storage errors, mismatched bytes, interactive prompts, and deletion failures SHALL report
PROBE_FAILED; an exceeded probe deadline SHALL report TIMEOUT. Remote timeouts or process
termination may leave isolated temporary entries and SHALL NOT be described as atomic cleanup.

#### Scenario: No session bus

- **WHEN** the session bus or service is absent
- **THEN** capabilities report unsupported, reason is NO_SESSION_BUS or NO_SERVICE,
  and the agent can choose Memory.

#### Scenario: Unlocked collection denies storage access

- **WHEN** an existing unlocked collection rejects writing, reading, or deleting a probe item
- **THEN** capabilities report unsupported, reason is PROBE_FAILED, and subsequent calls
  reuse the cached failure without retrying.

### Requirement: Unified software signing

RSA and Ed25519 SHALL be stored with complete public metadata in this
application's namespace. Sign SHALL retrieve the secret, invoke core software, and
zeroize the retrieved bytes. Status SHALL report software signing.
Deletion and clear SHALL operate only on this application's items.

#### Scenario: Real-platform verification

- **WHEN** a real unlocked Secret Service is available for manual acceptance
- **THEN** RSA and Ed25519 SHALL round-trip through storage and produce independently
  verified signatures, and owned items SHALL be removed by delete and clear.

### Requirement: Desktop-compatible item metadata

Items SHALL use the SSH comment as their label and expose `server=keyring-rs`,
`user=<public-key fingerprint>`, and `type=binary` for KWallet compatibility.
They SHALL retain `application=keyring-rs` and serialize the public `StoreRecord`
as JSON in the `payload` attribute. They SHALL omit `xdg:schema` and store the raw
Ed25519 seed or RSA PKCS#1 DER in the Secret.
Lookup and ownership checks SHALL use `server=keyring-rs`. Deletion and clear SHALL
NOT require `application`, `user`, `type`, or a valid `payload` attribute.
Listing and signing SHALL fail when the required public record is missing or invalid.

#### Scenario: Wallet editor removes custom metadata

- **WHEN** an owned item's `payload` or `application` attribute is removed or damaged
  while `server=keyring-rs` remains
- **THEN** delete and clear can still remove the item, and signing fails if `payload`
  is missing or invalid.

#### Scenario: Item belongs to another application

- **WHEN** an item's `server` attribute is absent or differs from `keyring-rs`
- **THEN** lookup excludes it and direct deletion rejects its handle.

### Requirement: Static build compatibility

The crate SHALL use zbus without libdbus or backend Cargo features. Its platform APIs
SHALL not leak into core, Bitwarden, or agent dependencies.
