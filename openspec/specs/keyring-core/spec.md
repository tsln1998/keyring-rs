# keyring-core Specification

## Purpose
Define the smallest shared traits and reusable primitives required for providers to publish SSH identities to the service layer without carrying runtime-owned models, protocol types, or provider-specific DTOs.

## Requirements
### Requirement: Minimal shared core surface
The `keyring-core` crate SHALL expose only the minimal shared traits and small reusable primitives needed by the workspace runtime, and SHALL NOT define shared structs for provider descriptors, identity handles, snapshots, refresh events, sign requests, sign responses, or secret wrappers.

#### Scenario: Inspect the public API surface
- **WHEN** another crate depends on `keyring-core`
- **THEN** it receives only small shared contracts and primitives instead of a shared runtime data model

### Requirement: Shared single-value cache primitive
The `keyring-core` crate SHALL provide a reusable async cache cell for one clonable value so multiple provider implementations can share the same TTL-based caching behavior without introducing provider-specific cache types into the core trait surface.

#### Scenario: Reuse a fresh cached value
- **WHEN** a caller asks for a cached value before the configured TTL expires
- **THEN** the cache cell returns the cached clone without rerunning the initializer

#### Scenario: Refresh an expired cached value
- **WHEN** a cached entry is missing or expired
- **THEN** one caller recomputes the value and stores the fresh result for later callers

### Requirement: Load-only provider trait
The `keyring-core` crate SHALL define one async provider trait whose only runtime operation is `load`, returning a collection of typed `ssh_key::PrivateKey` values.

#### Scenario: Implement a provider crate
- **WHEN** a provider crate implements the shared contract
- **THEN** it only needs to provide one async load path that returns OpenSSH private keys and does not implement refresh, sign, or descriptor accessors

#### Scenario: Store provider trait objects in service wiring
- **WHEN** upper layers keep providers behind trait objects
- **THEN** they can await `load` directly from request handling or startup wiring without introducing compatibility wrappers or mirrored sync APIs
