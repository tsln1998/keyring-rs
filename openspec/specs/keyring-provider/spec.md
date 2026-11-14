# keyring-provider

## Purpose

Load SSH materials from one Bitwarden account with operation-scoped credentials and crypto.

## Requirements

### Requirement: Concrete provider construction

BitwardenProvider SHALL implement the Provider trait from keyring-core. Construction SHALL
validate and retain configuration without authentication or sync. Each explicit load SHALL
create a fresh account session using the supplied password.

### Requirement: Explicit password bootstrap

The crate SHALL accept a zeroizing password only at unlock, use API-key client credentials,
derive from masterPasswordUnlock salt and KDF, initialize account crypto, and discard the
password before sync. Missing unlock metadata SHALL fail explicitly.

#### Scenario: Wrong master password

- **WHEN** the encrypted user key cannot be decrypted
- **THEN** no usable vault or SSH materials are returned.

### Requirement: Bounded authentication recovery

HTTP connect, read, and total timeouts SHALL be 5, 5, and 10 seconds. A sync 401 SHALL allow
one token renewal and one retry. Other failures SHALL propagate without that retry.
Tokens SHALL belong only to the current explicit load and SHALL NOT be renewed proactively
or retained between loads.

#### Scenario: Repeated unauthorized sync

- **WHEN** the retry also returns 401
- **THEN** the load fails without a third sync attempt.

### Requirement: Scoped decryption

The crate SHALL decrypt personal, organization, and item-wrapped SSH records; filter
non-SSH, deleted, archived, missing, and invalid keys; preserve stable comment fallback;
and return validated StoreMaterial. It SHALL NOT retain decrypted SSH-key snapshots.
Each load SHALL create fresh account crypto. Account decryption keys, access tokens, and
remote vault data SHALL be released before returning materials for backend import, using
zeroizing secret containers and clearing the crypto store. Failure or cancellation SHALL
release operation-owned secrets as in-flight work exits, including blocking tasks that
must finish before their data can be destroyed.

#### Scenario: A second explicit load

- **WHEN** a caller loads again after a successful load
- **THEN** authentication and password derivation run again without reusing previous
  access tokens or account keys.

#### Scenario: Archived item

- **WHEN** an SSH item is archived
- **THEN** it is skipped before attempting to decrypt its fields.
