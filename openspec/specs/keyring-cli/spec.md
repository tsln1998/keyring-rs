# keyring-cli

## Purpose

Provide the keyring binary, configuration, control client, and platform service lifecycle.

## Requirements

### Requirement: Strict single-account configuration

Configuration SHALL require one [bitwarden] table containing API/identity URLs and API
credentials. Unknown fields, provider arrays, name, dummy, password, and store options
SHALL be rejected. Debug output and parsing diagnostics SHALL not reveal credentials.

#### Scenario: Old password field

- **WHEN** configuration contains password
- **THEN** startup fails before binding the socket.

### Requirement: Terminal control commands

The default invocation SHALL serve; unlock, refresh, lock, and status SHALL use the same agent socket,
resolving --path before SSH_AUTH_SOCK. Unlock SHALL read its password without echo from
the terminal, without accepting argv or environment passwords. Status SHALL have stable
text and JSON forms, escape control characters, and distinguish not-running from locked.
Exit codes SHALL distinguish usage, connection, state conflict, and authentication failures.

### Requirement: Status layout

Human output SHALL start with STATUS and an uppercase state, followed by SNAPSHOT and
its load timestamp only when unlocked. A STORE / STATE table SHALL preserve the order of
the stores returned by the service, showing OK when available or a short uppercase reason
when unavailable.
The public-key table SHALL follow the store table only when unlocked and nonempty, with
FINGERPRINT, ALGORITHM, STORE, SIGNING, and COMMENT columns. Tables SHALL use a borderless
layout with automatically sized columns. JSON SHALL retain lowercase state values and return uppercase
reason codes, using null for available stores.

#### Scenario: Linux backend list

- **WHEN** the service holds FreeDesktop and Memory backends
- **THEN** status returns those two entries in service order and the client renders those
  two rows.

### Requirement: Client-composed refresh

Refresh SHALL send lock, require its successful response, reconnect, and send unlock using
a newly prompted terminal password. It SHALL use only the existing lock and unlock control
extensions. A failed lock SHALL stop the sequence. Password input or unlock failure after
successful lock SHALL leave the agent locked. Existing SSH connections SHALL be invalidated
by the lock.

#### Scenario: Refresh with an incorrect password

- **WHEN** refresh locks successfully and the new unlock password is incorrect
- **THEN** the unlock fails and the agent remains locked without restoring the old keys.

### Requirement: Bounded secret-aware transport

Transport SHALL bound packets to 1 MiB, zeroize raw framing buffers, avoid request debug
logging, detect disconnect during unlock, and bound decoded requests plus writes to
30 seconds except unlock at 180 seconds. Idle clients SHALL have no request timeout.

#### Scenario: Fragmented packet

- **WHEN** a valid frame arrives across multiple reads
- **THEN** it is decoded only after the whole frame is available.

### Requirement: Platform lifecycle

Unix sockets SHALL be 0600 and preserve active sockets, regular files, and symlinks during
stale-path reclamation. Windows SHALL retain named-pipe support. Unix SIGUSR1 SHALL validate
configuration before replacement and return successful reloads to locked; invalid reloads
SHALL preserve the active service. Shutdown SHALL drain for up to 30 seconds and clear stores.

### Requirement: Build and assembly

CLI SHALL assemble target-gated platform stores and universal Memory. Nix defaults SHALL
build the source version, use the keyring executable, and support runtime secret files.
Linux release binaries SHALL remain statically linked with musl.
