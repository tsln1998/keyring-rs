# keyring-cli Specification

## Purpose
Provide the single foreground executable that parses configuration, builds providers, prepares the Unix socket, and starts the `ssh-agent-lib` service loop.

## Requirements
### Requirement: Foreground binary entrypoint
The `keyring-cli` crate SHALL provide the only executable entrypoint for the workspace and MUST run as a single foreground service process on one Tokio runtime without subcommands or interactive control RPCs.

#### Scenario: Start the service process
- **WHEN** the user launches the binary with `--config` or `-c` plus `--path` or `-p`
- **THEN** `keyring-cli` starts one foreground async runtime, binds the requested Unix socket path, and does not expose additional command modes

#### Scenario: Launch without arguments
- **WHEN** the user starts the binary without any arguments
- **THEN** `keyring-cli` renders the generated help text and exits instead of attempting startup

### Requirement: Composition root ownership
The `keyring-cli` crate SHALL be the only crate responsible for assembling the top-level configuration document, `keyring-providers`, and `keyring-service` into a runnable service.

#### Scenario: Build the application graph
- **WHEN** startup proceeds with a valid configuration
- **THEN** `keyring-cli` constructs provider trait objects, passes them directly into `ServiceAgent::new`, and does not preserve startup-only bootstrap wrappers

### Requirement: Ordered bootstrap gating
The `keyring-cli` crate SHALL complete configuration loading, tracing initialization, provider construction, service assembly, and Unix listener setup in a fail-fast order before it accepts client requests.

#### Scenario: A provider fails during startup loading
- **WHEN** configuration parsing, static validation, or provider construction fails before the service loop begins
- **THEN** `keyring-cli` exits before publishing a live agent listener

### Requirement: Client failure isolation
The `keyring-cli` crate SHALL allow idle client connections to remain open and SHALL apply one cooperative 30-second deadline to each fully decoded request, covering handling and response transmission. Client errors, request timeouts, and unwinding client-task panics SHALL NOT terminate the service loop.

#### Scenario: Reuse a long-lived connection
- **WHEN** a client remains idle for more than 30 seconds and then sends a request
- **THEN** the connection remains usable and the new request receives its own deadline

#### Scenario: A client request times out
- **WHEN** request processing or response transmission reaches the request deadline
- **THEN** `keyring-cli` closes that client connection while other clients and the listener continue operating

### Requirement: CLI-owned config and socket lifecycle
The `keyring-cli` crate SHALL own the top-level TOML document, cross-provider static validation, the `--path` socket binding, and the signal-driven reload loop that rebuilds service state without a control RPC.

#### Scenario: Reclaim a stale Unix socket
- **WHEN** the requested path is an unchanged Unix socket whose connection probe is refused
- **THEN** `keyring-cli` removes that stale socket and retries the bind once

#### Scenario: Preserve an occupied or unsafe path
- **WHEN** the requested path has a live listener, is not a Unix socket, changes during probing, or cannot be inspected conclusively
- **THEN** `keyring-cli` fails the bind without removing the existing path

#### Scenario: Keep the listener across reloads
- **WHEN** the running process reloads its configuration
- **THEN** `keyring-cli` keeps the original listener open instead of rebinding the socket path

### Requirement: Signal-driven config reload
The `keyring-cli` crate SHALL treat the configuration file as the only supported control surface and SHALL reload that file only when the running process receives `SIGUSR1`. It SHALL build a candidate agent with local validation while the current agent continues accepting clients, and SHALL replace the current agent only when that build succeeds. Remote provider authentication and loading SHALL remain lazy.

#### Scenario: Reload the config file without rebinding the socket
- **WHEN** the running process receives `SIGUSR1`
- **THEN** `keyring-cli` re-reads the current `--config` file, rebuilds the provider-backed service state, and keeps serving on the original `--path`

#### Scenario: Reject an invalid reload
- **WHEN** candidate configuration parsing, static validation, or provider construction fails
- **THEN** the current agent, its client sessions, and the original listener remain available for a later reload attempt

#### Scenario: Drain the replaced generation
- **WHEN** a candidate agent replaces the current agent
- **THEN** new clients immediately use the new agent, idle old sessions close, and old sessions with an in-flight request close after transmitting its response or reaching its original deadline without accepting another request

#### Scenario: Coalesce concurrent reload signals
- **WHEN** one or more reload signals arrive while a candidate is being built
- **THEN** `keyring-cli` schedules one subsequent re-read and never builds multiple candidates concurrently

### Requirement: Signal-driven graceful shutdown
The `keyring-cli` crate SHALL treat `SIGINT` and `SIGTERM` as graceful shutdown requests on Unix. It SHALL stop accepting clients and applying candidate configurations, close idle sessions, and allow in-flight requests to finish within their original deadlines. After a cooperative 30-second drain deadline it SHALL cancel remaining client tasks and release its owned socket path. Individual client failures SHALL NOT change a requested shutdown into a service failure.

#### Scenario: Stop a systemd-managed service
- **WHEN** the running process receives `SIGTERM`
- **THEN** `keyring-cli` exits successfully after removing its owned Unix socket path so the same path can be bound on the next start

### Requirement: Secret-safe operational logging
The `keyring-cli` crate SHALL initialize logging from environment-driven tracing filters such as `RUST_LOG` and MUST NOT emit passwords, client secrets, decrypted private keys, or full remote response bodies in operational logs.

#### Scenario: Log a startup or runtime failure
- **WHEN** the service records an operational failure
- **THEN** the logs may include safe identifiers such as provider names and socket paths, but they omit raw secrets and private key material
