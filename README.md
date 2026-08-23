# keyring-rs

`keyring-rs` is a configuration-driven SSH agent service. It runs as one foreground process,
implements the minimal OpenSSH agent surface needed for identity listing and signing, and routes
those operations to pluggable key providers.

The workspace currently ships with two providers:

- `dummy`: generates one deterministic in-memory `ed25519` key at startup.
- `bitwarden`: authenticates against Bitwarden-compatible endpoints, loads SSH keys from
  `/sync`, and signs locally with the decrypted private key material.

## Workspace

- `crates/keyring-cli`: CLI args, TOML loading, Unix socket setup, and the `keyring` binary entrypoint.
- `crates/keyring-core`: shared provider traits and small reusable cache primitives.
- `crates/keyring-providers`: bundled provider implementations for dummy and Bitwarden.
- `crates/keyring-service`: `ssh-agent-lib` agent implementation that loads provider identities lazily per client session.

## Configuration

`keyring-rs` accepts a provider configuration document through `--config` and a Unix socket path
through `--path`. The service has no subcommands and no control RPC surface. When the running
process receives `SIGUSR1`, it reloads the config file currently passed through `--config`.

A minimal local setup with the dummy provider looks like this:

```toml
[[dummy]]
name = "local"
```

Run it directly from the Rust workspace:

```bash
cargo run -p keyring-cli -- --config ./keyring-rs.toml --path /tmp/keyring-rs.sock
```

The workspace `cargo run` / `cargo build` flow is intended for local development on the current
host. Distribution builds use the target-specific release workflow described below.

Run it from the flake package:

```bash
nix run .#keyring-rs -- --config ./keyring-rs.toml --path /tmp/keyring-rs.sock
```

Bitwarden-backed setups use the same root document and add `[[bitwarden]]` entries:

```toml
[[bitwarden]]
name = "vault"
api_url = "https://api.bitwarden.example"
identity_url = "https://identity.bitwarden.example"
client_id = "client-id"
client_secret = "super-secret"
password = "master-password"
```

## Nix

The flake exports:

- `packages.<system>.keyring-rs`: the packaged service.
- `formatter.<system>`: `treefmt` with `nixfmt`, `taplo`, and `rustfmt`.
- `nixosModules.keyring-rs`: a NixOS module that manages a systemd system service named `keyring-rs`.
- `homeModules.keyring-rs`: a Home Manager module that manages a systemd user service named `keyring-rs`.

The Nix package and service modules currently target Linux. Standalone release archives are
available for Linux and macOS.

For local or Nix-managed builds:

- Linux: `nix build .#keyring-rs` produces the Nix-managed package for the current system.
- Windows: `cargo xwin build --target x86_64-pc-windows-msvc --release` produces a single `.exe`
  with the MSVC CRT linked statically. The resulting binary still imports normal Windows system
  DLLs such as `KERNEL32.dll`, which is expected.

## Release artifacts

Pushing a version tag such as `v0.2.0` publishes a GitHub Release containing the `keyring` binary
for these targets:

| Archive | Target |
| --- | --- |
| `keyring-rs-v0.2.0-linux-x86_64.tar.gz` | Linux x86_64, statically linked with musl |
| `keyring-rs-v0.2.0-linux-arm64.tar.gz` | Linux arm64, statically linked with musl |
| `keyring-rs-v0.2.0-darwin-x86_64.tar.gz` | macOS x86_64 |
| `keyring-rs-v0.2.0-darwin-arm64.tar.gz` | macOS arm64 |

Each archive contains `keyring`, this README, and the MIT license. Verify the downloaded files
against the release's `SHA256SUMS` before extracting them:

```bash
# Linux x86_64
grep 'linux-x86_64.tar.gz$' SHA256SUMS | sha256sum --check

# macOS arm64
grep 'darwin-arm64.tar.gz$' SHA256SUMS | shasum -a 256 --check
```

The macOS binaries are not signed or notarized. If Gatekeeper quarantines a binary downloaded
from GitHub, inspect it first and then remove the quarantine attribute explicitly:

```bash
xattr -d com.apple.quarantine ./keyring
```

For local checkouts, prefer `git+file:///...` inputs or commands such as `nix build .#keyring-rs`.
Plain `path:` inputs copy the entire working tree into the Nix store, including large build
directories such as `target/`. If you need newly created files to be visible through a local Git
flake input, stage them with `git add` before building.

## NixOS

Import the flake module and configure `services.keyring-rs`. The module supports two ways to pass
the service configuration:

- `path`: the Unix socket path passed to `keyring-rs --path`.
- `settings`: inline Nix attributes rendered to TOML in the Nix store.
- `settingsFile`: an existing TOML file path passed directly to `--config`.

Use `settings` only for non-secret configurations. Anything rendered through `settings` becomes
readable from the Nix store. Secret-bearing providers such as Bitwarden should use `settingsFile`
with a runtime-managed secret path.

```nix
{
  inputs.keyring-rs.url = "git+file:///path/to/keyring-rs";

  outputs = { nixpkgs, keyring-rs, ... }: {
    nixosConfigurations.demo = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        keyring-rs.nixosModules.keyring-rs
        ({ ... }: {
          services.keyring-rs = {
            enable = true;
            path = "/run/keyring-rs/keyring.sock";
            settings = {
              dummy = [
                { name = "local"; }
              ];
            };
          };
        })
      ];
    };
  };
}
```

The NixOS module creates the `keyring-rs` system user and group automatically when you keep the
default `user` and `group` values.

For Bitwarden or any other secret-bearing configuration, prefer `settingsFile`:

```nix
services.keyring-rs = {
  enable = true;
  path = "/run/keyring-rs/keyring.sock";
  settingsFile = config.age.secrets."keyring-rs".path;
};
```

The module always creates the parent directory of `path` before the service starts.

The managed systemd service also supports manual reload:

```bash
systemctl reload keyring-rs
```

This sends `SIGUSR1` to the running process so it re-reads the current `--config` file without
changing the bound socket path.

## Home Manager

The Home Manager module exports the same `settings` and `settingsFile` interface, but it runs the
service as a systemd user unit:

```nix
{
  imports = [ keyring-rs.homeModules.keyring-rs ];

  services.keyring-rs = {
    enable = true;
    path = "${config.home.homeDirectory}/.local/state/keyring-rs/keyring.sock";
    settings = {
      dummy = [
        { name = "local"; }
      ];
    };
  };
}
```

As with the NixOS module, `settings` is suitable only for non-secret data because it is rendered
into the Nix store. Use `settingsFile` when the configuration includes credentials.

The user service exposes the same reload behavior through the corresponding user unit:

```bash
systemctl --user reload keyring-rs
```

## License

This project is licensed under the MIT license. See [LICENSE](./LICENSE).
