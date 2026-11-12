# keyring-rs

An SSH agent that loads RSA and Ed25519 keys from Bitwarden.
Supports Linux, macOS, and Windows.

## Install

From the repository:

```sh
cargo install --path crates/keyring-cli --locked
```

Nix users can build with `nix build .` and run `./result/bin/keyring`.

## Configure

Create `config.toml` with your Bitwarden personal API key:

```toml
[bitwarden]
api_url = "https://api.bitwarden.com"
identity_url = "https://identity.bitwarden.com"
client_id = "your-client-id"
client_secret = "your-client-secret"
```

Change the URLs for another region or a self-hosted server. Keep this file private.
Your master password is entered interactively when unlocking.

## Use

Start the service in one terminal:

```sh
keyring --config config.toml --path /tmp/keyring.sock
```

In another terminal, connect your SSH client and unlock:

```sh
export SSH_AUTH_SOCK=/tmp/keyring.sock
keyring unlock
ssh-add -L
ssh user@host
```

On Windows, use `\\.\pipe\openssh-ssh-agent` for `--path` and set
`SSH_AUTH_SOCK` to the same value.

The service starts locked and never refreshes automatically.

| Command | Description |
| --- | --- |
| `keyring unlock` | Load keys from Bitwarden using your master password. |
| `keyring refresh` | Reload keys, prompting for your master password again. |
| `keyring lock` | Lock the agent and clear loaded keys. |
| `keyring status` | Show the current state and loaded keys. |

Use `keyring status --json` for JSON output.

## License

MIT. See [LICENSE](./LICENSE).
