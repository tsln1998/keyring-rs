# Build the service executable from the local Rust workspace.
{ lib, rustPlatform }:

let
  src = lib.fileset.toSource {
    root = ../..;
    fileset = lib.fileset.unions [
      ../../Cargo.toml
      ../../Cargo.lock
      ../../crates
    ];
  };
in
rustPlatform.buildRustPackage {
  pname = "keyring-rs";
  inherit (builtins.fromJSON (builtins.readFile ./update.json)) version;

  # Keep the packaged source limited to the Rust workspace inputs so large local
  # directories such as `target/` never become part of the derivation input.
  inherit src;

  # Resolve dependencies from the same lock file used by workspace development.
  cargoLock = {
    lockFile = ../../Cargo.lock;
  };

  # The workspace contains multiple crates, but the published service artifact is the single
  # foreground binary from `keyring-cli`.
  cargoBuildFlags = [
    "--package"
    "keyring-cli"
    "--bin"
    "keyring"
  ];

  # Package validation covers supporting crates as well as the shipped executable.
  cargoTestFlags = [
    "--workspace"
  ];

  meta = with lib; {
    description = "Bitwarden SSH agent with platform key stores";
    homepage = "https://github.com/tsln1998/keyring-rs";
    license = licenses.mit;
    mainProgram = "keyring";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];
  };
}
