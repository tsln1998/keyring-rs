{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "keyring-rs";
  version = (builtins.fromTOML (builtins.readFile ../Cargo.toml)).workspace.package.version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "--package"
    "keyring-cli"
    "--bin"
    "keyring"
  ];

  cargoTestFlags = [ "--workspace" ];

  meta = {
    description = "Bitwarden SSH agent with platform key stores";
    homepage = "https://github.com/tsln1998/keyring-rs";
    license = lib.licenses.mit;
    mainProgram = "keyring";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];
  };
}
