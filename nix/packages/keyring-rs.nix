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
  version = "0.1.1";

  # Keep the packaged source limited to the Rust workspace inputs so large local
  # directories such as `target/` never become part of the derivation input.
  inherit src;

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

  # Running the package-local tests keeps the packaged service honest without expanding the flake
  # check surface to every workspace member.
  cargoTestFlags = [
    "--package"
    "keyring-cli"
  ];

  postInstall = ''
    ln -s $out/bin/keyring $out/bin/keyring-rs
  '';

  meta = with lib; {
    description = "Configuration-driven SSH agent service with pluggable key providers";
    homepage = "https://github.com/tsln1998/keyring-rs";
    license = licenses.mit;
    mainProgram = "keyring-rs";
    platforms = [
      "x86_64-linux"
      "aarch64-linux"
      "x86_64-darwin"
      "aarch64-darwin"
    ];
  };
}
