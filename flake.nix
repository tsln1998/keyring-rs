{
  description = "keyring-rs: Bitwarden SSH agent with platform key stores";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    systems.url = "github:nix-systems/triplet";

    flake-utils.url = "github:numtide/flake-utils";
    flake-utils.inputs.systems.follows = "systems";

    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      treefmt-nix,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        treefmt = treefmt-nix.lib.evalModule pkgs ./formatter.nix;
        package = pkgs.callPackage ./nix/package.nix { };
      in
      {
        formatter = treefmt.config.build.wrapper;

        packages = {
          default = package;
          keyring-rs = package;
        };

        checks = {
          inherit package;
          formatting = treefmt.config.build.check self;
        };

        devShells = {
          default = pkgs.mkShell {
            packages = [
              pkgs.cargo
              pkgs.rustc
              pkgs.rustfmt
              pkgs.clippy
              pkgs.rust-analyzer
              pkgs.nixd
            ];

            RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;
          };
        };
      }
    )
    // {
      homeModules = {
        keyring-rs = import ./nix/home.nix;
        default = self.homeModules.keyring-rs;
      };
    };
}
