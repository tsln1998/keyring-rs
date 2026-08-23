{
  description = "keyring-rs: configuration-driven SSH agent service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
    flake-utils.url = "github:numtide/flake-utils";
    flake-utils.inputs.systems.follows = "systems";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    {
      self,
      nixpkgs,
      systems,
      flake-utils,
      treefmt-nix,
    }:
    let
      eachSystem = flake-utils.lib.eachSystem (import systems);
    in
    eachSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        treefmtEval = treefmt-nix.lib.evalModule pkgs ./formatter.nix;
        sourcePackage = pkgs.callPackage ./nix/packages/keyring-rs.nix { };
        binaryPackage = pkgs.callPackage ./nix/packages/keyring-rs-bin.nix { };
      in
      {
        packages = rec {
          keyring-rs = sourcePackage;
          keyring-rs-bin = binaryPackage;
          default = keyring-rs-bin;
        };

        formatter = treefmtEval.config.build.wrapper;

        checks = {
          package = sourcePackage;
          package-bin = binaryPackage;
          formatting = treefmtEval.config.build.check self;
        };
      }
    )
    // {
      nixosModules = {
        keyring-rs = import ./nix/modules/nixos.nix { inherit self; };
        default = self.nixosModules.keyring-rs;
      };

      homeModules = {
        keyring-rs = import ./nix/modules/home.nix { inherit self; };
        default = self.homeModules.keyring-rs;
      };
    };
}
