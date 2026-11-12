# Share one formatter configuration between the flake wrapper and formatting check.
_: {
  # Anchor discovery at the repository root when invoked from a subdirectory.
  projectRootFile = "flake.nix";

  # Cover the workspace's Nix, TOML, and Rust sources with their native formatters.
  programs.nixfmt.enable = true;
  programs.taplo.enable = true;
  programs.rustfmt.enable = true;
}
