{
  lib,
  pkgs,
  defaultPackage,
}:

let
  format = pkgs.formats.toml { };
in
{
  mkBaseOptions =
    { defaultPathExample }:
    {
      enable = lib.mkEnableOption "the keyring-rs SSH agent service";

      package = lib.mkOption {
        type = lib.types.package;
        default = defaultPackage;
        defaultText = lib.literalExpression "inputs.keyring-rs.packages.${pkgs.system}.keyring-rs";
        description = "Package that provides the `keyring-rs` executable.";
      };

      path = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = defaultPathExample;
        description = ''
          Unix socket path passed to `keyring-rs --path`.

          The module prepares the parent directory for this path before the service starts.
        '';
      };

      settings = lib.mkOption {
        type = lib.types.nullOr format.type;
        default = null;
        example = {
          dummy = [
            { name = "local"; }
          ];
        };
        description = ''
          Inline TOML configuration rendered into the Nix store and passed to `keyring-rs
          --config`.

          The socket path is configured separately through `${lib.literalExpression "path"}` and
          must not be repeated in this document. This is convenient for non-secret setups such as
          the dummy provider. Do not place Bitwarden credentials or other secrets here because the
          generated file becomes readable from the Nix store.
        '';
      };

      settingsFile = lib.mkOption {
        type = lib.types.nullOr (
          lib.types.oneOf [
            lib.types.path
            lib.types.str
          ]
        );
        default = null;
        example = lib.literalExpression "config.age.secrets.\"keyring-rs\".path";
        description = ''
          Path to an existing TOML configuration file passed directly to `--config`.

          Use this for secret-bearing providers so credentials can stay outside the Nix store.
          Both store paths and runtime-managed string paths are accepted.
        '';
      };
    };

  mkAssertions = optionPath: cfg: [
    {
      assertion = cfg.path != null;
      message = "${optionPath}.path is required.";
    }
    {
      assertion = cfg.settings != null || cfg.settingsFile != null;
      message = "${optionPath} requires either `settings` or `settingsFile`.";
    }
    {
      assertion = !(cfg.settings != null && cfg.settingsFile != null);
      message = "${optionPath} accepts only one of `settings` or `settingsFile`.";
    }
    {
      assertion = cfg.settings == null || lib.attrByPath [ "service" ] null cfg.settings == null;
      message = "${optionPath}.settings must not define `service`; configure the socket path with `${optionPath}.path` instead.";
    }
  ];

  mkConfigFile =
    name: cfg:
    if cfg.settingsFile != null then
      cfg.settingsFile
    else if cfg.settings != null then
      format.generate "${name}.toml" cfg.settings
    else
      null;

  mkParent = cfg: dirOf (toString cfg.path);

  mkExecStart =
    cfg: configFile:
    lib.concatStringsSep " " (
      map lib.escapeShellArg [
        "${cfg.package}/bin/keyring-rs"
        "--config"
        (toString configFile)
        "--path"
        (toString cfg.path)
      ]
    );

  mkExecReload = "${pkgs.coreutils}/bin/kill -USR1 $MAINPID";
}
