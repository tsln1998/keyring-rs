# Keep service options and command construction consistent across both modules.
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
        defaultText = lib.literalExpression "inputs.keyring-rs.packages.${pkgs.stdenv.hostPlatform.system}.default";
        description = "Package that provides the `keyring` executable.";
      };

      path = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        example = defaultPathExample;
        description = ''
          Unix socket path passed to `keyring --path`.

          The module prepares the parent directory for this path before the service starts.
        '';
      };

      # Inline configuration becomes a Nix store file; runtime secret files avoid that.
      settings = lib.mkOption {
        type = lib.types.nullOr format.type;
        default = null;
        example.bitwarden = {
          api_url = "https://api.bitwarden.example";
          identity_url = "https://identity.bitwarden.example";
          client_id = "client-id";
          client_secret = "<runtime-secret>";
        };
        description = ''
          Inline TOML configuration rendered into the Nix store and passed to `keyring
          --config`.

          The socket path is configured separately through `${lib.literalExpression "path"}` and
          must not be repeated in this document. The required Bitwarden API credentials are secrets;
          prefer settingsFile so they are not made readable from the Nix store.
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

          Use this so Bitwarden API credentials stay outside the Nix store.
          Both store paths and runtime-managed string paths are accepted.
        '';
      };
    };

  # Require one configuration source and keep socket selection in the service options.
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

  # Preserve supplied file references; generate a store file only for inline settings.
  mkConfigFile =
    name: cfg:
    if cfg.settingsFile != null then
      cfg.settingsFile
    else if cfg.settings != null then
      format.generate "${name}.toml" cfg.settings
    else
      null;

  mkParent = cfg: dirOf (toString cfg.path);

  # Quote every argument independently, including user-supplied paths.
  mkExecStart =
    cfg: configFile:
    lib.concatStringsSep " " (
      map lib.escapeShellArg [
        "${cfg.package}/bin/keyring"
        "--config"
        (toString configFile)
        "--path"
        (toString cfg.path)
      ]
    );

  # SIGUSR1 reloads configuration; a successful reload clears the current agent
  # and leaves its replacement locked until the user explicitly unlocks it.
  mkExecReload = "${pkgs.coreutils}/bin/kill -USR1 $MAINPID";
}
