{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.keyring-rs;

  toml = pkgs.formats.toml { };
in
{
  options.services.keyring-rs = {
    enable = lib.mkEnableOption "the keyring-rs SSH agent service";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "Package that provides the `keyring` executable.";
    };

    path = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/home/user/.local/state/keyring-rs/keyring.sock";
      description = ''
        Unix socket path passed to `--path`. Its parent directory is created before startup.
      '';
    };

    settings = lib.mkOption {
      type = lib.types.nullOr toml.type;
      default = null;
      example.bitwarden = {
        api_url = "https://api.bitwarden.example";
        identity_url = "https://identity.bitwarden.example";
        client_id = "client-id";
        client_secret = "<runtime-secret>";
      };
      description = ''
        Inline TOML configuration passed to `--config`. This is readable in the Nix store;
        prefer `settingsFile` for Bitwarden credentials. Configure the socket with `path`,
        not a `service` section.
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
        TOML configuration file passed to `--config`. Use a runtime-managed string path
        to keep Bitwarden credentials outside the Nix store.
      '';
    };
  };

  config =
    let
      gernerate =
        if cfg.settingsFile != null then
          cfg.settingsFile
        else if cfg.settings != null then
          toml.generate "keyring-rs-user.toml" cfg.settings
        else
          null;
      command = lib.escapeShellArgs [
        "${cfg.package}/bin/keyring"
        "--config"
        (toString gernerate)
        "--path"
        (toString cfg.path)
      ];
    in
    lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.path != null;
          message = "services.keyring-rs.path is required.";
        }
        {
          assertion = (cfg.settings != null) != (cfg.settingsFile != null);
          message = "services.keyring-rs requires exactly one of `settings` or `settingsFile`.";
        }
        {
          assertion = cfg.settings == null || !(cfg.settings ? service);
          message = "services.keyring-rs.settings must not define `service`; configure the socket path with `services.keyring-rs.path` instead.";
        }
        {
          assertion = pkgs.stdenv.hostPlatform.isLinux || pkgs.stdenv.hostPlatform.isDarwin;
          message = "services.keyring-rs supports only Linux systemd and macOS launchd user services.";
        }
      ];

      home.packages = [ cfg.package ];

      systemd.user.services.keyring-rs =
        lib.mkIf (pkgs.stdenv.hostPlatform.isLinux && gernerate != null)
          {
            Unit = {
              Description = "keyring-rs SSH agent service";
              After = [ "network.target" ];
            };

            Service = {
              Type = "simple";
              ExecStart = command;
              ExecReload = "${pkgs.coreutils}/bin/kill -USR1 $MAINPID";
              Restart = "on-failure";
              RestartSec = 5;
              ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArg (dirOf (toString cfg.path))}";
            };

            Install.WantedBy = [ "default.target" ];
          };

      launchd.agents.keyring-rs = lib.mkIf (pkgs.stdenv.hostPlatform.isDarwin && gernerate != null) {
        enable = true;
        config = {
          ProgramArguments = [
            (toString (
              pkgs.writeShellScript "keyring-rs-start" ''
                ${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArg (dirOf (toString cfg.path))}
                exec ${command}
              ''
            ))
          ];
          KeepAlive = {
            Crashed = true;
            SuccessfulExit = false;
          };
          ProcessType = "Background";
          RunAtLoad = true;
          ThrottleInterval = 5;
        };
      };
    };
}
