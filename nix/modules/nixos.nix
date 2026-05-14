{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  common = import ./common.nix {
    inherit lib pkgs;
    defaultPackage = self.packages.${pkgs.system}."keyring-rs";
  };
  cfg = config.services.keyring-rs;
  configFile = common.mkConfigFile "keyring-rs" cfg;
  pathParent = common.mkParent cfg;
in
{
  options.services.keyring-rs =
    common.mkBaseOptions {
      defaultPathExample = "/run/keyring-rs/keyring.sock";
    }
    // {
      user = lib.mkOption {
        type = lib.types.str;
        default = "keyring-rs";
        description = ''
          User account that runs the `keyring-rs` system service.

          When left at the default value the module creates the system user automatically.
        '';
      };

      group = lib.mkOption {
        type = lib.types.str;
        default = "keyring-rs";
        description = ''
          Group that runs the `keyring-rs` system service.

          When left at the default value the module creates the group automatically.
        '';
      };
    };

  config = lib.mkIf cfg.enable {
    assertions = common.mkAssertions "services.keyring-rs" cfg;

    users.groups = lib.mkIf (cfg.group == "keyring-rs") {
      "keyring-rs" = { };
    };

    users.users = lib.mkIf (cfg.user == "keyring-rs") {
      "keyring-rs" = {
        description = "keyring-rs service user";
        group = cfg.group;
        isSystemUser = true;
      };
    };

    systemd.services.keyring-rs = lib.mkIf (configFile != null) {
      description = "keyring-rs SSH agent service";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      preStart = ''
        ${pkgs.coreutils}/bin/install -d -m0750 -o ${lib.escapeShellArg cfg.user} -g ${lib.escapeShellArg cfg.group} ${lib.escapeShellArg pathParent}
      '';

      serviceConfig = {
        Type = "simple";
        ExecStart = common.mkExecStart cfg configFile;
        ExecReload = common.mkExecReload;
        Restart = "on-failure";
        RestartSec = 5;
        User = cfg.user;
        Group = cfg.group;
        PermissionsStartOnly = true;
      };
    };
  };
}
