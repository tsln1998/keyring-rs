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
  configFile = common.mkConfigFile "keyring-rs-user" cfg;
  pathParent = common.mkParent cfg;
in
{
  options.services.keyring-rs = common.mkBaseOptions {
    defaultPathExample = "/home/alice/.local/state/keyring-rs/keyring.sock";
  };

  config = lib.mkIf cfg.enable {
    assertions = common.mkAssertions "services.keyring-rs" cfg ++ [
      {
        assertion = pkgs.stdenv.isLinux;
        message = "services.keyring-rs requires Linux systemd user services.";
      }
    ];

    systemd.user.services.keyring-rs = lib.mkIf (configFile != null) {
      Unit = {
        Description = "keyring-rs SSH agent service";
        After = [ "network.target" ];
      };

      Service = {
        Type = "simple";
        ExecStart = common.mkExecStart cfg configFile;
        ExecReload = common.mkExecReload;
        Restart = "on-failure";
        RestartSec = 5;
      }
      // {
        # The user service can create the socket parent directly because it runs with the same
        # account that will later own the socket file.
        ExecStartPre = "${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArg pathParent}";
      };

      Install = {
        WantedBy = [ "default.target" ];
      };
    };
  };
}
