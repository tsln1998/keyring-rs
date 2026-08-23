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
    defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
  };
  cfg = config.services.keyring-rs;
  configFile = common.mkConfigFile "keyring-rs-user" cfg;
  pathParent = common.mkParent cfg;
  inherit (pkgs.stdenv.hostPlatform) isDarwin isLinux;
  launchdStartScript = pkgs.writeShellScript "keyring-rs-start" ''
    ${pkgs.coreutils}/bin/mkdir -p ${lib.escapeShellArg pathParent}
    exec ${common.mkExecStart cfg configFile}
  '';
in
{
  options.services.keyring-rs = common.mkBaseOptions {
    defaultPathExample = "/home/alice/.local/state/keyring-rs/keyring.sock";
  };

  config = lib.mkIf cfg.enable (
    lib.mkMerge [
      {
        assertions = common.mkAssertions "services.keyring-rs" cfg ++ [
          {
            assertion = isLinux || isDarwin;
            message = "services.keyring-rs supports only Linux systemd and macOS launchd user services.";
          }
        ];
      }

      (lib.mkIf (isLinux && configFile != null) {
        systemd.user.services.keyring-rs = {
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
      })

      (lib.mkIf (isDarwin && configFile != null) {
        launchd.agents.keyring-rs = {
          enable = true;
          config = {
            ProgramArguments = [ "${launchdStartScript}" ];
            KeepAlive = {
              Crashed = true;
              SuccessfulExit = false;
            };
            ProcessType = "Background";
            RunAtLoad = true;
            ThrottleInterval = 5;
          };
        };
      })
    ]
  );
}
