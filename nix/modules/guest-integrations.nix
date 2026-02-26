# NixOS module: declare integration health checks for the mvm guest agent.
#
# Any workload can register itself by defining an integration entry.
# Each entry generates a JSON drop-in file in /etc/mvm/integrations.d/
# that the guest agent scans at startup.
#
# Example usage in a role module:
#
#   imports = [ ../../nix/modules/guest-integrations.nix ];
#
#   services.mvm-integrations = {
#     enable = true;
#     integrations.my-service = {
#       healthCmd = "systemctl is-active my-service.service";
#       healthIntervalSecs = 15;
#       healthTimeoutSecs = 5;
#     };
#   };

{ lib, config, ... }:

let
  cfg = config.services.mvm-integrations;

  integrationJson = name: entry: builtins.toJSON ({
    inherit name;
    health_cmd = entry.healthCmd;
    health_interval_secs = entry.healthIntervalSecs;
    health_timeout_secs = entry.healthTimeoutSecs;
  } // lib.optionalAttrs (entry.checkpointCmd != null) {
    checkpoint_cmd = entry.checkpointCmd;
  } // lib.optionalAttrs (entry.restoreCmd != null) {
    restore_cmd = entry.restoreCmd;
  } // lib.optionalAttrs entry.critical {
    critical = true;
  });

  integrationSubmodule = {
    options = {
      healthCmd = lib.mkOption {
        type = lib.types.str;
        description = "Command to run for health checks. Exit 0 = healthy.";
      };
      healthIntervalSecs = lib.mkOption {
        type = lib.types.int;
        default = 30;
        description = "Seconds between health checks.";
      };
      healthTimeoutSecs = lib.mkOption {
        type = lib.types.int;
        default = 10;
        description = "Timeout in seconds for each health check.";
      };
      checkpointCmd = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Command to checkpoint state before sleep.";
      };
      restoreCmd = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Command to restore state after wake.";
      };
      critical = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "If true, sleep is blocked until checkpoint succeeds.";
      };
    };
  };
in
{
  options.services.mvm-integrations = {
    enable = lib.mkEnableOption "mvm integration health check registration";

    integrations = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule integrationSubmodule);
      default = {};
      description = "Integration health checks to register with the guest agent.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc = lib.mapAttrs' (name: entry:
      lib.nameValuePair "mvm/integrations.d/${name}.json" {
        text = integrationJson name entry;
      }
    ) cfg.integrations;
  };
}
