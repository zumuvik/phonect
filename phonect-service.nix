# phonect-service.nix — NixOS module for the phonect unlock daemon.
#
# Add this to your NixOS configuration:
#
#   imports = [ ./path/to/phonect-service.nix ];
#
#   services.phonect = {
#     enable = true;
#     user = "zumuvik";
#     mobileIp = "192.168.1.100";
#     mobilePort = 9876;
#     publicKey = "/home/zumuvik/.config/phonect/trusted_device.pub";
#   };
#
# Or use the package directly:
#
#   systemd.user.services.phonect = {
#     # see the service definition below
#   };

{ config, lib, pkgs, ... }:

let
  cfg = config.services.phonect;

  phonectSrc = lib.cleanSourceWith {
    src = lib.cleanSource ./.;
    name = "phonect-source";
  };

  phonectPackage = pkgs.python3.pkgs.buildPythonPackage rec {
    pname = "phonect";
    version = "0.1.0";
    src = phonectSrc;
    pyproject = true;
    buildInputs = [ pkgs.python3.pkgs.setuptools ];
    propagatedBuildInputs = with pkgs.python3.pkgs; [
      cryptography
      dbus-next
    ];
    doCheck = false;
  };

  configFile = pkgs.writeText "phonect-config.toml" ''
    [device]
    mobile_ip = "${cfg.mobileIp}"
    mobile_port = ${toString cfg.mobilePort}

    [keys]
    public_key = "${cfg.publicKey}"

    [daemon]
    poll_interval_ms = ${toString cfg.pollIntervalMs}
    poll_timeout_seconds = ${toString cfg.pollTimeoutSeconds}
    unlock_on_start = ${lib.boolToString cfg.unlockOnStart}

    [logging]
    level = "${cfg.logLevel}"
  '';

in {
  options.services.phonect = {
    enable = lib.mkEnableOption "phonect P2P biometric unlock daemon";

    user = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "zumuvik";
      description = ''
        Unprivileged user to run the daemon as.
        Must own the login session so that ``loginctl unlock-session`` works.
        If empty, you must set ``systemd.services.phonect.serviceConfig.User``
        yourself.
      '';
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "phonect";
      description = "Group for the phonect daemon.";
    };

    mobileIp = lib.mkOption {
      type = lib.types.str;
      default = "";
      example = "192.168.1.100";
      description = "Static IP address of the Android phone on the LAN.";
    };

    mobilePort = lib.mkOption {
      type = lib.types.port;
      default = 9876;
      description = "TCP port the phone's listener is bound to.";
    };

    publicKey = lib.mkOption {
      type = lib.types.path;
      default = "/var/lib/phonect/trusted_device.pub";
      description = "Path to the trusted mobile device RSA public key (PEM).";
    };

    pollIntervalMs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 200;
      description = "Interval (ms) between TCP connection attempts during wakeup polling.";
    };

    pollTimeoutSeconds = lib.mkOption {
      type = lib.types.ints.positive;
      default = 10;
      description = "Maximum time (seconds) to keep polling before giving up.";
    };

    unlockOnStart = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Run one authentication cycle when the daemon starts.";
    };

    logLevel = lib.mkOption {
      type = lib.types.enum [ "DEBUG" "INFO" "WARNING" "ERROR" ];
      default = "INFO";
      description = "Daemon logging verbosity.";
    };

    package = lib.mkOption {
      type = lib.types.package;
      default = phonectPackage;
      description = "The phonect Python package derivation.";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── Group & user ──────────────────────────────────────────────────────
    users.groups.phonect = lib.mkIf (cfg.group == "phonect") {};

    users.users.phonect = lib.mkIf (cfg.user == "" && cfg.group == "phonect") {
      description = "phonect daemon user";
      group = cfg.group;
      isSystemUser = true;
      home = "/var/lib/phonect";
      createHome = true;
    };

    # ── Polkit: allow the phonect user to unlock login sessions ──────────
    security.polkit.extraPolicies = ''
      polkit.addRule(function(action, subject) {
        if (action.id == "org.freedesktop.login1.unlock-session" ||
            action.id == "org.freedesktop.login1.unlock-sessions") {
          if (subject.user == "${cfg.user}") {
            return polkit.Result.YES;
          }
        }
      });
    '';

    # ── Ensure the public key directory exists ──────────────────────────
    systemd.tmpfiles.rules = [
      "d /var/lib/phonect 0750 ${cfg.user} ${cfg.group} -"
    ];

    # ── Main service ────────────────────────────────────────────────────
    systemd.services.phonect = {
      description = "phonect P2P Biometric Laptop Unlock Daemon";
      after = [ "network.target" "suspend.target" "hibernate.target" "hybrid-sleep.target" ];
      wantedBy = [ "multi-user.target" ];
      partOf = [ "suspend.target" "hibernate.target" "hybrid-sleep.target" ];
      before = [ "sleep.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/phonect daemon --config ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;

        # ── Run as unprivileged user (never root) ─────────────────────
        User = lib.mkIf (cfg.user != "") cfg.user;
        Group = cfg.group;

        # ── D-Bus: system bus for logind signals ──────────────────────
        BusName = "";

        # ── Security hardening ────────────────────────────────────────
        CapabilityBoundingSet = [ "" ];
        DevicePolicy = "closed";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
        RestrictNamespaces = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];

        # Allow outbound TCP to the phone and inbound logind D-Bus
        IPAddressAllow = [
          "127.0.0.0/8"
          "10.0.0.0/8"
          "172.16.0.0/12"
          "192.168.0.0/16"
          "169.254.0.0/16"
        ];
        IPAddressDeny = [ "0.0.0.0/0" ];

        # Read-write for config/key updates
        ReadWritePaths = [
          "/var/lib/phonect"
          (builtins.toString cfg.publicKey)
        ];
      };
    };
  };
}
