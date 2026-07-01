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

  pythonEnv = pkgs.python3.withPackages (ps: with ps; [
    cryptography
    dbus-next
    # phonect itself — either from nixpkgs or a local source
  ]);

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
      default = "root";
      description = "User to run the daemon as (must own the session to unlock).";
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
    # Ensure the public key exists before the service starts
    systemd.tmpfiles.rules = [
      "d /var/lib/phonect 0755 ${cfg.user} root -"
    ];

    systemd.services.phonect = {
      description = "phonect P2P Biometric Laptop Unlock Daemon";
      after = [ "network.target" "suspend.target" "hibernate.target" "hybrid-sleep.target" ];
      wantedBy = [ "multi-user.target" ];

      # Bind to the resume-from-sleep path
      partOf = [ "suspend.target" "hibernate.target" "hybrid-sleep.target" ];
      before = [ "sleep.target" ];

      serviceConfig = {
        Type = "simple";
        ExecStart = "${cfg.package}/bin/phonect daemon --config ${configFile}";
        Restart = "on-failure";
        RestartSec = 5;

        # Run as the target user so loginctl works for their session
        User = cfg.user;

        # Security hardening
        CapabilityBoundingSet = [ "" ];
        DevicePolicy = "closed";
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectSystem = "strict";
        ProtectHome = "read-only";
        ReadWritePaths = [
          # Config directory (public key can be updated at runtime)
          "/var/lib/phonect"
        ];

        # D-Bus access (system bus for logind signals)
        BusName = "";

        # Allow talking to systemd-logind over D-Bus
        SystemCallFilter = [ "@system-service" ];
      };

      unitConfig = {
        # Stop the daemon cleanly before suspend
        StopWhenUnneeded = false;
      };
    };

    # Also expose the public key path as an environment hint
    environment.etc = lib.mkIf (cfg.publicKey != "") {
      "phonect/public_key".source = cfg.publicKey;
    };
  };
}
