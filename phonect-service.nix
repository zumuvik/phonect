# phonect-service.nix — NixOS module for the phonect unlock daemon (user service).
#
# Add this to your NixOS configuration:
#
#   imports = [ ./path/to/phonect-service.nix ];
#
#   services.phonect = {
#     enable = true;
#   };
#
# Then as the target user:
#   phonect init-config          # create ~/.config/phonect/config.toml
#   (edit ~/.config/phonect/config.toml with your mobile IP and key paths)
#   phonect gen-keys             # optional: generate PC key pair
#
# The user service will start automatically on login and listen for
# resume-from-sleep events via D-Bus (logind PrepareForSleep on the
# *system* bus — accessible from user services).

{ config, lib, pkgs, ... }:

let
  cfg = config.services.phonect;

  phonectSrc = lib.cleanSourceWith {
    src = lib.cleanSource ./.;
    name = "phonect-source";
  };

  phonectPackage = pkgs.python3.pkgs.buildPythonPackage rec {
    pname = "phonect";
    version = "0.2.3";
    src = phonectSrc;
    pyproject = true;
    buildInputs = [ pkgs.python3.pkgs.setuptools ];
    propagatedBuildInputs = with pkgs.python3.pkgs; [
      cryptography
      dbus-next
      textual        # TUI (required — always included)
      qrcode         # TUI QR-code rendering
    ];
    doCheck = false;
  };

in {
  options.services.phonect = {
    enable = lib.mkEnableOption "phonect P2P biometric unlock daemon";

    package = lib.mkOption {
      type = lib.types.package;
      default = phonectPackage;
      defaultText = lib.literalExpression "phonect package with all extras";
      description = "The phonect Python package derivation.";
    };
  };

  config = lib.mkIf cfg.enable {
    # ── Make the phonect CLI available in PATH ──────────────────────────
    environment.systemPackages = [ cfg.package ];

    # ── User service (runs on login, not as root) ───────────────────────
    systemd.user.services.phonect = {
      description = "phonect P2P Biometric Laptop Unlock Daemon";
      after = [
        "network.target"
        "suspend.target"
        "hibernate.target"
        "hybrid-sleep.target"
      ];
      wantedBy = [ "default.target" ];
      partOf = [
        "suspend.target"
        "hibernate.target"
        "hybrid-sleep.target"
      ];
      before = [ "sleep.target" ];

      serviceConfig = {
        Type = "simple";
        # No --config flag — daemon reads ~/.config/phonect/config.toml by default
        ExecStart = "${cfg.package}/bin/phonect daemon";
        Restart = "on-failure";
        RestartSec = 5;

        # Lightweight hardening (compatible with user services)
        NoNewPrivileges = true;
        PrivateTmp = true;
        RestrictNamespaces = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [ "@system-service" ];
      };
    };
  };
}
