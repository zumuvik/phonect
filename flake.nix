{
  description = "phonect Nix package and module checks";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      lib = nixpkgs.lib;
      package = pkgs.callPackage ./package.nix { };
      nixos = lib.nixosSystem {
        inherit system;
        modules = [
          ./phonect-service.nix
          {
            system.stateVersion = "25.05";
            users.users.testuser.isNormalUser = true;
            services.phonect = {
              enable = true;
              user = "testuser";
              settings = {
                keys = {
                  public_key = "/etc/phonect/trusted_device.pub";
                  private_key = "/etc/phonect/pc_private.pem";
                };
                device = {
                  pc_name = "nix-ci-laptop";
                  unlock_on_start = false;
                };
                daemon = {
                  listen_host = "0.0.0.0";
                  listen_port = 9876;
                  poll_interval = 0.3;
                  poll_timeout = 15.0;
                };
                logging.level = "INFO";
              };
            };
          }
        ];
      };
      moduleConfig = nixos.config;
      configSource = moduleConfig.environment.etc."phonect/config.toml".source;
      commandNixos = lib.nixosSystem {
        inherit system;
        modules = [
          ./phonect-service.nix
          {
            system.stateVersion = "25.05";
            users.users.testuser.isNormalUser = true;
            services.phonect = {
              enable = true;
              user = "testuser";
              settings.daemon = {
                unlock_backend = "command";
                unlock_command = [ "${pkgs.coreutils}/bin/true" "space arg" "quote\"arg" "back\\slash" ];
              };
            };
          }
        ];
      };
      commandConfigSource = commandNixos.config.environment.etc."phonect/config.toml".source;
      invalidCommandEmpty = lib.nixosSystem {
        inherit system;
        modules = [ ./phonect-service.nix {
          system.stateVersion = "25.05";
          users.users.testuser.isNormalUser = true;
          services.phonect.enable = true;
          services.phonect.user = "testuser";
          services.phonect.settings.daemon = { unlock_backend = "command"; unlock_command = [ ]; };
        } ];
      };
      invalidCommandBlank = lib.nixosSystem {
        inherit system;
        modules = [ ./phonect-service.nix {
          system.stateVersion = "25.05";
          users.users.testuser.isNormalUser = true;
          services.phonect.enable = true;
          services.phonect.user = "testuser";
          services.phonect.settings.daemon = { unlock_backend = "command"; unlock_command = [ "   " ]; };
        } ];
      };
      invalidLoginctlArgv = lib.nixosSystem {
        inherit system;
        modules = [ ./phonect-service.nix {
          system.stateVersion = "25.05";
          users.users.testuser.isNormalUser = true;
          services.phonect.enable = true;
          services.phonect.user = "testuser";
          services.phonect.settings.daemon = { unlock_backend = "loginctl"; unlock_command = [ "/bin/true" ]; };
        } ];
      };
      invalidMissingUser = lib.nixosSystem {
        inherit system;
        modules = [ ./phonect-service.nix {
          system.stateVersion = "25.05";
          services.phonect.enable = true;
        } ];
      };
      invalidUnknownUser = lib.nixosSystem {
        inherit system;
        modules = [ ./phonect-service.nix {
          system.stateVersion = "25.05";
          users.users.testuser.isNormalUser = true;
          services.phonect = { enable = true; user = "unknown"; };
        } ];
      };
      invalidNonNormalUser = lib.nixosSystem {
        inherit system;
        modules = [ ./phonect-service.nix {
          system.stateVersion = "25.05";
          users.users.testuser.isNormalUser = false;
          services.phonect = { enable = true; user = "testuser"; };
        } ];
      };
      invalidCommandEmptyEval = builtins.tryEval invalidCommandEmpty.config.system.build.toplevel.drvPath;
      invalidCommandBlankEval = builtins.tryEval invalidCommandBlank.config.system.build.toplevel.drvPath;
      invalidLoginctlArgvEval = builtins.tryEval invalidLoginctlArgv.config.system.build.toplevel.drvPath;
      invalidMissingUserEval = builtins.tryEval invalidMissingUser.config.system.build.toplevel.drvPath;
      invalidUnknownUserEval = builtins.tryEval invalidUnknownUser.config.system.build.toplevel.drvPath;
      invalidNonNormalUserEval = builtins.tryEval invalidNonNormalUser.config.system.build.toplevel.drvPath;
      testPython = pkgs.python3.withPackages (ps: [
        package
        ps.pytest
        ps.pytest-asyncio
      ]);
    in
    {
      packages.${system}.default = package;
      nixosModules.default = import ./phonect-service.nix;

      checks.${system} = {
        package = package;

        module = assert moduleConfig.services.phonect.package.drvPath == package.drvPath;
          assert moduleConfig.systemd.user.services.phonect.serviceConfig.ExecStart
            == "${package}/bin/phonect daemon --config /etc/phonect/config.toml";
          assert moduleConfig.systemd.user.services.phonect.unitConfig.ConditionUser == "testuser";
          assert lib.elem package moduleConfig.environment.systemPackages;
          assert moduleConfig.networking.firewall.allowedTCPPorts == [ 9876 ];
          assert moduleConfig.networking.firewall.allowedUDPPorts == [ 9875 ];
          pkgs.runCommand "phonect-module-evaluation" { inherit configSource; } ''
            test -f "$configSource"
            grep -Fx 'public_key = "/etc/phonect/trusted_device.pub"' "$configSource"
            grep -Fx 'private_key = "/etc/phonect/pc_private.pem"' "$configSource"
            grep -Fx 'pc_name = "nix-ci-laptop"' "$configSource"
            grep -Fx 'unlock_on_start = false' "$configSource"
            grep -Fx 'listen_host = "0.0.0.0"' "$configSource"
            grep -Fx 'listen_port = 9876' "$configSource"
            grep -Fx 'poll_interval = 0.300000' "$configSource"
            grep -Fx 'poll_timeout = 15.000000' "$configSource"
            grep -Fx 'unlock_backend = "loginctl"' "$configSource"
            grep -Fx 'unlock_command = []' "$configSource"
            grep -Fx 'level = "INFO"' "$configSource"
            touch "$out"
          '';

        command-module = assert !invalidCommandEmptyEval.success;
          assert !invalidCommandBlankEval.success;
          assert !invalidLoginctlArgvEval.success;
          assert !invalidMissingUserEval.success;
          assert !invalidUnknownUserEval.success;
          assert !invalidNonNormalUserEval.success;
          pkgs.runCommand "phonect-command-module-evaluation" {
            inherit commandConfigSource;
            expectedExecutable = "${pkgs.coreutils}/bin/true";
            nativeBuildInputs = [ package ];
          } ''
            test -f "$commandConfigSource"
            python - "$commandConfigSource" "$expectedExecutable" <<'PY'
            import sys
            from phonect.config import load_config

            config = load_config(__import__("pathlib").Path(sys.argv[1]))
            assert config.unlock_backend == "command"
            assert config.unlock_command == [sys.argv[2], "space arg", 'quote"arg', "back\\slash"]
            PY
            touch "$out"
          '';

        pytest = pkgs.runCommand "phonect-pytest" {
          nativeBuildInputs = [ testPython ];
        } ''
          mkdir source
          cp -r ${./tests} source/tests
          cp ${./pyproject.toml} source/pyproject.toml
          chmod -R u+w source
          cd source
          pytest tests/ -v --tb=short
          touch "$out"
        '';

        cli = pkgs.runCommand "phonect-cli" {
          nativeBuildInputs = [ package ];
        } ''
          phonect --help > help.txt
          grep -Eq '^[[:space:]]+daemon[[:space:]]' help.txt
          grep -Eq '^[[:space:]]+pair[[:space:]]' help.txt
          ! grep -Eq '^[[:space:]]+tui[[:space:]]' help.txt
          phonect pair --config config.toml
          touch "$out"
        '';
      };
    };
}
