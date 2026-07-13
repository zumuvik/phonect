{ lib, python3Packages }:

python3Packages.buildPythonPackage {
  pname = "phonect";
  version = "0.4.7.1";
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./pyproject.toml
      ./LICENSE
      ./src
    ];
  };
  pyproject = true;

  build-system = [ python3Packages.setuptools ];
  dependencies = with python3Packages; [
    cryptography
    dbus-next
  ];

  doCheck = false;
}
