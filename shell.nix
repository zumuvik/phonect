{ pkgs ? import <nixpkgs> {
    config = {
      allowUnfree = true;
      android_sdk.accept_license = true;
    };
  }
}:

(pkgs.buildFHSEnv {
  name = "phonect-android-fhs";
  targetPkgs = pkgs: with pkgs; [
    (jdk17.override { enableJavaFX = false; })
    gradle
    unzip
    patchelf
    curl
    bash
    coreutils
    findutils
    gnugrep
    gnutar
    gzip
    which
  ];
  multiPkgs = pkgs: with pkgs; [
    zlib
    libgcc
    glibc
    stdenv.cc.cc
  ];
  runScript = "bash";
}).env
