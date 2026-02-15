{ pkgs, ... }:

pkgs.stdenv.mkDerivation {
  name = "rootfs";
  src = ./.;
  installPhase = ''
    mkdir -p $out
    echo "hello from template rootfs" > $out/README
  '';
}
