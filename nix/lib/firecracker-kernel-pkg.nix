# Standalone Firecracker kernel package.
#
# Returns a kernel derivation directly (not a NixOS module), so it can
# be used both inside mkGuest (via the NixOS module wrapper) and inside
# mkMinimalGuest (no NixOS evaluation).
#
# The kernel is built from Firecracker's upstream aarch64 guest config
# with patches for PCI and crypto (systemd AF_ALG).

{ pkgs }:

let
  baseConfig = ../kernel-configs/firecracker-aarch64.config;

  # Patch the upstream config with options NixOS/systemd and mvm require.
  configFile = pkgs.runCommand "firecracker-nixos-config" {} ''
    cp ${baseConfig} $out
    chmod u+w $out

    # Enable PCI — mvm starts Firecracker with --enable-pci, which
    # presents virtio devices via PCI instead of MMIO.
    sed -i 's/# CONFIG_PCI is not set/CONFIG_PCI=y/' $out
    cat >> $out <<'PCI_OPTS'
    CONFIG_PCI_HOST_GENERIC=y
    CONFIG_VIRTIO_PCI=y
    CONFIG_VIRTIO_PCI_LEGACY=y
    PCI_OPTS

    # Enable crypto user API — systemd needs AF_ALG for hashing.
    sed -i 's/# CONFIG_CRYPTO_USER is not set/CONFIG_CRYPTO_USER=y/' $out
    sed -i 's/# CONFIG_CRYPTO_USER_API_HASH is not set/CONFIG_CRYPTO_USER_API_HASH=y/' $out
    sed -i 's/# CONFIG_CRYPTO_USER_API_SKCIPHER is not set/CONFIG_CRYPTO_USER_API_SKCIPHER=y/' $out
    sed -i 's/# CONFIG_CRYPTO_USER_API_RNG is not set/CONFIG_CRYPTO_USER_API_RNG=y/' $out
    sed -i 's/# CONFIG_CRYPTO_USER_API_AEAD is not set/CONFIG_CRYPTO_USER_API_AEAD=y/' $out
  '';

in
pkgs.linuxManualConfig {
  inherit (pkgs.linux_6_1) src version modDirVersion;
  configfile = configFile;
  allowImportFromDerivation = true;
}
