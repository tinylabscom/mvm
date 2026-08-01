Feature: Deterministic cargo initramfs

  The universal initramfs is a deterministic cargo artifact, not a Nix
  build: the pinned guest-agent source is cross-compiled once and packed as
  exactly "/init" in an epoch-zero, stably-ordered cpio. Its attestability
  comes from the reproducible build plus the content hash — the same agent
  bytes must always produce the same cpio, and the installed artifact's
  sidecars must describe exactly the bytes the boot path loads.

  Scenario: The cpio build is byte-deterministic
    Given fixed guest-agent bytes for the initramfs build
    When I assemble the initramfs cpio twice from those bytes
    Then the two cpios are byte-identical
    And their content hashes match
    And the cpio layout is exactly "." and "./init"

  Scenario: The installed artifact carries the content-address sidecar contract
    Given fixed guest-agent bytes for the initramfs build
    When I assemble and install the initramfs artifact into a fresh cache
    Then the artifact's hash sidecar is the SHA-256 of the uncompressed cpio
    And the size sidecar is the compressed byte length
    And the VERSION sidecar is the workspace version
    And the artifact resolves through the initramfs resolver
