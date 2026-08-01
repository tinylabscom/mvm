Feature: Sealed OCI boots skip the legacy initrd when the universal initramfs is cached

  A sealed OCI boot requires the runtime overlay, and its boot path
  historically resolved the legacy per-rootfs verity initrd up front — a
  resolution that can cross-compile every guest binary or fail the boot
  outright.  When the universal initramfs is already warm in the cache it
  replaces that initrd later in the boot, so resolving it is dead work: the
  effective initrd is whatever already sits on disk next to the rootfs, and
  the legacy build-or-fail ladder must not run.  On a cold universal cache
  the legacy initrd is the real guest init, so the ladder must still run.

  Scenario: A warm universal initramfs skips the legacy initrd resolution
    Given an isolated mvm home with a warm universal initramfs cache
    And a sealed OCI rootfs with no sibling initrd
    When the persistent OCI effective initrd is resolved for a required-overlay boot
    Then the effective initrd is empty

  Scenario: A cold universal cache still resolves the legacy verity initrd
    Given an isolated mvm home with a cold universal cache but a cached legacy verity initrd
    And a sealed OCI rootfs with no sibling initrd
    When the persistent OCI effective initrd is resolved for a required-overlay boot
    Then the effective initrd is the cached legacy verity initrd
