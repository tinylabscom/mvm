Feature: Sealed OCI boots rely on the universal initramfs

  A sealed OCI boot requires the runtime overlay. The legacy per-rootfs
  verity initrd is no longer supported; the universal initramfs attach step
  later in the boot owns the initramfs. The effective initrd resolved up
  front is therefore always empty for sealed OCI boots.

  Scenario: A sealed OCI boot resolves no up-front initrd
    Given an isolated mvm home with a warm universal initramfs cache
    And a sealed OCI rootfs with no sibling initrd
    When the persistent OCI effective initrd is resolved for a required-overlay boot
    Then the effective initrd is empty
