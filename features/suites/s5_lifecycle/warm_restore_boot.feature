Feature: Warm-restore positive boot path

  A running VM's vm_full checkpoint can be warm-restored into a fresh child
  VM that boots and reports Running.

  @live @firecracker @wip
  Scenario: a vm_full checkpoint warm-restores into a running child VM
    # Blocked: `machine checkpoint create --class vm-full` currently reports
    # Firecracker snapshot capability unsupported on this host, and the live
    # warm-pool test rootfs/kernel pair panics at init. Enable this scenario
    # once FC warm-restore is fully wired and a compatible live fixture is
    # available.
    Given a scenario awaiting its step implementation
