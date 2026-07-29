Feature: Warm-restore positive boot path

  A running VM's vm_full checkpoint can be warm-restored into a fresh child
  VM that boots and reports Running.

  @live @firecracker
  Scenario: a vm_full checkpoint warm-restores into a running child VM
    When I run mvmctl in an isolated live home with "machine run -d --image alpine --name warm-parent"
    Then the command exits with code 0
    When I capture a vm_full checkpoint from warm-parent
    Then the command exits with code 0
    When I stop the parent VM warm-parent
    Then the command exits with code 0
    When I warm-restore the checkpoint into a child named warm-child
    Then the command exits with code 0
    And the child VM warm-child is running
