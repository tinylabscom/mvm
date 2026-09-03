Feature: Encrypted block volume lifecycle and attachment

  Managed volumes are authenticated ciphertext at rest, become live block
  attachments only after explicit unlock and admission, and fail closed at the
  path, plan, and backend boundaries.

  Scenario: an immutable snapshot restores prior encrypted volume bytes
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine volume create work --size 16M"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock work"
    Then the command exits with code 0
    When I write byte 65 to the end of managed volume "work"
    And I run mvmctl in the isolated mvm home with "machine volume lock work"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume snapshot work before"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock work"
    Then the command exits with code 0
    When I write byte 66 to the end of managed volume "work"
    And I run mvmctl in the isolated mvm home with "machine volume lock work"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume restore work before"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock work"
    Then the command exits with code 0
    And managed volume "work" ends with byte 65

  Scenario: a locked managed volume cannot be registered for launch
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine volume create locked --size 16M"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume mount bdd-locked --volume locked --guest /data"
    Then the command exits with code 1
    And the error output contains "is locked"

  Scenario: a guest mount path cannot traverse into a denied system prefix
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine volume create guarded --size 16M"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock guarded"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume mount bdd-guarded --volume guarded --guest /data/../../etc"
    Then the command exits with code 1
    And the error output contains "rejected by policy"

  Scenario: a volume absent from the signed plan is refused
    Given a signed execution plan with no admitted volume shares
    Then the unadmitted volume attachment is refused

  Scenario: a backend reports unsupported block attachment honestly
    When I ask the Docker backend to attach a block volume
    Then the backend refuses the unsupported block volume before boot

  Scenario: remote volume operations require explicit authenticated configuration
    When I run remote volume catalog without gateway configuration
    Then the command exits with code 1
    And the error output contains "MVM_GATEWAY_URL is required"

  @live
  Scenario: a failed persistent start releases its volume attachment lease
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-failed-volume --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume create work --size 16M"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock work"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume mount bdd-failed-volume --volume work --guest /data --rw"
    Then the command exits with code 0
    When I attempt a direct start of machine "bdd-failed-volume" with backend "not-a-backend"
    Then the command exits with code 1
    And the local volume attachment lease catalog is empty

  @live @firecracker @workload_kernel @guest_bins
  Scenario: a writable block volume persists guest bytes across restart
    Given an isolated mvm home
    And a cached live workload kernel
    When I run mvmctl in the isolated mvm home with "machine create bdd-persistent-volume --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume create work --size 16M"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock work"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume mount bdd-persistent-volume --volume work --guest /data --rw"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-persistent-volume --hypervisor firecracker"
    Then the command exits with code 0
    When I execute shell command "printf volume-persisted > /data/marker" in machine "bdd-persistent-volume"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-persistent-volume --yes"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-persistent-volume --hypervisor firecracker"
    Then the command exits with code 0
    When I execute shell command "cat /data/marker" in machine "bdd-persistent-volume"
    Then the command exits with code 0
    And the output contains "volume-persisted"
    When I run mvmctl in the isolated mvm home with "machine stop bdd-persistent-volume --yes"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume lock work"
    Then the command exits with code 0

  @live @firecracker @workload_kernel @guest_bins
  Scenario: a read-only block attachment refuses a guest write
    Given an isolated mvm home
    And a cached live workload kernel
    When I run mvmctl in the isolated mvm home with "machine create bdd-readonly-volume --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume create work --size 16M"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock work"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume mount bdd-readonly-volume --volume work --guest /data"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-readonly-volume --hypervisor firecracker"
    Then the command exits with code 0
    When I execute shell command "touch /data/refused" in machine "bdd-readonly-volume"
    Then the command exits with code 1
    And the error output contains "Read-only file system"
    When I run mvmctl in the isolated mvm home with "machine stop bdd-readonly-volume --yes"
    Then the command exits with code 0

  # A *directory*-kind registration, not a managed block volume. Every live
  # scenario above registers `machine volume create` output, which resolves to
  # `VmVolumeKind::Disk`. `--host <dir>` takes the other arm —
  # `LocalVolumeKind::Directory` → an unmaterialized `VmVolumeKind::DirShare`.
  #
  # Measured for the *transient* path already: the registration is silently
  # ignored, the mount point is absent, and the boot succeeds. That answer does
  # not generalise, because `machine start` resolves through
  # `merge_registered_volumes_for_launch` rather than dropping the volume.
  # The persistent path does consume the registration. Because Firecracker has
  # no directory-share device, it must refuse before boot rather than silently
  # discard the grant or start a guest without the registered data.
  @live @firecracker @workload_kernel @guest_bins
  Scenario: a directory-kind registration is refused before persistent boot
    Given an isolated mvm home
    And a cached live workload kernel
    When I run mvmctl in the isolated mvm home with "machine create bdd-dir-volume --image alpine"
    Then the command exits with code 0
    When I register host directory volume "dirvol" at "/data/dirvol" for machine "bdd-dir-volume"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-dir-volume --hypervisor firecracker"
    Then the command exits with code 1
    And the error output contains "live host-directory share can't be expressed"
