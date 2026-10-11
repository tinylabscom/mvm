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

  Scenario: the removed Docker backend refuses a volume-bearing launch before boot
    Given an isolated mvm home on encrypted backing storage
    When I run mvmctl in the isolated mvm home with "machine create bdd-docker-volume --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume create work --size 16M"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume unlock work"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine volume mount bdd-docker-volume --volume work --guest /data"
    Then the command exits with code 0
    When I attempt a direct start of machine "bdd-docker-volume" with backend "docker"
    Then the command exits with code 1
    And the error output contains "Docker backend has been removed"
    And the local volume attachment lease catalog is empty

  Scenario: remote volume operations require explicit authenticated configuration
    When I run remote volume catalog without gateway configuration
    Then the command exits with code 1
    And the error output contains "MVM_GATEWAY_URL is required"

  @live
  Scenario: a failed persistent start releases its volume attachment lease
    Given an isolated mvm home on encrypted backing storage
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

  @live @firecracker @workload_kernel
  Scenario: a writable block volume persists guest bytes across restart
    Given an isolated mvm home on encrypted backing storage
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

  @live @firecracker @workload_kernel
  Scenario: a read-only block attachment refuses a guest write
    Given an isolated mvm home on encrypted backing storage
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

  # `--host <dir>` is the ad-hoc arm. It used to register a live directory
  # share, which no workload backend can serve: `machine start` refused it at
  # boot ("a live host-directory share can't be expressed", measured on both
  # Firecracker and HVF) and `machine run` booted without the mount. The two
  # launch paths disagreed about the same registration.
  #
  # It now snapshots the directory into a cached ext4 image and registers that,
  # the same treatment `--mount HOST:/GUEST` gives a transient run. A start
  # fingerprints the source again and refreshes the registered image on change.
  Scenario: a host directory is registered as a snapshot image
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-dir-volume --image alpine"
    Then the command exits with code 0
    When I register host directory volume "dirvol" at "/data/dirvol" for machine "bdd-dir-volume"
    Then the command exits with code 0
    And the output contains ".ext4"

  Scenario: a missing registered host snapshot source refuses start
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-missing-dir-volume --image alpine"
    Then the command exits with code 0
    When I register host directory volume "missing-dirvol" at "/data/dirvol" for machine "bdd-missing-dir-volume"
    Then the command exits with code 0
    When I remove the source for host directory volume "missing-dirvol"
    And I attempt a direct start of machine "bdd-missing-dir-volume" with backend "not-a-backend"
    Then the command exits with code 1
    And the error output contains "does not exist"

  @live @firecracker @workload_kernel
  Scenario: restarting refreshes a registered host directory snapshot
    Given an isolated mvm home
    And a cached live workload kernel
    When I run mvmctl in the isolated mvm home with "machine create bdd-refresh-dir-volume --image alpine"
    Then the command exits with code 0
    When I register host directory volume "refresh-dirvol" at "/data/dirvol" for machine "bdd-refresh-dir-volume"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-refresh-dir-volume --hypervisor firecracker"
    Then the command exits with code 0
    When I execute shell command "cat /data/dirvol/marker" in machine "bdd-refresh-dir-volume"
    Then the command exits with code 0
    And the output contains "dir-volume-visible"
    When I run mvmctl in the isolated mvm home with "machine stop bdd-refresh-dir-volume --yes"
    Then the command exits with code 0
    When I replace the marker in host directory volume "refresh-dirvol" with "dir-volume-refreshed"
    And I run mvmctl in an isolated live home with "machine start bdd-refresh-dir-volume --hypervisor firecracker"
    Then the command exits with code 0
    When I execute shell command "cat /data/dirvol/marker" in machine "bdd-refresh-dir-volume"
    Then the command exits with code 0
    And the output contains "dir-volume-refreshed"
    When I run mvmctl in the isolated mvm home with "machine stop bdd-refresh-dir-volume --yes"
    Then the command exits with code 0

  @live @ci_live @ps11_live @firecracker @workload_kernel
  Scenario: an instruction-bearing writable host snapshot is effectively read-only
    Given an isolated mvm home
    And a cached live workload kernel
    When I run mvmctl in the isolated mvm home with "machine create bdd-instruction-ro --image alpine"
    Then the command exits with code 0
    When I register host directory volume "instruction-ro" read-write at "/data/work" for machine "bdd-instruction-ro"
    Then the command exits with code 0
    When I add an instruction file to host directory volume "instruction-ro"
    And I run mvmctl in an isolated live home with "machine start bdd-instruction-ro --hypervisor firecracker"
    Then the command exits with code 0
    When I execute shell command "touch /data/work/refused" in machine "bdd-instruction-ro"
    Then the command exits with code 1
    And the error output contains "Read-only file system"
    When I run mvmctl in the isolated mvm home with "machine stop bdd-instruction-ro --yes"
    Then the command exits with code 0

  # Reviewed workspace apply (PS-08): the registered snapshot is both the
  # baseline and the live image until a guest writes, so these scenarios
  # exercise the apply surface — refusal, prompting, and empty history —
  # without a live guest. The engine's write/undo/crash semantics are
  # covered by mvm-fs's workspace_apply tests against real ext4 images.
  Scenario: applying with no workspace volume names the remedy
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-apply-none --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine apply bdd-apply-none --yes"
    Then the command exits with code 1
    And the error output contains "no workspace volume"

  Scenario: an unchanged workspace has nothing to apply
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-apply-dry --image alpine"
    Then the command exits with code 0
    When I register host directory volume "applyvol" read-write at "/data/applyvol" for machine "bdd-apply-dry"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine apply bdd-apply-dry --yes"
    Then the command exits with code 0
    And the output contains "no changes"

  Scenario: undo with no apply history says so
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine create bdd-undo-none --image alpine"
    Then the command exits with code 0
    When I register host directory volume "undovol" read-write at "/data/undovol" for machine "bdd-undo-none"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine undo bdd-undo-none"
    Then the command exits with code 0
    And the output contains "nothing to undo"

  # The end of a foreground run on a named machine offers the guest's
  # workspace changes back through the same reviewed apply. The suite drives
  # mvmctl with captured stdio and no controlling terminal, so it reaches the
  # two branches that need none: the printed command, and `--apply`. The
  # terminal prompt is unit-tested against a scripted terminal. The entrypoint
  # script stands in for an agent: it deletes the seeded marker and writes a
  # file, giving the apply one removal and one write.
  @live @workload_kernel
  Scenario: a run that ends without a terminal applies nothing and names the command
    Given an isolated mvm home
    And a cached live workload kernel
    When I run mvmctl in the isolated mvm home with "machine create bdd-exit-pointer --image alpine"
    Then the command exits with code 0
    When I register host directory volume "exitptr" read-write at "/data/exitptr" for machine "bdd-exit-pointer"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-exit-pointer"
    Then the command exits with code 0
    When the entrypoint of machine "bdd-exit-pointer" runs attached with script "rm /data/exitptr/marker && echo agent-wrote > /data/exitptr/agent.txt" and flags ""
    Then the command exits with code 0
    And the output contains "nothing was applied"
    And the output contains "mvmctl machine apply bdd-exit-pointer"
    And host directory volume "exitptr" has file "marker" containing "dir-volume-visible"
    And host directory volume "exitptr" has no file "agent.txt"
    When I run mvmctl in the isolated mvm home with "machine stop bdd-exit-pointer --yes"
    Then the command exits with code 0

  @live @workload_kernel
  Scenario: a run that ends with --apply applies the workspace without asking
    Given an isolated mvm home
    And a cached live workload kernel
    When I run mvmctl in the isolated mvm home with "machine create bdd-exit-apply --image alpine"
    Then the command exits with code 0
    When I register host directory volume "exitapply" read-write at "/data/exitapply" for machine "bdd-exit-apply"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-exit-apply"
    Then the command exits with code 0
    When the entrypoint of machine "bdd-exit-apply" runs attached with script "rm /data/exitapply/marker && echo agent-wrote > /data/exitapply/agent.txt" and flags "--apply"
    Then the command exits with code 0
    And the output contains "applied 2 change(s)"
    And the output does not contain "Review and apply with"
    And host directory volume "exitapply" has file "agent.txt" containing "agent-wrote"
    And host directory volume "exitapply" has no file "marker"
    When I run mvmctl in the isolated mvm home with "machine stop bdd-exit-apply --yes"
    Then the command exits with code 0

  # Replay (PS-08): re-run recorded input from a checkpoint. The full
  # fork-boot-reexec flow needs a live VM; these scenarios pin the
  # fail-closed surface. Selection and the input journal itself are
  # unit-tested in mvm-cli.
  Scenario: replaying an unknown checkpoint names the error
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine replay ckpt-nope"
    Then the command exits with code 1
    And the error output contains "no checkpoint"

  Scenario: replay with a name for the restored VM still verifies the checkpoint first
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "machine replay ckpt-nope --as replayed-vm"
    Then the command exits with code 1
    And the error output contains "no checkpoint"
