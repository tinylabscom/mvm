Feature: a committed project survives staged edits without widening admission

  @live @firecracker @policy_generation
  Scenario: the first generation keeps the built source and its CPU ceiling
    Given an isolated built-policy project with a one-CPU ceiling
    When I build and activate the isolated policy-generation project
    Then the command exits with code 0
    When I widen the staged policy and manifest
    And I request two CPUs from the committed manifest
    Then the command exits with code 1
    And the error output contains "policy's max_cpus of 1"
    When I run the committed entrypoint with one CPU
    Then the command exits with code 7
    When I run the committed project flake with one CPU
    Then the command exits with code 7

  @live @firecracker @policy_generation
  Scenario: an entrypoint cannot drop its committed CPU-share ceiling
    Given an isolated built-policy project with a CPU-share ceiling
    When I build and activate the isolated policy-generation project
    Then the command exits with code 0
    When I run the committed entrypoint with one CPU
    Then the command exits with code 1
    And the error output contains "cannot yet carry policy shares or a CPU-share ceiling"
