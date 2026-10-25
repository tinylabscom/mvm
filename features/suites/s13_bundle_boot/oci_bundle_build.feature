@live
Feature: Package an OCI image and verify the signed archive

  This workflow acquires real OCI and authenticated runtime assets and
  materializes a rootfs before signing. Run it only on an explicitly opted-in
  live host, never as a hermetic CLI parsing check.
  Both the output directory and HOME/MVM_HOME are temporary. The freshly
  generated host key remains local authority; no publisher trust is enrolled.
  Archive boot is a separate workflow and is not claimed by this scenario.

  @runtime_candidate
  Scenario: Build and inspect an Alpine OCI package under local authority
    Given an isolated mvm home
    And a scratch working directory
    And the isolated mvm home is prepared for live launches
    When I run mvmctl in the scratch directory with "build docker.io/library/alpine:3.20 --from image --out alpine.mvmpkg --debug-out alpine.bundle.json"
    Then the command exits with code 0
    And the output contains "OCI digest: sha256:"
    And the output contains "Bundle SHA-256:"
    And the scratch directory contains file "alpine.mvmpkg"
    And the scratch directory contains file "alpine.bundle.json"
    When I run mvmctl in the scratch directory with "machine check-artifact ./alpine.mvmpkg"
    Then the command exits with code 0
    And the output contains "local build, signed by this host's key; not release-verified"
