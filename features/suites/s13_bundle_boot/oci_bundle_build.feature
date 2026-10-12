@live
Feature: Package an OCI image and verify the signed archive

  This workflow acquires real OCI and authenticated runtime assets and
  materializes a rootfs before signing. Run it only on an explicitly opted-in
  live host, never as a hermetic CLI parsing check.
  Both the output directory and HOME/MVM_HOME are temporary. The freshly
  generated publisher key is enrolled explicitly; no ambient trust is reused.
  Archive boot is a separate workflow and is not claimed by this scenario.

  Scenario: Build and verify an Alpine OCI package with explicit publisher trust
    Given an isolated mvm home
    And a scratch working directory
    When I run mvmctl in the scratch directory with "bundle build --image docker.io/library/alpine:3.20 --out alpine.mvmpkg --debug-out alpine.bundle.json"
    Then the command exits with code 0
    And the output contains "OCI digest: sha256:"
    And the output contains "Bundle SHA-256:"
    And the scratch directory contains file "alpine.mvmpkg"
    And the scratch directory contains file "alpine.bundle.json"
    When I run mvmctl in the scratch directory with "bundle fetch ./alpine.mvmpkg"
    Then the command exits with code 1
    And the failure names the untrusted publisher key
    When I trust the isolated home's bundle signer
    Then the command exits with code 0
    When I run mvmctl in the scratch directory with "bundle fetch ./alpine.mvmpkg"
    Then the command exits with code 0
