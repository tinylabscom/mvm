Feature: s13_bundle_boot verify-and-boot

  Conformance scenarios for MVM-SEC-25: a signed `.mvmpkg` named on
  `machine run` is verified against the publisher trust store before anything
  else happens, and only an archive that verifies is installed and booted.

  The refusals are hermetic. Each scenario seals a small bundle with a fixed
  test key, enrols that key in an isolated `MVM_HOME` (or does not, or files
  another key under its id), and runs the real `mvmctl` with `--dry-run`. The
  verifier is the one a boot runs, and a dry run stops before a backend is
  chosen, so none of them needs a hypervisor.

  The live scenario seals a real OCI image with the home's own signer and boots
  it as the positional source on whichever backend the host selects. It is the
  per-backend boot witness, and runs only on a host that opts in to live
  scenarios.

  @MVM-SEC-25 @build
  Scenario: A trusted artifact verifies and plans without installing or booting
    Given an isolated mvm home
    And a scratch working directory
    And a signed artifact "app.mvmpkg" in the scratch directory
    And the isolated mvm home trusts the artifact's publisher
    When I run mvmctl in the scratch directory with "machine run --dry-run ./app.mvmpkg -- /bin/true"
    Then the command exits with code 0
    And the error output contains "verified ./app.mvmpkg as bundle"
    And the isolated mvm home has no installed bundle

  @MVM-SEC-25 @build
  Scenario: An artifact from an unenrolled publisher is refused before install
    Given an isolated mvm home
    And a scratch working directory
    And a signed artifact "app.mvmpkg" in the scratch directory
    When I run mvmctl in the scratch directory with "machine run ./app.mvmpkg -- /bin/true"
    Then the command exits with code 1
    And the error output contains "trust store has no entry for key_id"
    And the isolated mvm home has no installed bundle

  @MVM-SEC-25 @build
  Scenario: An artifact whose key id is enrolled under another key is refused
    Given an isolated mvm home
    And a scratch working directory
    And a signed artifact "app.mvmpkg" in the scratch directory
    And the isolated mvm home holds another key under the publisher's key id
    When I run mvmctl in the scratch directory with "machine run ./app.mvmpkg -- /bin/true"
    Then the command exits with code 1
    And the error output contains "but trust store entry is for"
    And the isolated mvm home has no installed bundle

  @MVM-SEC-25 @build
  Scenario: An artifact altered after signing is refused before install
    Given an isolated mvm home
    And a scratch working directory
    And a signed artifact "app.mvmpkg" in the scratch directory
    And the artifact "app.mvmpkg" has its rootfs altered after signing
    And the isolated mvm home trusts the artifact's publisher
    When I run mvmctl in the scratch directory with "machine run ./app.mvmpkg -- /bin/true"
    Then the command exits with code 1
    And the error output contains "sha256 mismatch"
    And the isolated mvm home has no installed bundle

  @MVM-SEC-25 @build
  Scenario: A file that carries no signed manifest is refused
    Given an isolated mvm home
    And a scratch working directory
    And an unsigned file "app.mvmpkg" in the scratch directory
    When I run mvmctl in the scratch directory with "machine run ./app.mvmpkg -- /bin/true"
    Then the command exits with code 1
    And the error output contains "app.mvmpkg"
    And the isolated mvm home has no installed bundle

  @live @bundle_boot_live
  Scenario: A signed OCI artifact boots as the positional source
    Given an isolated mvm home
    And a scratch working directory
    When I seal "docker.io/library/alpine:3.20" into a signed artifact in the live home
    And I boot the signed artifact in the live home with "-- /bin/echo bundle-boot-witness"
    Then the command exits with code 0
    And the output contains "bundle-boot-witness"
