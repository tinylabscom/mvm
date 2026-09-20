Feature: Fresh install release authentication
  A new host must authenticate the release without depending on a preinstalled
  signature verifier and must never execute unauthenticated downloaded code.

  Scenario: Baked release bootstraps its verifier from an authenticated archive
    Given a fresh host with neither mvmctl nor cosign
    When the installer selects a verifier for the baked release
    Then the archive trust anchor is checked before its mvmctl executes
    And the tag-pinned signature bundle is mandatory
    And there is no unsigned fresh-install fallback
