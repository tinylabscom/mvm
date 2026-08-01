Feature: Transcript evidence is authenticated before decryption

  A sealed transcript carries a content address over its capture binding and
  ordered ciphertext chunk records. Export succeeds only when that exact root
  is present in the verified host audit chain.

  Scenario: a host-anchored sealed transcript exports successfully
    Given an isolated mvm home
    And a sealed transcript anchored to the host audit chain
    When I run mvmctl in the isolated mvm home with "trust audit transcript export bdd-transcript --tenant local"
    Then the command exits with code 0
    And the output contains "authenticated transcript evidence"

  Scenario: a manifest binding change is refused before export
    Given an isolated mvm home
    And a sealed transcript anchored to the host audit chain
    And the sealed transcript binding is tampered
    When I run mvmctl in the isolated mvm home with "trust audit transcript export bdd-transcript --tenant local"
    Then the command exits with code 1
    And the error output contains "verifying transcript manifest root"
