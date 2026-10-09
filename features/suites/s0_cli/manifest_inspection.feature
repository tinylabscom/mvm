@manifest_inspection
Feature: Built-manifest inspection through the client facade
  Registry inspection does not require a running machine. The CLI retains its
  output contract and refuses unsupported verification rather than claiming
  that unsigned artifacts have been authenticated.

  Scenario: An empty registry has an empty JSON listing
    When I run mvmctl with "manifest ls --json" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "[]"

  Scenario: An empty orphan listing keeps its human message
    When I run mvmctl with "manifest ls --orphans" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "No orphaned slots."

  Scenario: Tag filters retain their sorted intersection diagnostic
    When I run mvmctl with "manifest ls --tag zeta --tag alpha --tag alpha" and an isolated mvm home
    Then the command exits with code 0
    And the output contains "No built slots match tag filter [alpha, zeta]."

  Scenario: Signature verification is refused before resolving a manifest
    When I run mvmctl with "manifest verify absent-manifest.toml --check-signature" and an isolated mvm home
    Then the command exits with code 1
    And the error output contains "--check-signature"
    And the error output contains "not yet wired"
