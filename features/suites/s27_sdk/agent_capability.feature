@sdk
Feature: Typed agent capability bindings
  A typed host capability is admitted by exact descriptor identity and never
  records the private payload that it serves.

  Scenario: an admitted capability validates and audits only digests
    Given an admitted typed echo capability
    When I create a typed invocation for the private value "private credential"
    Then the typed invocation is valid
    And the capability audit excludes the private value

  Scenario: a descriptor downgrade is refused
    Given an admitted typed echo capability
    When I change the admitted descriptor limits
    Then the typed invocation is refused for a binding mismatch
