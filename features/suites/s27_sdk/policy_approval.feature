@sdk
Feature: Unified policy and human approval
  Static signed admission remains authoritative while human approval adds a
  bounded, durable decision for policy rules that require an operator.

  Scenario: unadmitted operations fail closed before approval
    Given an unadmitted policy request
    Then policy denies it without an approval request

  Scenario: an authorized first response is durable
    Given a signed-admission policy requiring approval
    When I create the approval request
    And an unauthorized operator responds
    Then the response is refused without changing approval state
    When the authorized operator approves
    Then the approval is durable and approved

  Scenario: expired approvals cannot be released after restart
    Given a signed-admission policy requiring approval
    When I create the approval request
    And the approval expires
    And a late authorized operator responds
    Then the late response is refused
    And restart keeps the approval expired
