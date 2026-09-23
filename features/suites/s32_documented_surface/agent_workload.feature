Feature: The agent workload example boots with a placeholder, not a key

  The published example is executable documentation. The live docs lane boots
  its real flake, lowers its test-only SecretRef into the signed execution plan,
  and invokes the baked entrypoint. The smoke path does not contact a model API;
  it proves the guest received the host-minted placeholder and the pinned agent
  binary starts.

  @live
  Scenario: the documented agent workload runs without putting a key in the guest
    Given the agent workload smoke secret is stored
    When I run the agent workload example with "machine run --flake examples/agent-workload --entrypoint --from-workload-ir examples/agent-workload/workload-smoke.json --allow-host api.anthropic.com:443 --timeout 120"
    Then the command exits with code 0
    And the output contains "agent-workload smoke: placeholder-present"
    When I verify the agent workload audit chain
    Then the command exits with code 0
    Then the agent workload smoke secret is removed with "secret rm agent-workload-smoke"
