Feature: README persistent machine lifecycle works end to end

  The hermetic README contract proves these commands still parse. This narrow
  live witness proves the documented persistent-machine path actually operates
  one real microVM without paying for every registry, Nix, and bundle example.

  @live @firecracker @ci_live
  Scenario: the documented persistent machine path operates a real guest
    Given an isolated mvm home on encrypted backing storage
    When I run mvmctl in the isolated mvm home with "machine create bdd-readme-web --image nginx --cpus 2 --memory 512M"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-readme-web"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine exec bdd-readme-web -- nginx -v"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine logs bdd-readme-web"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine inspect bdd-readme-web"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-readme-web --yes"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine rm bdd-readme-web --yes"
    Then the command exits with code 0

  @live @firecracker @ci_live
  Scenario: detached start returns only after the guest control channel answers
    Given an isolated mvm home on encrypted backing storage
    When I run mvmctl in an isolated live home with "machine run -d --name bdd-detached-ready --image alpine"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine ps"
    Then the command exits with code 0
    And the output contains "bdd-detached-ready"
    When I run mvmctl in the isolated mvm home with "machine exec bdd-detached-ready -- /bin/true"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-detached-ready --yes"
    Then the command exits with code 0

  @live @firecracker @tool_live
  Scenario: a persistent machine mediates declared and bound commands across restart
    Given an isolated mvm home on encrypted backing storage
    When I run mvmctl in an isolated live home with "machine create bdd-tool-command --image alpine --policy features/suites/s8_readme_contract/fixtures/tool-command.toml"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-tool-command"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool shell -- /bin/sh -c 'echo mediated-ok'"
    Then the command exits with code 0
    And the output contains "mediated-ok"
    When I run mvmctl in the isolated mvm home with "machine restart bdd-tool-command"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool shell -- /bin/sh -c 'echo mediated-after-restart'"
    Then the command exits with code 0
    And the output contains "mediated-after-restart"
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool shell -- sh -c 'echo alias-should-not-run'"
    Then the command exits with code 1
    And the output does not contain "alias-should-not-run"
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool unlisted -- sh -c 'echo should-not-run'"
    Then the command exits with code 1
    And the output does not contain "should-not-run"
    When I run mvmctl in the isolated mvm home with "trust audit tail --chain -n 20"
    Then the command exits with code 0
    And the output contains "host.tool.decision"
    When I run mvmctl in the isolated mvm home with "trust audit verify"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-tool-command --yes"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine rm bdd-tool-command --yes"
    Then the command exits with code 0

  @live @firecracker @tool_live
  Scenario: a workload-origin declared command is mediated and audited before it runs
    Given an isolated mvm home on encrypted backing storage
    When I run mvmctl in an isolated live home with "machine create bdd-tool-workload --image alpine --policy features/suites/s8_readme_contract/fixtures/tool-command.toml"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-tool-workload"
    Then the command exits with code 0
    # The outer /bin/sh is host-initiated and allowed by the endpoint. The
    # inner /bin/sh is a workload-origin spawn of the declared path: it runs
    # only after the shim reports it to the endpoint over the broker and the
    # gate allows it, so the marker appears only on an audited allow.
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-workload --tool shell -- /bin/sh -c '/bin/sh -c \"echo mediated-inner-ok\"'"
    Then the command exits with code 0
    And the output contains "mediated-inner-ok"
    # The inner argv is exactly the denied command line, so the shim refuses
    # it before any spawn and the workload sees the denial, not the tool.
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-workload --tool shell -- /bin/sh -c '/bin/sh -c id'"
    Then the command exits with code 126
    And the output does not contain "uid="
    # Workload-origin decisions carry the guest_broker origin label next to
    # the chain-signed host.tool.decision entry.
    When I run mvmctl in the isolated mvm home with "trust audit tail --chain -n 40"
    Then the command exits with code 0
    And the output contains "host.tool.decision"
    And the output contains "guest_broker"
    When I run mvmctl in the isolated mvm home with "trust audit verify"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-tool-workload --yes"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine rm bdd-tool-workload --yes"
    Then the command exits with code 0
