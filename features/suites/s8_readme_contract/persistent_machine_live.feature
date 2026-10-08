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
    When I run mvmctl in an isolated live home with "machine create bdd-tool-command --image python:3.12 --policy features/suites/s8_readme_contract/fixtures/tool-command.toml"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-tool-command"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool python -- /usr/local/bin/python3 -c print(31337)"
    Then the command exits with code 0
    And the output contains "31337"
    When I run mvmctl in an isolated live home with "machine restart bdd-tool-command"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool python -- /usr/local/bin/python3 -c print(31338)"
    Then the command exits with code 0
    And the output contains "31338"
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool python -- /usr/local/bin/python -c print(31339)"
    Then the command exits with code 1
    And the output does not contain "31339"
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool unlisted -- /usr/local/bin/python3 -c print(31340)"
    Then the command exits with code 1
    And the output does not contain "31340"
    When I run mvmctl in the isolated mvm home with "trust audit tail --chain -n 20"
    Then the command exits with code 0
    And the output contains "host.tool.decision"
    And the output contains "guest_broker"
    When I run mvmctl in the isolated mvm home with "trust audit verify"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-tool-command --yes"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine rm bdd-tool-command --yes"
    Then the command exits with code 0

  @live @firecracker @tool_live
  Scenario: a command the workload starts itself is mediated before it runs
    Given an isolated mvm home on encrypted backing storage
    # The run command is plain sh (not a declared tool), so it starts
    # directly; the python3 it spawns is the declared tool and must pass the
    # per-VM gate before it executes.
    When I run mvmctl in an isolated live home with "machine run --image python:3.12 --policy features/suites/s8_readme_contract/fixtures/tool-workload-origin.toml -- /bin/sh -c '/usr/local/bin/python3 -c print(31337)'"
    Then the command exits with code 0
    And the output contains "31337"
    # The same tool with argv outside the admitted patterns is refused
    # before it runs: the workload sees the mediation refusal exit and no
    # tool output.
    When I run mvmctl in an isolated live home with "machine run --image python:3.12 --policy features/suites/s8_readme_contract/fixtures/tool-workload-origin.toml -- /bin/sh -c '/usr/local/bin/python3 -h'"
    Then the command exits with code 126
    And the output does not contain "usage:"
    When I run mvmctl in the isolated mvm home with "trust audit tail --chain -n 20"
    Then the command exits with code 0
    And the output contains "guest_broker"
    When I run mvmctl in the isolated mvm home with "trust audit verify"
    Then the command exits with code 0
