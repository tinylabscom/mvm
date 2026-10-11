Feature: README persistent machine lifecycle works end to end

  The hermetic README contract proves these commands still parse. This narrow
  live witness proves the documented persistent-machine path actually operates
  one real microVM without paying for every registry, Nix, and bundle example.

  @live @firecracker @ci_live
  Scenario: the documented persistent machine path operates a real guest
    Given an isolated mvm home on encrypted backing storage
    And the image "nginx" is prepared in the live home
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
    And the image "alpine" is prepared in the live home
    When I run mvmctl in an isolated live home with "machine run -d --profile dev --name bdd-detached-ready --image alpine"
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
    And the image "python:3.12" is prepared in the live home
    When I run mvmctl in an isolated live home with "machine create bdd-tool-command --image python:3.12 --policy features/suites/s8_readme_contract/fixtures/tool-command.toml"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine start bdd-tool-command"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine exec bdd-tool-command --tool python -- /usr/local/bin/python3 -c print(31337)"
    Then the command exits with code 0
    And the output contains "31337"
    When I run mvmctl in the isolated mvm home with "machine restart bdd-tool-command"
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
    When I run mvmctl in the isolated mvm home with "trust audit verify"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine stop bdd-tool-command --yes"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "machine rm bdd-tool-command --yes"
    Then the command exits with code 0

  @live @firecracker @tool_live
  Scenario: a workload-origin tool receives only its scoped route and secret
    Given an isolated mvm home on encrypted backing storage
    And the image "python:3.12" is prepared in the live home
    When I run mvmctl in the isolated mvm home with "secret set tool-live --host httpbin.org --type bearer --value tool-live-credential"
    Then the command exits with code 0
    # /bin/sh is not declared. The python process it starts is workload-origin,
    # so its route and secret work only after the broker returns a bound allow.
    # The guest receives an opaque TOOL_LIVE placeholder, never the value.
    When I run the workload-origin scoped-secret live witness
    Then the command exits with code 0
    And the output contains "True"
    And the output does not contain "tool-live-credential"
    # An argv outside the admitted patterns is refused before the tool runs.
    When I run mvmctl in an isolated live home with "machine run --image python:3.12 --policy features/suites/s8_readme_contract/fixtures/tool-workload-origin.toml --secret tool-live -- /bin/sh -c '/usr/local/bin/python3 -h'"
    Then the command exits with code 126
    And the output does not contain "usage:"
    When I run mvmctl in the isolated mvm home with "trust audit tail --chain -n 80"
    Then the command exits with code 0
    And the output contains "host.tool.decision"
    And the output contains "guest_broker"
    And the output contains "secret.substituted"
    And the output contains "httpbin.org"
    And the output does not contain "tool-live-credential"
    When I run mvmctl in the isolated mvm home with "trust audit verify"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "secret rm tool-live"
    Then the command exits with code 0
