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

  @live
  Scenario: machine stop confirms while a guest keeps admitted HTTPS egress open
    # Use the suite home so an unconfirmed stop retains its supervisor evidence.
    And the image "curlimages/curl:8.21.0" is prepared in the live home
    When I run mvmctl in an isolated live home with "machine run -d --profile dev --name bdd-egress-stop-open --image curlimages/curl:8.21.0 --allow-host example.com:443"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine exec bdd-egress-stop-open -- /bin/sh -c 'curl -fsSL --limit-rate 1 https://example.com >/dev/null 2>&1 </dev/null & pid=$!; sleep 3; IFS=\" \" read -r _ _ state _ </proc/$pid/stat; test \"$state\" != Z; echo active-egress'"
    Then the command exits with code 0
    And the output contains "active-egress"
    When I run mvmctl in an isolated live home with "machine stop bdd-egress-stop-open --yes"
    Then the command exits with code 0
    When I run mvmctl in an isolated live home with "machine rm bdd-egress-stop-open --yes"
    Then the command exits with code 0

  @live @firecracker @ci_live
  Scenario: a persistent machine refuses legacy tool policy before boot
    Given an isolated mvm home on encrypted backing storage
    And the image "python:3.12" is prepared in the live home
    When I run mvmctl in an isolated live home with "machine create bdd-tool-command --image python:3.12 --policy features/suites/s8_readme_contract/fixtures/legacy-tool-policy.toml"
    Then the command exits with code 1
    And the output contains "tool-specific policy is no longer supported"

  @live @firecracker @ci_live
  Scenario: a workload process uses admitted egress and a destination-bound secret
    Given an isolated mvm home on encrypted backing storage
    And the image "python:3.12" is prepared in the live home
    When I run mvmctl in the isolated mvm home with "secret set egress-live --host httpbingo.org --type bearer --value egress-live-credential"
    Then the command exits with code 0
    # The guest receives an opaque EGRESS_LIVE placeholder, never the value.
    When I run the workload-origin network-secret live witness
    Then the command exits with code 0
    And the output contains "True"
    And the output does not contain "egress-live-credential"
    When I run mvmctl in the isolated mvm home with "trust audit tail --chain -n 80"
    Then the command exits with code 0
    And the output contains "secret.substituted"
    And the output contains "httpbingo.org"
    And the output does not contain "egress-live-credential"
    When I run mvmctl in the isolated mvm home with "trust audit verify"
    Then the command exits with code 0
    When I run mvmctl in the isolated mvm home with "secret rm egress-live"
    Then the command exits with code 0
