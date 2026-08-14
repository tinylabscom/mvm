Feature: mvmctl template build and run --template

  Templates can be backed by pinned OCI image references. Users build a
  reusable image template with `mvmctl template build --image <ref>` and then
  run commands against it with `mvmctl run --template <name>`. Built-in
  language templates are always available offline.

  These scenarios are hermetic: they use `--dry-run` so no VM boots and no
  network is touched.

  Scenario: template build creates an image-backed template
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "template build --image python:3.12-alpine --name my-python"
    Then the command exits with code 0
    And the output contains "Built image template 'my-python'"

  Scenario: template list shows built and built-in image templates
    Given an isolated mvm home
    And I have run mvmctl in the isolated mvm home with "template build --image python:3.12-alpine --name my-python"
    When I run mvmctl in the isolated mvm home with "template list"
    Then the command exits with code 0
    And the output contains "my-python"
    And the output contains "python"

  Scenario: run --template uses a built image template
    Given an isolated mvm home
    And I have run mvmctl in the isolated mvm home with "template build --image python:3.12-alpine --name my-python"
    When I run mvmctl in the isolated mvm home with "run --dry-run --template my-python -- python3 -c print()"
    Then the command exits with code 0
    And the output contains "image: OCI reference"

  Scenario: run --template uses a built-in language template
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "run --dry-run --template python -- python3 -c print()"
    Then the command exits with code 0
    And the output contains "image: OCI reference"

  Scenario: template info shows the image reference for an image template
    Given an isolated mvm home
    When I run mvmctl in the isolated mvm home with "template info python"
    Then the command exits with code 0
    And the output contains "source:      image"
    And the output contains "python:3.12-alpine"
