Feature: mvmctl template registry

  Templates can be bundled with mvmctl or fetched from a remote registry.
  The bundled core presets are always available offline; richer templates are
  fetched from the configured registry on first use and cached locally.

  Scenario: template list shows bundled core presets
    When I run mvmctl with "template list"
    Then the command exits with code 0
    And the output contains "minimal"
    And the output contains "python"

  Scenario: template info resolves a bundled preset
    When I run mvmctl with "template info python"
    Then the command exits with code 0
    And the output contains "source:      bundled"

  Scenario: generate template fetches a remote template and scaffolds its files
    Given a local template registry with a demo template
    When I generate a project from template "demo"
    Then the command exits with code 0
    And the generated project contains file "flake.nix"
    And the generated project contains file "mvm.toml"
    And the generated project contains file "app.py"

  Scenario: template search finds a remote template
    Given a local template registry with a demo template
    When I run mvmctl with "template search demo" against the local template registry
    Then the command exits with code 0
    And the output contains "demo"

  # The documented invocation, spelled as the README prints it. The remote-demo
  # scenario above drives `generate template` through a step that assembles its
  # argv in Rust, which the README structural check cannot read — so the
  # documented line sat exempt while a scenario for the same verb was green.
  # This one runs from a scratch directory because the argument is a relative
  # path: from the workspace root it would scaffold a project into the tree.
  Scenario: the documented generate template invocation scaffolds a python project
    Given an isolated mvm home
    And a scratch working directory
    When I run mvmctl in the scratch directory with "generate template python ./my-python-app"
    Then the command exits with code 0
    And the scratch directory contains file "my-python-app/flake.nix"
    And the scratch directory contains file "my-python-app/mvm.toml"
