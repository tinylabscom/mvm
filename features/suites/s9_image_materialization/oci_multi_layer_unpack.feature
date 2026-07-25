Feature: OCI multi-layer unpack replaces prior-layer paths

  Each OCI image layer is unpacked onto the same rootfs tree. A later layer
  must be able to replace a path written by an earlier layer, including
  changing its entry type (file to directory, directory to file, etc.), while
  still refusing duplicate entries within the same layer.

  Scenario: A later layer file overrides an earlier layer file
    Given an empty OCI unpack root
    When I unpack a layer containing:
      | path    | kind | content |
      | foo.txt | file | first   |
    When I unpack a layer containing:
      | path    | kind | content |
      | foo.txt | file | second  |
    Then the path "foo.txt" exists as a file
    And the path "foo.txt" contains "second"

  Scenario: A later layer directory replaces an earlier layer file
    Given an empty OCI unpack root
    When I unpack a layer containing:
      | path    | kind | content |
      | foo/bar | file | hello   |
    When I unpack a layer containing:
      | path    | kind      | content |
      | foo/bar | directory |         |
    Then the path "foo/bar" exists as a directory

  Scenario: A whiteout removes a path and a later layer recreates it
    Given an empty OCI unpack root
    When I unpack a layer containing:
      | path    | kind | content |
      | foo.txt | file | first   |
    When I unpack a layer containing:
      | path        | kind     | content |
      | .wh.foo.txt | whiteout |         |
    Then the path "foo.txt" does not exist
    When I unpack a layer containing:
      | path    | kind | content |
      | foo.txt | file | third   |
    Then the path "foo.txt" exists as a file
    And the path "foo.txt" contains "third"

  Scenario: A duplicate entry in the same layer is refused
    Given an empty OCI unpack root
    When I unpack a layer containing:
      | path    | kind | content |
      | foo.txt | file | first   |
      | foo.txt | file | second  |
    Then the unpack report has 1 refused entries
