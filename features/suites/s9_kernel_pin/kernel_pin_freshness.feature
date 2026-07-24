Feature: Kernel pin freshness watcher
  mvm pins the guest kernel in two places — the libkrunfw bundled tarball and
  the nix-built workload/builder kernel. Both are pinned to an exact upstream
  LTS point release, so a pin can trail the latest release of its series, where
  the maintainer backports security fixes. The watcher flags such a pin and
  recommends a bump; it must never recommend action on missing knowledge.

  Scenario: Both kernel pins at the latest point release recommend no action
    Given a local kernel pin "libkrunfw" at version "6.12.97"
    And a local kernel pin "nix-kernel" at version "6.12.97"
    And the latest upstream point release for series "6.12" is "6.12.97"
    When the kernel pin freshness is assessed
    Then the advisory does not recommend action
    And every assessed pin is reported up to date

  Scenario: A pin trailing the latest point release recommends a bump
    Given a local kernel pin "libkrunfw" at version "6.12.91"
    And a local kernel pin "nix-kernel" at version "6.12.97"
    And the latest upstream point release for series "6.12" is "6.12.97"
    When the kernel pin freshness is assessed
    Then the advisory recommends action
    And the worst pin is reported behind by 6 patch releases

  Scenario: Missing upstream data never recommends action
    Given a local kernel pin "libkrunfw" at version "6.12.91"
    And no upstream release data
    When the kernel pin freshness is assessed
    Then the advisory does not recommend action
    And the worst pin status is unknown
