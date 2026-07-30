Feature: Prime within verity only

  Page-cache priming is limited to blocks covered by the dm-verity root hash.
  Data outside the sealed rootfs must not be primed into the warm pool.

  @wip
  Scenario: page-cache priming refuses an unverified rootfs
    Given a scenario awaiting its step implementation
