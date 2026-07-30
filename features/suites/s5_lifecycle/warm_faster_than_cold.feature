Feature: Warm start is faster than cold start

  The warm-restore path must beat the cold-boot SLO on the same image.

  @live @firecracker @wip
  Scenario: warm restore timing beats cold boot timing on the same image
    Given a scenario awaiting its step implementation
