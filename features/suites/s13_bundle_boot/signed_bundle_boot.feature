Feature: Signed bundle boot on a runtime-only host

  The edge/runtime-only path: a host that never builds anything installs a
  signed, content-addressed `.mvmpkg` and boots it by content address. This is
  what a remote host does with a bundle published from a build machine — verify,
  admit, boot — with no flake, no builder VM and no network fetch of an image.

  Sealing a bundle is a full image build, far too slow to do inline, so the
  archive is supplied by the operator with `MVM_BDD_BUNDLE=<path to .mvmpkg>`.
  These scenarios boot a real Firecracker microVM, so on top of that they need
  `MVM_BDD_LIVE`, a usable `/dev/kvm` and a `firecracker` binary; the harness
  skips them cleanly wherever any of that is missing.

  @live @firecracker @bundle
  Scenario: a published bundle installs by content address and boots
    When I install the bundle fixture
    Then the command exits with code 0
    And the install reports a bundle content address
    When I boot the installed bundle with "--entrypoint --timeout 120"
    Then the command exits with code 0
