Feature: Signed bundle boot on a runtime-only host

  The edge/runtime-only path: a host that never builds anything installs a
  signed, content-addressed `.mvmpkg` and boots it by content address. This is
  what a remote host does with a bundle published from a build machine — verify,
  admit, boot — with no flake, no builder VM and no network fetch of an image.

  Sealing a bundle is a full image build, far too slow to do inline, so the
  operator supplies the archive with `MVM_BDD_BUNDLE=<path to .mvmpkg>` and the
  publisher key it was sealed under with `MVM_BDD_BUNDLE_PUBKEY=<path to .pub>`.
  `scripts/make-bundle-fixture.sh` produces both.

  The key is not optional bookkeeping. A scenario installs into an isolated
  `MVM_HOME` whose trust store starts empty, and verification refuses an unknown
  `key_id` — claim 9, working as designed. Before this suite supplied a trust
  anchor these scenarios could not have passed even with an archive present;
  nothing noticed, because nothing set `MVM_BDD_BUNDLE` either.

  Verifying and installing an archive needs no hypervisor, so those scenarios
  are gated on the fixture alone and run wherever one exists. Only the boot
  additionally needs `MVM_BDD_LIVE`, a usable `/dev/kvm` and `firecracker`.

  @bundle
  Scenario: a published bundle installs by content address
    When I install the bundle fixture
    Then the command exits with code 0
    And the install reports a bundle content address

  @bundle
  Scenario: a bundle from an unenrolled publisher is refused
    When I install the bundle fixture without trusting its publisher
    Then the command exits with code 1
    And the failure names the untrusted publisher key

  @live @firecracker @bundle
  Scenario: an installed bundle boots by content address
    When I install the bundle fixture
    Then the command exits with code 0
    And the install reports a bundle content address
    When I boot the installed bundle with "--entrypoint --timeout 120"
    Then the command exits with code 0
