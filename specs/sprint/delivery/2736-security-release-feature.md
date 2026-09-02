- [x] The release-artifact bootstrap path is compiled with warnings denied on
      every code-changing pull request instead of first being seen by the
      nightly reproducibility build. The stale CLI-version binding left behind
      when builder downloads moved to the boot-image release tag is removed.
      The merge-queue fuzz compile gate also consumes refreshed committed
      lockfiles with `--locked`, so newly published registry versions cannot
      replace the reviewed graph while the invariant job is running.
      Readiness witnesses now reject invalid authentication signals, broken
      live-endpoint channels, and endpoint death through the public launch
      boundary; direct tests also pin secret-redacted debug output, optional
      spawn-builder projection, and FlowMux identity configuration.
      The root graph and every affected standalone fuzz graph pin `arrayref`
      to a byte-for-byte vendored copy of the reviewed 0.3.9 upstream revision.
      A discovery-based regression test proves each manifest and lockfile use
      it, verifies the vendored file hashes, and keeps Git sources denied.
      Nix image-source filtering and the mirrored host build fingerprint retain
      the vendored dependency directory, with a regression test covering the
      omission that previously broke offline runtime-overlay builds.
      The first exact full Security rerun also exposed two newly measured
      capability-builder mutants: a direct all-operations assertion now kills
      the real field-loss mutation, while the constructor-to-`Default`
      replacement is recorded as provably identical with the required
      mutation-baseline rationale.
      The exact feature check fails on the prior source and passes after the
      fix; every fuzz manifest compiles from its lockfile, and workspace
      all-target Clippy, workflow syntax, formatting, and the workspace suite
      pass, with the sole transient doctest target passing on its isolated
      rerun after the suite's nested Cargo process exited.
