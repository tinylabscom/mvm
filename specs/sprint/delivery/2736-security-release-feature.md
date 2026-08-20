- [x] The release-artifact bootstrap path is compiled with warnings denied on
      every code-changing pull request instead of first being seen by the
      nightly reproducibility build. The stale CLI-version binding left behind
      when builder downloads moved to the boot-image release tag is removed.
      The merge-queue fuzz compile gate also consumes refreshed committed
      lockfiles with `--locked`, so newly published registry versions cannot
      replace the reviewed graph while the invariant job is running.
      The root graph and every affected standalone fuzz graph pin `arrayref`
      to a byte-for-byte vendored copy of the reviewed 0.3.9 upstream revision.
      A discovery-based regression test proves each manifest and lockfile use
      it, verifies the vendored file hashes, and keeps Git sources denied.
      The exact feature check fails on the prior source and passes after the
      fix; every fuzz manifest compiles from its lockfile, and workspace
      all-target Clippy, workflow syntax, formatting, and the workspace suite
      pass, with the sole transient doctest target passing on its isolated
      rerun after the suite's nested Cargo process exited.
