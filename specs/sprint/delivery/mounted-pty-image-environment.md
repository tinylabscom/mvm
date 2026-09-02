Backing: shipped-source
Validation: check-sprint-append

# Mounted PTY image environment

`mvmctl machine run --image rust --mount ... -it -- /bin/bash` booted the
correct image and carried Cargo at `/usr/local/cargo/bin/cargo`, but `cargo`
was absent from command lookup. The mount left a directory share on the
request, which made PTY dispatch replace the absolute Bash argv with
`/bin/sh -lc <wrapper>`. Debian's login profile then replaced the OCI `PATH`
before Bash started.

Absolute interactive commands now go directly to the guest console whether or
not the launch also carries host-directory shares. The guest agent therefore
applies the image runtime environment once and execs the requested command
without a login shell rewriting it. Relative commands retain the wrapper they
need for shell path lookup.

The focused regression first demonstrated the mounted request lowering to the
login wrapper, then passed with `/bin/bash` and the caller environment preserved
on the direct request. A live `@dir_share` scenario mirrors the reported Rust
launch and jointly checks a real PTY, mounted content, `NAME=ari`, and Cargo at
the image-declared path. The regular BDD run compiles and discovers that
scenario; execution remains with the opted-in hardware lane.

Validation completed with the focused PTY dispatch tests, the workspace test
suite, `mvm-build` doc tests, full all-target/all-feature Clippy with warnings
denied, Linux and BDD gated-target checks, formatting, and the 243-scenario
non-live BDD suite (242 passed, one capability scenario skipped).
