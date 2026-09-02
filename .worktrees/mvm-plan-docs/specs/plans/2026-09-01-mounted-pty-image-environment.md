Backing: shipped-source
Validation: check-sprint-append

# Mounted PTY image environment

An absolute command passed to `machine run -it` normally reaches the guest
console directly, preserving the OCI image environment assembled by the guest
agent. Adding `--mount` incorrectly disabled that direct path and introduced a
`/bin/sh -lc` wrapper. The image's login profile could then replace its declared
`PATH`; `rust` still contained Cargo under `/usr/local/cargo/bin`, but an
interactive Bash session could not resolve it.

## Delivery

- [x] Reproduce the mounted absolute-command dispatch through the login-shell
      wrapper with a focused failing regression.
- [x] Keep mounted absolute PTY commands on the direct console path while
      retaining shell lookup for relative commands.
- [x] Add a live Rust-image scenario covering the PTY, host mount, CLI
      environment, and image-declared Cargo path together.
- [x] Pass formatting, workspace tests, zero-warning Clippy, gated-target, and
      non-live BDD validation; leave the hardware-backed scenario to the opted-in
      live lane.
- [x] Record the completed repair in the sprint and refactor rollup.
- [ ] Merge the repair through the queue.
