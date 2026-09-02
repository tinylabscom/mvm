# Portable dev-VM socket resolver test

Backing: shipped-source
Validation: check-sprint-append

**Issue:** [#2973](https://github.com/tinylabscom/mvm/issues/2973)

## Outcome

The dev-VM libkrun socket test asserts the canonical socket-directory choice
instead of assuming every host can place Unix sockets beneath the VM state
directory. It continues to pin the per-port filename while accepting the
intentional hashed short namespace on deep macOS paths.

## Delivery checklist

- [x] Reproduce the deterministic failure under the stock macOS temporary
      directory.
- [x] Update the assertion to the shared state-or-short directory resolver.
- [x] Pass the focused regression and the full `mvm-vmm` test suite.
- [x] Pass workspace Clippy, formatting, and repository policy gates.
- [x] Record the completed implementation in the sprint and refactor rollup.
- [ ] Merge the tested pull request and close #2973 through its linkage.
