# Scheduled CI and kernel freshness repair

The four open `github-actions` issues were two root failures, one stale pin,
and one downstream freshness symptom:

- Security mutation shards had real survivor gaps repaired concurrently by
  #3610, a mutation-copy test environment without Git metadata, and a retired
  package feature;
- Extended CI inherited a non-root session bus across `sudo`, documented an
  interactive stdin grant that sealed workloads refuse, and registered a
  persistent VM without its runtime directory;
- both kernel consumers still pinned Linux 6.12.110 after 6.12.111 shipped;
- claim-bearing freshness correctly went stale because Security was red.

PR #3610 landed direct mutation witnesses for command-line separation, GPU
transport selection, backend GPU capability claims, and Firecracker process
observation while this repair was in progress. This repair completes the lane:
mutation copies retain VCS metadata, and the mvm-build shard no longer asks
that package for the removed `pure-mkfs` feature. The live warm claim clears
user-session bus variables at the privilege boundary. The agent workload uses
its baked per-call entrypoint without requesting streaming stdin, and
persistent registration now records the canonical VM state directory.

Linux 6.12.111 is synchronized across the Nix kernel and libkrun firmware
consumers. The downloaded archive matched kernel.org's published SHA-256 and
its detached signature verified against Greg Kroah-Hartman's published stable
release key fingerprint.

Local validation is complete. The focused mutation batches caught the repaired
runtime and backend mutations; the copied-tree mutation baseline also passed
with Git metadata present. The serial workspace unit and integration suites,
the full workspace doctest lane, workspace check and Clippy, gated Linux and
BDD targets, Nix kernel configuration validation in the builder VM, formatting,
and all 74 repository policy gates pass. The aarch64 kernel configuration
remains at its exact 960-symbol budget. Fresh Security and Extended CI runs are
the remaining remote evidence before merge.
