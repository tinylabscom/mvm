# Scheduled CI and kernel freshness repair

The four open `github-actions` issues were two root failures, one stale pin,
and one downstream freshness symptom:

- Security mutation shards had real survivor gaps repaired concurrently by
  #3610, a mutation-copy test environment without Git metadata, and a retired
  package feature;
- Extended CI inherited a non-root session bus across `sudo`, omitted the
  standby parent's FlowMux identity drive from the checkpoint restored into a
  child, documented an interactive stdin grant that sealed workloads refuse,
  used a PATH-dependent smoke input reader, registered a persistent VM without
  its runtime directory, relied on quota-period wall-clock timing, and started
  the documented seven-disk HVF service plane with a six-disk device ceiling;
- both kernel consumers still pinned Linux 6.12.110 after 6.12.111 shipped;
- claim-bearing freshness correctly went stale because Security was red.

PR #3610 landed direct mutation witnesses for command-line separation, GPU
transport selection, backend GPU capability claims, and Firecracker process
observation while this repair was in progress. This repair completes the lane:
mutation copies retain VCS metadata, and the mvm-build shard no longer asks
that package for the removed `pure-mkfs` feature. The live warm claim clears
user-session bus variables at the privilege boundary and preserves complete
Firecracker restore diagnostics. `DeviceAnchors` now records the optional
`flowmux-identity.ext4` device and capture includes it in the checkpoint, so a
materialized child can reopen every PCI block backing file encoded in the
snapshot. The agent workload uses its baked per-call entrypoint without
requesting streaming stdin, its smoke script invokes the store-pinned
`coreutils` input reader, and persistent registration now records the canonical
VM state directory. The quota witness coordinates period completion with a
condition variable instead of guessing at scheduler timing. Native HVF boot now
waits for the agent socket and reports supervisor diagnostics on failure; the
retired virtio-fs MMIO band supplies nine additional disk slots, allowing the
documented seven-disk service plane without moving the RNG, balloon, or any
other snapshot-visible address.

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
remains at its exact 960-symbol budget. The first repaired-head KVM diagnostic
passed parent boot and failed at the actual snapshot boundary with Firecracker
HTTP 400: the restored PCI block device still named the parent's missing
`flowmux-identity.ext4`. Focused serialization, Firecracker anchor-discovery,
and checkpoint-materialization tests cover the repair, and the shared-type
gated-target check passes. Full focused validation also passes for `mvm-vmm`
(767 tests), `mvm-backends` (258 tests), and `mvm-runtime` (1,044 passed, 8
ignored), including 20 repeated direct runs of the quota witness and all 43
focused HVF tests. The focused agent-socket mutation batch caught 13 of 16
variants with one unviable and only two pre-existing accepted capability
constants; the baseline dropped 20 exemptions that the repaired witnesses now
catch. Fresh Security remains the final remote evidence before merge; Extended
CI, standard PR CI, and kernel freshness are green.
