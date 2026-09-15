# GitHub Actions issue reconciliation

Backing: shipped-source
Validation: check-sprint-append

**Issues:** [#3248](https://github.com/tinylabscom/mvm/issues/3248),
[#3249](https://github.com/tinylabscom/mvm/issues/3249), and
[#3250](https://github.com/tinylabscom/mvm/issues/3250)

## Outcome

Restore current evidence behind the scheduled security claims, close the two
new mutation-witness gaps, and move both carried kernel source pins to the
verified Linux 6.12.110 LTS archive. The claim-freshness report closes only
after a successful Security run replaces the red scheduled evidence.

## Delivery checklist

- [x] Reproduce the supply-chain failure and identify RUSTSEC-2026-0285 in
      rustls 0.23.41.
- [x] Update rustls and its cryptographic dependencies to the fixed compatible
      release set; pass both supply-chain gates locally.
- [x] Identify the two surviving `read_handoff_response` mutants from the
      failed mvm-backends shard.
- [x] Add focused EOF-boundary regressions that distinguish both mutated
      branches.
- [x] Verify the Linux 6.12.110 archive digest against kernel.org's signed
      checksum manifest and the release maintainer's detached signature.
- [x] Update both kernel consumers and the structural synchronization pin.
- [x] Pass focused tests, workspace tests/check, gated compilation,
      zero-warning Clippy, formatting, supply-chain checks, and all repository
      policy gates. The macOS mutation run catches the two reported mutants;
      the authoritative Linux ratchet runs in PR CI.
- [ ] Pass Linux kernel evaluation/build and the authoritative Linux mutation
      ratchet in PR CI.
- [ ] Merge the tested pull request and record the landed evidence.
- [ ] Re-run Security on current `main`, reconcile the claim-freshness watcher,
      and close all three bot issues with links to the green evidence.
- [ ] Configure the requested weekly watch for newly opened
      `github-actions[bot]` issues.

## Source verification

The upstream archive SHA-256 is
`8cee19e1839bb6ff4d5254d761933ae6ab670492d5ed030e09a80538320d5c4c`,
which converts to the Nix SRI hash
`sha256-jO4Z4YObtv9NUlTXYZM65qtnBJLV7QMOCagFODINXEw=`.

The downloaded archive matches the entry in kernel.org's clearsigned
`v6.x/sha256sums.asc` manifest. Independently, the detached signature over the
uncompressed archive verifies against Greg Kroah-Hartman's published release
key fingerprint `647F 2865 4894 E3BD 4571 99BE 38DB BDC8 6092 693E`.

## Rollout

The repository pin does not alter already-running VMs. Locally managed VMs move
with `mvmctl vm rekernel`; fleet rollout remains owned by mvmd.
