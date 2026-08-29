# Default-backend host-services broker witness

- [x] Materialize the real service-plane fixture tree into a deterministic
      read-only ext4 image for live scenarios.
- [x] Attach the fixture through `--volume` so default Firecracker and HVF
      backends do not depend on a host-directory share.
- [x] Pin the negative witness to the guest-visible `not bound` broker result.
- [x] Add and pass focused fixture-image coverage.
- [x] Compile the complete BDD conformance target.
- [x] Pass the full workspace and repository gates.
- [ ] Pass the live default-backend broker witnesses.
- [ ] Merge through the queue and close #2988 through the PR link.
