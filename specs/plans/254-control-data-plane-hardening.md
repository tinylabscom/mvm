# Plan 254 — Control/data-plane hardening

**Status:** Implementation complete — Linux merge gate pending

## Goal

Make the documented host↔guest control/data-plane boundary executable and
preserve control-plane responsiveness while bounded data-plane work is active.

## Tasks

- [x] Enforce the 256 KiB guest-protocol frame cap symmetrically on readers and
      writers, with tests proving oversized frames are rejected before bytes are
      written.
- [x] Bound user-content chunks below the JSON frame cap and make `mvmctl fs`
      and `mvmctl cp` transfer larger files as multiple offset-addressed chunks.
- [x] Add an exhaustive traffic-plane classification for every guest verb and
      tests that all streaming response contracts are data-plane contracts.
- [x] Serve guest-agent connections concurrently under explicit total and
      data-plane limits so bounded control-plane capacity remains available.
- [x] Reject console data-channel connections whose AF_VSOCK peer CID is not
      the host CID.
- [x] Refresh the guest-agent reference and stale packet-tunnel comments to
      describe the implemented transport accurately.
- [x] Run `cargo test --workspace`, `cargo check --workspace`, generated-stub
      drift checks, and all-target/all-feature clippy for every affected crate.
- [ ] Run workspace-wide all-target clippy in the Linux builder/CI environment
      before merge; the headless builder has no local arbitrary-command surface.

## Acceptance gates

- A serialized worst-case filesystem chunk fits below the frame cap in both
  directions.
- Oversized frame writes return an error and write zero bytes.
- At most 48 data-plane requests can occupy the 64-connection guest-agent
  budget, leaving 16 slots for control traffic.
- Every `Verb` has an exhaustive `TrafficPlane` mapping.
- Console relay peer authorization accepts CID 2 and rejects guest-local CIDs.
