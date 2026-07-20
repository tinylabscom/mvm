# Close-out — Issues, PRs, Removals

What happens to the open issue/PR backlog as this sprint absorbs it, and the biggest pieces of code this restructure has confirmed dead and slated for removal.

## Issue / PR disposition

| # | Kind | Disposition |
|---|---|---|
| **1637** | PR (draft) | **KEEP OPEN** — one-command microVM docs/blog; WS12 makes it true |
| 1701 | issue | Fold → WS-NET (finish vsock tunnel), then close |
| 1717 | PR | Fold → WS-NET (FC transparent net over vsock), then close |
| 1601 | issue | Fold → WS-NET (HVF host-vsock-proxy), then close |
| 1674 | issue | Fold → WS1c / WS8 (OCI unpack O_EXCL), then close |
| 1654 | issue | Fold → WS4 (runtime sockets under `~/.mvm/run`), then close |
| 1462 | issue | Fold → WS2 (verb-grant delivery), then close |
| 1366 | issue | Fold → WS7 (Sandbox.connect dev-only exec guard), then close |
| 1283 | issue | Fold → WS10 (kernel boot-probe strip), then close |
| 1264 | issue | Fold → WS10 (kernel pin bump), then close |
| 1716 | PR | Superseded by this sprint — close |
| 1718 | PR | Folded (dev_vz→builder_vm rename subsumed by WS1) — close |
| 1713 | PR | Contradicts consolidation (splits SDK) — close |

Note: SPRINT.md's Appendix B table refers to "WS3" for the vsock-tunnel-related fold targets (1701, 1717, 1601); this document set's workstream list renamed that workstream to **WS-NET** (it absorbs the old WS3 — see [06-execution-plan.md](06-execution-plan.md)), so the fold targets above point at WS-NET. The underlying disposition is unchanged.

Per [06-execution-plan.md](06-execution-plan.md) WS13: fold each still-relevant intent into its workstream, then close the 8 issues + 4 PRs with a pointer to the superseding WS. **#1637 stays open** — it's the story this whole sprint is meant to make true, not a task the sprint folds away.

## Biggest confirmed removals

- **Userspace network gateways** — passt, gvproxy, and the opt-in native/rvproxy `native_gateway` subsystem (~1,281 lines); all replaced by the one vsock seam (WS-NET).
- **`mvm/src/vm/egress_proxy.rs`** L7 stub — dead (WS8).
- **`mvm/src/storage/`** dm-thin substrate — every method returns "phase-2 work" (WS8).
- **QEMU backend** (WS1e), Vz remnants, `mvm-vz-supervisor` Swift dir (WS0.4).
- **28 member features → 2** (WS5); ~24 `#[cfg]`-heavy gates collapse.

These removals are what backs several of the headline metrics in [01-goals.md](01-goals.md) — the feature-count target, the files-over-1500-lines target, and part of the crate-count reduction all come directly from this list.
