# Live witness — Firecracker and HVF, first pass

**Status:** Evidence record. Every result below was produced by running the command shown on the host shown.
**Date:** 2026-08-03
**Owner:** mvm
**Scope:** The two priority backends: Firecracker (Linux + KVM) and HVF (macOS 26+ Apple Silicon).

## Why

The claim-reality audit (`claim-reality-audit-2026-08-02.md`) was static. It established that controls are *wired*; it could not establish that they *hold*. Its closing line was that closing the readiness question needs a witness per claim per shipping backend on real hosts. This is the first of those.

The distinction earned its keep immediately: the one finding here is invisible to every static gate in the tree, and was found by running one command twice.

## Hosts and commits

| | Firecracker | HVF |
|---|---|---|
| Host | Hetzner, Linux 6.8.0-124 x86_64, `/dev/kvm` present, 8 cores / 62 GiB | macOS 26.5.2, arm64 |
| Binary | `/usr/local/bin/firecracker`, mvmctl built from `1dc35e5d4` | mvmctl built from `main` @ `a9fb158ca` |

The Firecracker checkout is roughly a week behind `main` and carries an unrelated uncommitted change (a netd sanitizer-test rewrite) belonging to another session. It was deliberately left untouched, so that side witnesses `1dc35e5d4` rather than `main`. Nothing in the intervening commits touches the paths exercised here, but the difference is stated rather than glossed.

## Command

```
mvmctl machine run --image alpine [--hypervisor hvf] -- /bin/sh -c '
  echo MVM_BOOT_OK; id
  wget -T 6 -q -O- http://1.1.1.1/ 2>&1 | head -2
  ip -o addr 2>/dev/null'
```

## Results

| | Firecracker | HVF |
|---|---|---|
| Boots and executes | ✅ `MVM_BOOT_OK` | ✅ `MVM_BOOT_OK` |
| Entrypoint uid | **`uid=901 gid=901`** | **`uid=0(root) gid=0(root)`** |
| Egress to `1.1.1.1` | ❌ `Network unreachable` | ❌ `Network unreachable` |
| `ip -o addr` | empty | empty |

## What this witnesses

**Claim 10 (default-deny egress) holds on both backends, live.** A workload launched with no network policy could not reach the internet.

The *form* of the failure is the interesting part. `Network unreachable` is what you get when there is no route, not when a packet is dropped — a filtering control would time out instead. Combined with `ip -o addr` returning nothing, this is enforcement by **absence of a network interface**, which is exactly the mechanism ADR-001 is corrected to describe in #2090 and the property `check-vsock-only-egress` asserts statically. Static gate and live behaviour agree.

**Both backends boot an OCI image and run a command.** Worth recording because prior project notes claimed live witnesses had failed on both hosts. They no longer do. That is the third instance in two days of a pessimistic note outliving the problem it described — see the audit's F3 and F4 — and it is a good argument for re-checking notes before planning against them.

## The finding

**Firecracker drops the entrypoint to uid 901; HVF runs it as root.** Same command, same image, two backends. Confirmed twice on HVF.

Grounded in the tree: the drop is `crates/mvm-agentd/src/bin/mvm-guest-agent/init.rs:115`, calling `guest_mount::drop_privilege(WORKLOAD_UID, WORKLOAD_GID)` with `WORKLOAD_UID = 901`. It has exactly one caller, and neither `mvm-oci-init.rs` nor `mvm-oci-entrypoint.rs` contains any setpriv or uid logic. Firecracker's path therefore cannot be the OCI init path; HVF's evidently is.

Filed as #2091. **Not asserted here:** whether HVF-at-root is a defect or an accepted dev-tier property. ADR-001 marks virtiofs-root as dev-tier and explicitly not a witness for claim 3, but says nothing equivalent about claims 1 or 2 on the OCI path, so the tier is genuinely unstated rather than obviously acceptable. That is an owner call.

Strictly, claim 2 concerns a guest binary *elevating* to uid 0, so an entrypoint that **starts** as root does not violate it. What it does remove is the defence-in-depth the drop provides, and it leaves two backends the project calls Tier 1 and Tier 2 with materially different privilege postures for identical input.

### Why no static check caught it

Both backends pass `check-uniform-vsock-egress` and `check-vsock-only-egress`. The ledger lists claim 2 as Shipped, witnessed by `fn:set_no_new_privs` — a unit test which is entirely true and says nothing about whether a given backend's boot path ever reaches the drop. A per-claim witness can be green while a per-backend behaviour diverges, and only running both tells you.

## Not witnessed by this pass

Stated so the record is not mistaken for more than it is:

- **Claim 3** (tampered rootfs fails to boot) — needs a dm-verity image and a deliberate byte flip.
- **Claim 15** (no interactive access to a sealed production microVM) — needs a sealed prod image; the alpine image used here is neither sealed nor prod.
- **Claims 1, 2 proper** — witnessing these needs a guest that attempts host-fs access and attempts elevation, not merely a report of its starting uid.
- **Claims 4–9, 11–14, 16** — untouched by this pass.
- Anything under load, over time, or with a real workload rather than `/bin/sh`.

## Reproduction

Both commands are in "Command" above and need no fixture. The Firecracker host needs `PATH=/root/.cargo/bin:$PATH` under a non-interactive SSH session, or the run fails building the verity initrd with a bare `spawn cargo: No such file or directory`.

One incidental observation: Firecracker printed `wait failed: No child process (os error 10)` during teardown. It did not affect the result and was not investigated.
