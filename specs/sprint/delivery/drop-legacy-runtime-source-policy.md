# Drop the legacy runtime-source policy

`RuntimeSourcePolicy` described itself as staged-rollout scaffolding — "to make
the intended runtime source machine-readable in launch configs and audit events
**without changing any backend behavior yet**" — and its `#[default]` was
`RootfsOnly`. The rollout it was staging is finished: the runtime overlay is the
only source of the guest binaries. The enum is gone, along with the selector,
the `mvm.runtime_source_policy=` cmdline token, and the branching each backend
carried for the three postures.

## What the policy was hiding

A workload booting with `required_overlay` on the cmdline got the overlay
attached as a block device and then never mounted it: `mvm-oci-init`, the PID 1
baked into a workload rootfs, has no code that mounts `/mvm/runtime`. Only the
universal initramfs agent does. So a host that could not resolve the initramfs
booted the rootfs `/init`, found no egress client (the `RuntimeLean` injection
had deliberately deleted the baked copy), and panicked — surfacing to the
operator as a 30-second agent-readiness timeout naming nothing.

The overlay-free fallbacks are now gone at every layer rather than gated:

- `attach_runtime_overlay` returns `Err` on a cold cache instead of leaving the
  fields `None` and booting. The caller's acquisition ladder still catches that
  and builds or downloads; what cannot happen is a silent overlay-free boot.
- `mvm-hostd`'s `Err(e) => { /* boot legacy, don't fail */ Ok(()) }` arm is
  deleted.
- `admit_runtime_overlay_contract` requires a runtime-lean rootfs on every boot,
  not only a required-overlay one. `admit_overlay_aware` was a weaker alias of
  the same call and is deleted.
- The guest-side resolvers lost both the policy *and* the baked candidate:
  `resolve_runtime_binary_for` now takes one path. A stray executable at the old
  `/usr/local/bin/` location no longer satisfies the lookup, which is pinned by
  its own test.
- Injection is always lean and now actively *strips* an agent/netinit/egress
  client an image shipped, rather than leaving it to shadow the overlay.

## Two deliberate behaviour changes

**virtiofs-root now carries the block overlay.** It previously declared
`RootfsOnly` and reached its binaries from a baked copy that no longer exists.
`build_activation_environment` already attaches the overlay purely on the triple
being present, independent of root strategy, so the mount the old comment said
this shape was waiting for is there. HVF's
`bail!("required-overlay hvf boots do not support virtiofs-root")` went with it:
that refusal existed because virtiofs-root's PID 1 was the rootfs `/init`.

**`CheckpointMeta`'s frozen digest moved**, because the field left the struct.
The literal is updated and the comment now records why, so it still fails loudly
on an accidental move. Checkpoints captured before this read as schema-stale
rather than tampered — the accepted cost of the no-back-compat rule on local
state.

`mvm-oci-init` is deleted. `mvm-verity-init` is **not**: the per-rootfs verity
initramfs is a separate removal, scoped on its own because it touches the sealed
boot path behind claim 3 and wants a real sealed boot as evidence.

## Decomposing `exec.rs`

Removing the policy deleted `mod runtime_source_policy_tests`, which sat at line
160 of `crates/mvm-cli/src/exec.rs`. `check-file-size` counts production lines
*before the first top-level `#[cfg(test)]`*, so that early module had been
capping the count at 160 while the file was really 2351. Deleting it exposed the
debt rather than created it.

`exec.rs` is now a module tree — `launch_plan.rs` (the mvmforge JSON parser),
`session.rs` (warm-VM lifecycle), `transient.rs` (boot/restore/teardown), and
`guest_run.rs` (in-guest dispatch and console diagnostics) — with each moved
test following the code it exercises. The `check-cli-runtime-surface` exemption
that covered `exec.rs` is extended to the new files with a reason naming them as
the same code, not a new reach.

## Gates

`fmt --all`, `clippy --workspace --all-targets` (zero warnings),
`nextest --workspace` (12,199 pass), `cargo test -p mvmctl`, `--doc`,
`just check-gated` (Linux cross-compile + the `--features bdd` conformance
build), and `xtask check-all` (61 gates).

Two gates caught misses a Rust-only sweep would have shipped:
`check-guest-binary-lists` found `mvm-oci-init` still listed in
`nix/packages/mvm-guest-agent.nix`, `nix/images/runtime-overlay/flake.nix`, and
three places in `.github/workflows/release-boot-image.yml`; and two `mvm-vmm`
tests caught an over-removal — `workload_cmdline`'s early return is real
behaviour (a bare config yields an empty cmdline so the driver uses its own
base) and only its policy conjunct was dead.
