# The trust model for a type-1 mvm (no host OS)

Date: 2026-08-18
Status: research. No decision taken; nothing here is implemented.

## The question

A [bare-metal EL2 spike](#appendix-what-the-spike-established) showed that mvm's
device model can drive a guest with no operating system underneath it. That
settles feasibility of the *mechanism*. It does not settle the question that
actually decides whether a type-1 mvm is a product direction:

> mvm's security posture rests on separate host processes and a filesystem.
> Bare metal has neither. What happens to the claims?

A type-1 mvm that quietly dropped claims 8, 12 and 13 would be a downgrade
wearing the same name. This note works out what those claims actually require,
which requirements survive, and which do not.

## What the claims rest on — mechanism, not policy

Three claims carry host-side state:

- **Claim 8** — every workload runs from a signed, audited `ExecutionPlan`.
  Needs: an Ed25519 private key that only the signer can read; an append-only,
  hash-chained log that survives reboot; and admission that runs before dispatch.
- **Claim 12** — every host service is bound to a signed `services` binding,
  enforced before handler dispatch. Needs: the enforcement point to be
  unreachable-around, and the enforcing code to be separable from the code that
  parses untrusted guest frames.
- **Claim 13** — no raw secret crosses the broker channel. Needs: an address
  space that holds cleartext secrets and that the guest-facing parser cannot
  read.

ADR-022 §3 states the structural rule: crates may merge, but "the separate
address-space *processes* that back the signing, audit, and admission claims may
not." ADR-020's ledger, which `xtask check-trust-gradient` enforces, is more
precise, and the precision matters:

| Tier | Layer | Forbidden authorities |
| --- | --- | --- |
| 2 | host | (none — holds all authority) |
| 1 | builder | signing-key, plan-admission, audit-writer |
| 0 | workload | signing-key, plan-admission, audit-writer, DevOnly verbs, console |

**That ledger is a capability model, not a process model.** It names *authorities
a tier may not hold*. A Unix process is the mechanism that currently enforces it,
not the thing being claimed. This is the hinge for everything below: the
requirement is an isolation boundary that a compromise cannot cross, not
specifically `fork()`.

## What bare metal removes — and what it adds

Removed: processes, a filesystem, uids, `setpriv`, seccomp, and every claim-1/2
mechanism that depends on a Linux kernel running on the host.

Added, and easy to undervalue:

- **EL2 is a stronger boundary than a process.** A Unix process is isolated by
  page tables the host kernel controls; compromise the kernel and every process
  falls together. An EL1 partition under an EL2 hypervisor is isolated by
  stage-2 translation the hypervisor controls, and the hypervisor is a few
  thousand lines rather than tens of millions. This is the entire argument
  pKVM and Hafnium make, and it applies here unchanged.
- **Measured boot is available.** With no OS underneath, the hypervisor is the
  first non-ROM code to run, so what it measures is what actually executed.
  Today's posture explicitly excludes hardware-backed key attestation as out of
  scope; bare metal is the tier where it becomes reachable.
- **The attack surface below mvm goes to approximately zero.** Today mvm trusts
  a Linux host it does not control. Out-of-scope threat #1 in ADR-001 is "a
  malicious host". A type-1 mvm *is* the host.

## Requirement by requirement

### The process moat → EL1 partitions

Map each host-tier role to its own EL1 partition under the mvm EL2 hypervisor:
signer, admission, audit-writer, and the guest-facing parser each get a
partition; stage-2 denies each access to the others' memory. The parser holds no
key and the signer never sees a guest frame — the same moat, on a stronger
primitive.

Cost: each partition needs a minimal runtime, and the inter-partition channel
becomes a new parsing surface that itself needs fuzzing — the moat's whole point
is that a parser compromise steals nothing, so the channel must be as fail-closed
as the vsock framing is today.

**Verdict: survives, and arguably improves.** `check-trust-gradient` would need a
new witness form (partition rather than `[[bin]]`), but the ledger it enforces is
unchanged.

### The keystore → derive, don't store

Today: an Ed25519 private key in a mode-0600 file. Bare metal has no file and no
uid to hide it behind.

The better answer is not to reproduce the file. Derive the host signing key at
boot from a hardware root — an eFuse/OTP secret or a TPM/OP-TEE-sealed blob —
into the signer partition's memory only, so it exists nowhere else and no
persistent artifact can be stolen offline. On a Pi 4 specifically there is **no
usable hardware root of trust** (no secure boot, no eFuse key storage a
third party can rely on), so on that board this reduces to "a key in flash",
which is weaker than mode 0600 on a trusted host.

**Verdict: better than today on hardware with a root of trust; worse on hardware
without one. This is a per-board property, and any claim has to state it.**

### The audit chain → the hard one

This is the requirement that does not have a clean answer.

The chain needs durable, append-only, ordered storage that survives reboot.
Bare metal means writing raw blocks (SD/eMMC/NVMe), so mvm would own: a storage
driver, a log structure, wear behaviour, and torn-write recovery — implementing
a large part of what a filesystem does, in the trusted computing base, where
every line is attack surface.

Three options, none free:

1. **Log-structured append to a raw partition.** Self-contained; adds a
   nontrivial driver and log implementation to the TCB.
2. **Externalize the chain.** The device holds only the chain head and streams
   entries to a remote log. Keeps the TCB small and matches the Merkle
   transparency work, but makes availability a dependency of admission — and a
   device that cannot reach the log must then decide between refusing to boot
   and running unaudited.
3. **Sealed volume on a host-managed medium.** Only coherent in a hybrid
   deployment, not true bare metal.

One thing that must not be overstated in either direction: **tail truncation is
already undetectable today.** The current chain detects tampering of interior
entries and detects a removed segment, but a truncated tail is not caught. Bare
metal has to match that bar, not exceed it.

**Verdict: the genuine blocker. Solvable, but it is the piece that decides
whether this is a year or a quarter.**

### Claims 1 and 2 → not applicable, and that is fine

"No host-fs access beyond explicit shares" and "no guest binary elevates to uid
0" are properties of a Linux host confining services with uids and seccomp.
A type-1 hypervisor has no host filesystem to reach and no host uids to
escalate to. The threat those claims answer is structurally absent.

The honest framing is *not* "claims 1 and 2 hold trivially" — it is that they
are the wrong claims for this tier, and the tier needs its own: stage-2
confinement of a guest to its assigned IPA range, and no guest path to EL2.
Those are new claims with new witnesses, not inherited ones.

## What genuinely cannot carry over

- **Anything depending on a Linux host kernel**: seccomp profiles, `setpriv`,
  uid separation, dm-verity as currently implemented (the mechanism moves into
  the hypervisor's own image verification).
- **The builder tier.** The builder VM runs `nix build` and needs a full Linux
  userspace. A type-1 mvm can *host* a builder VM as a guest, but it cannot be
  one. This is already the intended edge shape — a runtime-only host admitting
  signed bundles built elsewhere — so it costs little in practice.
- **`--prod` gating that lives in mvmd**, which assumes a control plane the
  device may not reach.

## Recommendation

Sequence the unknowns by what would kill the idea, cheapest first.

1. **Decide the audit-chain strategy before writing more VMM code.** It is the
   only requirement without a clean answer, and options 1 and 2 imply very
   different systems. Everything else is bounded work; this is a fork in the road.
2. **State the hardware-root dependency up front.** The keystore answer is a
   property of the board, not of mvm. A Pi 4 prototype cannot demonstrate the
   production key story, and should not be presented as though it could.
3. **Re-express the trust gradient in terms of authorities, not processes**,
   so `check-trust-gradient` can accept a partition as a tier boundary. This is
   useful independent of any bare-metal work: it makes the ledger say what it
   means.
4. **Only then** extend the spike — storage driver, SMP, a second partition —
   with the target shape known.

The thing to resist is building the VMM further because it is tractable and
enjoyable, while the audit question stays open. The VMM is not the risk.

## Appendix: what the spike established

A 430-line `no_std` aarch64 program boots at EL2, builds stage-2 tables, ERETs
into a guest at EL1, traps the guest's MMIO via `ESR_EL2`/`HPFAR_EL2`, and
emulates the device — the hypervisor received `"hi\n"` from a guest writing to
an unmapped "UART". It runs under `qemu-system-aarch64 -machine
virt,virtualization=on -cpu cortex-a72`, the same core (MIDR `0x410fd083`) as
the Pi 4 available for testing.

Its decoded exit matches `mvm_vmm::vmm::hv::VcpuExit::Mmio { phys_addr, write,
len, data }` field for field — not by design, but because `VcpuExit::Exception
{ syndrome, phys_addr }` already models the raw arm64 trap that an EL2 handler
reads. Measured host coupling in the existing device model: roughly 1,800 lines
carry none (`fdt.rs`, `kernel_image.rs`, `hv.rs`, `device_state.rs`,
`virtio_rng.rs`); the coupling is confined to `guest_mem.rs` (mmap),
`virtio.rs` (backing files) and `run.rs` (vCPU threads).

The spike carries no security claims and is not a production path.

## Prior art worth reading before committing

Rust type-1 hypervisors at EL2 exist and are published: Rust-Shyper
(peer-reviewed), syswonder/hvisor, a ~30K-line `no_std` ARM64 hypervisor
replacing Hafnium's SPMC, and Leo (type-1 for the Pi 4 specifically). ~30K lines
is the demonstrated scale of a real one — a useful anchor against the spike's
430.

Also relevant to the "how small can the hosting tier get" question: Cortex-R52+
is a *microcontroller* with EL2 and ships commercial hypervisors, and RISC-V's
H-extension scales down to small embedded parts. The tier boundary is "does the
part have a hypervisor mode and enough RAM", not "is it a microcontroller".
ESP32 specifically has neither an MMU nor a hypervisor mode and is genuinely
excluded.
