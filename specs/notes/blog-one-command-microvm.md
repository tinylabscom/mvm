# Blog draft — "Hello anna": what it takes to prove a downloaded CLI boots a microVM in one command

**Status:** Draft outline + Section 3 written. Not published.
**Source:** Synthesized from the macOS-26 bring-up + release-packaging work (PRs #1300, #1302, #1303, #1307, #1309, #1367, #1369).

---

## Outline

**Working title:** "Hello anna": what it actually takes to prove a downloaded CLI boots a microVM in one command
*(alt subtitles: "The iceberg under `mvmctl run`" / "Every layer between a one-liner and a running guest")*

### 1. The hook: one command, one honest question
- The literal goal: `mvmctl run --image alpine -- echo "Hello anna"` should Just Work for someone who **downloaded a binary** — no repo, no build, no docs.
- Thesis: a single command is a *user-facing* simplicity paid for by *cross-cutting* complexity — and requiring it for a **downloaded** artifact (not your dev checkout) brings a dozen hidden assumptions due at once.
- Two distinct problems: (a) the layers that must line up for the guest to boot, and (b) the meta-problem of **proving** they line up without cutting a real release.

### 1.5 Background: what mvm is, and the words we'll need *(read this first)*
- **What mvm is:** a command-line tool (`mvmctl`) for building and running lightweight **microVMs** on macOS and Linux. Target UX: run a container/OCI image inside a real, isolated Linux VM with one command.
- **microVM vs container, in two sentences:** a container shares the host's kernel (namespaces + cgroups); a **microVM boots its own kernel behind a hypervisor** — hardware-level isolation, but small and fast (sub-second boot, a handful of virtual devices). Firecracker (the thing behind AWS Lambda/Fargate) is the reference point.
- **Host vs guest:** the *host* is your Mac/Linux box running `mvmctl`; the *guest* is the Linux VM it boots.
- **Two kinds of VM in play:** a **builder VM** (mvm builds guest images with Nix, and runs Nix *inside a Linux VM* for determinism) and a **workload VM** (runs your actual image). Both boot the same shared kernel — which is why the kernel story hits both.
- **The backends, and why they differ by platform:** you can't run Firecracker on macOS (no KVM), so the *same command* dispatches to a **different hypervisor** depending on the host — **Firecracker** (Linux/KVM), **libkrun** (older macOS), or **Apple's Virtualization.framework — "vz"** (macOS 26+). This platform-dependent dispatch is the seed of the whole post.
- **Vocabulary the rest leans on:** *virtio* (the standard paravirtual device protocol — disk, net, console, vsock), *vsock* (a host↔guest socket channel), the *guest agent* (a small in-guest process the host talks to over vsock), and *supervisors/sidecars* (host-side helper processes mvm spawns per VM).
- **Why it's here:** every later section assumes this. A reader who's never heard of mvm should still follow the "guest boots blind" story.

### 2. The command is a small lie (process topology)
- Naive model: "a CLI runs a VM." Reality: `mvmctl` orchestrates **multiple host processes** per guest — a per-VM supervisor (`mvm-vz-supervisor` / `mvm-libkrun-supervisor`) and a gateway/audit sidecar (`mvm-bridge`).
- Why split (external-VMM backends fork+exec a supervisor; the bridge enforces egress/audit out-of-process).
- **Takeaway:** "single command" ≠ "single process." Anything that ships or resolves binaries must know the whole process tree.

### 3. The guest actually has to boot (kernel × hypervisor device models)
- virtio-over-PCI (vz / Apple Virtualization.framework) vs virtio-over-MMIO (libkrun / Firecracker).
- A kernel-slimming pass dropped PCI ("MMIO-only, dead weight") — safe for two backends, silently fatal for the third; vz guests boot blind.
- One shared kernel config serving three device models; the bug that looked like two bugs.
- **Takeaway:** the device-presentation contract is invisible until it isn't; shared cross-backend artifacts need a per-backend boot check, not "it compiles."

### 4. Getting the bits onto the machine (packaging & binary resolution)
- Release shipped only `mvmctl`; helpers never packaged → stranded on a download.
- Resolver ladder: `MVM_BRIDGE_PATH` → adjacent-to-exe → source `target/`. "Adjacent" is the whole ballgame for a download.
- Two edits, one idea: bundle helpers in the tarball **and** install them next to `mvmctl`.
- **Takeaway:** the unit of distribution is the *process tree*, not the entrypoint; "works from my checkout" hides this because `target/` does the resolver's job for free.

### 5. The machine has to trust the bits (signing, entitlements, supply chain)
- macOS: VMM supervisors need VZ/Hypervisor entitlements; they **self-sign** at first spawn.
- The trust chain: cosign keyless signing, SHA-256 checksums, hash-pinned seeds — a chain, not a step.
- Surprise cameo: Homebrew's untrusted-tap policy (`brew trust`) — a dependency's own supply-chain gate breaking our build.
- **Takeaway:** "downloaded" implies a trust boundary at every hop; each is a place the one-liner can silently fail.

### 6. State hides behind a "stateless" command (warm pool & lifecycle)
- Red herring: an "orphan supervisor" that was the intentional warm/standby pool (always-warm residency, TTL).
- Real bug: the standby reaper only ran on `cache prune`, never the launch path → no-daemon TTL never enforced on use. Reap-on-use fix.
- No-daemon lifecycle: expiry is lazy or self-expiring; TTL relations between independent constants become tested invariants.
- **Takeaway:** a stateless-looking command still leaves state; telling "intended cache" from "leak" is half the work.

### 7. It has to build the *same* thing everywhere (reproducibility)
- The unseen bootstrap: pinned Nix seed → builder VM image → materialize OCI rootfs, so a download builds locally with no host Nix.
- Determinism trap: a narHash divergence between Nix versions — same source, different computed hash — broke fresh-machine builds while warm caches masked it.
- **Takeaway:** "reproducible" has a version axis; a pinned input isn't enough if the tool computing identity drifts. Warm caches hide fresh-install breakage.

### 8. The platform matrix multiplies all of the above
- Three worlds: macOS 13–25 (libkrun), macOS 26 (vz), Linux (Firecracker) + builder-backend selection + auto-fallbacks.
- Per-OS feature gating as design: `libkrun-sys` is macOS-only → "Linux doesn't ship the libkrun supervisor, by design" (a follow-up that turned out to be a non-issue after investigation).
- **Takeaway:** every piece above is really *piece × platform*.

### 9. The meta-problem: proving it without shipping it
- Your dev machine cheats (source tree, warm caches, pre-signed bins), so building it ≠ knowing it works for a download.
- The wall: only a `v*` tag runs the release pipeline, and that tag is an irreversible publish (public release + crates.io). No dry-run existed.
- The fix: a no-publish dry-run (`workflow_dispatch` + gated `dry_run`) that builds + packages on real runners and publishes nothing; download artifacts and inspect the tarball as proof.
- The twist: the dry-run immediately surfaced two pre-existing, unrelated release-blockers (brew tap; a stale smoke test hitting a renamed subcommand).
- **Takeaway:** "prove it works" needs a safe way to run the real thing; a dry-run is a first-class feature and doubles as a fast fix loop.

### 10. Two habits that did the heavy lifting
- Transient vs. real: a scary "storage device attachment invalid" that was corrupted state from killed debug runs — reproduce from clean state before believing an error.
- Investigate before implementing: the "Linux libkrun packaging" follow-up that traced out to *unnecessary* — got a comment, not code.
- (Optional) the plumbing tax: merge queues, stacked PRs, rebasing after a squash.

### 11. Closing: the shape of "just works"
- A one-liner is an SLA against a whole stack + a way to prove it without shipping.
- One-sentence recap per layer.
- End on the "Hello anna" payoff — same six words, now provable on a machine that never saw the source.

### Appendices (optional)
- "Layer cake" diagram: download → install (adjacent bins) → resolve → sign → boot (PCI!) → bridge → guest.
- PR trail (the receipts).
- Checklist: "Is your one-command CLI actually downloadable?" (ships all processes? resolves adjacent? signs at runtime? builds deterministically? has a no-publish dry-run?).
- **Glossary** — one-line definitions (drafted below) for skimmers who jump straight to a section.

---

## Background — what is mvm? (draft)

If you've never touched mvm, here's everything you need to follow the rest of this post.

**mvm is a command-line tool for running microVMs.** You point it at a container image and it boots that image inside a real, isolated Linux virtual machine — `mvmctl run --image alpine -- echo hi`. The whole design goal is to make that feel about as light as running a container while giving you the isolation of a full VM.

**Why a microVM instead of a container?** A container isn't really its own machine — it's a set of processes running on *your* kernel, walled off with namespaces and cgroups. A microVM is an actual virtual machine: it boots its own Linux kernel behind a hardware hypervisor, so a compromise inside the guest can't reach the host kernel the way a container escape can. The trick that makes this practical is stripping the VM down to almost nothing — a minimal kernel, a few paravirtual devices, no BIOS, no emulated legacy hardware — so it boots in a fraction of a second. Firecracker, the microVM monitor AWS built for Lambda, is the canonical example; mvm uses it on Linux.

**The catch that drives this whole post: you can't run Firecracker on a Mac.** Firecracker needs KVM, the Linux kernel's virtualization interface, which doesn't exist on macOS. So mvm has to use whichever hypervisor the host *does* offer, and that changes by platform:

- **Linux** → **Firecracker** (via `/dev/kvm`)
- **older macOS** → **libkrun**, a lightweight in-process VM monitor
- **macOS 26+** → **Apple's Virtualization.framework**, which we call **vz**

So the same one-line command runs on a *different hypervisor* depending on who typed it — and, as the next section shows, those hypervisors don't hand the guest its virtual devices the same way.

**A few more words you'll see:**
- **Host** and **guest** — the host is your laptop running `mvmctl`; the guest is the Linux VM it boots.
- **virtio** — the standard way a guest talks to its virtual disk, network, console, etc.: a paravirtual device protocol every modern Linux kernel speaks.
- **vsock** — a socket that connects host and guest directly (no network involved), which mvm uses to reach a small **guest agent** process running inside the VM.
- **builder VM** — mvm builds its guest images with Nix and, for reproducibility, runs Nix *inside its own Linux VM* rather than on your host. So two VMs appear in this story: the *builder VM* that produces images and the *workload VM* that runs yours. Both boot the same shared kernel.

With that, the failure in the next section — a guest that boots but comes up deaf and blind — will make sense.

---

## Section 3 — The guest actually has to boot (draft)

Before packaging matters, before signing matters, before any of the download story matters, one brute fact has to hold: the guest kernel has to boot and find its devices. A microVM is worthless if it comes up deaf and blind — and "deaf and blind" is exactly the failure mode that cost us the most, because it doesn't look like a boot failure. It looks like a hang.

Here's the thing nobody tells you when you support more than one hypervisor: **they don't present devices the same way.** A modern Linux guest talks to its virtual disk, console, network, and vsock through virtio, but virtio is just the device *protocol* — it still has to be attached to a *bus* the kernel probes. libkrun and Firecracker attach virtio devices over **MMIO** (memory-mapped I/O, a flat register window the kernel is told about on the command line). Apple's Virtualization.framework — the backend we use on macOS 26 — attaches them over **PCI**. Same virtio, different bus. The guest kernel needs `CONFIG_VIRTIO_MMIO` to see the first kind and `CONFIG_PCI` + `CONFIG_VIRTIO_PCI` to see the second.

We ship one kernel config, shared across all three backends. That's deliberate: one artifact, one thing to audit, one thing to slim. And slimming is a real goal — every built-in driver is attack surface, so we run a subtraction pass that strips subsystems a headless microVM never touches. At some point that pass dropped `PCI` and `VIRTIO_PCI`, with an entirely reasonable-sounding justification in the diff: *libkrun and Firecracker present virtio over MMIO.* Which is true. It's just not the whole sentence. The whole sentence ends "…and vz presents it over PCI," and that clause was missing.

The result was a kernel that booted perfectly on two of three backends and, on the third, booted into a void. The vz guest started, the CPU ran, and then — nothing. No virtio-console, so the console log was **literally zero bytes**. No virtio-block, so no root filesystem. No virtio-vsock, so no way for the host to reach the in-guest agent. The VM was "running" in every sense the hypervisor cared about and unreachable in every sense we cared about.

What made this genuinely nasty is that it didn't present as one bug. It presented as two, in two different subsystems, filed separately:

- The **builder VM** (the guest that runs `nix build` to produce images) came up blind, never wrote its "ready" line to the console we were tailing, and got reaped by a 30-minute timeout. That looked like a *build hang*.
- The **workload VM** (the one running your actual `alpine` container) came up blind, so the host's agent handshake over vsock never connected. That looked like an *agent-reachability timeout*.

Two tickets, two symptoms, two subsystems — one missing kernel symbol. And crucially, **nothing failed to compile.** The kernel built. It linked. It passed the size budget (it was *smaller*, which was the point). It booted fine in every test that happened to run on libkrun. There was no red X anywhere pointing at the actual defect; the only signal was a hypervisor-specific symptom two layers away from the cause.

The fix was three lines — re-enable `PCI`, `PCI_MSI`, and `VIRTIO_PCI` (the generic ECAM host controller the AVF bus needs comes back automatically from `make defconfig` once PCI is on). The proof it worked was the console log going from 0 bytes to the boring, beautiful output you want from a boot:

```
EXT4-fs (vdb): mounted filesystem ... r/w      ← virtio-block, over PCI
mvm-guest-agent: control plane ready (0ms)     ← virtio-vsock, over PCI
mvm-builderd: listening on AF_VSOCK port 21473
```

Both "bugs" closed on that one change.

There's a real tension worth naming, because it's not a story about a careless mistake. The slimming was *correct engineering* — a smaller kernel is less attack surface and a faster boot, and re-adding PCI cost us about 73 built-in symbols we'd rather not carry. The failure wasn't the ambition to slim; it was that a **shared artifact serving several consumers with different, invisible contracts** is a landmine, and the contract that got violated (device presentation) is exactly the kind that never shows up in a type signature or a linker error. You only find out at boot, on one specific backend, as a symptom in a different subsystem.

The durable lesson: when one artifact has to satisfy multiple backends, the backends' *implicit* requirements need to be as loud as their explicit ones. A comment that says "MMIO-only, dead weight" is a claim about all consumers, and it was wrong about one of them. We now keep PCI in with a comment that spells out *why* — that vz needs it — so the next person running a subtraction pass reads the whole sentence. And the broader defense isn't a comment at all: it's that a shared kernel change isn't "done" when it compiles and passes a size gate; it's done when it has **booted, once, on every backend that consumes it.** Two of three green is how you ship a guest that comes up blind.

---

## Appendix — Glossary (draft)

- **microVM** — a stripped-down virtual machine (minimal kernel, a few paravirtual devices, no legacy hardware) that boots in a fraction of a second; VM-grade isolation at near-container speed.
- **host / guest** — the host is your Mac/Linux machine running `mvmctl`; the guest is the Linux VM it boots.
- **hypervisor / backend** — the thing that actually runs the VM. mvm's backends: **Firecracker** (Linux/KVM), **libkrun** (older macOS, in-process), **vz** (Apple's Virtualization.framework, macOS 26+).
- **KVM** — the Linux kernel's hardware-virtualization interface (`/dev/kvm`). Firecracker needs it; it doesn't exist on macOS.
- **virtio** — the standard paravirtual device protocol a guest uses for disk, network, console, vsock, etc.
- **PCI vs MMIO** — the two *buses* virtio devices can be attached to. libkrun/Firecracker use MMIO; vz uses PCI. The guest kernel needs the matching support compiled in to see its devices (Section 3).
- **vsock** — a direct host↔guest socket channel (no network) used to reach the guest agent.
- **guest agent** — a small process inside the VM that the host talks to over vsock (readiness, exec, etc.).
- **builder VM vs workload VM** — mvm runs Nix *inside a Linux VM* to build guest images (the builder VM); the workload VM is the one that runs your image. Both boot the same shared kernel.
- **supervisor / sidecar** — host-side helper processes mvm spawns per guest: a per-VM VMM *supervisor* (`mvm-vz-supervisor` / `mvm-libkrun-supervisor`) and the `mvm-bridge` gateway/audit *sidecar*.
- **mvmctl** — the CLI binary; "mvm" is the project.
