# Blog draft — "Hello anna": what it takes to prove a downloaded CLI boots a microVM in one command

**Status:** Continuous draft of the opening arc (hook → grounding → process topology → the boot bug). Sections 4–11 still outlined below. Not published.
**Source:** Synthesized from the macOS-26 bring-up + release-packaging work (PRs #1300, #1302, #1303, #1307, #1309, #1367, #1369).

*(alt subtitles: "The iceberg under `mvmctl run`" / "Every layer between a one-liner and a running guest")*

---

## Draft (continuous — in progress)

The command is six words long:

```
mvmctl run --image alpine -- echo "Hello anna"
```

Type it, wait a beat, and `Hello anna` prints. In that beat a real Linux virtual machine booted from a container image, ran your command, and tore itself down. The whole promise of a tool like this is that those six words are all you should ever have to hold in your head — no flags, no setup, no hint that a VM was ever involved.

This is a post about everything underneath the six words, and about a specifically harder version of the promise: that they work for someone who *downloaded* the tool. Not you — you have the source checked out, a warm build cache, and a laptop that's been booting microVMs all week. A stranger, on a clean machine, who ran an install script an hour ago and knows none of the internals. That one change of audience moves almost everything, because a downloaded binary can't quietly lean on the scaffolding your development machine has been providing for free.

Making it true meant reasoning through a surprising stack of independent concerns: the fleet of processes the single command actually spawns, whether the guest kernel can even see its own disk, how a binary finds its helpers on a machine it has never run on, what the operating system will let it do, the state it leaves lying around, whether it builds the same bytes everywhere — and the fact that all of it multiplies across three different hypervisors. Then a second problem stacked on the first: how do you *prove* the whole thing works without cutting a real, irreversible release to find out?

None of that elaborateness is accidental, and this is the lens worth carrying through the rest of the post: mvm is a security-first tool, and almost every layer below is a security decision before it's a functionality one. The reason to reach for a microVM at all is that you want to run code you don't fully trust behind a hardware isolation boundary rather than a shared kernel you're hoping holds. Once that's the starting posture, a cascade follows and stops being optional. The guest gets the smallest kernel that will still boot, because every driver compiled in is attack surface a hostile guest could probe. Its only path to the network runs through a separate, confined process that default-denies egress and writes a tamper-evident audit log — because the one place untrusted guest traffic meets the host is exactly the place you want isolated and watched. And the artifact you downloaded has to be one you can actually verify — signed, checksummed, reproducible — because a security tool you can't check is just a liability with good intentions. The download problem is hard in large part *because* the security bar is high; a lower bar would let you ship a single fat binary and call it done.

We'll walk the layers roughly in the order the guest meets them. First, though, some grounding for anyone who hasn't met mvm before.

### First, some grounding: what is mvm?

mvm is a command-line tool for running microVMs. You hand it a container image and it boots that image inside a real, isolated Linux virtual machine — `mvmctl run --image alpine -- echo hi` — and the whole point is to make that feel about as lightweight as running a container while giving you the isolation of a full VM.

That distinction carries more weight than it sounds. A container isn't really its own machine; it's a set of processes sharing *your* kernel, fenced off with namespaces and cgroups. A microVM is an actual virtual machine with its own kernel running behind a hardware hypervisor, so a break-in inside the guest is contained by the CPU's virtualization boundary rather than by kernel features that occasionally spring leaks. That isolation used to mean a slow, heavy VM — but a microVM strips the machine down to almost nothing (a minimal kernel, a handful of virtual devices, no BIOS or emulated legacy hardware), which pulls boot times back down to a fraction of a second. Firecracker, the monitor AWS wrote to run Lambda and Fargate, is the canonical example, and it's what mvm uses on Linux.

Which brings us to the complication at the heart of this post: Firecracker only runs on Linux. It leans on KVM, the kernel's hardware-virtualization interface, and there is no KVM on macOS. But mvm is a tool people run on their laptops — most of them Macs — so it can't insist on Firecracker. Instead it uses whatever hypervisor the host happens to offer: Firecracker on Linux, libkrun (a lightweight in-process monitor) on older macOS, and Apple's own Virtualization.framework — which we'll call vz — on macOS 26 and up. The thing to hold onto is that the *same one-line command* boots on a *different hypervisor* depending on who runs it, and those hypervisors, as we're about to see, don't present the guest's virtual hardware the same way.

A little shared vocabulary and you're set. The *host* is your laptop running `mvmctl`; the *guest* is the Linux VM it boots. The guest reaches its virtual disk, network, and console through *virtio*, the paravirtual device standard every modern Linux kernel speaks, and the host talks to a small agent process inside the guest over *vsock*, a direct host-to-guest socket that never touches the network. One last wrinkle worth planting now: mvm builds its guest images with Nix, and for reproducibility it runs Nix *inside its own Linux VM* rather than on your host — so two VMs keep turning up in these stories, the *builder VM* that produces images and the *workload VM* that runs yours. Both boot the same kernel, which is precisely why a single kernel change can knock out both at once.

### The command is a quiet lie

Start with the shape of what "run" actually does, because it's the first place the one-command story stops being literally true. You typed one command and you're waiting on one exit code, so it's natural to imagine one program doing the work. There isn't one. For every guest it boots, mvm stands up a small constellation of *host-side* processes: a per-VM supervisor that owns the hypervisor and the VM's lifecycle — `mvm-vz-supervisor` on macOS 26, `mvm-libkrun-supervisor` on older macOS — and, alongside it, a sidecar called `mvm-bridge` that sits between the guest's network and the outside world, enforcing egress policy and writing the audit log.

The split is deliberate, and it's a security decision before it's an architectural one. `mvm-bridge` sits on the single path where untrusted guest traffic reaches the host, and it does the two jobs you most want isolated and watched: it enforces the guest's egress policy — default-deny, opened only to what the workload was explicitly allowed to talk to — and it writes a tamper-evident audit log of what crossed. Because it's the component chewing on potentially-hostile bytes, it runs in its own process (confined with seccomp and Landlock on Linux) where a bug in it can't reach the process holding the hypervisor handle. The supervisor owns that handle, which makes it the natural owner of start, stop, and teardown. Put together, "one command" is really an orchestrator quietly conducting a handful of programs that all have to be present, findable, and trusted for the six words to work — and the reason there's more than one program in the first place is that confinement wants boundaries between them.

That last clause is why this section exists. Run mvm from a source checkout and you never notice the constellation, because every one of those binaries is sitting in your `target/` directory where the tooling finds them without trying. Ship it, and the entrypoint and its helpers immediately part ways. Almost everything that follows is, in one form or another, about keeping them together on a machine that only ever received a single download.

### The guest has to actually boot

Those helper processes all assume something they can't provide for themselves: a guest that actually came up. And before packaging or signing or any of the download story matters, that blunt fact has to hold — the guest kernel has to boot and find its devices. A microVM is worthless if it comes up deaf and blind, and "deaf and blind" is exactly the failure mode that cost us the most, because it doesn't look like a boot failure. It looks like a hang.

Here's the thing nobody tells you when you support more than one hypervisor: they don't present devices the same way. A modern Linux guest talks to its virtual disk, console, network, and vsock through virtio, but virtio is just the device *protocol* — it still has to be attached to a *bus* the kernel probes. libkrun and Firecracker attach virtio devices over **MMIO** (memory-mapped I/O, a flat register window the kernel is told about on the command line). Apple's Virtualization.framework — the backend we use on macOS 26 — attaches them over **PCI**. Same virtio, different bus. The guest kernel needs `CONFIG_VIRTIO_MMIO` to see the first kind and `CONFIG_PCI` + `CONFIG_VIRTIO_PCI` to see the second.

We ship one kernel config, shared across all three backends. That's deliberate: one artifact, one thing to audit, one thing to slim. And slimming isn't cosmetic — it's the same security posture again. A hostile guest runs on this kernel, so every built-in driver is attack surface it could probe, and we run a subtraction pass that strips subsystems a headless microVM never touches. The bug in this story is, in a real sense, the *cost* of a security decision: the drive to carry the least kernel we can is exactly what made someone reach for the delete key on a subsystem one backend quietly needed. At some point that pass dropped `PCI` and `VIRTIO_PCI`, with an entirely reasonable-sounding justification in the diff: *libkrun and Firecracker present virtio over MMIO.* Which is true. It's just not the whole sentence. The whole sentence ends "…and vz presents it over PCI," and that clause was missing.

The result was a kernel that booted perfectly on two of three backends and, on the third, booted into a void. The vz guest started, the CPU ran, and then — nothing. No virtio-console, so the console log was **literally zero bytes**. No virtio-block, so no root filesystem. No virtio-vsock, so no way for the host to reach the in-guest agent. The VM was "running" in every sense the hypervisor cared about and unreachable in every sense we cared about.

What made it genuinely nasty is that it didn't present as one bug. It presented as two, in two different subsystems, filed separately:

- The **builder VM** (the guest that runs `nix build` to produce images) came up blind, never wrote its "ready" line to the console we were tailing, and got reaped by a 30-minute timeout. That looked like a *build hang*.
- The **workload VM** (the one running your actual `alpine` container) came up blind, so the host's agent handshake over vsock never connected. That looked like an *agent-reachability timeout*.

Two tickets, two symptoms, two subsystems — one missing kernel symbol. And crucially, nothing failed to compile. The kernel built. It linked. It passed the size budget (it was *smaller*, which was the point). It booted fine in every test that happened to run on libkrun. There was no red X anywhere pointing at the actual defect; the only signal was a hypervisor-specific symptom two layers away from the cause.

The fix was three lines — re-enable `PCI`, `PCI_MSI`, and `VIRTIO_PCI` (the generic ECAM host controller the vz bus needs comes back on its own from `make defconfig` once PCI is enabled). The proof it worked was the console log going from 0 bytes to the boring, beautiful output you want from a boot:

```
EXT4-fs (vdb): mounted filesystem ... r/w      ← virtio-block, over PCI
mvm-guest-agent: control plane ready (0ms)     ← virtio-vsock, over PCI
mvm-builderd: listening on AF_VSOCK port 21473
```

Both "bugs" closed on that one change.

There's a real tension worth naming, because this isn't a story about a careless mistake. The slimming was *correct engineering* — a smaller kernel is less attack surface and a faster boot, and re-adding PCI cost us about 73 built-in symbols we'd rather not carry. The failure wasn't the ambition to slim; it was that a shared artifact serving several consumers with different, *invisible* contracts is a landmine, and the contract that got violated — how devices are presented — is exactly the kind that never shows up in a type signature or a linker error. You only find out at boot, on one specific backend, as a symptom in a different subsystem.

The durable lesson: when one artifact has to satisfy multiple backends, the backends' implicit requirements need to be as loud as their explicit ones. A comment that says "MMIO-only, dead weight" is a claim about *all* consumers, and it was wrong about one of them. We keep PCI in now with a comment that spells out why — that vz needs it — so the next person running a subtraction pass reads the whole sentence. And the broader defense isn't a comment at all: a shared kernel change isn't "done" when it compiles and passes a size gate; it's done when it has booted, once, on every backend that consumes it. Two-of-three green is how you ship a guest that comes up blind.

> **Still to draft (in this same continuous voice):** §4 packaging & binary resolution · §5 trust/signing/supply-chain · §6 warm-pool state & lifecycle · §7 reproducible builds · §8 the platform matrix · §9 proving it without shipping · §10 the two habits · §11 close. Outline below.

---

## Outline (the full map)

### 1. The hook: one command, one honest question *(drafted above)*
- The literal goal: `mvmctl run --image alpine -- echo "Hello anna"` should Just Work for someone who **downloaded a binary** — no repo, no build, no docs.
- Thesis: a single command is a *user-facing* simplicity paid for by *cross-cutting* complexity — and requiring it for a **downloaded** artifact (not your dev checkout) brings a dozen hidden assumptions due at once.
- Two distinct problems: (a) the layers that must line up for the guest to boot, and (b) the meta-problem of **proving** they line up without cutting a real release.

### 1.5 Background: what mvm is *(drafted above)*
- What mvm is; microVM vs container; host vs guest; builder VM vs workload VM; the per-platform backends (Firecracker/libkrun/vz); the virtio/vsock/guest-agent vocabulary.

### 2. The command is a quiet lie (process topology) *(drafted above)*
- One command → multiple host processes per guest (supervisor + `mvm-bridge` sidecar); why they're split; from a checkout `target/` hides it; shipping parts them.

### 3. The guest actually has to boot *(drafted above)*
- virtio-over-PCI (vz) vs -MMIO (libkrun/Firecracker); the slim-kernel cut that booted vz blind; one bug that looked like two; boot-on-every-backend as the real gate.

### 4. Getting the bits onto the machine (packaging & binary resolution)
- Release shipped only `mvmctl`; helpers never packaged → stranded on a download.
- Resolver ladder: `MVM_BRIDGE_PATH` → adjacent-to-exe → source `target/`. "Adjacent" is the whole ballgame for a download.
- Two edits, one idea: bundle helpers in the tarball **and** install them next to `mvmctl`.
- **Security angle:** "adjacent-to-exe" isn't only convenience — resolving the helper *you shipped* (over, say, whatever `mvm-bridge` happens to be on `$PATH`) keeps the trust boundary tight; the confined sidecar the CLI spawns should be the exact signed binary that came in the tarball.
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
- **Security angle:** reproducibility is the thing that makes "trusted download" *checkable* — if the same inputs don't yield the same bytes, "verify before you run" is meaningless and hash-pinning/signing lose their teeth. Determinism is a supply-chain integrity property, not just hygiene.
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
- Glossary (below).

---

## Glossary

- **microVM** — a stripped-down virtual machine (minimal kernel, a few paravirtual devices, no legacy hardware) that boots in a fraction of a second; VM-grade isolation at near-container speed.
- **host / guest** — the host is your Mac/Linux machine running `mvmctl`; the guest is the Linux VM it boots.
- **hypervisor / backend** — the thing that actually runs the VM. mvm's backends: **Firecracker** (Linux/KVM), **libkrun** (older macOS, in-process), **vz** (Apple's Virtualization.framework, macOS 26+).
- **KVM** — the Linux kernel's hardware-virtualization interface (`/dev/kvm`). Firecracker needs it; it doesn't exist on macOS.
- **virtio** — the standard paravirtual device protocol a guest uses for disk, network, console, vsock, etc.
- **PCI vs MMIO** — the two *buses* virtio devices can be attached to. libkrun/Firecracker use MMIO; vz uses PCI. The guest kernel needs the matching support compiled in to see its devices (the boot section).
- **vsock** — a direct host↔guest socket channel (no network) used to reach the guest agent.
- **guest agent** — a small process inside the VM that the host talks to over vsock (readiness, exec, etc.).
- **builder VM vs workload VM** — mvm runs Nix *inside a Linux VM* to build guest images (the builder VM); the workload VM is the one that runs your image. Both boot the same shared kernel.
- **supervisor / sidecar** — host-side helper processes mvm spawns per guest: a per-VM VMM *supervisor* (`mvm-vz-supervisor` / `mvm-libkrun-supervisor`) and the `mvm-bridge` gateway/audit *sidecar*.
- **mvmctl** — the CLI binary; "mvm" is the project.
