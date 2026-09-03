# Changelog

All notable changes to mvm are documented in this file.

## [0.18.0] — 2026-09-02

### Added
- **mvm-cli**: Fetch + apply the signed pack revocation list (Plan 213 §I)
- **release**: Publish + verify a signed pack revocation list
- **mvm-build**: Runtime pack carries verity-sealed rootfs (kernel+rootfs+verity+roothash)
- **mvm-cli**: Boot a workload from a verified runtime pack (§E E1b, claims intact)
- **backend**: Delete the Vz backend — HVF is the sole macOS backend (Plan 226 R1P1)
- **mvm-cli**: Default machine run auto-prefers a verified runtime pack
- **mvm-cli**: Boot persistent machines from a verified runtime pack
- **mvm-cli**: Explain why instant launch is unavailable + add `mvm prepare`
- **mvm-cli**: Mvm cache status + pack cache index + expired-pack prune
- Enterprise pack mirror + fetch-policy modes
- **mvm-cli**: `mvm explain <run-id>` renders a run's attestation from the audit chain
- **guest**: Deliver host-signer verb-grant anchor to vsock-only guests
- **hvf**: Gate egress endpoint on admitted policy
- **oci**: Verity-seal foundation — fail-closed initrd guard + seal capability
- **oci**: Assemble the verity initramfs in-process (Slice 2a)
- **oci**: Wire --prod to a bootable verity-sealed image (Slice 2b)
- **net-tunnel**: Raw-L3 host-forwarded egress data plane (Plan 236 Phase 2A)
- **net-tunnel**: MacOS userspace smoltcp TCP egress forwarder (Plan 236 Phase 2A)
- **net-tunnel**: Macos smoltcp UDP egress forwarder (ICMP deferred)
- **oci**: Bake verb-trust.json into the sealed image (Plan 236 §1.4)
- **net-tunnel**: Macos smoltcp ICMP echo relay
- Roll out readonly guest runtime overlay
- **net-tunnel**: Unify host egress on smoltcp, retire host-TUN + kernel NAT
- **oci-run**: Log workload-kernel provenance on resolution
- **deps**: RustCrypto 0.10→0.11 + aws-lc-rs removal (Plan 126 B4/C1)
- **net**: Wire the smoltcp egress tunnel into the transient run path
- **overlay**: Overlay-only runtime — make the runtime overlay the sole guest-binary source, delete mkGuest baking
- **net**: Wire the smoltcp egress tunnel into the HVF workload backend
- **net**: Ship mvm-guest-netd in the runtime overlay (OCI tunnel pump)
- **builder**: Enable the steady-state libkrun builder on Linux
- **xtask**: Gate file production size at 1500 lines (check-file-size)
- **runtime**: Dispatch backend metadata through the VmmDriver seam
- **runtime**: Share the workload kernel-cmdline assembler with WorkloadRunner
- **runtime**: Lift the host-services broker into WorkloadRunner
- **runtime**: Carry user-volume disks + mvm.uvols token through WorkloadRunner
- **cli**: Mvmctl build address + workload semantic-identity conformance lock + BDD
- **runtime**: Make the workload base bootargs driver-provided
- **runtime**: Add LibkrunDriver (VmmDriver mechanics, dormant)
- **libkrun-sys**: Allow an explicit host UDS for a host-listen egress port
- **runtime**: Route libkrun workloads through WorkloadRunner
- Hash-linked, chain-anchored checkpoint lineage
- **net**: Add policy-gated in-seam DNS resolver
- **fs**: Add portable snapshot store
- **runtime**: Converge Firecracker onto the WorkloadRunner (FcDriver)
- **runtime**: Gate the uniform vsock-egress convergence + drop dead start_firecracker
- **runtime**: Converge HVF onto the vsock runner + fail-closed egress
- **sdk**: Sandbox.connect() inherits the dev-only exec guard
- **bdd**: Live transient sandbox boot, ping egress, and cleanup
- **mvm-core**: Content-address plan_id
- **mvm-core**: Image-lineage node model, store, and verification (B1 of #1808)
- **mvm-cli**: Create audited image-lineage nodes on build
- **lineage**: Read-only machine timeline over checkpoint and image DAGs
- **lineage**: Time-travel revert/rewind/advance restore verbs (C2, closes #1809)
- **lineage**: Restore exact flake image revisions
- **mvm-protocol**: No_std Merkle transparency-log module (#1811 slice 1)
- **audit**: Host Merkle root builder + trust-audit verbs, tenant-bound
- **plan-255**: Vsock-first snapshot storage — Phase 0 + Phase 1
- Plan 265 fast-start foundation — no-NIC restore guard, page-merge policy, SLO helper
- Add mvm.toml examples and manifest parser fixture tests
- **light-guest**: Static-musl setpriv drops glibc from the guest rootfs, gated in CI
- **mvm-runtime**: Plan 265 warm restore — no-NIC guard on pause/resume + fork un-bail + live @live harness + positioning docs
- **plan-255**: Warm-pool claim substrate — Phase 2 slice one
- **mvm-runtime**: Adopt vm-memory behind the GuestMem seam
- **mvm-cli**: Instant-loop interaction-latency gate; retire the ops bench verb
- **mvm-runtime**: Adopt virtio-queue for the in-house VMM's vsock TX ring walk
- **mvm-runtime**: Adopt virtio-queue for the in-house VMM's vsock RX delivery
- **mvm-runtime**: Adopt virtio-vsock's typed packet for the vsock header parse/format
- **mvm-runtime**: Adopt virtio-queue for the in-house VMM's block and fs rings
- Complete vsock-first warm-pool adoption
- **plan-255**: Live Firecracker warm-claim substrate (capability disarmed)
- **mvm-cli**: Add a machine warm-restore verb for vm_full checkpoints
- **runtime**: Converge HVF onto the vsock workload runner + fail-closed egress
- **conformance**: Model-driven claim register and R1-R4 gates
- **standby**: Give a claimed child the host channels a cold boot gets
- **270**: Universal initramfs with vsock-activated boot
- **apple-container**: Stage-1 backend skeleton + plan 271
- **qemu**: Converge onto the unified workload runner + vsock activation
- **pool**: Let egress-allowing launches use the warm pool
- **docker**: Opt-in dev-tier container backend with agent-as-PID-1 activation (ADR-034)
- **xtask**: Mutation-test the claim witnesses, not just their presence
- **test**: Give nextest the ci profile the Justfile has always named
- **abi**: Pin every repr(C) layout to its authoritative header and gate it
- **apple-container**: Boot Apple's container stack on the in-house HVF VMM + vminitd gRPC client + no-VZ gate
- **egress**: Make a refusal say why
- **wasm**: Deliver the activation contract to WASI modules via preopens + activation file
- **sdk-sidecar**: Publish and hash-verify the sidecar so a downloaded mvmctl can boot an SDK workload
- **release**: Cosign-verify the downloaded runtime overlay and SDK sidecar
- **ci**: Notice when a claim-bearing lane stops running, not just when it fails
- **core**: DesiredMount schema + MountVolume/UnmountVolume hostd verbs (mvmd plan 59 stage 0)
- **egress**: Host-mediated ICMP echo over vsock, so ping works in the guest
- **audit**: Bind transcripts to signed manifest roots
- **cli**: One listing — machine ls shows transient and persistent microVMs
- **core**: Volume-bridge wire protocol for FUSE-over-vsock mounts (mvmd plan 59 stage 0)
- **apple-container**: Admit the backend into the workload funnel
- **xtask**: Let a surface file name the features the mutation build needs
- **build-cache**: Content-addressed dev build cache with verify-on-read (plan 276 WS6)
- **l3**: Opt-in L3 TUN-over-vsock networking for workloads that need a real IP stack
- **guest**: Substitute mediated tools by absolute path on a sealed rootfs
- Add HVF virtio rng
- **xtask**: Stop a workload path reaching the unrestricted-egress constructor
- **plan-276**: Claim evidence pinning, replay vectors, σ/κ types, and one shared verifier corpus
- **mvm-client**: Expose the canonical unified machine inventory
- **plan**: Pin the execution environment, starting with the kernel
- **cli**: Derive agent verb tier from run shape
- **mvm-client**: Add the write-only secret lifecycle service
- **mvm-client**: Expose normalized verified audit events for UI consumers
- **plan291**: Add local workload deploy attestation
- **plan291**: Capture dependencies from development sandboxes
- **core**: Carry attested deployment references
- **machine**: Boot local attested deployments
- **client**: Complete persistent and transient launch lifecycle through LocalBackend
- Add native HVF warm handoff
- **hostd,runtime**: Host-side eBPF vsock egress telemetry
- **netd**: Rebase IPv6 backend onto main
- **conformance**: Rebase BDD witnesses onto main
- **cli**: Mvmctl seccomp-audit command and shared syscall table
- **core**: ExecutionReceipt, ConformanceBadge, and did:key codec
- **cli**: Add generate command and template registry
- **hostd,cli,client**: Runtime emission of ExecutionReceipts (WS4)
- **client**: Give MvmClient a capability surface
- **secrets**: Mvm-side primitives for the tenant-secrets egress broker (RemoteResolver + pluggable backend)
- **backend**: Uniform capability negotiation that names an alternative
- **hvf**: Complete save/restore so checkpoint and fork work on macOS
- **audit**: A sealed run that cannot record its admission does not boot
- **core**: Egress-secrets payload on the agent instance-start wire
- Add typed agent capability bindings
- **dx**: Add `just worktrees-prune` to remove worktrees that are finished
- **wasm**: Enforce fuel, epoch, and store limits on the wasm tier
- **cli**: Forward ports from machine run
- **web**: Redesign hero diagram into clean 3-step execution pipeline
- **contract**: RFC 6962 consistency proofs for audit merkle trees
- Feat/320 e2 3 substitution registry
- **hvf**: TCP port forwarding over authenticated vsock
- **site**: Apply 316 design review polish
- Enforce CpuGrant::Share on HVF via in-process vCPU quota scheduler
- **demo**: Finish Plan 320 hardening — Worker, parity tests, CI lane, landing teaser
- **mvm-build**: Wire before_build lifecycle hook in builder VM
- **net**: Extract shared authenticated session and rename to NetworkFlow
- Feat/329 browser wasm backend
- **runtime**: Remove DockerBackend and make MVM microVM-only
- **cli**: Machine fork/restore with --as and --branch
- **audit**: Phase 4 decision query API and causal chains
- **cli**: Auto-create persistent machines on mvmctl machine start
- **audit**: Mirror chain-signed audit appends to tracing
- **provenance**: Optional TIBET-JSON export for decision records
- **adr,contract**: The check-time law and frozen audit JCS vectors (Plan 306 WS4, WS6)
- **cli**: Dashboard launcher — artifact resolution, validation, posture gate
- **site**: Integrate product site into docs landing
- **http**: Route the workload egress forward leg through an upstream proxy
- **xtask**: Name new plans by slug, not by number
- **xtask**: Claim-bearing prose must declare what backs it (Plan 306 WS1)
- **sec**: Sign the checksum manifests that gate boot bytes
- **image**: Key the OCI rootfs cache on the injected runtime, not a hand-bumped epoch
- **337**: Own the SDK env-var names in Rust and generate both bindings
- **337**: Own the SDK error taxonomy in Rust and generate both bindings
- **sec**: Bind a secret to a named provider, not a typed hostname
- **release**: Boot the staged microVM image before publishing it
- **337**: Generate the Tier A and Tier B constructors from a declarative registry
- **cli**: Let a source checkout opt out of building its own boot image
- **release**: Give boot images their own release train
- **337**: Tier F decision, close-out, and Tier C transport as a declared subset
- **net**: Finish the one-transport cutover — WS4–WS7 and the gate that keeps it
- **image**: Record where a boot image came from, and let it be inspected
- **sec**: The claim set a workload presents to an identity consumer
- **337**: Finish Tier C with sessions, and close the plan
- **cli**: Make `--help` describe the product the docs describe
- **cli**: `mvmctl run npm test` picks the image
- **build**: An `image =` manifest builds instead of being refused
- **assurance**: Admission-bound AI assurance sessions
- **cli**: `mvmctl bench` — give the latency harness a front door
- **assurance**: Fail-closed evidence emission and the workload probe API
- **cli**: Agent plugin install, and `completions` becomes a verb again
- **assurance**: Open the campaign session on the boot path
- **broker**: Derive the tool catalog from admission, constrain arguments, and make refusals teach
- **cli**: State the security presets once, and let doctor read them
- **assurance**: Run a declared campaign from the client launch path
- **assurance**: Assemble the evidence a trial is actually judged on
- **xtask**: Refuse an outbound tool client in guest-shipped code
- **assurance**: Let one ledger serve both audit routes
- **checkpoint**: Enforce a forked child's declared secret bindings (#2698 A3)
- **assurance**: Carry the admitted session on the signed registration
- **contract**: Compile an upstream tool namespace into bindable capabilities
- **mcp**: Route MCP through MvmClient
- **sdk**: Add opt-in Obscura browser provider
- Resume --boot cold-boots a parked durable session
- Bound FlowMux transformations at the endpoint
- **weblinux**: Add WebLinux browser backend, portable contracts, and Nix-packaged QEMU-Wasm engine
- **capture**: Evidence-backed Linux environment capture frontend
- **audit**: Signed evidence archives over the chain-signed audit log
- **weblinux**: QEMU-Wasm browser smoke demo with SLIRP and allow-host plumbing
- SCITT-compatible action state capsules with hash chaining
- Add SCITT-compatible action state capsules with hash chaining
- Workload service plane — peer names, host.kv.v1, runnable catalog entries
- Complete ExecutionReceipt v1
- **attestation**: Real TPM2 provider, packaging, and ADR-001 amendment
- **nix**: Render mkGuest healthChecks into the guest probe drop-ins
- **hostd**: Operationalize the audit Merkle log — root history, consistency proofs, off-host witness
- Expose workload address API
- **admission**: Admit externally-signed plans from pinned fleet signers
- **hvf**: Give the guest the vCPUs it asked for, or say what it got
- **image**: Record the guest's libc in the image sidecar
- Record measured resource utilization in the execution receipt
- **sdk**: Build and package a musl SDK host-services sidecar
- **web**: Add OPFS cache store
- **mount**: Deliver a granted directory as a block image, not virtio-fs
- **sdk**: Select the sidecar variant from the catalogued runtime's libc
- **xtask**: Ratchet the virtio-fs surface so it cannot grow back
- **sdk**: Select the sidecar variant from the image's own recorded libc
- **builder**: Move the QEMU builder onto the disk transport
- **xtask**: Gate prose that asserts absence, and commit agent findings
- **builder**: Carry the libkrun seeded closure on the input disk
- **xtask**: Refuse a vCPU ceiling derived from a wire type
- **mount**: Find a materialized mount by label rather than by slot
- **builder**: Move the persistent HVF builder onto the disk transport
- **xtask**: Pin the SDK cdylib closure free of host HTTP/TLS/async
- **vmm**: Attribute a helper resolved from the other build profile
- **fs**: Stream host file contents into the image instead of buffering them
- **memory**: WS5-WS6 agent memory plane store and handler (+47 more)

### Changed
- Ignore transfer directory
- Ignore local dev dir and document PR metadata rule
- Finish Vz removal — scrub docs + drop the dead vz-drainer bridge endpoint
- Prune plan 236 cleanup scaffolding
- Simplify just runtime overlay commands
- **conformance**: Renumber OCI unpack suite s9 → s10
- Remove the MCP server
- **mvm-client**: Reserve service-module seams for the mvm-studio wave
- Remove the retired macOS backend from the working tree
- Ignore local Python environments
- **build**: Drop mvm-build's unused tokio dependency
- **justfile**: Correct what test-cached actually adds over a global sccache
- **just**: Add check-gated for the targets --all-targets cannot see
- **just**: Add docs-publish, so publishing the site is a documented step
- Speed up Rust development compilation
- Add release-min profile to shrink shipped mvmctl
- Scope the pre-commit clippy, and move stable to 1.97.1
- **kernel**: Bump synchronized pins to 6.12.106
- **site**: Add reproducible Wrangler deployment
- **kernel**: Bump synchronized pins to 6.12.107
- Ignore the generated output/ tree
- Measure the witness-reachability gate, refuse it, fix what it found
- **hvf**: Delete the now-dead virtio-fs share wiring
- **vmm**: Delete the virtio-fs device and its FUSE server
- Remove worktrees from git history

### Documentation
- Plan HVF density memory reductions
- Add Plan 238 streamed ext4 follow-up
- Add Plan 239 kernel config follow-up
- **plan-236**: Phase 1 scoping — host-authority boundary and 2A runway
- **plan-236**: Record Phase 2A egress data plane landing (Linux + macOS)
- **adr**: ADR-110 uniform userspace vsock egress
- **adr-110**: Record measured smoltcp vs kernel egress benchmark
- **plan-236**: Phase 2B production host-forwarder unification plan
- Keep scratch/temp files in /tmp, never the repo tree
- Define runtime overlay control-plane boundary
- Record Rust best-practices in the agent working agreement
- Decide non-prod OCI verity-boot (incident follow-up #3)
- Libkrun steady-state builder is enabled on Linux (Plan 250 complete)
- Refresh README for the post-consolidation layout + current CLI
- Drop removed Apple-Vz backend refs + fix CLAUDE.md crate-path drift
- **website**: Refresh guides/reference for the post-consolidation crates + CLI
- **research**: Backlog analysis notes (planes/provable-chains, veilid, complexity, unsafe/no_std, external-sandbox, serde_jcs)
- **bdd**: README accuracy pass + s8 README-contract suite
- **research**: Add UOR Framework integration exploration
- **research**: Add UOR Framework integration exploration
- **plan**: Uniform vsock-egress convergence + followups (258)
- **sprint**: Mark #1786/#1785/#1791 issues closed and WS10 kernel task done
- **mvm-hostd**: Document the two audit-chain canonicalizations + add a spine test
- **cli**: Document machine timeline/revert/rewind/advance verbs
- **vsock**: Record vsock production-hardening track (WS1-WS4)
- **vsock**: Virtio-vsock device audit findings + staged hardening plan
- **contributing**: Use pinned just toolchain-embed; note cross-target re-add after a toolchain pin
- **adr-033**: Adopt audited rust-vmm primitives for the in-house VMM virtio devices
- Close vsock overload hardening track
- Plan the non-nested aarch64 machine-run witness
- **plans**: Commit the backend shim-removal plan as 269 with its known gaps
- **plans**: Add universal initramfs + vsock-activated boot plan (270)
- **notes**: Check in the universal-initramfs kickoff note as superseded
- Design note for an `ai` command — deferred draft, no implementation
- **plans**: Witness rigor — ABI layout contracts, a real nextest profile, and what mutation testing cannot reach
- **research,plans**: UOR × Hologram recon + content-addressing conformance/defense plan
- **plan-255**: Record the fifth live run — the claim executes and fails closed
- **verification**: Record the planted defects for the three CI-lane witnesses
- **research**: Vsock-chokepoint data-plane provability + Lean-4 reference-spec note
- **plan-278**: Transparent connect interception, without a NIC
- **posture**: Say plainly that workload microVMs have no NIC
- Assess BrewFS volume integration
- **plan-279**: Build action identity and a real artifact manifest
- **research**: Identity & permissions in the packet (recon §7.7)
- **research**: Fast attestable content-addressed builds and Lean 4 verification
- **plan-278**: Measure W0, which refutes the plan's own framing
- **specs**: Reconcile the plan-270/271 bookkeeping with what shipped
- **research**: Reconcile the deterministic-builds proposal with an adversarial audit
- **warm-pool**: Record audited parent live validation
- **plan-276**: Reconcile with main, and fold in the recon revision that reverses its premise
- Complete open-issue reconciliation
- **claude.md**: Trim the --help-derivable command dump from Build and Run
- Collapse the duplicate plan-270 rollup entry and correct dead dev-VM prose
- **plan-288**: Scope the kernel cache verify-on-read work
- **audit**: Check the security claims against the tree, not the specs
- **adr-001**: Say how claim 10 is actually enforced, and drop a dead CI step
- **witness**: First live evidence on Firecracker and HVF
- **plan-291**: The develop → build → deploy path to an attested image
- **plan291**: Record merged workstreams
- **ci**: Correct claim witness workflow references
- **plan291**: Record console posture hardening
- Describe run-shaped agent authority
- **plan291**: Record attested boot acceptance
- Mark Plan 287 as landed in SPRINT.md
- Mark eBPF live Linux validation complete
- Add open issue closeout plan
- **plan-301**: Design of record for finishing WS11 — WasmBackend + browser slice
- **plan-306**: Declared backing, tier honesty, and the check-time law
- Plan 311 — launch critical-path waste on real-sized images
- Measure both backends at p50/p95/p99 and decompose the Firecracker gap
- **research**: Assess a funded agent-execution-layer entrant
- Evaluate Reticulum for mvm and mvmd networking
- **plan 307**: Record WS2 as applied and close the plan
- **plan 313**: Record Phase 0 findings — the substitution path cannot stream
- **plan 313**: Phase 1 is standalone — the 2314 window closed
- The warm-claim blocker is not BUG-2; the console line was probe noise
- Design a live wasm sandbox demo, and plan wasm-in-microVM
- **adr**: Correct claim 18's limits to what main actually enforces
- Complete Plan 323 persistent-builder docs
- **plans**: Mark Plan 324 complete and resolve Plan 326 WS-D
- **plan-326**: Point status section at the merged regression test
- **plan-326**: Clean up status section wording
- **316**: Add website redesign design review note and update status
- **315**: Mark HVF vsock credit regression complete with Linux gate evidence
- **status**: Mark Plan 316 website redesign sign-off complete
- **320**: Mark plan shipped and update status/checkboxes post-#2429
- **300**: Reconcile 39 open issues, close 8, update disposition and phases
- **sprint**: Mark issue-closeout batch #2165 #2321 #2323 complete
- **plan**: Mark Plan 323 fully complete
- **plan-315**: Refresh verification evidence and clarify builder-VM gate blocker
- **plan-315,316**: Spin out local builder-VM gates into Plan 316
- **AGENTS**: Allow wasm backend to run on macOS host
- **300**: Update #2135, #2292, #2318 disposition and progress
- **300**: Second reconciliation pass — 28 → 23 open issues
- Machine start auto-create follow-up
- **316**: FlowMux is not on the production path
- **332**: Move the tracker into the plans and open the work register
- **deps**: Say which graph each duplicate-major list measures
- Plan 338 — refresh the CLI grammar doctrine and gate the surface
- **bench**: Publish the launch budgets, and gate the page against them
- **plans**: Boot image lifecycle — gate it, version it, expose it
- **claims**: Witness the wall-clock timer against the wire carrier
- **plans**: The kernel-repo-split premise moved, and the case got weaker
- Correct the edge-tier record and supersede the Tier-1 witness plan
- Decide the agent tool surface and the memory plane
- **research**: The trust model for a type-1 mvm, and the one question that gates it
- Scope the tool plane, and record what controller-launched children must not break
- Establish FlowMux single-path closeout
- Document host-side eBPF egress telemetry
- **338**: Record PR #2776 merge status and pending build verification
- **weblinux**: Scope browser-hosted WebLinux demo plan
- Add BrowserWasi backend documentation
- Align markdown table columns in builder-vm.md and troubleshooting.md
- **adr**: Reconcile the spawned-microVM and durable-messaging designs
- Document vsock binary protocol over guest agent and FlowMux
- Execution contract artifact identity qualification plan
- Expand vsock protocol documentation with FlowMux details
- Plan for .mvmev offline verifiability
- **mvmev**: Specify canonical verification format
- Generate /llms.txt, add markdown twins and an agent entry point
- **claims**: Drop a claim-13 witness that tests an uncalled function
- **security**: Correct factual claims on the security and architecture pages
- **backends**: Warn at the libkrun capability fields that they are overwritten
- Correct claims the docs make about the CLI, SDK, and backends
- **stream**: Record landed fleet edge caller
- **e2e**: Record the verified host kv volume witness
- **status**: Drop the duplicated refactor-status entries
- **status**: File the sidecar libc selection as landed
- **plan**: Re-scope Stage C's persistent builder against the tree
- Close caller commitment delivery
- **qemu**: Record why this backend declares no vCPU ceiling
- Stop crediting mvm-sdk with a cdylib it does not build
- **plan**: The Stage C re-scope was overtaken by #3061
- Plan for cutting the 0.18 release
- Record the release-gate decisions in the 0.18 plan
- **notes**: Record the mvm-hostd --lib tracing flake
- Correct the virtio-fs claims the code no longer supports
- **plan**: Design out retiring VmVolumeKind::DirShare
- Add implementation prompt for issue plans
- Point the helper rebuild at the recipe, and finish the crate list

### Fixed
- **hvf/oci**: Guest BROKER_PORT bridge + OCI rootfs self-heal
- **machine**: Make `run -d -- <cmd>` detach instead of foreground-blocking
- **machine**: Gate persistent OCI egress backends
- Fix ext4 merge-queue determinism
- Accept OCI manifests without digest header
- Build source-checkout kernels and host binaries locally on cache miss
- Harden agent reconnect restart races
- Unblock in-process HVF boots through the MvmClient facade
- Use Docker Hub registry API host
- **guest**: Use libc::Ioctl in mvm-oci-init
- **guest**: Verify PostRestore verb-grant re-pin against the host anchor
- **guest**: Accept agent control connections only from the host CID
- **release**: Verify published workload kernel manifests
- **build**: Resolve guest-build workspace from the invoking checkout
- **cli**: Make builder and doctor transport truth explicit
- Restore dev-env wrappers for just recipes
- **build**: Scope host-binary manifest parse to HOST_BINARIES
- **oci-run**: Boot the dm-verity workload kernel, never the builder kernel
- **builder**: Deliver libkrun Stage 0 /work as an ext4 disk to avoid virtio-fs handle exhaustion
- **oci-run**: Guard verity kernel host-side + clarify sealed-agent verb denials
- **builder**: Scope the Linux/KVM steady-state guard to the libkrun backend
- **builder**: Seed the builder VM clock from the host (cold-store HTTPS)
- **kernel**: Enable x86 KVM paravirt-clock so the builder kernel boots under libkrun on KVM
- **builder**: Seed the HVF builder VM clock from the host too
- **kernel**: Enable VIRTIO_MMIO_CMDLINE_DEVICES (x86) so the builder kernel boots under libkrun/KVM
- **cli**: Make workload kernel creation explicit
- **net**: Enforce --allow-host on the --entrypoint path
- **overlay**: Fail closed on a missing guest agent in both guest inits
- **builder**: Defer single-shot build result to the on-disk finalize on a guest halt
- **builder**: Make cold nix builds resilient to a flaky substituter link
- **net**: Reconcile Firecracker tunnel vs iptables egress
- **pack**: Unbreak the --all-features build of the release-pack download path
- **net**: Stop double-wiring the L3 tunnel on host-vsock-proxy backends
- **net**: Resolve the OCI egress client overlay-first and fail closed
- **hostd**: Allow lseek in the substitution-endpoint seccomp allowlist
- **net**: Complete admitted egress — honest CONNECT ack + happy-eyeballs connect
- **cli**: Honor --hypervisor on a transient machine run
- **cli**: Legible first-run OCI launches + transient VM state cleanup
- **dns**: Reject IPv4-mapped IPv6 SSRF + audit malformed DNS queries
- **mvm-fs**: Ext4 fast-symlink threshold off-by-one truncated 60-byte targets
- **net**: Fall over to a pinned host's IPv4 when the guest dials its unreachable IPv6
- **oci**: Invalidate the run-image rootfs cache on a guest-source change
- **hvf,egress**: Ring crypto provider, /tmp endpoint log, 3 s DNS timeout on macOS
- **fc/fork**: Kernel path, inherited agent verbs, and verity sidecars for fork boot
- **cli**: Clean both requested and effective warm-pool transient state dirs
- **runtime**: De-flake substitution endpoint rollback test
- **kernel**: Pin guest kernels to 6.12.97 and decouple from the nixpkgs channel
- **mvm-fs**: OCI multi-layer unpack replaces prior-layer paths
- **cli**: Transient teardown cleanup and live BDD validation
- **mvm-cli**: Image-lineage node creation save-then-emit + ancestor self-heal
- **kernel**: Bump guest pins to 6.12.98
- **hostd**: Key firewall state by workload identity
- **vsock**: Strict Firecracker CONNECT/OK ack parser
- **vmm**: Validate virtqueue geometry so a hostile QueueNum can't panic the host
- **vsock**: Bound guest-selected connection state
- **vmm-vsock**: Harden RX/descriptor paths against a hostile guest
- **vsock**: Bound egress budgets and teardown
- **mvm-runtime**: HVF builder mirrors artifacts to the caller's artifact_out
- **mvm-build**: Pass ARM64 Image kernels through to Firecracker
- **mk-guest**: Read the host-signer pubkey from the cmdline when no config drive
- **bundle**: Carry the guest sidecar so exported bundles can boot
- **mvm-runtime**: Refuse a workload boot whose kernel cmdline would be truncated
- **vmm**: Make the virtqueue used index device-owned across drains
- **mvm-runtime**: Frame Firecracker API responses on Content-Length, not EOF
- **runtime**: Pin the host-signer anchor even when no verb grant is minted
- **pool**: Stop the CLI and the runner both reserving the same warm parent
- **cache**: Verify the initramfs at admission and share one cross-root seed
- **cache**: Verify the builder image at admission and keep its sidecars
- **boot**: Give the legacy initramfs its cmdline back, and prove agent readiness
- **guest**: Create the early mount points before mounting them
- **deps**: Collapse the duplicate curve25519-dalek out of the guest agent
- **test**: Actually commit the nextest profile, which a global gitignore ate
- **ci**: Point the fuzz lane at the crates it was renamed to, and isolate the mutation lane
- **guest**: Mount devtmpfs unconditionally so dm-verity has a control node
- **guest**: Give PID 1 the host-signer anchor it refuses to serve without
- **virtio-fs**: Stop a guest-chosen read size from sizing a host allocation
- **xtask**: A mutation run that tested nothing must not read as clean
- **xtask**: Resolve a ci: witness to a real job, not any mention of its name
- **activation**: Wait for guest agent readiness before ActivateEnvironment
- **cache**: Let the universal-initramfs cache see guest source changes
- **ci**: Restore the claim witnesses that had been red for ten nights
- **runtime**: Stop auto-detect selecting the opt-in apple-container tier
- **fuzz**: Repair the two targets that have not compiled since the consolidation
- **agentd**: Drain the child's pipes before reporting a terminal state
- **runtime**: List one row per VM, from the backend that owns it
- **pool**: Audit a captured standby parent so a claim can verify it
- **xtask**: Catch tests that seed from the real $HOME without moving MVM_HOME
- **cli**: Skip the legacy verity-initrd resolution when the universal initramfs is warm
- **warm-claim**: Deliver child verb grant after restore
- **oci**: Make `machine run --image` work on a case-insensitive host
- **witnesses**: Make the claim surface measurable, and close what measuring it found
- **runtime**: Fail closed when stopping Firecracker machines
- **guest-agent**: Stop PID-1 reaping from destroying workload exit codes
- **guest**: Run the guest environment setup on the universal-initramfs path
- **guest**: Deliver mediated tools on a sealed rootfs via PATH
- **apple-container**: Require a digest sidecar for the fetched kernel; complete stage-2 live validation
- **build**: Rebuild the per-VM supervisors when mvm-runtime changes
- **vmm**: Seed the guest CSPRNG at boot, cutting machine run 5.4s to 1.35s
- **agentd**: No workload runs as root — OCI init privilege drop + fail-closed gate
- **cli**: Only the dedicated workload kernel may boot a workload
- **vmm**: Enforce virtio-vsock transmit credit on HVF egress
- **agentd**: Give UID 901 a writable HOME
- **hostd**: Real IPv4 destination extraction for eBPF egress probe
- **audit**: Serialize chain-head reads so concurrent writers cannot fork a chain
- **ci**: Make the kernel budget check able to block a merge
- **ci**: Stop paying a full validation cycle for a flake or a stuck requeue
- **audit**: Report an unverifiable chain as unverifiable, not as a missing entry
- Refresh Linux kernel pin
- **test**: Size lease-TTL tests from a measured stall, not a 20ms guess
- **kernel**: Restore the x86_64 symbol budget and gate edits to it
- Restore security mutation witnesses
- **audit**: Store the bytes a chain line's signature covers
- **dx**: Make `just clean` remove the dev state root, and classify worktrees
- **test**: Stop the builder-runner tests leaking a shell process per run
- Refresh synchronized kernel pins
- **audit**: Bind OCI provenance to the plan that boots, not a synthetic one
- **ci**: Re-point the process-handshake test group at the package that has the tests
- **plan**: Record the transport a launch gives the guest, not None
- Automate macOS VM entitlement signing
- **receipt**: A lost or corrupt chain head silently forks the receipt store
- Align workload root modes and bound forward responses
- **cli**: Clarify workload-kernel artifact recovery
- Restore security mutation witnesses
- **pool**: A failed claim must stop advertising the child it destroyed
- **kernel**: Two boot paths routed around the verified kernel seam
- Retry transient busy lifecycle hooks
- Filter HVF builder work inputs
- **ci**: Guarantee merge queue forward progress
- Fix HVF virtiofs shared memory discovery
- **oci**: Normalize image repository capitalization
- **public**: Constrain landing diagrams and space positioning heading
- **web**: Build and deploy the wasm demo at /demo
- **web**: Ignore generated demo tree and add Astro demo route
- **fc**: Split driver_boot, remove sudo bash launch, read pid in-process
- **xtask**: Add check-nextest-groups lint
- **hostd**: Record receipt-as-record decision and torn-head recovery
- **hostd**: Treat FlowMux peer reset as graceful close
- **agentd**: No_new_privs and a bounded capability set on the OCI workload path
- **hostd**: Survive transient accept errors on every egress listener
- **cleanup**: Make --nuclear mean every entry under ~/.mvm
- **stage0**: Gate persistent-store reuse on a clean ext4 superblock
- **release**: Stop requiring mvm-bridge, a binary Plan 305 deleted
- **seccomp-audit**: Follow clones and track syscall state per tracee
- **333**: Dependency hygiene — target-gate hickory-proto, prune dead dep config, gate both closures
- **egress**: Bound simultaneous raw TCP tunnels per workload
- The guest agent could not spawn itself — capability bounding set, wrong order
- **hostd**: Make wall-clock bounds actually enforceable, on libkrun and HVF
- **fc**: Take the pid marker from the process that becomes Firecracker
- **docs,contract**: Correct claim 10 and pin the egress refusal direction (Plan 306 WS5)
- **hostd**: Retry the accept errors that describe a pending connection
- **sdk**: Repair runtime SDK parity and cover live mode with BDD
- **nix**: Put the /init shebang back on byte 0
- **sec**: Delete the dead wasm branch, witness the launch plan binding, baseline three equivalences
- **ci**: Report both kernel contexts when the kernel lane is out of scope
- **ci**: The Test aggregate must accept a succeeding out-of-scope kernel lane
- **build**: Stop reporting a slow endpoint exec as an unresponsive builder
- **ci**: Stop the test aggregate asserting a conclusion the kernel lane no longer has
- **sec**: Let a mutation shard finish, and say so when it does not
- **hostd**: Accept the signed plan the launch path actually sends
- **client**: Type the rootfs declaration instead of probing for it
- **release**: Read the bytes the kernel execs, not just their checksum
- **runtime**: Call the network-endpoint stub by the name it has
- **xtask**: Stop the assertive-vocabulary check matching inside words
- **cache**: Stop prune deleting live caches, and stop it overstating by 8x
- **sec**: Cut mvm-hostd four ways, because two was measured to be too few
- **xtask**: Stop the ADR gate reading the changelog as a live reference
- **sdk**: Give host_port and dns_resolver one verdict in every language
- **client**: Type MachineSpec.image, hoisting RootfsSource into mvm-core
- **sec**: Count the security jobs that never finished, and let the fuzz lane finish
- **net**: Make the FlowMux endpoint serve sessions, and refuse a builder guest with no egress
- **sdk-ts**: Bound the machine subprocess, and name what actually failed
- **bench**: A launch that bound no host service is not degraded
- **bench**: Stop the runner's trace write clobbering the driver's
- **build**: Refuse a network endpoint older than the mvmctl running it
- **net**: Resume cancelled frame reads and send one Reset per stream
- **net**: Make FlowMux name the stale half instead of failing silently
- **nix**: Emit the ELF the x86_64 loader needs, and assert the format
- **kernel**: Bind the extracted ELF to the vmlinux it came from
- **sec**: Fold host case in the web-fetch allowlist
- **cli**: Mark a fetched boot image as fetched, and close out the plan
- **net**: Dial the egress port the builder actually allocated
- **ci**: Let the orchestration gate see an out-of-line test module
- **conformance**: Stop the SDK codegen step leaking a target dir per run
- **nix**: Manifest the kernel the loader takes, not the first one ls returns
- **build**: Stop the Stage 0 source copy walking into its own output
- **release**: Give the boot gate the toolchain its own test needs
- **jailer**: Let the confined endpoint write the audit entry it is granted
- **release**: Give the boot image jobs their toolchain, and refuse a partial publish
- **machine**: Remove a machine's runtime state with it, not just its spec
- **image**: Stop `machine run --image` panicking on a fresh MVM_HOME
- **release**: Pick the boot image by version, and refuse an incomplete one
- **docs**: CLAUDE.md showed five commands that do not exist
- **ci**: Attach the runtime overlay to the boot gates, which is where the agent lives
- **ci**: Install the wasip1 target the pages demo guest needs
- **ci**: Bound the apt step so a stalled mirror stops reading as a red PR
- **release**: Ship every per-VM binary mvmctl spawns, from one registry
- **stage0**: Find the Nix store by label, and refuse a disk that is not one
- **release**: Sign boot images under the environment that admits their tags
- **release**: Gate the CLI signing job on the environment that admits v* tags
- **bundle**: Refuse a foreign-arch bundle at boot and at admission
- **ci**: Repair Pages and boot-image signing deployments
- **bench**: Declare a runtime-source policy so the guest is told where the overlay is
- **hvf**: Say which check failed instead of "BadKernel"
- **release**: Publish kernels on release, and tell the truth about a 404
- **ci**: Drop the dead libcap-ng dep, and repair the mirrorlist apt actually uses
- **nix**: Serialize runtimeLean into the sidecar the admission gate reads
- **doctor**: Derive the builder-backend line from the platform it is given
- **seccomp**: Restore epoll for confined roles on aarch64
- **ci**: Give cache-warm the same env as its consumers, so the cache can restore
- **guest**: An abandoned readiness probe is not a failed authentication
- **guest**: A NIC-less workload guest is the design, not a bring-up failure
- **guest**: A read-only rootfs is one fact, not six failures
- **ci**: Verify the boot-latency manifest's signature before trusting its digests
- **bench**: Establish the host signer key the boot path requires
- **hooks**: Lint workflow files in pre-commit, where CI already does
- **hostd**: Witness the fail-closed audit the mutation lane caught
- **guest**: Read the mount table once, as the comment claims
- **assurance**: Roll the launch back when a declared campaign cannot open
- **guest**: Mount writable runtime tmpfs
- **checkpoint**: Measure a fork child's grants against the tier that boots it
- **release**: Publish the initramfs, so a sealed boot is reachable from a release
- **guest**: Silence expected missing identity drive
- **ci**: Bound apt setup in the BDD gate
- **vsock**: Dial the per-VM endpoint when the guest connects, not on its first byte
- **egress**: Stop leaking https requests in cleartext, and unblock pool-less backends
- **update**: Fetch published images from the boot image tag, not the CLI version
- **stage0**: Find labelled disks wherever they are attached, and attach each once
- **xtask**: Skip nested .claude/worktrees in source policy scans
- Enforce FlowMux limits per VM
- **kernel**: Refresh synchronized pins to 6.12.104
- Keep phase timing JSON-safe
- **ci**: Compile the release bootstrap feature
- **security**: Declare xtask license
- **vsock**: Stop stdout over ~25 KB from desyncing the control session
- **ci**: Use util-linux for builder hook mounts
- **machine**: Builder VMs are not user machines
- **test**: Resolve the provider binary at compile time so nextest can find it
- **site**: Restore architecture header spacing
- **site**: Strengthen architecture proof points
- **security**: Contain arrayref registry incident
- **site**: Clarify architecture proof points
- **ci**: Activate the staged sealed boot image
- **oci**: Resolve a workload's environment once, for both ways in
- **security**: Pack mutation shards by cost, and let the watcher report a timeout
- **mount**: Close the guest-mount shadowing hole and de-duplicate the policy
- **guest**: Set hostname from machine name
- **ci**: Reconcile scheduled security outcomes
- **builder**: Preserve hook artifacts and gate TCG smoke
- **mount**: Drop /mnt from the guest-volume allow-list
- **audit**: Seal production transcript chains
- **guest**: Serve ping from the process that holds the FlowMux identity
- **runtime-overlay**: Add forward_proxy field to RuntimeOverlayGuestLayout
- **security**: Restore scheduled policy lanes
- **guest**: Give the forward proxy a process that can authenticate
- **guest**: Hand FlowMux identity to the Nix egress service
- **cli**: Emit guest console diagnostic when transient VM start fails
- **builder**: Seal rootfs journal before export
- **cli**: Improve error message for machine logs on stopped VM without state
- **mvmctl**: Improve stopped VM logs errors
- **mvmctl**: Improve error message for stopped VMs with no state dire…
- **ci**: Restore extended witnesses
- **kernel**: Bump Linux pins to 6.12.105
- **builder**: Seal rootfs journal before export
- **ci**: Restore scheduled security witnesses
- **builder**: Keep rendered rootfs sealing self-contained
- **builder**: Make copied rootfs writable before sealing
- **builder**: Make copied rootfs writable before sealing
- **builder**: Unmount the before-build subtree before sealing; close two BDD gaps
- **pages**: Disable Determinate Nix FlakeHub login in Pages deploy
- **cli**: Stop telling users to run commands that do not exist
- **pages**: Build weblinux assets from the nix/ subflake
- **nix**: Use writable /build/deps path in qemu-wasm build
- **ci**: Repair extended platform witnesses
- **weblinux**: Make staged demo assets writable
- **wasm-demo**: Preserve weblinux assets when staging wasm demo
- **http**: Bound every connect and try IPv4 first
- **conformance**: Stop HOME isolation from hiding the Rust toolchain
- **launch**: Build the universal initramfs on every host, refuse without one
- **http**: Bound idle reads so a silent peer cannot park a request forever
- **rpc**: Preserve guest policy refusals
- **site**: Isolate the whole site so the embedded demo gets SharedArrayBuffer
- **nix**: Fetch crates from the static CDN
- **admission**: Pin the booting kernel into every CLI-signed plan
- **run**: Stop reading stdin that nobody handed us
- **sdk**: Align documented surface contracts
- **hvf**: Stop the per-VM supervisor holding its caller's stderr
- **hvf**: Refuse unsupported multi-vCPU launches
- **cli**: Allow detached declared ingress
- **ci,nix**: Unblock the site deploy — gh --jq -r, and crates.io 403ing Nix
- **test**: Stop the stdin readiness probe leaking its pipe into subprocesses
- **web**: Forward terminal control keys to qemu
- **ci**: Pass release filter directly to gh jq
- **sdk**: Say when the cached SDK sidecar predates the working tree
- **exec**: Apply image environment to ad hoc commands
- **ci**: Restore documented surface witnesses
- **run**: Refuse --mount up front on a backend that cannot serve it
- **cli**: Stop advertising /mnt as a volume mount root
- **perf**: Share the warm launch hard ceiling
- **audit**: Exclude root histories from chain sweeps
- **build**: Build SDK sidecar from source in Stage 0
- **run**: Resolve flake builds through the slot registry
- **guest**: Seed cold-boot wall clock in PID 1
- **ci**: Make documented surface builds executable
- **doctor**: Report why a tool check failed to spawn
- **hvf**: Route machine fork/restore at the backend that captured the checkpoint
- **bdd**: Probe capabilities in the home the scenarios run against
- **guest**: Mount devpts so an interactive console can open
- **stream**: Deliver fleet edges through guest input
- **admission**: Refuse wasm SDK host services explicitly
- **security**: Repair scheduled supply-chain witnesses
- **ci**: Restore extended platform witnesses
- **pool**: Make image launches warm-claimable
- **admission**: Refuse a host-services sidecar the guest cannot load
- **guest**: Resolve a bare argv[0] against the image PATH
- **vmm**: Stop a machine's measured CPU falling when its vCPU threads exit
- **ci**: Repair Linux documented-surface prerequisites
- **security**: Update wasmtime to 46.0.3
- **hostd**: Stop a supervisor test queueing an hour for a lock it holds
- **e2e**: Rebuild the per-VM helpers, and boot the README's python examples
- **vmm**: Say why a supervisor died instead of naming an empty console
- **vmm**: Confine both virtiofsd flavors
- **cli**: Retry diff handshake peer hangups
- **e2e**: Let the runners honour a worktree's own MVM_HOME
- **builder**: Reset the guest staging roots instead of extracting over them
- **sdk**: Copy the workspace, not the flake subdirectory, for sidecar builds
- **agentd**: Two live-guest verb defects — machine diff session, machine wait entrypoint
- **build**: Stop Stage 0 promotion from destroying the cached workload kernel
- **flowmux**: Distinguish policy refusal from upstream failure
- **warm**: Authenticate restored child readiness
- **xtask**: Make the kernel-reads gate see hand-rolled cache paths
- **release**: Publish both SDK sidecar libc variants
- **run**: Propagate baked workload exit codes
- **ci**: Rebuild stale guest artifacts before live witnesses
- **e2e**: Stop forcing a fetch the contributor binary cannot perform
- **sdk**: Finish the sidecar libc selection — compare real values, and enforce it on the run path
- **ci**: Close residual documented-surface regressions
- **build**: Bootstrap SDK sidecars from unembedded CLI
- **build**: Stop a plain cargo build from un-embedding mvmctl
- **vmm**: Declare the vCPU ceiling each VMM boots, not the wire type's
- **build**: Stop the bootstrap helper rebuilding the payload it is running
- Fix contributor runtime recovery paths
- **just**: Let build-supervisors target a profile
- **cli**: Preserve image PATH for mounted PTY runs
- **hooks**: Stop the pre-commit hook reporting a non-member package as a clippy failure
- **build**: The typed persistent route read back an empty export
- **ci**: Let Extended CI's red mean a regression again
- **ci**: Fix the two Extended CI failures that were not the product
- **release**: Require e2e-docs to have succeeded, not merely finished
- **xtask**: Register check-release-evidence with the gate lane
- **core**: Enforce the 0700 mvm-home posture at the creation seam
- **build**: Refuse a disk-transport session instead of hanging on its lock
- **vsock**: Stop the exec stream inheriting a connect timeout
- **doctor**: Ask diskutil about the volume, not the directory
- **guest**: Name the missing device-mapper instead of the missing file
- **mount**: Say what a transient run will and will not attach

### Other
- OCI materialize hygiene: multi-block ext4 dirs + builder orphan-sweep
- Speed up default Rust builds
- Gate persistent OCI egress to vsock backends
- Fix web search query URL building
- Reduce CLI dependency surface
- Harden OCI runtime injection
- Remove Vz backend and scrub current surface docs
- Update gvproxy retirement planning docs
- Slim default-path dependencies
- Fix source-checkout machine start and Stage 0 fallbacks
- Document deferred WSL2 and native Windows support work
- Add plan 236 go checker
- Add host-authority runtime roadmap
- Fix OCI run cold-cache DX
- Make verbosity global and rename host shares
- Finish vsock port-handler registry production closeout
- Slim workload kernel config and refresh budget gate
- Refresh Plan 219 grant-delivery branch on main
- Add HVF OCI allow-host proxy support
- Document workload BPF invariant
- Implement streamed ext4 rootfs materialization
- Refactor guest vsock egress session plumbing
- Fix libkrun vsock-only machine egress
- Close out Plan 219 Linux verb-grant proof gaps
- Fix Stage 0 build wedge from leftover /homeless-shelter
- Implement Plan 237 Phase 0 cache repair harness
- Compile native per-VM host helpers at build time, not run time
- Restore HVF default for macOS dev
- Plan 213: harden pack-signing custody + add reproducibility gate
- Plan 213 SP1: versioned pack cache + lifecycle facade + mvmctl pack
- Remove PackBackend::Vz + --builder vz (orphaned by #1620 early-merge)
- Plan 213 SP2: prefetch the dev-shell image at install time
- Bind restore-time verb grants to VM lineage
- Fetch pinned workload kernels on installed builds
- Plan 213 SP4: instant-first-use benchmark harness (ops bench first-use)
- Remove stray sprint conflict marker
- Fix Docker Hub OCI manifest fetch
- Route OCI prod verity sealing through the builder VM
- Prep 0.18.0 runtime overlay rollout surface
- Builder DX: capture supervisor rebuild logs + honest one-time-build label (re-land of Plan 246 Phase 1 survivors)
- Fix host HTTP egress release path
- Plan 213 SP3 (producer + guest import): carry & import a seeded nix closure
- Ship runtime overlay tarball transport
- Plan 246 Phase 2: remove the `mvmctl dev` interactive command (builder VM → headless)
- Plan 247: fix macOS-26 common commands — retire the dev-VM dependency from host shell ops
- Fix doctor HVF reporting and quiet failures
- Guard HVF density preflight conditions
- Dev-removal followups: reword stale code comments + Plan 249 (larger deferred items)
- Plan 249 WS-B PR-1: fix builder disk-transport input bloat (unblocks --flake, layer 2)
- Remove stub embed build path
- Add runtime-owned reversible replacement
- Fix interactive OCI dev console on HVF
- Document reversible replacement behavior
- Refresh Plan 219 timeout closeout slice on current main
- Split SDK crates and add selective SDK release workflows
- V1 simplification restructure: crate consolidation 32→16 + no_std protocol split
- Remove dead egress_proxy/HttpRegistry stubs + MVM_HVF_DUMP_DTB gate
- Gate the mock VM backend behind test-support (keep it out of the prod closure)
- Plan-126 B4/C1: ban aws-lc-rs from default closure, document completion
- Shorten CLI help text
- Harden guest control and data planes
- Document broad BDD coverage expectation
- Gate release publishing on BDD tests
- V1 simplification: integrate plan/mvm-simplification into main
- Stop workload guest boot-probing 9pnet/btrfs/gnss/vlan
- Make Firecracker workloads vsock-only
- FC vm_full fork path remapping and resume-from-snapshot
- Verify libkrun supervisor plan envelopes
- Enforce authenticated encrypted vsock control
- Reduce and fence `unsafe` across the workspace
- Add user-space SOCKS5 UDP egress
- Reconcile backend recovery capabilities
- Reconcile Plan 265 WS2/WS4 warm-pool work with main
- Shrink the complete guest footprint below 50 MB
- Reference Rust engineering best practices
- Attach the SDK sidecar automatically from the signed plan's host-service bindings
- Retire obsolete CLI workload binary embedding
- Fix remaining security and reliability issues
- Fix orphaned helper process lifecycle
- Cache missing initramfs release artifacts
- Establish object-store contract and live volume attachment
- Wire authenticated remote volume lifecycle
- Restore scheduled security witnesses
- Shrink guest kernels to the virtual hardware floor
- Fix machine logs on macOS
- Harden sensitive-data enforcement on protected egress
- Add fenced block-volume worker transfer protocol
- Close production volume plan
- Extract a reusable local encrypted-volume lifecycle service
- Add sandbox dependency capture command
- Add mvmctl watch for local workload changes
- Verify precomputed rootfs digests before admission
- Bind deploy records to exact boot artifacts
- Add tiered artifact storage and warm-start plan
- Pre-open console listeners only for dev profiles
- Workload stream plane: live stdout/stderr, and a grant-gated stdin channel
- Document homepage claim parity checklist
- Stream plane follow-ups: bind fingerprints, release the carry on silence
- Record mvmd-only production launch authority
- Complete generated runtime SDK surface
- Fix dynamic OCI volume mounts for transient runs
- Improve one-command microVM developer experience
- Redact the console fallback on read
- Agent/oci homepage claim audit
- Add the stream-edge primitives a fleet composes
- Fix builder sockets for deep worktree paths
- Simplify VMM channel specs and wire L3 vsock
- Preserve large egress downloads under byte limits
- Clean mvm cache with just clean
- Gate the two defects review kept catching instead of CI
- Connect a producer's output to a consumer's stdin
- Add Semantica decision-provenance assessment with UOR/mvm bindings
- Fix multi-machine nftables isolation
- Unprivileged L3 networking: the userspace socket datapath
- Add contributor development flake
- Close plan 296: state what an edge guarantees, and document it
- Implement sub-300ms resident warm launch
- **runtime**: Trap release overflow, durable audit appends, bounded OCI reads, panic redaction
- Prepared cold-launch measurement and the optimizations it found (Plan 299 Phase 0)
- Define durable agent session and event contract
- Add lifecycle density benchmark
- Add microVM lifecycle benchmark
- Cut 23 crates from the shipped mvmctl closure (Plan 309 Phases 0-1)
- Instrument HVF stop teardown phases
- Fs2 → std locking, and mvm-http: the client to replace reqwest (Plan 309)
- Add README BDD coverage contract
- Plan 313: egress token accounting, streaming responses, and opt-in compaction
- Keep CLI help within 80 columns
- Scrub guest RAM before release
- Retire reqwest: closure 286 → 242 (Plan 309 Phase 2)
- Perf/2280 host matrix gates
- Workload grants: one signed declaration, per-backend enforcement (Plan 308 WS1-WS4)
- Fix HVF vsock credit accounting for large downloads
- Make bootstrap prepare a verified workload kernel
- Resolve a bootable launch config without starting a VM, so the warm pool can be filled
- Grant surfaces: make a workload grant expressible, and therefore real (Plan 308 WS6)
- Align top-level command help descriptions
- Fix hostd test environment isolation
- Make the interactive guest usable as the uid it actually runs as
- Fix Stage 0 cache reuse and ARM64 workload boot
- Refuse a restored child whose grants exceed its parent's (Plan 308 WS5b)
- Add event-driven lifecycle shutdown
- Make #[instrument] produce timings, then instrument and export them (Plan 318)
- Verify audit chains incrementally in doctor, keep the full walk for trust audit verify
- Enforce single-line CLI help
- Fix/308 report enforced tier
- Redesign the marketing site and docs chrome
- Plan single flow-aware vsock networking
- Fix long-running console input and shutdown
- Freeze the audit chain bytes before refactoring the writer
- Give the claim-12 bind check a single definition
- Close two gate evasions with one shared scanner, and correct a false CLAUDE.md claim
- Enforce the wall-clock bound, and stop encoding it twice (Plan 308)
- Relocate the egress-decision core into mvm-contract
- Feat/308 ws5b gaps
- Move the placeholder leaf down, and give the two prefixes distinct names
- Stop resetting throttled egress streams; lift workload ceilings off the builder VM
- Queue on a contended builder store image instead of failing the build
- Give HVF a persistent builder, so concurrent builds have somewhere to go
- Freeze the raw-packet networking path and ratify one flow-aware vsock path
- Feat/308 admission budget
- Rotate the audit log without making removed history silent
- Give each delivery entry its own file so sessions stop colliding
- Fix persistent machine create syntax
- Map the E2/E3 moves-and-stays boundaries before touching the code
- Fix the libkrun supervisor's build: the field is `plan`, not `plan_json`
- Make the eBPF telemetry lane actually gate the merge
- Pin AppleContainer's egress coverage as a checked invariant
- Give the audit chain link one definition of hash_line
- Cover the whole security claim set in the docs, not just the first seven
- Make pruning a retired audit prefix accountable rather than impossible
- Plan 327: a CPU quota for the HVF tier, with its Phase 0 spike measured
- Attribute a spliced egress error to the half that produced it
- Make builder-store durability expressible, and fail fast when it is gone
- Repoint the vsock-only-egress gate at its real workload paths
- Pin the FlowMux wire contract: framing, opcodes, and the state machine
- Fix SDK sidecar host service startup
- Share the builder that holds the store image instead of queueing for it
- Name an unknown flag instead of shipping it to the guest
- Bound a warm-claimed child by the host grant ceiling (Plan 308)
- Add signed transport-neutral network limits
- Give the store lock to the process whose life matches the VM's
- Run-first CLI ergonomics and upstream-sandbox adoption
- Plan 330: decision provenance layer
- Hidden __builder-shell-job command for Linux builder-VM gates
- Fix reset race, rate limiting, and audit pipeline
- Decision provenance layer — Phases 1-3: PROV-O export, event enrichment, DecisionRecord store
- Wire guest egress/DNS adapters to FlowMux reconnect client
- Feat/316 guest flowmux adapter
- ADR-043 — frame the client-interface conformance decision
- Plan the SDK binding fan-out, and correct what it would cost
- V0.18.0
- Trigger production deployment
- Upgrade sigstore-verify stack 0.9 → 0.11; ratchet stale rand allowlist entries
- Add Graft repo context integration
- Add capability-secure workflow specifications
- Ignore local specs notes
- Secret bindings for forked children: design + W0 diagnostic
- Integrate product site, audit-driven truth fixes, and execution-contract repositioning
- Declare fork child secret bindings
- Fix FlowMux session readiness race
- Durable agent sessions: content-addressed resume points, park state machine, and resume admission
- Add FlowMux network performance evidence
- Add admission-bound AI assurance extension sessions
- Add architecture one-pager and link it from the landing nav
- Implement declared ingress on FlowMux
- Remove retired public L3 network surface
- House the architecture page in the site shell, calm the type
- Show measured launch latency against its budget on the homepage
- Close the FlowMux evidence matrix
- **aarch64**: Pi end-to-end fixes and reliable QEMU teardown
- Ignore .qwen/ directory
- Ignore .qwen/ directory
- Add quantum-safe cryptography transition plan for mvm and mvmd
- Build the site QEMU-WASM pack on boot-image tags
- Add qemu-wasm-smoke-pack build/download scripts
- Realign landing page with the MVM one-pager
- Bind caller commitments into signed execution plans
- Merge remote-tracking branch 'origin/main' into worktree-release-0-18-plan

### Performance
- **verb-grant**: Base64 the cmdline envelope instead of hex
- **verb-grant**: Serialize the signature as base64 instead of a number array
- **mvm-runtime**: Talk to the Firecracker API directly instead of spawning curl
- **build**: Narrow the nix workspace filter to what cargo can actually read
- In-memory builds and streamed OCI layer unpack
- **launch**: Take image-size-dependent work off the prepared launch path
- **hvf**: Measure demand-faulted RAM and restore mapping cost
- **fc**: Take the shell and its subprocesses off the Firecracker boot path
- **bench**: Capture guest-agent RSS in density reports
- **bench**: Add unprivileged warm resident/fault evidence
- **audit**: Fsync where a record authorizes an action, not on every entry
- **core**: Fdatasync the atomic write, not fsync
- **stream**: Wake the console follower on stop — 174ms of a 407ms teardown
- **hooks**: Scope the pre-commit clippy run to leaf crates
- **fs**: Stop copying every file's bytes into the ext4 plan
- **build**: Reuse prebuilt musl host binaries in dev builds
- **ci**: Resolve the test-support features once instead of five times
- **kernel**: Drop debug instrumentation a sealed guest has no reader for
- **fc**: Stop narrating every boot across an emulated serial port
- **launch**: Cut the sleep quantization out of teardown, and read the phases as a tree
- **build**: Key mvm-cli's nested binaries by content, not by profile
- **agent**: Stop charging every exec a 50ms poll tick to notice a child that already exited
- **fc**: Skip sudo on the launch line when already root
- **fc**: Remove nested readiness retry floor
- Enforce and reduce prepared launch timing
- **vsock**: Send sealed control frames as binary instead of JSON
- **build**: Take the per-VM aux-helper leg off the inner loop
- **build**: Compute the guest source fingerprint once per process
- **kernel**: Stop hashing the workload kernel twice on every boot
- **admission**: Stop syncing reconstructible caches
- **launch**: Stop re-verifying the audit chain and sleeping past guest readiness
- **build**: Take mvm-cli's build script off the inner loop
- **audit**: Fold a cached prefix instead of re-reading the log
- **timing**: Name the parts of the admit window

### Refactored
- Typed PackBuilder authority, --sbom-uri, protected signing env, runtime-pack producer
- Split oversized CLI command modules
- **backend**: Rename no_guest_nic to no_routable_guest_nic
- **guest**: Remove dead HostBoundRequest surface; record Phase 1 progress
- **cli**: Rename the misnamed `dev_vz` module to `builder_vm`
- **ws8**: Split guest-agent handle_client dispatch into per-verb handlers
- **ws8**: Split OCI unpack_layer into per-entry-type handlers
- **ws8**: Split libkrun build_supervisor_config into cmdline + config assembly helpers
- **ws8**: Split configure_flake_microvm_with_drives_dir into per-section Firecracker config helpers
- **ws8**: Split exec.rs run_inner into phase helpers
- Rename the dev-shell Cargo feature to interactive
- **fs**: Decompose oci/unpack.rs into an unpack/ module tree
- **cli**: Decompose doctor.rs into a doctor/ module tree
- **cli**: Decompose image/mod.rs shared OCI core into submodules
- **cli**: Decompose ops/bench.rs into a bench/ module tree
- **runtime**: Decompose template/lifecycle.rs into a lifecycle/ module tree
- **cli**: Decompose vm/up.rs admission path into an up/ module tree
- **hostd**: Decompose supervisor/gateway_bridge.rs into a gateway_bridge/ module tree
- **runtime**: Decompose microvm.rs Firecracker backend into a microvm/ module tree
- **libkrun-sys**: Split the safe wrapper lib.rs into submodules
- **agentd**: Decompose vsock.rs into a vsock/ module tree
- **agentd**: Decompose the mvm-guest-agent binary into bin submodules
- **runtime**: Delegate reflink CoW to mvm-fs, drop the cow.rs duplicate
- Remove the dead smoltcp L3 egress path
- **mvm-agentd**: Native tokio-vsock dial for guest host-vsock session
- **mvm-agentd**: Consolidate guest AF_VSOCK sites onto a nix leaf
- **mvm-runtime**: Put the fork load behind SnapshotIO so the guard is testable
- **apple-container**: Drop vminitd — Apple's container kernel on the HVF runner with the universal initramfs
- **initramfs**: Build the universal initramfs as a deterministic cargo artifact, not a Nix build
- **build**: Delete the shell-env dev build path production never takes
- Consolidate protocol and volume contracts
- **agent**: Enforce DevOnly verbs at runtime
- **sdk**: Fold mvm-host-services-ffi into mvm-sdk
- **runtime**: Backend crate separation, HVF DAX, and QEMU virtio-fs
- **backends**: Extract VmmDriver seam and scaffold mvm-backends crate
- **backends**: Move HVF, libkrun, QEMU, and Mock drivers into mvm-backends
- Remove the retired backend's name from the tree, and gate it
- **backends**: Complete the Firecracker extraction into mvm-backends
- **oci**: Extract the no_std OCI decoders into mvm-contract (plan 301 B1)
- **net**: Delete the dead guest-NIC gateway stack
- **runtime,backends**: Invert driver/backend relationship
- **316**: Rename the endpoint spawner and give the FlowMux port one home
- Builders for every input-parameter struct
- **deps**: Move subscriber assembly out of mvm-core and the sealed agent
- **sec**: One host-binding predicate, and delete the dead one
- **cli**: One argument core behind `run` and `machine run`
- **deps**: Declare three crate edges where they are actually used
- **flowmux**: Delete superseded L3 networking
- **network**: Enforce the single FlowMux path
- **cli**: Drop legacy verity initrd fallback, always use universal initramfs
- **runtime**: Make the overlay the only guest-runtime source
- **boot**: Drop the per-rootfs verity initramfs
- **build**: Drop the builder-route decision seam
- **template**: Drop name-keyed template slots
- **backends**: Rename the *_legacy driver modules to *_process
- Drop two dead compat fields, correct the prose on the rest
- **sdk**: Give the in-guest host-services C ABI its own crate
- **contract**: Move GuestLibc below the crates that need it
- **hvf**: Delete the dev-tier virtio-fs root
- **qemu**: Refuse virtio-fs shares and delete the virtiofsd module

### Testing
- Test(guest)+build: verify detached-workload handler in CI; keep embedded agent fresh
- **mvm-cli**: Lock in runtime-pack warm-standby eligibility
- **net-tunnel**: Fuzz the raw-L3 egress gate packet parser (claim 5)
- **bdd**: Implement the uniform vsock-egress claim scenarios
- **sdk**: Enforce cross-language IR address parity
- Pin UOR-ADDR conformance vectors
- **cli**: Regression test for guest-source invalidation of OCI rootfs cache
- **egress**: Cover literal fallback edge cases
- **mvm-build**: Fix runtime-overlay build witnesses
- **mvm-conformance**: Capability-gate firecracker BDD scenarios
- **mvm-runtime**: Fuzz virtio-vsock virtqueue geometry + descriptor walk
- **mvm-conformance**: Signed-bundle boot scenario + gate the BDD target on PRs
- **runtime**: Assert a grant-less launch still pins the host anchor
- **mvm-build**: Isolate HOME so the builder-image refusals are hermetic
- Close the non-hermetic $HOME class and gate it in CI
- **bundle**: Make claim 9's witnesses discriminate on path safety and signature bytes
- Make two clock-sensitive test failures diagnose themselves
- **raw-egress**: Stop two connect fixtures depending on the ambient network
- **entrypoint**: Stop using a spawn deadline as if it were an assertion
- **bdd**: Move the decidable-without-a-VM contracts into the hermetic lane
- **release**: Consume the published artifacts through the real download path
- Close the subprocess half of the MVM_HOME isolation gate
- **worker-pool**: Replace the warm-pool's fixed sleeps with the conditions they stood for
- **hostd**: Stop racing a clock for a spawned process
- **worker-pool**: Stop sizing call timeouts as a multiple of the expected call
- **guest**: Gate guest-init parity and cover the egress path in BDD
- Classify bounding-set syscall results
- **agent**: Prove prod-safe grants refuse interactive verbs
- **agent**: Cover sealed profile dev-only refusals
- **broker**: Wait for the chain lock instead of assuming abort released it
- **agentd**: Assert eviction complexity by work done, not by a clock
- Test all CLI help entry points at 80 columns
- Close remaining mutation witness gaps
- **mvm-build**: Regression test for store-image lock survival
- **sec**: Cover surviving Security-lane mutants
- **sec**: Accept remaining Security-lane mutants in mvm-backends and mvm-runtime
- **audit**: Pin the two mirror properties #2475 left unwitnessed
- **sec**: Direct witnesses for the four surviving Security-lane mutants
- **egress**: Witness the blocking vsock leg's raw tunnel bound
- **sdk**: Make the fake-mvm double match the CLI it stands in for
- **sec**: Kill two substitution mutants; delete an unreachable wasm guard
- **vmm**: Witness the upstream-proxy egress config
- **ci**: Execute the Test aggregate against a synthetic scope matrix
- **sec**: Witness the redaction gate and the fail-closed cap
- **audit**: Witness segment selection, and name the two mutants that cannot be
- **bdd**: Say what the suite did not attempt
- **claim5**: Fuzz the post-auth path production actually takes
- **docs**: Verify every documented mvmctl command against the real CLI
- **docs**: Verify every documented example — CLI, Rust, Python, TypeScript, Nix
- **conformance**: Give the bundle scenarios a trust anchor and a fixture recipe
- **security**: Witness peer policy bindings
- **conformance**: Gate the workload-kernel fixture instead of panicking on it
- **docs**: Execute the documented surface instead of parsing it
- Stop two local-environment faults from faking test failures
- **nextest**: Refuse to run on a nextest too old for the build layout
- **e2e**: Raise the warm launch ceiling to the number the path holds
- **flowmux**: Use CONNECT-capable HTTPS clients in live witnesses
- **docs**: Reap what the e2e run created, and refuse to share a home
- **doctor**: Stop asserting the host has rustup
- **vmm**: Resolve portable dev VM socket path
- **bdd**: Gate virtio-fs directory shares, and stop handing live steps the wrong home
- **hostd**: Wait for replacement worker identity
- **docs**: Gate a release on every documented example running
- **bdd**: Witness broker on default backends
- **bdd**: Ratchet the parse tier so it cannot grow unnoticed
- **e2e**: Rebuild the per-VM supervisors before the launch gate boots
- **release**: Gate a release on evidence the documented surface ran
- **e2e**: Point the --mount witnesses at the directory the README mounts

## [0.17.0] — 2026-07-08

### Removed
- **backend**: Removed the Apple Virtualization.framework backend — its
  supervisor bin, builder, objc bindings and control shim, its builder module,
  its private `host_gvproxy` path, and the objc2/Virtualization dependency
  cluster. HVF is the sole macOS workload backend, with libkrun as the
  fallback; libkrun (+ gvproxy) and passt are untouched (Plan 226 R1P1). Its
  `--hypervisor` and `--builder` values are gone (they now fall through to
  auto-detect), and `xtask check-no-vz` fails the build if the backend or its
  name returns. `machine
  checkpoint/fork` is temporarily unsupported on macOS pending HVF save/restore
  (Plan 226 WS-E); the macOS-26 dev VM temporarily falls back to libkrun.

### ADR-003
- Rust-native egress gateway replaces the vendored Go gateway (Proposed)

### Added
- **stage0**: Add stage0-init — PID 1 of the nix-tarball Stage 0 seed (plan 160, 0a)
- **stage0**: Embed stage0-init via a SEED_BINARIES manifest list (plan 160, 0b wiring)
- **stage0**: Host-side nix-seed materialization + MVM_STAGE0_SEED branch (plan 160)
- **stage0**: Nix-tarball seed is the only Stage 0 path — drop Alpine/apk/pgp (plan 160 0c)
- **stage0**: In-process xz decode + Plan 164 (multi-arch embed) for x86_64
- **network**: BridgeTapNetworkProvider — Firecracker through the NetworkProvider seam (plan 123 A1 step 2)
- **network**: EgressEnforcer seam + SupervisorEgressEnforcer adapter (plan 123 A2.1)
- **network**: Route supervisor enforce-on-launch through the EgressEnforcer seam (plan 123 A2.2)
- **network**: Route supervisor teardown through the EgressEnforcer seam (plan 123 A2.3)
- **network**: SubstitutionStage + ScanStage egress seams, no-op (plan 123 A3.1)
- **builder**: Auto-GC the persistent /nix store so it stops growing unbounded
- **network**: Wire substitution/scan stages into the live egress pipeline (plan 123 A3.2)
- **network**: Thread egress stages from ObserverWiring (plan 123 A3.3)
- **network**: DNS sink-hole egress scan (plan 123 A4)
- **network**: Libkrun gvproxy/passt NetworkProvider (plan 123 L3 slice A)
- **network**: Host-side mandatory-deny egress scan (plan 123 A2)
- **network**: Wire mandatory-deny as the live default egress scan (plan 123 A2)
- **network**: NetworkPolicy L4 egress scan primitive (plan 123 A2)
- **network**: Per-tenant L4 egress enforcement at the gateway bridge (plan 123 Slice 3)
- **build**: Per-arch embedded host-binary target (Plan 164 Tasks 1-3)
- **stage0-init**: QEMU builder backend support (Plan 165 Phase 1, guest side)
- **qemu**: Host-side QEMU builder backend + Stage-0 selector wiring (Plan 165)
- **admission**: Wire the tenant PolicyBundle into the bridge (plan 123 Slice 3b)
- **guest**: Gate PTY-over-vsock console behind the runtime profile and signed grant boundary (Plan 165 WS-C)
- **sdk**: No-entrypoint policy — has_declared_entrypoint + compile fail-closed (Plan 165 WS-B B1/B3)
- **hostd**: Admission fail-closed on sealed image with no entrypoint (Plan 165 WS-B B4)
- **plan-124 A1**: Runtime-free gate for the guest agent closure
- **plan-124 A3**: Netinit rtnetlink → synchronous raw netlink; drop tokio
- **network**: Wire DnsSinkholeScan per-tenant from the egress allow-list (plan 123 Slice 3 DNS)
- **plan-124 B1**: Mvm-host-vm-init forks mvm-guest-agent (universal agent)
- **plan-124 B2**: Check-guest-agent-in-all-images enforcement gate
- **network**: Audit names the dropping scan, not the chain wrapper (plan 123 Slice 3 polish)
- **secrets**: SecretRef gains auth_type + allowed_hosts; lift the not-implemented gate (plan 129 Phase A)
- **plan-166**: QEMU run_build — steady-state builds (Task 1.5)
- **plan-166**: Route mvmctl build through the selected builder backend
- **plan-166**: Skip egress lockdown on the dev-tier QEMU builder (ADR-007)
- **plan-124 C1/2a**: Wire runtime-overlay resolver into the up/run boot path
- **mvm-backend**: Public sign_binaries/entitlements_present API
- **mvm-backend**: Collect_sign_targets aggregator
- **mvm-cli**: Emit_json shared output helper
- **mvm-cli**: Mvmctl sign command
- **mvm-cli**: Doctor signing security check
- **mvm-cli**: Cache info --json
- **mvm-cli**: Network list/inspect --json
- **mvm-cli**: Snapshot ls --json
- **mvm-cli**: Audit ls --json
- **mvm-core**: Most_recent_running session selector
- **mvm-cli**: Session attach --continue/--resume
- Session start --ephemeral with post-attach teardown
- **mvm-cli**: Resumable dev-image download (curl -C -)
- **mvm-cli**: Honest one-time-cost framing for dev image download
- **secrets**: SecretResolver trait + LocalResolver over SecretStore (plan 129 B1)
- **secrets**: FileBindingStore for local secret binding metadata (plan 129 B2)
- **secrets**: Mvmctl secret set + binding-aware ls/rm (plan 129 B2)
- **secrets**: Signing keyholder — SigV4 + HMAC, key never leaves (plan 129 C1)
- **secrets**: Injecting keyholder — bearer/basic, bound-before-decrypt (plan 129 C2)
- **plan-166**: QEMU workload runtime backend (Phase 2 Task 2.1 + 2.2)
- **plan-166**: Dev-tier workload kernel fallback for QEMU
- **secrets**: Substitution registry + endpoint dispatch core (plan 129 D1)
- **secrets**: PlaceholderLeakScan — drop smuggled placeholders, live (plan 129 E1 baseline)
- **plan-124 D1.1**: Protocol schema SSOT — JsonSchema on the RPC wire types
- **secrets**: Host substitution endpoint request prep (plan 129 D-T1)
- **secrets**: Running host substitution endpoint over UDS (plan 129 D-T2)
- **plan-166**: Make ls/down backend-aware (QEMU/libkrun VMs visible + stoppable)
- **secrets**: Admission-time substitution registry assembly (plan 129 #1a)
- **secrets**: SubstitutionService::from_plan constructor (plan 129 #1b core)
- **plan-169**: Backend-agnostic fs/cp agent RPC (+ plan)
- **secrets**: Secret.substituted/placeholder_dropped audit (plan 129 E2, claim 13)
- **secrets**: Signer-path endpoint dispatch — SubstitutionEndpoint::sign (plan 129 #3)
- **plan-169**: Backend-agnostic proc/diff agent RPC
- **secrets**: In-guest substitution client relay (plan 129 #4b)
- **plan-169-wsa**: Reconcile convergence core (mvm::vm::reconcile)
- **plan-169-wsa**: Mvmctl reconcile verb
- **plan-169-wsa**: Converge on CLI entry + doctor drift line
- **secrets**: In-guest forward-proxy front (plan 129 #4c, model ii)
- **secrets**: SigV4 canonical-request builder (plan 129 #4 signing)
- **plan-170-wsb**: Last_active field + touch_last_active on VmRegistration
- **plan-170-wsb**: Activity-driven idle-sleep in the reaper
- **plan-170-wsb**: Touch last_active on console attach + wake
- **secrets**: Boot-wiring helpers — guest env + forward-proxy bootstrap (plan 129 #4)
- **mvm-guest**: WORKLOAD_EXIT_PORT control vsock constant
- **mvm-guest-helpers**: Mvm-exit-report AF_VSOCK exit reporter
- **nix**: Bake mvm-exit-report into the guest rootfs
- **nix**: /init captures workload exit code, reports, poweroff -f
- **mvm-vm-host**: Backend-agnostic workload exit-capture unit
- **libkrun-sys**: Add_host_listen_port (listen=false control port)
- **supervisor**: Bind workload-exit control listener + capture thread
- **mvm-backend**: Libkrun registers control port + wait() surfaces exit code
- **mvm-cli**: Plan.exited audit event
- **mvm-cli**: Up --wait propagates workload exit code + plan.exited
- **secrets**: Host AF_VSOCK listener for QEMU guest->host substitution (plan 129)
- **guest**: Workload env injection via RunEntrypoint protocol (plan 129)
- **mvm-guest**: ExecEvent stream variant (Plan 159 WS-5 E)
- **mvm-guest**: Send_exec_streaming host reader (Plan 159 WS-5 E)
- **mvm-guest**: Exec_stream core — progressive stream_exec (dev-shell)
- **mvm-guest-agent**: Stream Exec via do_exec_streaming (Plan 159 WS-5 E)
- **mvm-cli**: Exec.rs streams exec (run live / run_captured accumulate)
- **mvm-cli**: Console --command streams exec output
- **mvm-backend**: Exec_via_vsock streams + accumulates (Plan 159 WS-5 E)
- **mvm-cli**: Session run-code streams ExecEvent (Plan 159 WS-5 E)
- **mvm-cli**: Apple-container dev status streams exec probe (Plan 159 WS-5 E)
- **hostd**: Mvm-substitution-endpoint per-VM secret moat (plan 129, stage 1)
- **qemu**: Spawn the per-VM substitution endpoint when the plan has secrets (plan 129, stage 2a)
- **secrets**: Inject HTTP_PROXY + placeholders at invoke; guest starts forward proxy (plan 129, stage 2b+2c)
- **sdk-py**: Egress-binding secret() + retire in-guest substitution (plan 129)
- **sdk-ts**: Egress-binding secret() + retire in-guest substitution + docs (plan 129)
- **plan-173**: Enforce exec timeout_secs (pgroup kill + ExecEvent::TimedOut)
- **resume**: Host-side PostRestore sender (plan 123 Phase C prerequisite)
- **storage**: Linux LUKS2 arm of EncryptedStorage (plan 123 B2)
- **secrets**: Egress redact-to-XXX detector for undeclared secrets/PII (plan 129 Phase E)
- **plan-123 C4**: Libkrun disk-only warm-start + doctor warm-start matrix
- **secrets**: Plan 129 SDK-free egress — transparent terminator core
- **secrets**: Plan 129 — wire egress terminator into Firecracker (TAP redirect)
- **secrets**: Local secret-workload launch + endpoint egress redaction (plan 129)
- Plan 118 WS-1 supervisor warm pool (1a–1b-iii) — prelaunched standbys + backend-agnostic trait seam + up auto-claim
- **plan-129**: Stage 2 — transparent https egress secret substitution (name-constrained CA)
- **checkpoint**: Plan 159 WS-2 PR1 — fs_quick checkpoint + fork
- **checkpoint**: Plan 159 WS-2 PR2 — vm_full memory checkpoint + restore + fork
- **invoke**: Ephemeral secret-workload invoke via admission + endpoint (plan 129)
- **secrets**: Emit secret.placeholder_dropped on endpoint claim-12 refusal (plan 129 E2)
- **secrets**: Undeclared-secret/PII egress redaction mechanism (plan 129 E1 Step 2)
- **checkpoint**: Plan 159 WS-2 PR3 — checkpoint diff + pause/resume (finishes WS-2)
- **secrets**: Admission carriage — redaction policy plan->backend->endpoint->service (plan 129 E1)
- **cli**: Mvmctl up --redact authors per-destination egress redaction (plan 129 E1)
- **secrets**: Enrich always-on default secret list with 17 vendor token shapes (plan 129 E1)
- **secrets**: Egress no-secret-to-guest leak-gate — claim 16 Preview (plan 129 Phase F)
- **terminator**: Redaction + fail-closed + audit on the transparent terminator path via a typed error (plan 129)
- **secrets**: Live PII spans into name co-occurrence on the redact path (plan 129 E1)
- **secrets**: SigV4/HMAC forward-path signing, bind-checked (plan 129)
- **secrets**: Self-applied jailer confinement on the substitution endpoint (plan 129)
- **plan-129**: Audit recorder in spawned endpoint + stamp Plan 129 COMPLETE
- **cli**: Mvmctl dev status --json (Plan 189 WS-3 first slice)
- **cli**: Library-consumable plan synthesis + caller audit_labels passthrough
- **checkpoint**: Fork --boot — the two-copy fork (admitted child boot)
- **cli**: Mvmctl dev down --json (Plan 189 WS-3)
- **checkpoint**: Instant memory fork — second live VM from a running parent in 0.91s
- **dev**: Add `dev up --json` lifecycle envelope (plan 189 WS-3)
- **net**: MVM_NETWORKING=native gateway flag (ADR-003 Phase 1)
- **sdk**: Generate host↔guest protocol type stubs from protocol-v0.json (plan 124 D1.2a)
- **backend**: WorkloadBackend type-bar — core security features non-skippable (Plan 197 Phase 1)
- **guest**: Machine-readable host↔guest RPC request→response contract (plan 124 D1.2 step 2a)
- MacOS egress secret substitution — vsock-5253 channel on libkrun (Plan 197 Phase 2a)
- **guest**: Contract-checked host-side RPC client over the response contract (plan 124 D1.2 step 2b)
- **core**: WASI fs/env capability projection (ADR-024 A1 / Plan 192)
- **up**: `--console` boots straight into an interactive shell
- **sdk**: Sandbox copy_in/copy_out in both Python + TS SDKs (plan 125 B1a)
- **sdk**: Sandbox forward/ports in both Python + TS SDKs (plan 125 B1b)
- **sdk**: TS Sandbox.exec parity with Python (plan 125 D1)
- **sdk**: Async Sandbox surface in both SDKs (plan 125 B2)
- **sdk**: Sandbox id + info lifecycle accessors in both SDKs (plan 125 B3)
- **sdk**: CodeSandbox code-runner preset in both SDKs (plan 125 C1)
- **sdk**: BrowserSandbox preset in both SDKs — completes Phase C (plan 125 C2)
- **doctor**: Per-backend capability matrix (plan 125 E3)
- **cli**: --secret NAME:host binding on `up` (plan 125 E2)
- **policy+cli**: Named security profiles — production default, dev never deploys (plan 125 E4)
- **plan-125**: E5.1 in-guest broker transport (mvm-guest::broker_client)
- **plan-125**: E5.3a reserve BROKER_PORT in host_listen_ports (libkrun)
- **plan-125**: E5.2 host.audit.v1 + E5.4 host.time.v1/host.cost.v1 typed methods (mvm-guest)
- **plan-125**: E5.3b-0 per-VM workload audit-chain verifier + mvmctl audit verify
- **plan-125**: E5.3b-1 mvm-audit-signer per-VM spawn helper
- **plan-125**: E5.3b-2a mvm-broker per-VM spawn helper
- **plan-125**: E5.3b-2b-core gated broker-services spawn + RAII reaper
- **plan-125**: E5.3b-2b-wire (libkrun) spawn broker services on admitted up
- **plan-125**: E5.3b-2c broker reassigns a server-authoritative correlation id
- **plan-200**: Mvmctl machine run — beginner image-backed runner (WS-A/B kickoff)
- **plan-193**: WS-2.2a — lower egress policy into rvproxy's native [policy] config
- **plan-125**: In-guest audit-probe + opt-in mkGuest bake (E5.3b-4 in-guest driver)
- **plan-193**: WS-2.2a — full-fidelity policy lowering (L4 proto/port + DNS sinkhole)
- **doctor**: Surface the builder VM's last net-bootstrap outcome (Plan 183 final item)
- **plan-125**: E5.3b-3a in-guest host-services SDK type codegen (no pyo3/napi)
- **plan-199 B2**: Release artifact matrix + fail-closed verification gate
- **plan-200**: Image source classifier + run --image seam
- **plan-193**: WS-2.2b — emit the full rvproxy run --config TOML
- **plan-200**: OCI image-layout archive reader (mvm-oci)
- **plan-125**: E5.3b-3a cdylib core for the in-guest host-services SDK veneer
- **plan-193**: WS-2.2b — native rvproxy launch via run --config
- **plan-200**: Wire OCI archive ingest into run --image
- **plan-125**: E5.3b-3b cross-compile + bake + Python ctypes veneer
- **plan-193**: WS-2.2c — re-feed rvproxy flow events into the chain-signed audit
- **plan-200**: Stdin + rootfs-dir ingest for run --image
- **plan-125**: E5.3b-3c Node/TS koffi veneer over the same cdylib
- **plan-200**: --net/--allow-host uniform egress enforcement for transient runs (WS-B)
- **plan-200**: Default binary-closure budget CI gate
- **plan-202**: Host-agent control protocol — RegisterVm/DeregisterVm (1a)
- **plan-200**: Emit plan.launched/plan.failed on the transient run path (WS-B follow-up)
- **plan-200**: Admit MCP code-runs so deny-all egress is enforced (WS-B follow-up)
- **plan-202**: Resident per-tenant host-agent daemon (Phase 1, 1b+1d)
- **plan-202**: Backend host-agent daemon seam — ensure/register/deregister (1c-wire-a)
- **plan-200**: Admit the MCP warm-session VM too (claim-10 closeout)
- **plan-202**: Wire start/stop onto the host-agent daemon behind a flag (1c-wire-b)
- **plan-200**: Uniform host:port L4 egress on the libkrun bare path (WS-B follow-up)
- **plan-200**: Decide + pin DHCP/ARP posture under deny-all (loopback-only) (WS-B follow-up)
- **plan-202**: Make the host-agent daemon the default (Phase 3a)
- **cache**: Reap orphaned dead-microVM helpers by default in `cache prune`
- **plan-193**: WS-2.2d — native rvproxy audit feed + native-enforcement parity arm (proven live)
- **plan-200**: Run --image boots OCI images end-to-end (Session 3 item 1)
- **plan-202**: Report host-agent daemon state in doctor
- **plan-202**: Add tenant signer helper core
- **plan-202**: Proxy host signing through signer helper
- **plan-202**: Rebuild signer helper heads on restart
- **plan-202**: Persist host-agent registrations
- **plan-202**: Supervise host-agent restarts
- **machine**: Persist specs and add named VM wrappers
- **machine**: Add persistent OCI-backed start path
- **plan-202**: Add tenant cost agent wire messages
- **bench**: Add density report substrate
- **core**: Add delegated host service protocol variants
- **bench**: Add live density benchmark hooks
- **plan-205**: Workstream A — machine-checked trust-gradient invariant
- **plan-204**: Mvm-builderd binary, rootfs embedding, and boot launch (WS-A)
- **plan-205**: Workstream B — residency policy + observability
- **plan-204**: Typed build-op handlers — BuildGuestImage/BuildHostTool/PrefetchSource/QueryStorePath (WS-C)
- **plan-205**: Workstream D — parked standbys (snapshot park/resume, logic slice)
- **cli**: Mvmctl bootstrap — pre-fetch the builder VM image (instant first run)
- **plan-205**: Builder-daemon no-authority gate — trust gradient now covers all three daemons
- **plan-205**: Builder residency Step 1 — MVM_RESIDENCY governs the builder VM (warm/cold)
- **cli**: Tiered, liveness-guarded cache reclamation
- **plan-205**: Builder-residency decision core (keeper action + snapshot freshness)
- **cli**: Quiet by default; -v/-vv/-vvv verbosity + downgrade boot-race vsock warning
- **plan-200**: Artifact extract — verify-before-extract + machine portable-artifact primitive
- **plan-189**: Add linux-native dev status json detail
- **cli**: Heartbeat during the silent Stage 0 builder-image build
- **plan-200**: Machine check-artifact — portable-artifact runner security core
- **cli**: Make [mvm] ui chatter opt-in via RUST_LOG/--verbose
- **plan-205**: Enforce persistent builder residency
- **stage0**: Stream the in-guest nix build log to the host console live
- **plan-189**: Expose pinned dev base fingerprint
- **plan-175**: VMGenID delivery on PostRestore (Task 1)
- **plan-175**: FirecrackerBackend::warm_start + vm resume --warm (Task 4)
- **plan-205**: Close resident builder live gates
- **plan-175**: Primed ready-barrier protocol (Task 3, Step 1)
- **plan-201**: WS-A WarmLease — RAII borrow-handle over the standby pool
- **plan-203**: Slice-1 forensic transcript manifest + bounds + verifier
- **sdk**: Expose machine artifact checks
- **plan-201**: WS-B/C ExecBuilder + ExecOutcome (Tier 1 one-stream pipelining)
- **plan-203**: Capture writer + at-rest encryption + verify-and-decrypt export
- **plan-203**: Transcript key-wrapping — host KEK + at-rest data-key seal
- **plan-206**: Primed-barrier wiring + honest warm-start reseed verb
- **plan-201**: WS-D ExecBatch Tier-2 — one-round-trip staged batched exec
- **plan-203**: Mvmctl trust audit transcript CLI + lifecycle audit kinds
- **xtask**: Add duplicate-major dependency budget gate
- **plan-201**: WS-E verification_loop example — closes Plan 201
- **xtask**: Add binary-size budget gate
- **xtask**: Freeze builder shell-job dispatch sites (Plan 204 WS-D lint)
- **plan-203**: Hostd transcript capture sink + gateway-bridge tap
- **plan-200**: Make the <200ms dispatch bar a surfaced, pinned, tested construct
- **plan-204**: No-host-nix gate (WS-C) + builder_route compat-adapter seam (WS-D)
- **plan-204**: Add typed guest-image build adapter to builder_route (WS-D)
- **plan-204**: Export built image artifacts to a host-readable share (WS-D)
- **plan-204**: Route persistent guest-image builds through mvm-builderd (WS-D)
- **cli**: Animated spinner for the builder-VM build wait
- **cli**: Stream the Stage 0 builder build log under -v/RUST_LOG
- **nix**: Drop the Rust toolchain from the dev builder rootfs
- **nix**: Drop the Rust toolchain from the dev builder rootfs
- Additional improvements
- **build**: Stream the build image / template build nix log under -v
- **machine**: Unified run lifecycle — persistent + interactive (Plan 207)
- **build**: Auto-fall-back to the qemu builder on a libkrun VMM failure
- **build**: Extend libkrun→qemu auto-fallback to the dev_build + Stage 0 paths
- **build**: Per-host libkrun-builder health cache (skip the doomed attempt)
- **cli**: Consolidate workload CLI onto `machine` (Plan 208, Tasks 1–7)
- **plan-204**: Default guest-image builds to the typed mvm-builderd route + raw-shell debug gate (WS-D)
- **machine**: --volume host shares + auto-recreate for managed `machine run`
- **cli**: Fold `up`/`run` into `machine run` — source axis (Plan 208 Task 4, pt 1)
- **vm-host**: ADR-007 + Plan 209 Tasks 1–2 — unified mvm-bridge sidecar contract + binary
- **vm-host**: Plan 209 Task 4 — fold FC sidecars into mvm-bridge (libkrun merged); live-verified
- Add attested pack manifest verifier core
- **backend**: Fail-closed capability model (Plan 214 slice 1)
- **machine**: Machine/MachineBuilder library with capability-gated construction
- **backend**: Capability-aware backend selection (fail-closed)
- **machine**: Machine::select_backend links the library to fail-closed selection
- **machine**: Translate Machine into a launchable VmStartConfig
- **core**: Hardened snapshot frame v0 (cap-bounded, fail-closed parsing)
- **core**: Snapshot frame v0 section-table parsing
- **core**: Guest lifecycle markers + snapshot timing
- **core**: Flat launch-metadata parsers for mvm-init
- **core**: Resident-memory accounting for warm pools
- **core**: Add NetworkMode to the signed ExecutionPlan (Plan 214 Phase 6)
- **core**: Mvm-init supervisor core logic (metadata to exec spec + markers)
- **core**: Host egress-broker decision logic, closed-by-default (Plan 214 Phase 6)
- **core**: W3C trace context for audit correlation (Plan 214 Phase 3)
- **core**: Reusable freshness primitive for signed-payload replay protection
- **core**: Host ingress-broker decision logic, closed-by-default (Plan 214 Phase 6)
- **core**: Guest mvm-netd proxy env-var injection
- **core**: Egress-broker handler composing decision + trace + audit
- **client**: Mvm-client crate — MvmClient facade trait + DTO contract + mock (Plan 216 S0)
- **core**: Ingress-broker handler composing decision + trace + audit
- **core**: Host-side egress secret substitution — secrets never enter the guest (Plan 214 Phase 6)
- **core**: Ingress secret redaction (mask secret values before they reach the guest)
- **client**: GatewayBackend — complete remote MvmClient over mvmd-gateway (Plan 216 S3+S5)
- **core**: Add snapshot_at to the signed ExecutionPlan (Plan 214 Phase 5/11)
- **cli**: Machine rm accepts multiple names and --all
- **backend**: In-house VMM driver seam + claim-10 gate relocation + WorkloadRunner (Plan 214)
- **core**: Record build provenance in the signed ExecutionPlan (schema v8 to v9)
- **build**: Build-provenance recorder (Plan 214 Phase 4)
- **sdk**: Cross-language machine-verb conformance harness + close all audit gaps
- Converge SDK on the MvmClient facade — extract mvm-client-local + SDK subprocess impl (Plan 218 P0/P1)
- **cli**: Emit chain-signed verb_denied on a session set-timeout refusal
- **sdk**: Status-aware machine ls (close the facade's "always Stopped" gap)
- **cli**: Audit verb_denied across the agent-RPC verb surface (exec/run-code/attach)
- **run**: Drop --stdin, auto-detect non-TTY stdin (backend-deprecation Phase 1 / Plan 220)
- **hostd**: Admit_and_start — the shared admitted-boot entrypoint (#1388 slice 4a)
- **build**: Auto-detect the in-house HVF builder on macOS-26 (replacement fallback) — #1403
- **sdk**: Wire MvmClient::run to boot real admitted machines
- **ext4**: Mvm-ext4 — memory-safe pure-Rust ext4 writer (Plan 221 B2)
- **ext4**: Pure-Rust dm-verity root hash + veritysetup CI differential (Plan 221 B)
- **ext4**: Emit full dm-verity hash tree, byte-diffed vs veritysetup (Plan 221 B)
- **build**: Materialize_ext4_pure — in-process rootfs materialize (Plan 221 B)
- **mvm-build**: Compute dm-verity in-process in materialize_ext4_pure
- **mvm-hostd**: In-process local-run admission seam (admit_and_boot_local)
- **mvm-client-local**: Boot local runs in-process via the admission seam
- **mvm-ext4**: Multi-block-group images (rootfs past 128 MiB)
- **run**: Materialize the run-path rootfs in-process by default
- **console**: Interactive -it shell over the in-house VMM (backend-deprecation Phase 2A / Plan 221)
- **mvm-ext4**: Depth-1 extent tree for files past 4 inline extents
- **mvm-client-local**: Resolve registry refs + unpacked dirs in LocalBackend.run
- **run**: Embed guest-agent binaries so end-user run --image works offline
- **machine**: Positional name for `machine start` + confirm prompt on `machine stop`
- **mvm-ext4**: Native in-inode xattr support (preserve file capabilities)
- **machine**: Positional name for `machine exec` / `machine shell`
- **machine**: Actionable "machine does not exist" errors
- **machine**: `machine rm` prompts for confirmation like `machine stop`
- **machine**: `ps` as a visible alias for `machine ls`
- **verb-grant**: Measured verb-trust policy + restore reconciliation (ADR-001, #1381 item 3)
- **machine**: Auto-generate a name for `machine create` when omitted
- **machine**: Batch `machine stop <name>...`
- **machine**: Batch `machine start <name>...`
- **verb-grant**: Stage A — launcher-gated enforcement flip (ADR-004, #1381 item 3)
- **run**: Virtiofs-root tier gate + backend capability (Plan 223 A4/A1)
- **machine**: Aligned `machine ls` table with header + AGE column
- **mvm-client**: Add inspect/create/start/remove to the MvmClient trait
- **vmm**: Read-only FUSE server for a virtio-fs root (Plan 223 A1)
- **machine**: `machine restart <name>...` (stop if running, then start)
- **vmm**: Virtio-fs MMIO device wiring the FUSE server to the virtqueues (Plan 223 A1b)
- **machine**: Make `machine exec <name>` argv optional (drop into a shell)
- **machine**: `machine reconfigure` verb + MvmClient facade op (Plan 224 Phase 1)
- **hvf**: Wire the virtio-fs root device into the in-house boot path (Plan 223 A1b-ii)
- **mvm-client-local**: Real local remove_machine (stop-based teardown)
- **run**: Virtiofs-root selection wired into run --image on HVF (Plan 223 A4→run path)
- **audit**: Chain-signed plan.grant_required entry (M1, #1457)
- **virtiofs-root**: Chain-audit the resolved boot posture (A3)
- **checkpoint**: Resolve fs_quick rootfs backend-neutrally (backend-neutral step 1, #1478)
- **egress**: Slice 1 Phase A — libkrun transparent-TCP vsock egress (flag-gated, NIC retained)
- **kernel**: Strip unreachable block drivers from the workload kernel (Plan 209 Batch 6)
- **checkpoint**: Backend-neutral vm_full capture on Firecracker (#1478 step 2 capture)
- **mvm-client**: MachineSpec builder pattern + refresh examples & Rust SDK docs
- **machine**: Workload healthcheck as a lifecycle signal (phase A)
- **hvf**: Demand-zero guest RAM (working-set residency, 638→144 MB idle)
- **healthcheck**: Phase C — active probing + bounded restart
- **hostd**: Chain-sign workload health transitions and restarts
- **hvf**: Share kernel image mappings
- **mvm-core**: Bind keyless pack signer id to the verifying identity

### Changed
- **stage0**: Scrub stale Alpine/pgp references from comments + test fixtures
- Gitignore default mvmctl compile output dir (/out/)
- **specs**: Renumber QEMU plan 165 → 166 (165 taken by entrypoint plan on main)
- **xtask**: Gate man-page deps behind a `man` feature
- **mvm-vm-host**: Declare per-VM substrate_server_category (architecture invariant #1)
- Scrub stale references to the deleted apple_container / docker / cloud_hypervisor backends + dead Vfkit variant
- **vsock**: Delete dead VsockProxyTransport
- Refresh folded-crate names in comments (mvm-security/plan/policy/ir/base/providers → post-121 paths)
- **xtask**: Ban sigstore/opendal/pgp from mvmctl's default closure (plan 126 D1)
- **mvm**: Delete the orphaned FC instance/pool/tenant lifecycle subtrees (Plan 185 Task 6)
- Gitignore the .superpowers/ scratch dir
- **just**: Add `check-linux` — zig cross-compile-check for Linux on macOS
- **just**: Add watch-prs recipe for tailing open PR merge state
- **mvm**: Delete orphaned security/cgroups module
- **net**: Drop rvproxy first-party gateway — CI gate + ADR status (Plan 214)

### Documentation
- **plan-160**: Drop Alpine from Stage 0 — seed with busybox + static Nix
- **plan-160**: Phase 0 spike — official nix tarball confirmed; seed needs a /init userland
- **plan-160**: Grounded stage0-init design + de-risk-first sequence
- **plan-160**: 0a findings — networking is free, overlay nix-store already exists
- **plan-160**: 0b ACHIEVED — nix-seed Stage 0 builds the builder VM + reaches "Dev environment ready"
- **plan-160**: State x86_64 reality plainly — aarch64-guest only today
- **plan-123**: Sequence the remaining Phase A lift (L1-L4) with security findings
- **plans**: Add Plan 165 — entrypoint-presence policy + sealed-prod interactivity prohibition
- **plans**: Plan 165 A0 verdict — wrapper is a shell script
- **plan-123**: Reconcile Phase A — claims-gated lift landed (A1-A4 + L3-A)
- **plan-152**: Record minimal-launcher prior art; flip Plan 134 gate
- **plan-166**: Promote cold-state guarantee to a witnessed non-persistence claim
- **plan-167**: Renumber non-persistence plan 166->167 (collision with feat/plan-166-qemu-builder)
- ADR-007 + Plan 165 — QEMU dev/builder backend (Firecracker stays prod)
- **adr-072,plan-165**: Scope QEMU to Linux; the macOS built-in is the equivalent
- **claim15**: Catalog row + ADR-001 + CLAUDE.md — no interactive access to a sealed prod microVM (Plan 165 WS-C)
- **plan-165**: Tick WS-B/WS-C; defer A4 invoke witness + note latent B4 gate
- **sdk**: Clarify B1 comment — B4 enforces via the entrypoint_present wire field, not this predicate (Plan 165 review fix)
- **plan-124 A4**: Record the −27-crate cut; defer A2 (serde_json unremovable)
- **plan-157,adr-072**: Warm-snapshot prior-art adoption boundary
- **adr**: Renumber ADR-007 (then numbered 072) → ADR-025 (072 taken by qemu-dev-builder-backend on main)
- **adr-073**: Fix half-applied renumber (072→073 in headings + Plan 157 links)
- **adr-073,plan-157**: Scope page-cache priming to the immutable rootfs
- **plan-166**: Record QEMU run_build reachability gap found on box
- **plan-166**: Record Task 1.5 box verification + egress-lockdown follow-up
- **plan-166**: Task 1.5 fully green on box — networked QEMU run_build E2E
- **plan-168**: Record final-review follow-ups (json migration, doctor coverage)
- **plan-166**: Phase 2 done + box-proven (workload boot + agent round-trip)
- **spike**: Recast success threshold as separation + materiality gates
- **spike**: Implementation runbook + fat-image working-set refinement
- **spike**: A+B fixed , Bug C surfaced
- **plan-129**: Mark #1a + #1b-core done; scope remaining bin glue
- Refer to the external fork/snapshot sibling obliquely (Plans 148, 157)
- **plan-169**: Mark box verification done (QEMU diff/fs round-trip; proc reaches agent)
- **plan-169**: Host-side lifecycle convergence + single-host density
- **plan-170**: Renumber 169→170, mark WS-A done, defer --repair
- Refer to all external sandbox/VMM sibling projects obliquely
- Scrub external sibling names from published docs (new since rebase)
- **plan-129**: Consolidate status — host+guest Rust foundation landed (12 PRs); scope remaining boot/SDK work + 2 design decisions
- **plan-170**: Mark WS-B mvm-side mechanism done; backend SleepFn + loop are mvmd-side
- **plan-170**: Fill in WS-B PR number
- **plan-170**: Update status line for WS-B
- **plan-152-wsa**: Design note for guest /init exit-code + poweroff parity
- **plan-169**: Implementation plan for Plan 152 WS-A (init exit-code + poweroff)
- Correct control-port comment (listen=false, 4-byte LE) + VmExitStatus.success + capture_once best-effort
- **plan-169**: Record T3.4 E2E status — fixture done, live boot blocked on builder staging (not WS-A)
- **plan-169**: T3.4 live E2E PASSED — mvmctl exits 7, plan.exited chain entry; +2 E2E-found fixes
- Renumber WS-A implementation plan 169 -> 171 (169/170 taken on main)
- **plan-166**: Reconcile status — Phase 2 DONE, Plan 169 follow-up ticked
- **plan-152**: WS-B threading-model decision — serial queue + delegate, tokio current-thread I/O
- **plan-129**: Record the workload-env-injection finding (env_clear; new agent-protocol plumbing needed)
- Add cross-plan REFACTOR-STATUS rollup checklist
- **plan-170**: Density (WS-B/C/D) is owned by mvmd; close out mvm-side
- Keep REFACTOR-STATUS.md current during the major refactor
- **plan-129**: Box-validation finding — guest->host vsock transport is backend-shaped (QEMU AF_VSOCK vs Firecracker UDS-mux)
- **plan-129**: Mark host AF_VSOCK listener done; transport complete both directions
- **plan-159 WS-5 E**: Design — truly streamed exec (ExecEvent, progressive)
- **plan-172**: Implementation plan for WS-5 E streamed exec
- **plan-172**: T8 live E2E PASSED — progressive streaming proven (first…2s…second)
- Refresh REFACTOR-STATUS — plan 129 transport+env, 170 closed mvm-side, +159 row
- **plan-129**: Record endpoint-moat decision + stage 1/2 split
- Correct REFACTOR-STATUS PLAN 159 row — Plan 168  slice shipped, not gated
- **plan-129**: Egress-substitution loop wired end-to-end (QEMU) + boot-e2e runbook
- **examples**: Secret-egress workload + boot-e2e toolchain finding (plan 129)
- **prompts**: Plan 123 kickoff — per-tenant egress enforce + full remaining map (A/B/C)
- **refactor-status**: Record Plan 129 Phase E (egress redact-to-XXX) — PR #733
- Require reuse-first, small testable units, builder/trait patterns
- **prompt-129**: Mark Phase E done ; narrow next session to local launch glue
- **plan-175**: Carve out Firecracker live-memory warm-start from Plan 123 C2
- Name ~/.cache/mvm + mvm_cache_dir in the use-the-helpers rule (AGENTS+CLAUDE)
- **plan-129**: Terminator core+FC wiring delivered (#735/#744); defer live FC e2e to bringup session
- **plan-129**: Stage 2 (CA + https) TDD plan; note #745 local-launch glue in bringup handoff
- Rewrite project overview as security-first product overview
- **network**: Add rvproxy gateway ownership ADR and plan
- **refactor-status**: Mark Plan 159 WS-1 warm pool DONE (#758 closes bundled-kernel compat)
- **plan-129**: Close local-admission-launch gate + Stage 2 status (#761/#763)
- Feature-surface reduction — ADRs + plans (backend + CLI consolidation)
- **refactor-status**: Plan 178 ✅ DONE (run-family merged in #768)
- **refactor-status**: WS-2 complete  — flip restored after the Plan 178 merge dropped it
- **plan-181**: App-builder product surface — ADR-014 + plan + rollups
- **refactor-status**: Add top-level 'Plans at a glance' checklist above the details
- **refactor-status**: Sync glance with details (Plan 180 done, 129 reachability fixed, 177 P2 in progress)
- Plan 183 — builder-VM egress posture + guest network bootstrap
- **plan-129**: Record clean-room recipe e2e (QEMU green) + FC-leg follow-ups
- **plan-177**: Record Phase 2 landing  — prune ADR-001 tier matrix; sync rollup
- **plan-177**: Mark Phase 2 DONE; spin DX-parity into Plan 189
- **adr-002**: Record the wasm-sandbox Tier-0 preview substrate in the tier matrix
- **specs**: ADR-024 program rollup (REFACTOR-STATUS + SPRINT 62) + Plan 190 kernel-wiring spec
- **sprint**: Refresh stale Current Status header (v0.13.0 → v0.16.1)
- ADR-024 wasm-component runner + Plan 192 (A1 capability projection fs/env)
- **plan-192**: Propose rvproxy network substrate (replace gvproxy/passt) + record gvproxy/build-perf findings
- **rollup+sprint**: Record warm-claim admission-sha reuse
- **rollup**: Cite #826/#833 on the two-copy-fork + instant-memory-fork lines
- **deps**: Record the plan 126 Phase D final dependency measure
- **adr-082**: Align flag literal with shipped `native` (was `rvproxy`)
- **claude**: MVM_NETWORKING now accepts the opt-in `native` value
- **plan-197**: Phase 2 design spike — terminator → rvproxy; split into 2a (mvm vsock channel) + 2b (rvproxy-gated)
- **plan-124**: Close out at core-complete; descope Phase E as superseded premise
- **rollup**: Plan 185 Phase 3 complete (naming + typed selectors)
- **plan-185**: Close Phase 5 Task 9 by verification (feature/dep boundaries)
- **notes**: Plan 185 deferred-work handoff for the next session
- **plan-193**: Design WS-2 (claim-10 enforcement port) + the R2 contract it needs
- **notes**: Scope Plan 125 E5 (host-services SDK / guest→broker client)
- **notes**: Rvproxy R2 session close-out + slices 2–4 handoff prompt
- **rollup**: Plan 197 2a default-path plan-persist gap closed
- **plan-197**: Phase 2a egress substitution data plane proven live (follow-on to #917)
- Ban clippy::too_many_arguments outright; builder-pattern struct is the fix
- **plan-181**: Record preview-ingress DX benchmark, validate L4-first
- Sync REFACTOR-STATUS/SPRINT/handoff to R2 build started (slice 1 merged)
- **plan-185**: Task 6 done — all too_many_arguments allows eliminated
- **plan-183**: Close resolved DHCP follow-up; re-confirm the two deferred items
- **plan-185**: Phase 6 Task 13 — renames doc-clean; clear mvm-core broken intra-doc links
- **mvm-build**: Fix unconditional broken intra-doc links (Plan 185 Task 13)
- **plan-185**: Sync Phase 6 Task 12 done + Task 13 mvm-build/platform finding
- Record security roadmap shipped state
- **plan-185**: Sync Task 11 done; Phase 6 status (10/11/12 + core/build Task 13)
- **plan-185**: Phase 7 closeout — Linux test gate green; document deferred debts
- Track final machine UX lessons
- **plan-185**: Clear the Task 13 broken-intra-doc-link tail (122 → 0 on Linux)
- Record kernel-less embedded Wasm VMM as prior art for the wasm line
- **notes**: Rvproxy R2 close-out + WS-2 phase-0 record
- **plan-125**: Close out Phase A (52→≤15 CLI) as satisfied — scope amendment
- **plan-199**: WarmLease borrow-handle + batched guest exec
- **warm-path**: Sync fork/snapshot prior-art into plans 148/157/175 + tag-traversal audit
- **plan-185**: Task 8 done → Plan 185 COMPLETE
- **adr-084**: Host services as a per-tenant daemon, not per-VM spawn (+ Plan 202)
- **plan-118**: Part C density+concurrency bench + prior-art decision note
- Track Plan 202 (host-services daemon) in REFACTOR-STATUS + Sprint 57
- **refactor-status**: Wave-1 bucket-A closeout — tick 123/124/197 at mvm-scope
- **adr-084**: Single host-agent daemon + signer helper; tenant boundaries
- **plan-200**: Investigated implementation plan for transient network policy
- **plan-200**: Mark network-policy implementation note SUPERSEDED by #1003 (WS-B)
- **plan-200**: Add three scoped session prompts for the remaining work
- **plan-200**: Tick deferred items closed by #1010/#1013 + the closure-budget gate
- **refactor-status**: Mark Plan 200 WS-B network enforcement MERGED
- **refactor-status**: Correct Plan 125 E5.3b glance line (3c + 4 are done)
- **refactor-status**: Roll up the Plan 200 WS-B deferred-list closeout
- Scrub the forbidden external project name from spec text
- **plan-200**: Tick transient-guest eth0 enabler + record live validation (WS-B follow-up)
- **refactor-status**: Plan 199 rollup + tick WS-B deferred items done
- **adrs**: Record bundle and GPU posture decisions
- **refactor**: Record remaining plan sequencing
- **refactor**: Close Plan 125 and sync Plan 200 bookkeeping
- Update AGENTS merge workflow
- Reconcile refactor status bookkeeping
- **plan-202**: Update mvmd adoption rollup
- Close Plan 202
- **dev**: Close out builder VM fingerprint narrowing
- Propose builder VM resident control plane
- Plan 205 / ADR-020 — resident builder control plane + residency model (umbrella)
- **plan-205**: Workstream F — what-runs-where, residency config, threat-model delta
- **plan-205**: Make the "instant" bar a CI-gated latency budget
- **troubleshooting**: Stage 0 BadActivate on a fresh isolated cache
- Reconcile Plan 205 / Sprint 63 rollups to shipped state (A/B/D/F merged, E #1102, C via Plan 204)
- **plan-126**: Record Step-0 decision — rehome aws-lc-rs removal + reqwest-major unify
- **plan-126**: Wire upstream PR #274 into the rehome decision + correct platform-verifier claim
- **rollup**: Freshen REFACTOR-STATUS for the 2026-06-20 landings
- **plan-205**: Refresh residency rollup
- **plan-126**: Bridge-spike + RustCrypto feasibility — B4 upstream-gated
- **plan-204**: WS-E — document the resident builder control plane
- Close plan 189
- Mark plan 189 complete in rollup
- **plan-175**: Mark CORE COMPLETE; rehome UFFD substrate + primed wiring to Plan 206
- **plan-205**: Mark rollup complete
- **plan-205**: Reconcile the parked-resume latency budget with measured reality
- **plan-175**: Correct token-delivery overclaim from the live capture
- **plan-193**: Add transparent-terminator hookup ladder (post-R4 acceptance)
- **hostd**: Spec host-agent daemon idle-registration self-termination (follow-up to #1174)
- **plan-200**: Add machine use-case guards
- **plan-200**: Correct binary-install-first backend docs
- **plan-204**: Live-validate builder daemon boot + WS-E install note; correct WS-D status
- **plan-200**: Frame old verbs as advanced/underlying surfaces (§A 821)
- **plan-204**: Sync REFACTOR-STATUS WS-D state (FlakeCheck routing landed; build route blocked)
- **plan-200**: Record live Firecracker-lane machine-run phase timing (KVM)
- **machine**: Unified `machine run` lifecycle — ADR-027 + Plan 207
- **adr-092**: `machine` as the sole workload CLI surface (consolidation)
- **adr-093**: Linux builder auto-fallback over libkrun, default unchanged
- **plan-210**: Kernel-pin security watcher (ADR-007 §6 follow-up)
- **adr-096**: Stage 0 seed Nix 2.31.1 narHash regression — write-up + open decision
- **agents**: Forbid spec/ADR/PR refs in code comments (matches CI lint gate)
- **plan-204**: WS-D build-default flip + raw-shell gate merged
- **plan-208**: Machine run --up-json contract + staged SDK up migration
- Rename removed top-level verbs to the `machine` surface
- **plan-211**: Sub-second machine run via warm-pool claim (design + phases)
- Plan attested fast first boot packs
- **plan-211**: Task 5 cleanup — repoint bridge fuzz labels + stale-ref sweep
- **release**: Record why Linux intentionally doesn't ship mvm-libkrun-supervisor
- Plan 214 clean-replacement architecture + ADR-007
- ADR-014 + Plan 215 plan-bound agent verb capabilities
- Plan 216 — mvm-client local/remote facade implementation plan
- Mvm-client facade design + mvmd cloud-readiness assessment (research)
- ADR-027 + Plan 218 — converge SDK/facade machine-driving on MvmClient
- **plan**: Plan 221 — in-process rootfs materialization (no subprocess)
- **adr**: ADR-004 — Phase-A/Phase-B build boundary (Plan 221 B0)
- **adr**: ADR-004 virtiofs-root integrity decision + Plan 223 impl plan
- **claims**: Scope claim 3 to block+ext4 backends; note virtiofs-root posture (ADR-004)
- **adr**: ADR-001 — attested launch anchor for real verb-grant key separation
- **plan**: Plan 227 — instant-resume sandboxes over a vsock-only auditable data plane
- **plan**: Plan 228 — release 0.17.0 (HVF default, working & documented)
- **release**: Backfill CHANGELOG (0.15.2–0.16.1) + guard release flow + fix claim-3 scoping (Plan 228 WS-2/WS-4)
- Refresh CLI command tree (compile→build compile, up→machine run)
- CLI-tree cleanup — exec split, backend names (HVF-aware), Docker/Tier-3 → ADR-001
- **plan**: Land Plan 226 clean-replacement roadmap as a strategic reference
- Add DEPLOYMENT.md and update version pins
- **release**: Reconcile Plan 228 for 0.17.0 — WS-1/2/3/4/5 done, only WS-6 (cut) remains
- **plan-231**: Add P7 — security-driven dependency surface reduction
- How to use mvm from studio, mvmd, and custom frontends

### Fixed
- **storage**: Reject path traversal in S3 mount prefix
- **stage0**: Drive the nix-seed Stage 0 boot to a working nix build (plan 160, 0b)
- **guest**: Treat a non-wrapper entrypoint marker as 'not offered', not failed
- **stage0-init**: Raise RLIMIT_NOFILE before the seed-store copy (x86_64 EMFILE)
- **qemu**: Seed pseudo-fs mountpoints + disk cleanup — Phase 1 CLI-proven
- **firecracker**: Host-arch download URL (was hardcoded aarch64) — Plan 166 Task 3.1
- **build**: Always zigbuild the musl host-vm embed — drop broken native fast-path
- **admission**: De-conflate bundle_json — carry the PolicyBundle, not the artifact pin (plan 123 Slice 3a)
- **network**: MacOS-safe resolve_networking_mode + workload honors MVM_NETWORKING (plan 123 L3-B)
- **secrets**: Thread auth_type+allowed_hosts into the mvm-cli SecretRef test fixture (plan 129 A1)
- **plan-166**: Support both C and Rust virtiofsd flavors
- **builder-vm**: Use iptables-legacy in the builder rootfs (kernel is x_tables)
- **plan-166**: Qualify dev_tier_builder_from_cmdline call as crate:: (mod linux)
- **plan-166**: Skip builder-image bootstrap when MVM_BUILD_STUB_OUTDIR is set
- **plan-124 C1**: Bump stale runtime-overlay version pin + add CI gate
- **mvm-cli**: Drop redundant closure in signing check (clippy -D warnings)
- **plan-124 D1.0**: Unbreak gen-stubs (-p mvm-ir → mvm-sdk) + resync stale SDK IR
- **secrets**: Allow Debug on SecretBindingMeta (no bytes; security-lane lint)
- **plan-166**: Harden the QEMU bridge/lifecycle (adversarial review #3)
- **mvm-cli**: Up --wait is libkrun-only + mutually exclusive with --detach
- **exit-capture**: Ack handshake so guest poweroff waits for durable workload.exit (race fix)
- **mvm-exit-report**: Skip ack read if timeout unarmable (bulletproof no-hang)
- **mvm-cli**: Up --wait skips persistent-agent wait (one-shot powers off; read exit via backend.wait)
- **mvm-backend**: Wait() polls workload.exit not PID (PID-reuse hang fix)
- **secrets**: Guest->host AF_VSOCK transport for the forward proxy (plan 129)
- **mvm-guest**: Join drain threads on exit (no tail-flush race)
- **mvm-guest-agent**: Do_run_code error paths stream ExecEvent (consistent response type)
- **mvm-cli**: Restore inbound-RPC audit emit in dispatch_in_session
- **mvm-cli**: Flush per chunk in session run-code stream (progressive output)
- **secrets**: Preserve the source chain in forward-leg errors
- **doctor**: Signing check probes all sign targets, not just mvmctl
- **secrets**: Substitution endpoint forwards http to the destination's real port
- **netinit+init**: Make the guest's own loopback functional
- Make the libkrun mkGuest warm claim fire end-to-end (Plan 118 WS-1 1b)
- **firecracker**: Extract ELF vmlinux from a bzImage at boot
- **dev**: Degraded builder store — fail fast + cache repair + doctor health
- **firecracker**: Make the guest agent reachable on live FC boots
- **guest-init**: Detach sealed-workload stdin from input-less console + sleeper liveness fixture
- **builder-vm**: Scope egress lockdown to the install arm (Plan 183 WS-A)
- **firecracker**: Three live-bringup fixes from the FC egress e2e session (plan 129)
- **builder-vm**: Guest network bootstrap — static gvproxy fallback + writable resolv.conf (Plan 183 WS-B/C)
- **supply-chain**: Duplicate-major lock-gate + restore red cargo-deny/cargo-audit (Plan 126 D2)
- **fuzz**: Pin time below 0.3.48 in rcgen-pulling fuzz crates (unblock Fuzz — parsers)
- **checkpoint**: Clippy unnecessary_literal_unwrap in resource-shape test
- **oci**: Close the layer-unpacker TOCTTOU with openat2 (plan 161 / 143 R2+R3)
- **oci**: Route whiteout removal through openat2 too (plan 161 follow-up)
- **pool**: Serialize warm_to_target with a pool-dir flock (Plan 118)
- **guest-console**: Drop post-fork malloc; SAFETY-audit the console (Plan 185 Task 8)
- **cli**: Persist plan.json pre-start so libkrun egress substitution actually spawns (Plan 197 Phase 2a)
- **console**: Route workload consoles to their own VM, not the builder
- **fc**: Sub-second down + kernel-less flake boot for Firecracker
- **fc**: Skip the vestigial secrets drive when it has no content
- **host-vm-init**: TestEnv-guard the TMPDIR-inherit test so it can't break parallel tests (Plan 185 Phase 1)
- **host-vm-init**: Clear pre-existing Linux-only clippy lints (Plan 185 Phase 7 follow-up)
- **plan-193**: Match rvproxy's dns_hostname_allowlist field name + reconcile WS-2 status
- **plan-200**: Renumber mvm.toml schema v2 -> v1 (no pre-release schema)
- **audit**: Resolve the supervisor signing-key dir through mvm_keys_dir()
- **plan-125**: Spawn the host-services broker for any admitted workload (E5.3b-4 live)
- **plan-200**: OCI cache index Default sets schema_version 0 (breaks fresh cache)
- **net**: Bring up the workload guest's eth0 — libkrun workloads had no egress
- **plan-200**: Thread the resolved network policy through the `up` boot path
- **net**: Tie gvproxy/passt to the supervisor's lifetime so a dead supervisor never orphans them
- **plan-202**: Clean up host-agent restart docs
- **ci**: Drop stale broker-services wording
- **libkrun**: Thread x86 kernel format for live bench
- **plan-200**: Reply to libkrun's -krun.sock so bridge egress actually reaches the guest
- **cli**: Build the prod default microVM image locally on a source checkout
- **plan-205**: Harden host_signer gate + document OCI machine warm-pool intent
- Keep json stdout clean for dev convergence
- **builder**: Fail fast on a Stage 0/builder build that halts the guest
- **oci**: Key the run-image guest-agent cache by the dev-shell variant
- **oci**: Re-materialize a run-image rootfs when the baked agent is stale
- **security**: Close command-injection in warm_restore_instance snapshot/load
- **run**: Boot --image OCI runs on a prebuilt workload kernel (avoid Nix + 220 MB on the OCI path)
- **hostd**: Exit moat helpers when their supervisor dies; add reap-helpers backstop
- **hostd**: Host-agent daemon self-terminates when idle (follow-up to #1174)
- **plan-204**: Builderd enables nix-command/flakes; live over-the-wire FlakeCheck driver
- **cache**: Make `cache prune`/`repair` report their result by default
- **egress**: Defer DNS to the DNS layer so a curated allow-list can resolve
- **builderd**: Don't path:-wrap scheme-qualified flake refs in flake_check_argv
- **guest-net**: Static fallback when udhcpc/resolv.conf tooling is absent (OCI --net)
- **firecracker**: Make the gateway-bridge sidecar actually run (plan.json decode + seccomp gaps)
- **plan-204**: Make the typed BuildGuestImage daemon path actually build (writable nix HOME/XDG) (WS-D)
- **plan-203**: Capture denied (dropped) egress in the forensic transcript
- Keep the host-gvproxy socket path under the AF_UNIX sun_path limit
- **cli**: Pre-open interactive console data ports on libkrun (Plan 207 regression)
- **cli**: Fast teardown for interactive-transient `machine run -t` (Ctrl+D no longer reads as a hang)
- **sdk-python**: Migrate live-mode Sandbox ops to `machine` verbs
- **build**: Stream typed mvm-builderd build progress to stderr (no more silent "hang")
- **builder**: Page-align the libkrun builder kernel (Linux KVM rc -22)
- **stage0**: Bump seed Nix 2.31.1 → 2.34.7 (lock-matching narHash; fixes ADR-004 regression)
- **kernel**: Harden --boot-check — force libkrun + builder-image precondition
- **cli**: Name a manifest/source change in the machine-recreate diff
- **builder**: Pin builder VM materialize toolchain as a GC root so cap-GC can't reap mkfs.ext4
- **cli**: `machine run --up-json`/`--ttl` + migrate SDK boot off retired `up` (un-break live mode)
- **builder-vm**: MkGuest symlinks multi-output package binaries (fixes /sbin/mkfs.ext4 — OCI materialize regression)
- **machine**: Docker-parity for `machine run -it` (job control, quiet boot, no codesign noise)
- **machine**: Hash flake slot identities without canonicalizing
- **sdk**: Restore hidden no-vm transport
- **kernel**: Re-enable PCI/VIRTIO_PCI for PCI-attached backends — fixes #1297 (builder hang) + #1298 root cause
- **release**: Ship per-VM host binaries so a downloaded mvmctl can spawn them
- **pool**: Reap stale standbys on the launch path (no-daemon TTL enforcement)
- **machine**: Run interactive argv in PTY
- **security**: Forbid shell production entrypoints
- **xtask**: Deterministic protocol stub codegen (unblocks check-stubs gate)
- **core**: Remove deliver-to-guest secret path from SecretBinding (secrets never enter the microVM)
- **core**: Ingress redaction — mask longest secrets first to stop tail leak
- **hvf**: Make the in-house VMM guest agent host-reachable over vsock
- **cli**: Gate verb grant on run mode — stop breaking interactive/ad-hoc runs
- **builder**: Per-kind warm gcroot so alternating builds don't evict each other
- **run**: Wire dev_console on the interactive transient -it path
- **build**: Decode mvm.verb_grant cmdline token in the OCI guest init
- **oci**: Egress-CA parity for OCI workloads (guest /init decode + host TLS env)
- **run**: Actually enable the pure in-process rootfs materialize in mvmctl
- **machine**: Populate flake slot kernel fallback
- **cli**: Mint default agent-verb grant only for sealed images (#1381 item 2)
- **run**: Make the default in-process rootfs materialize fail-safe
- **machine**: `machine start` on an already-running machine is a no-op notice
- **machine**: `machine rm` refuses a running machine (orphan guard)
- **vmm**: Confine the virtio-fs FUSE server to the served root (symlink escape)
- **run**: Default macOS 26 workloads to in-house hvf VMM + reach its agent over vsock
- **hvf**: Reset the guest stream when the host drops an agent connection
- **stage0**: Format the persistent Nix store in-process on macOS
- **run**: Reuse the builder kernel for dev image launches (no Stage 0)
- **vmm**: Reset the guest side of host-closed agent streams (Plan 228 WS-1)
- **run**: Stop macOS-26 HVF workload runs from waking the builder/dev VM (+ wire interactive console)
- **hvf**: Warn when the per-VM supervisor binary is stale
- **hvf**: Stop reconcile from reaping live HVF machines (+ supervisor-path fallback)
- **hvf**: Per-VM helper bins just work — shared resolve-or-build + release packaging
- **hvf**: Give the HVF backend a real security profile (was tier Unknown)
- **build**: Pin the embed zig via ziglang, fail clearly if drifted

### Performance
- **dev**: Narrow builder-VM source fingerprint (plan 195)
- **pool**: Warm claim reuses the admission image sha, drops the re-hash
- **build**: Host-side flake build cache (Plan 198) — skip the builder VM on an unchanged flake
- **ci**: Move feature-gated test steps off the Test critical path

### Refactored
- **mvm-backend**: Clarify re-probe + tighten sign test assertion
- **mvm-cli**: Consistent sign --json shape across platforms
- **mvm-cli**: Route existing --json through emit_json
- **mvm-cli**: Snap_ls via emit_json; cache info uses CacheInfo.exists
- **secrets**: Share substitution wire contract in mvm-core (plan 129 #4a)
- **mvm-guest-helpers**: Wrap vsock fd with TcpStream (codebase convention)
- **supervisor**: Use KrunContext::vsock_socket_path for control socket
- **exit-capture**: Move file convention + reader to mvm-core (dep direction)
- **mvm-guest**: Extract read_exec_stream (shared by Exec + RunCode)
- **mvm-guest**: Remove single-frame ExecResult (superseded by ExecEvent)
- **sdk**: Retire dead in-guest substitution scaffolding (ADR-023)
- **deps**: Replace opendal with object_store in the template registry (plan 126 B2)
- **backend**: Backend matrix consolidation 8→4 (Plan 177 Phase 1)
- **cli**: CLI surface consolidation ~56→~28 (Plan 178)
- **cli**: Merge exec into run (Plan 178 Task 7)
- **audit**: Hoist AuditEmitter into mvm_hostd::audit (library API for mvmd)
- **comments**: Strip plan/PR/ADR/sprint refs from source comments + lint gate (Plan 180)
- Tighten backend traits and rust hygiene
- **backend**: Promote the catalog into a descriptor registry (Plan 184)
- **cli**: Mvm-cli unary call sites adopt the contract-checked client (plan 124 D1.2 step 2c)
- **build**: Fold last mvm-build env-test locks into TestEnv + decide poison policy (Plan 185 Phase 2)
- **storage**: Rename storage::Backend → DeviceMapperBackend (Plan 185 Phase 3 Task 4)
- **backend**: Typed BackendKind selectors over name() strings (Plan 185 Phase 3 Task 5)
- **egress**: Name the two EgressProxy traits by layer (Plan 185 Phase 3 Task 4 Step 3)
- **guest**: SAFETY invariants on simple-syscall unsafe blocks (Plan 185 Phase 5 Task 8)
- **verity-init**: SAFETY invariants + safe ioctl wrapper (Plan 185 Task 8)
- **guest-agent**: SAFETY notes on the remaining unsafe blocks (Plan 185 Task 8)
- **build**: Group boot_builder_vsock args into BuilderVsockBoot (Plan 185 Task 6)
- **hostd**: Group sign_into_headers args into a SignRequest builder (Plan 185 Task 6)
- **hostd**: Group terminate_and_substitute args into a TlsTermination builder (Plan 185 Task 6)
- **egress**: Dedup FC plan-secret decode + drop QEMU's dead substitution arm
- **plan-200**: Drop the vestigial BridgeConfig.policy field + the AllowAll type (WS-B follow-up)
- **plan-202**: Move host-agent control protocol to mvm-core (1c-prep)
- **builder**: Make the persistent build route typed-only (drop legacy shell)
- **sdk**: Facade delegates argv to machine.rs builders (single source)
- **core**: Move plan synthesis into mvm-core (slice 1 of the #1388 boot seam)
- **hostd**: Move plan admission into mvm-hostd (#1388 slice 2)
- **machine**: Lift persist engine to `mvm::machine::persist` + real local reconfigure (Plan 225 Phase 2)
- Rename inhouse → hvf across the codebase
- **client**: Fold MvmClient into mvm-core, collapse two client crates to one
- Two product surfaces — host runtime + user client (Plan 230 WS-1)
- Consolidate to two product surfaces — host + user (Plan 230 WS-3a/3b/5a)

### Testing
- **ci**: Per-PR passt framing regression gate (Plan 141)
- **mkguest**: Surface withDevShell + assert dev-console wiring (Plan 165 WS-B B2)
- **claim15**: Host-gate + write-only console-capture witnesses (Plan 165 WS-C)
- **network**: Live-bridge L4 egress enforcement on real sockets (plan 123 Slice 3)
- **mvm-cli**: Mvmctl sign surface tests
- --continue empty-store error + comparator coverage
- **mvm-cli**: Session resume/ephemeral help surface
- **secrets**: Declare audit posture for `secret set` (plan 129 B2)
- **secrets**: Add SecretSet to known-audit-kinds allowlist (plan 129 B2)
- **plan-166**: Exempt hidden subcommands from the summary-length check
- **plan-166**: Declare audit posture for __qemu-vsock-bridge
- **examples**: Exit_code one-shot fixture for WS-A E2E
- **examples**: Re-author exit_code fixture as canonical inputs.mvm user flake (WS-A E2E)
- **secrets**: E2e substitution over real AF_VSOCK loopback (plan 129)
- **plan-152**: WS-B Swift↔Rust supervisor parity gate (P1: boot)
- **storage**: S3 MountProvider coverage without S3 (plan 123 B4)
- **network**: Add rvproxy↔gvproxy gateway parity gate (ADR-003 / Plan 193 WS-1.5)
- **core**: Migrate mvm-core env tests onto TestEnv + close out Plan 182
- **hostd,build**: Migrate env tests onto TestEnv (Plan 185 tail)
- **build**: Migrate libkrun_builder + builder_vm_runtime onto TestEnv (Plan 185)
- **core,libkrun-sys**: Migrate env tests onto TestEnv + drop 3 more local locks (Plan 185)
- **cli**: Artifact_verify + sandbox_record env tests onto TestEnv (Plan 185)
- **cli**: Session + up env tests onto TestEnv (Plan 185)
- **cli**: Template_cmd LLM-probe tests onto TestEnv (Plan 185)
- **cli**: Unify doctor ts-runner tests onto TestEnv, drop local ENV_LOCK (Plan 185)
- **cli**: Tenant_resolution + ops/mcp onto TestEnv — completes mvm-cli (Plan 185)
- **sdk**: Python⇔TypeScript decorator coherence — one IR, two front-ends (plan 125 E1)
- **secret-exposure**: Prove Debug redaction for HostSigner/EgressCa/ResolvedBinding (Plan 185 Task 12)
- **key-rotation**: Match typed RotationError variant instead of error string (Plan 185 Task 10)
- **plan**: Shared PlanFixture builder; collapse 6 duplicated ExecutionPlan fixtures (Plan 185 Task 11)
- **plan-125**: E5.3b host-spine round-trip integration test
- **plan-200**: OCI archive reader ignores unexpected/extra tar entries
- Close Plan 200 image source status
- **plan-202**: Close host-agent cost semantics
- **plan-200**: Harden the libkrun egress matrix with unrestricted + duplex bridge coverage
- **machine**: Gate artifact admission preview
- **machine**: Pin interactive image shell parsing
- **core**: Cargo-fuzz target for the snapshot-frame parser
- **ci**: Loop-mount mvm-ext4 output on the real kernel (Plan 221 B3)
- **mvm-ext4**: Fuzz the build_image rootfs writer
- **mvm-ext4**: Adversarial-tree regression suite + 3 writer fixes (Plan 221 B3)
- **hostd**: Allow slower broker restart recovery
- **sdk**: Conformance-pin the create --image shape across all surfaces
- **virtio-fs**: Fuzz the FUSE-server request parser

### Merge

### Spec
- **adr-002,claude**: HVF is the macOS-26 default

# Changelog

All notable changes to **mvm** are recorded here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
uses [SemVer](https://semver.org/) once it reaches 1.0.

## [Unreleased]

## [0.16.1] — 2026-06-05

### Added
- **storage**: StorageProvider trait + LocalStorage (plan 123 B1)
- **storage**: EncryptedStorage at-rest arm, macOS (plan 123 B2)
- **storage**: Content-addressed + snapshot-upper volumes (plan 123 B3)
- **storage**: MountProvider registry + IR MountSource::External (plan 123 B4 steps 1-3)
- **storage**: S3 MountProvider via object_store, feature-gated (plan 123 B4 step 4)
- **backend**: SnapshotCapability per-backend warm-start tier (plan 123 C1)
- **network**: Mvm-network crate — NetworkProvider seam + NetworkMode::Custom (plan 123 A1/A2/A5)

### Documentation
- **plan-123**: Reconcile post-121 paths + pin B→A→C order
- **plan-123**: Tick B1 (StorageProvider trait + LocalStorage)
- **plan-123**: Mark Phase B storage/mount acceptance complete
- **plan-141**: Mark closed (merged via #609/#614); track passt live-KVM follow-up
- **plan-123**: Tick Phase A seam (A1/A2/A5); track claims-gated lift as follow-up

### Fixed
- **apple-container**: Don't re-copy an already-per-instance rootfs

### Release
- V0.16.1

## [0.16.0] — 2026-06-05

### Added
- **compile**: Warn when Node package.json deps won't be baked
- **cli**: Mvmctl kernel build (compile arm) via Stage 0
- **cli**: Kernel build --source download/auto + --arch
- **cli**: Dev up --kernel-source (boot on a downloaded kernel)
- **xtask**: Machine-check the security-claim → witness map
- **verify**: Serverless in-browser audit-log verifier (ADR-024)
- **builder**: Add verbose-gated console echo helper
- **builder**: Thread --verbose to stream Stage 0 console to stderr
- **kernel**: Elapsed heartbeat + --verbose console stream on compile
- **install**: Add curl-able install.sh
- **homebrew**: Formula template + render script + test
- **default-image**: Prod download (5-asset contract) + release job + test
- **nix**: Default-tenant flake build-validated (both variants) on the dev host
- **default-image**: BuildMode-aware resolution — dev builds locally (Task 3b)
- **volumes**: Custom volumes + fix read-write-disk flock collision
- **dev**: Mount devpts in guest /init + add config::is_dev_mode (Plan 162)
- **crypto**: Collapse AEAD call sites into crypto::aead (plan 122 A1)
- **crypto**: MacOS volume-at-rest via per-file AEAD (plan 122 A2)
- **crypto**: 90-day KEK rotation timer (plan 122 B1)
- **crypto**: Per-rebuild DEK binding on WrappedKey (plan 122 B2)
- **crypto**: Content-addressed, Ed25519-signed snapshots (plan 122 C)
- **crypto**: VMGenID generation token + guest CSPRNG reseed (plan 122 D)
- **network**: Etherparse dep + pure L3/L4 parse + payload rebuild (Plan 141 Tasks 1-2)
- **network**: Observer::on_packet + Verdict/Directions/PacketCtx (Plan 141 Task 3)
- **audit**: Flow_observer_fault chain entry (Plan 141 Task 4)
- **network**: Per-observer latency recorder + scrape file (Plan 141 Task 5)
- **network**: Synchronous observer fan-out runner (Plan 141 Task 6)
- Flow-byte-log policy field + append-only writer (Plan 141 Task 7)
- **bridge**: Wire packet-observer pipeline into libkrun/gvproxy (Plan 141 Task 8)
- **bridge**: Frame-aware Passt loop + broaden metrics scrape filter (Plan 141 Task 9)
- **cache**: Flow-byte-log retention sweep in cache prune (Plan 141 Task 10)

### Changed
- **sdk-ts**: Trailing commas in tsconfig (JSONC)
- **network**: Clippy — drop unnecessary drop(), flatten sweep with let-else (Plan 141)
- **release**: Defer x86_64-apple-darwin (Intel-macOS runners unavailable)

### Documentation
- **plan**: 145 — complete the build-time application-deps story
- **plan**: 145 — WS-B/C corrected (pnpm/yarn route to WS-A; warnings done in #553)
- **plan120**: Lead README + Python quickstart with the five-line Sandbox.exec
- **adr-046**: Kernel acquisition — compile or download
- **plan**: 147 — Lima test backend + Linux/FC core_demo E2E parity (deferred)
- **plan120**: Back-reference the deferred Lima/FC-parity/default-microvm bullets → Plan 147
- **plan**: 146 — WASI-polyglot workload language (deferred to the refactor)
- **notes**: WebAssembly support exploration — two framings, status, B recommendation
- **audit-verify**: Build the wasm bundle in the builder/dev VM, not the host
- **plans**: Add Plan 146 — cloud-hypervisor Tier-1 parity (Kuasar-referenced)
- **plans**: Add Plan 147 — portable runnable artifacts (mvmctl artifact run)
- **plan**: Add Plan 149 — mvmctl watch unified live operator event stream
- **plans**: Add Plan 150 (OSV deps scan + remediation) and Plan 151 (fs-access evidence)
- Contributor host-setup (libkrun builder) + plan drafts 144/148
- **plan120**: Mark Status: COMPLETE — all acceptance boxes ticked
- **plans**: Resolve duplicate plan numbers 144/146/147 on main
- **plans**: Fix internal titles after 144/146/147 → 153/154/155 rename
- **plans**: Add 156 binary-size reduction; refresh 126 baseline + cross-refs
- **plans**: Add Plan 157 — warmed parent recipes (forkd-inspired)
- **spec**: Design for install.sh, Homebrew tap, download docs, compile logging
- **plan**: Implementation plan for install & download experience
- **kernel**: Note heartbeat + verbose streaming in module doc
- Guide for mvmctl kernel build (compile/download/auto)
- Releases & downloads reference
- **releases**: Expand Homebrew tap token setup steps
- **adr-002**: Document the verified-boot verity surface post-consolidation
- **plan-158**: Plan to restore the bundled default microVM image
- **specs**: Scrub prior-art product name from Plan 143
- **specs**: Record host-side Landlock-envelope widening as a deferred Plan 143 follow-up
- **specs**: Plan 161 — OCI-unpacker openat2 TOCTTOU fix + ADR-001 note
- **plan-158**: Dual dev/prod default image keyed on BuildMode
- **crates**: Finalize plan 121 — ADR-022 corrections, CLAUDE.md, old→new ident map
- **adr**: Descope B4 framing — authenticated frame stays its own protocol
- **plan**: Record B4 Option B as a tracked deferred follow-up
- **plan**: Record B4 Step 2 (config_envelope) descope + Step 3 (paths) outcome
- **plan**: Close out B4 — descope Step 4 (subprocess) + Step 5, reconcile Acceptance
- Close out plan 121 — stamp COMPLETE + reconcile mvm-core runtime-free claim
- **plans**: Fold plan-121's 3 spawned follow-ups into their active plans
- **plan-121**: Record the production verification in the Status header
- **plan-121**: Cross-ref #587 extending the B4 paths centralization
- **plans**: Add Plan 162 — dev-mode interactivity (guest devpts + MVM_ENV=dev)
- **plan-141**: Note the Plan 152 drop-Swift conflict (reciprocal)
- **plan-122**: Tick A1, mark A0 deferred
- **plans**: Reconcile 152 WS-D nested-virt with Plan 147 Lima
- **plan-126**: A1 dependency baseline + correct the Phase-B premises
- **plan-126**: B4 finding — aws-lc-rs is the oci-client/reqwest-0.13 chain (= C1)
- **plan-126**: B4 is upstream-blocked — oci-client hardcodes aws-lc
- **adr-066**: Reconcile §5/§7 with plan 122 (Phase E)
- **plans 123,140**: Cross-ref the plan 122 D VMGenID substrate + entropy-source decision

### Fixed
- **nix**: Keep kernel base.nix inside the builder-vm flake tree
- **cli**: Gate host_arch + download_kernel behind builder-vm
- **specs**: Renumber duplicate ADR-024 (browser verifier) to 070
- **gvproxy**: Free ssh-port + reap orphaned daemons on startup
- **nix**: Default-tenant flake evals — description must be a literal
- **nix**: Expose passthru.rootfs so the builder-VM dev build emits mvm-meta.json
- **ci**: Repair plan-121 CI breaks — architecture invariant allowlist + mvm-build dev-shell feature
- **hostd**: Drop useless i64::from on c_long syscall nr (clippy 1.95 on Linux)
- **volumes**: Mount user volumes in mkGuest /init (the dev VM's PID 1)
- **volumes**: Default user volumes read-only; allow-list mount roots
- **mkguest**: Gate Stage 2.3 modprobe behind user-volume presence
- **dev**: Libkrun dev VM console attach + e2e-core-demo recipe
- **bootstrap**: Drop stale per-crate source hash from builder-vm fingerprint
- **libkrun**: Wait for the vsock socket in start(), not just the PID file
- **dev**: Only open the interactive console when stdin is a TTY
- **release**: Install zig/cargo-zigbuild in the binary build job
- **ci**: Correct zig macOS arch name + ensure /opt in install-zigbuild
- **ci**: Install libkrun for macOS release builds; Intel on native runner
- **dev**: Idle PID 1 in the dev VM /init so it survives the console EOF (Plan 162)
- **bridge**: Bind gvproxy-facing datagram socket; live DHCP e2e test (Plan 141 follow-up)
- **build**: Give nested host-vm cargo its own target dir (release deadlock)
- **ci**: Smoke test reads global.requests_total (metrics now sectioned)
- **jailer**: Use SYS_newfstatat on aarch64 (no SYS_fstatat there)

### Performance
- **test**: Faster workspace test runs (nextest gate + embed-skip fast path)

### Refactored
- **kernel**: Use Relaxed ordering for heartbeat stop flag
- **crates**: Fold mvm-runner into mvm-guest as a [[bin]]
- **crates**: Fold mvm-base into mvm-backend::base (Lima-era leftover)
- **sdk**: Fold mvm-ir into mvm-sdk::ir (one SDK crate)
- **core**: Fold mvm-plan into mvm-core::plan
- **core**: Fold mvm-policy into mvm-core::policy (keep policy::security re-export)
- **core**: Fold mvm-security into mvm-core::crypto (pure crypto; no async in core)
- **backend**: Relocate+rename mvm-libkrun -> crates/deps/libkrun-sys
- **backend**: Fold mvm-providers into mvm-backend::providers
- **backend**: Relocate orphaned MvmContainerBridge swift pkg with providers
- **hostd**: Consolidate supervisor/broker/signers/jailer into mvm-hostd
- **vm-host**: Consolidate per-VM supervisors into mvm-vm-host (cfg-gated [[bin]]s)
- **guest**: Consolidate addon-dns + vsock-bridge into mvm-guest-helpers
- **build**: Move host-vm-init + egress-proxy into mvm-build [[bin]]s (ADR-004)
- **core**: Dedup length-prefixed framing into core::framing (B4 Option A)
- **core**: Route mvm-core data-dir derivations through a strict resolver (plan 121 B4)
- **cli,hostd,build**: Route data/cache-dir derivations through canonical resolvers (plan 121 B4)
- **core**: Centralize per-VM vsock/state paths in mvm-core::config
- **backend,build**: Route per-VM paths through mvm-core::config
- **cli**: Centralize ~/.mvm keys/audit/overlays/secrets via mvm-core::config
- **core**: Drop tokio from mvm-core's default closure (plan 126 B5 PR-1)
- **core**: Make mvm-core's default build runtime-free (plan 126 B5 PR-2)
- **crypto**: Sign snapshots with attestation identity, trusted-signer set (plan 122 C)

### Testing
- **cli**: Declare audit posture for the kernel command
- **install**: Hermetic install.sh download + tamper-reject test
- **fuzz**: Packet parse+rebuild fuzz target; tick Plan 141 (Task 11)

### Dev
- Default dev up to an interactive shell
- Fall back to libkrun for the auto-selected builder

### Draft
- **nix**: Default-tenant flake — dev + prod variants (Plan 158 Task 1)

### Merge
- Bring feat/custom-volumes up to date with main

### Nix
- **kernel**: Shared config base + slim builder/workload split

### Security
- **volumes**: Admission-enforced shares + libkrun ro guard + claim witnesses

## [0.15.2] — 2026-06-03

### Added
- **security**: Implement claim-4 prod-agent symbol-contract check
- **sdk**: TypeScript/Node workloads end-to-end

### Documentation

### Fixed
- **security**: Scope agent symbol greps to the mvm_guest_agent crate

## [0.15.1] — 2026-06-03

### Added

- **SDK package READMEs.** `sdks/python/README.md` rewritten against the
  current `mvmctl` surface (the old copy referenced the deprecated
  `mvmforge` CLI), and a new `sdks/typescript/README.md` mirrors it. These
  render on the PyPI (`mvm`) and npm (`@runmvm/mvm`) package pages; the
  registries are immutable per version, so this patch ships them to the
  live pages.

## [0.15.0] — 2026-06-03

### Added

- **Architecture-aware artifact model (Plan 134).** `GuestArch`/
  `KernelFormat` in `mvm-core`; `MicrovmBackend` + data-driven
  `BackendCompat` matrix + the `artifacts` module in `mvm-backend`;
  `NixMicrovmBuilder` adapter; static `ArtifactValidator` +
  `FirecrackerConfigWriter`; `mvmctl artifact model-inspect|
  model-validate|model-config|model-build`.
- **`mvmctl invoke` works end-to-end** (function workloads return their
  encoded result over vsock `RunEntrypoint`). The build-time `@mvm.app`
  decorator is stripped from the bundled source at compile time, so the
  guest never imports the SDK.
- **SDK publish workflows** — PyPI (`mvm`) + npm (`@runmvm/mvm`),
  release-triggered with a version==tag guard.
- **Stage 0 builder-VM nix-store persistence** across `dev up` runs.

### Fixed

- **Function-workload boot** is genuinely stable: PID 1 (the idle
  bootScript at `/etc/mvm/boot`) no longer aborts on a bare `mkdir`, so
  the VM stays up instead of rebooting at ~5s (previously boot→ping only
  "passed" via the agent answering inside that window).
- OCI→ext4 materialization is byte-deterministic on e2fsprogs ≥1.47
  (`-O ^orphan_file`), restoring the ADR-017 verity-cache invariant.

- **Plan 63 Phase 2 — encryption everywhere.** Closed in six
  workstreams (commits `b9e4e64`, `1ea9352`, `f7e39a7`, `a30f866`,
  `6fc798d`, plus this CHANGELOG entry):
  - **W1** — `mvm-security::key_rotation` module with `rewrap_dek`
    (dispatches on `WrapAlgorithm`; `Aes256Gcm` in-crate, `AesKwp`
    refused with a pointer at mvmd), `rotate_master_key` +
    `MasterKeyManifest` (versioned on-disk key store with atomic
    manifest writes), `migrate_wrapped_keys` (resumable bulk
    re-wrap), `rotate_luks_slot` (cryptsetup shell-out via
    mode-0600 tempfiles — never argv), `reseal_snapshot`
    (verify-under-old + reseal-under-new + atomic). 19 tests.
  - **W2** — every secret-carrying type wraps `secrecy::SecretBox<T>`.
    `KeyProvider::get_data_key` returns `SecretBox<Vec<u8>>`;
    `snapshot_hmac::load_or_init_key` returns
    `SecretBox<[u8; HMAC_KEY_BYTES]>`. xtask
    `check-no-display-on-secret-types` lint runs on every PR.
  - **W3** — `mvm-security::keystore` now ships `KeyringProvider`
    (OS-native keystore: macOS Keychain via `new_with_target`,
    Linux Secret Service, Windows Credential Manager) +
    `FileKeyProvider` (raw 32 bytes at `<keys_dir>/<tenant>.key`,
    mode 0600/0400) + `default_provider()` (auto-detects best
    available impl). `keyring = "3"` lifted into workspace deps.
    25 tests.
  - **W4** — `mvm-security::secret_store` with the `SecretStore`
    trait + `FileSecretStore` + `KeyringSecretStore` for
    multi-key tenant secrets (distinct from `KeyProvider`'s
    single-master-DEK shape). `mvmctl secret put/get/ls/rm`
    CLI surface; the `get` handler refuses TTY without `--force`.
    Audit log at `~/.mvm/audit/secrets.jsonl` records every CRUD
    op without ever recording the value. 25 tests.
  - **W5** — `mvm-security::snapshot_encryption` chunked
    AES-256-GCM file-bound primitives + integration into
    `mvm::vm::instance_snapshot::{pause_and_seal,
    verify_and_resume}`. Snapshots encrypt transparently when a
    tenant DEK is configured; HMAC seal covers the ciphertext.
    Resume probes for MVSE magic and refuses unencrypted-under-
    keyed-tenant as a downgrade defence (override via
    `MVM_ALLOW_UNENCRYPTED_SNAPSHOT=1` for one-time migration).
    19 tests.
  - **W6** — ADR-008 ("Encryption substrate") documents the full
    surface + this CHANGELOG entry. Plan 63 closes.

  Tests: workspace at **2082 passed / 0 failed** post-W6. Plan-60
  Phase 2 ("Encryption everywhere") moves from "substrate-only"
  to user-observably true; tenant DEK rotation works without
  re-encrypting data, snapshots are encrypted at rest, and
  `mvmctl secret put` is the documented prod-safe surface.

- **Plan 64 — supervisor wiring.** `mvmctl up` now admits a
  signed `ExecutionPlan` through `mvm-plan::verify_plan` + G4
  validity window + nonce replay-store, and emits chain-signed
  audit entries to `~/.mvm/audit/<tenant>.jsonl`. CLAUDE.md
  security claim 8 ("every workload runs from a signed, audited
  ExecutionPlan") is now user-observably true. ADR-014 documents
  the lifecycle; `policy_resolver::resolve_supervisor_components`
  (W5) is the substrate that hands `ResolvedSlots` to a future
  `Supervisor::launch` consumer once the mvm-hostd lift lands.

## [0.14.0] — 2026-05-11 — v1 → v2 cutover

**This release replaces v1 with a complete rewrite at the same canonical
project name (`mvm`) and binary name (`mvmctl`). The two versions are
not API-compatible. See [`MIGRATING-FROM-V1.md`](MIGRATING-FROM-V1.md)
for the upgrade path.**

The v1 final tip is preserved on this repository as the `legacy/v1`
branch and the `v1-final` tag — all v1 commit URLs, PR URLs, and
release-tag URLs (`v0.7.1`–`v0.13.0`) continue to resolve.

### Why a rewrite

v1 was a 5-crate skeleton with substantial Lima coupling on macOS, a
hand-rolled rootfs init path, and a hypervisor abstraction that
ossified around Firecracker. v2 is a 13-crate workspace built around:

- **`microvm.nix`** as the image-build substrate (deterministic,
  composable, declarative — replaces the hand-rolled rootfs init)
- **libkrun as the cross-platform default backend** (Linux/KVM
  via libkrun, macOS via Hypervisor.framework, Windows pending)
- **Firecracker preserved as Tier 1 on Linux+KVM** with explicit
  Cloud Hypervisor support for workloads that need VFIO/GPU/virtio-fs
- **Lima removed entirely** — direct host execution on Linux; Apple
  Container or libkrun on macOS
- **Busybox as PID 1** in guests (replaces NixOS+systemd; meets the
  ≤300 ms cold-boot p50 floor recorded in ADR-004)
- **`ExecutionPlan`-shaped substrate** for the supervisor / audit /
  policy work in plans 37 and 60 Phases 2–10

### Added

- 13-crate workspace: `mvm-core`, `mvm-security`, `mvm-storage`,
  `mvm-plan`, `mvm-policy`, `mvm-supervisor`, `mvm-providers`,
  `mvm-backend`, `mvm-base`, `mvm`, `mvm-build`, `mvm-guest`,
  `mvm-cli`, `mvm-mcp` (plus root `mvmctl` facade and `xtask`)
- `AnyBackend` dispatch with `auto_select()` per ADR-004: Linux+KVM →
  Firecracker; macOS 26+ on Apple Silicon → Apple Container or
  libkrun; KVM-less Linux / older macOS / Intel → libkrun;
  Cloud Hypervisor opt-in for VFIO/GPU
- `mkGuest` Nix function with three entrypoint forms (shell, command,
  services), build-time `accessible`/`sealed` mode inference, and
  `passthru.mvm` sidecar metadata threading
- `BuildMode::{Dev, Prod}` — `mvmctl up <flake>` defaults to Prod
  (sealed image, `mvmctl console` refused unless `--force`); `--dev`
  opts into the accessible image with `do_exec` available
- Cross-compiled real `mvm-guest-agent` in the rootfs (replaces the
  v1 stub; preserves the `prod-agent-no-exec` symbol gate)
- Snapshot-integrity HMAC at restore (`mvm-security::snapshot_hmac`)
- `mvm-security::snapshot_crypto` (AES-256-GCM primitives) and
  `mvm-security::keystore` (`KeyProvider` trait + `EnvKeyProvider`)
  — Phase 2 substrate
- `LibkrunBuilderVm` — Nix builds in a libkrun sandbox on
  macOS Intel / KVM-less Linux when host Nix isn't on `PATH`
- `mvmctl invoke` (Sprint 45 W3) — production-safe call surface for
  function-entrypoint workloads; `mvmctl exec` remains dev-only
- Workspace clippy gate: `clippy::too_many_arguments = "deny"`
- CI `lint` lane folds `fmt` + `clippy` + `xtask check-adr-coverage`
  into one runner (~3 min wall-clock saved per PR)
- 1937 workspace tests (up from v1's 1068)

### Changed (breaking)

- **`mvmctl up <flake>` produces a sealed image by default.**
  `mvmctl console <vm>` refuses with a clear error pointing at
  `--force` and `--dev`. v1 users who relied on `up` + `console` for
  a shell need `mvmctl up --dev <flake>` (intentionally less
  ergonomic in prod — security claim 4 is now enforced at runtime,
  not just at the CI symbol gate).
- **Lima is not used on macOS anymore.** v1's `mvmctl dev` booted a
  Lima VM; v2's `mvmctl dev` either uses Apple Container (macOS 26+
  Apple Silicon) or the host shell directly (Linux+KVM), and emits a
  clear bail with a libkrun-builder pointer on other hosts.
- **Image build substrate moved to `microvm.nix`.** v1's hand-rolled
  rootfs init paths are gone; users with custom `flake.nix` files
  need to migrate to `mkGuest` (the API is documented at
  `nix/lib/default.nix`).
- **The `mvm` binary was renamed to `mvmctl`** in v1's history; v2
  retains `mvmctl`. (Noted because the project is still called
  `mvm` and the rename trips up muscle memory.)
- **`mvmctl template` namespace retired.** Image building lives at
  `mvmctl build`; `mvmctl up --launch-plan` is the manifest path.
- **CLI argument parsing now uses `bon`-derived builders** for any
  command surface with more than ~3 args (workspace lint enforces).

### Removed

- v1's `mvm-runtime` crate — split into `mvm`, `mvm-base`, and
  `mvm-backend`
- v1's `mvm-apple-container` and `mvm-libkrun` crates — collapsed
  into `mvm-providers` (FFI/SDK shim layer)
- Lima support (`vm/lima.rs`, `lima.yaml.tera` template, all `mvmctl
  bootstrap` / `doctor` Lima checks)
- `tests/cli.rs.spec` — 900 lines of never-wired scaffolding

### Security

- 7 CI-enforced claims preserved from v1 (see CLAUDE.md "Security model"
  for the canonical statement):
  1. No host-fs access beyond explicit shares
  2. No guest binary can elevate to uid 0
  3. Tampered rootfs ext4 fails to boot (dm-verity)
  4. Guest agent has no `do_exec` in production builds
  5. Vsock framing is fuzzed
  6. Pre-built dev image is hash-verified
  7. Cargo deps are audited on every PR
- New in v2: snapshot HMAC at restore; `mvmctl console` accessible/
  sealed gate enforced at runtime; busybox-as-PID-1 in guests
  (smaller attack surface than systemd); `--force-with-lease` on the
  v1→v2 cutover itself (preserving v1 history)

### Known limitations / "not yet" list

These are intentional deferrals for the rewrite's first cut. Each
has a tracking pointer; none is silently broken.

- **mvmd contract build** is blocked on the upstream `libkrun
  0.4.5 ⊥ iroh-base 0.96.1 over sha2` conflict. Targeted package
  builds confirm every `mvmctl::*` path mvmd imports still resolves;
  end-to-end `cargo build --workspace` greens when the upstream
  resolves the dep version mismatch.
- **Live-KVM smoke** for `mvmctl up` + `mvmctl invoke` is gated on
  `MVM_LIVE_SMOKE=1` + `MVM_TEST_ROOTFS=...` and a capable host. The
  substrate compiles and skips cleanly without those — `tests/smoke_e2e_boot.rs::boots_real_rootfs_within_tripwire_then_tears_down_clean` runs the live exercise.
- **Cloud Hypervisor lifecycle** ships the JSON-over-Unix-socket
  control plane behind the same backend trait; pure pieces (config
  builder, path helpers, JSON escaping) carry 8 unit tests, but the
  spawn-dance is reviewed against CH's published API rather than run
  against a Linux+CH host (none in the dev environment).
- **L7 egress proxy runtime** has its foundation (PR-on-`legacy/v1`
  #23: `EgressMode` enum, `EgressProxy` trait, `StubEgressProxy`)
  but the mitmdump-driven runtime backing is plan 34 territory and
  hasn't shipped in v2 yet.
- **Phases 3–10 of plan 60** (network isolation, attestation,
  artifact capture, multi-tenant, supervisor surface, confidential
  computing) are sequenced but not started. Plan 60 carries the
  schedule; CLAUDE.md "Security model" lists what's shipped vs. what
  isn't.
- **Several v1 in-flight branches** carry feature work that hasn't
  been ported to v2 yet:
  - Plan 37 waves 2.2–2.6 (PII redactor, secrets scanner, SSRF guard,
    injection guard, L7 proxy v2) — slated for plan 60 Phase 2/3
  - Mesh DNS / vsock-bridge scaffolding (ADR-0018/0020) — slated for
    plan 60 Phase 3
  - Session lifecycle plans 51/52 — partial coverage in v2's
    `mvmctl invoke`; full surface deferred to a follow-up
  - Function-service factories plans 48/49 — landed in v2 at
    `nix/lib/factories/`; mvmforge consumes them via
    `mvm.lib.<system>`
  See [`MIGRATING-FROM-V1.md`](MIGRATING-FROM-V1.md) §"Feature parity
  status" for the per-feature delta.

[Unreleased]: https://github.com/tinylabscom/mvm/compare/v0.18.0...HEAD
[0.18.0]: https://github.com/tinylabscom/mvm/compare/v0.17.0...v0.18.0
[0.16.1]: https://github.com/tinylabscom/mvm/compare/v0.16.0...v0.16.1
[0.16.0]: https://github.com/tinylabscom/mvm/compare/v0.15.2...v0.16.0
[0.15.2]: https://github.com/tinylabscom/mvm/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/tinylabscom/mvm/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/tinylabscom/mvm/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/tinylabscom/mvm/releases/tag/v0.14.0
