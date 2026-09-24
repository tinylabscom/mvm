# Kubernetes in a single microVM

Backing: shipped-source
Validation: check-sprint-append

**Tracking:** tinylabscom/mvm#3554 (runtime), tinylabscom/mvm-templates#2
(guest template PR) and tinylabscom/mvm-templates#1 (template tracking).
The shared image repositories carry no Kubernetes-specific artifacts —
consumption is mvm kernel flake -> `mvmctl kernel build` -> launcher
resolution. Branch: `feat/kubernetes-in-microvm` (merged).

**Status: W1 + W2 merged (#3555); W3 kernel-variant and template
scaffolds landed (#3572, tinylabscom/mvm-templates#2). W4 is BLOCKED on
#3599, resolved to root cause 2026-09-23: the clone()-in-a-fresh-pid-ns
failure is a long-standing upstream kernel bug under virtualization
(Debian 6.1/6.12/6.18 kernels all reproduce under TCG, HVF, and x86_64
KVM with pristine userspace; bare metal reportedly works). Not a config,
toolchain, or image-train problem — no mvm-side kernel change will fix
it; see #3599 for the full matrix and
`specs/notes/2026-09-23-fork-in-fresh-pid-ns-upstream-report.md` for the
upstream report draft. The
mvm-side kernel build/boot-selection bridge lands with the kernel-variant
workstream. A generically-named datapath kernel posture in mvm-images was
rejected by the image lane (PR #24 closed: guest network devices violate
the permanent invariant); the interim kernel remains the in-repo
`workload-k8s` variant, and the invariant-compatible durable shape is host
networking plus the loopback/vsock egress proxy.**

## Product requirement

A single mvm microVM can boot a complete, working single-node Kubernetes
cluster (k3s), so that a whole cluster is a disposable, fork-able,
digest-pinned artifact: control plane and container runtime together inside
one guest that owns its kernel. Standing up a cluster is one `mvmctl machine
run` against a purpose-built image, and tearing it down is `mvmctl machine
down` — no shared host kernel, no privileged-container workarounds, no
separate provisioning step.

## Why a microVM succeeds where a container fights you

The kubelet and its container runtime expect to own a kernel: they configure
cgroup hierarchies, load kernel modules, mount filesystems, and program
netfilter. Inside a container all of that runs against a kernel the workload
does not own. A microVM gives the workload a real kernel, a real devtmpfs, a
real cgroup v2 hierarchy, real overlayfs, and real netfilter — the pieces
that are fragile under nesting behave as they do on a dedicated host, and the
hypervisor (not a container runtime) remains the boundary between tenants.

## Reference design findings

An external runtime's engineering write-up on Kubernetes-in-a-microVM (URL in
the tracking issue; the vendor's name is not used anywhere in this repo)
contributes two transferable findings, plus one constraint mvm already
satisfies differently:

1. **/dev/kmsg (char 1:11) is a hard kubelet requirement.** The kubelet opens
   it during startup and refuses to run without it. A bare VM gets it from
   devtmpfs; a `/dev` assembled from an allow-list must include it or nested
   Kubernetes fails before doing anything. Their fix added the device to the
   container device set with a regression test asserting its presence.
2. **Nested container storage must sit on a real filesystem.** Their VM
   rootfs is an overlay, and Docker's overlay2 graph driver cannot nest on
   overlay, so container storage lives on a separate ext4 disk. mvm's guest
   rootfs is a plain read-only verity ext4 (not an overlay), and writable
   space already exists via disk volumes — the transferable point is only
   "give the cluster's state a real writable disk, not the rootfs".
3. **Full capabilities inside the guest are safe in a microVM in a way they
   are not in a container**, because the isolation boundary is the
   hypervisor. mvm keeps the stricter posture anyway: the workload identity
   is uid 901 and guest code never runs as root (the no-root-workload gate is
   a claim-2 backstop). k3s must therefore run rootless rather than relax the
   gate — see "Design within mvm's constraints" below.

## Design within mvm's constraints

| Concern | mvm today | Design |
|---|---|---|
| Workload identity | uid 901 after the activation-time privilege drop; workload-spawning verbs are refused at root (`mvm-agentd/src/vsock/workload_privilege.rs`) | k3s server `--rootless` (RootlessKit + user namespaces). Rootless masks/fakes `/dev/kmsg`, which resolves the device-mode question for the workload uid. |
| Guest networking | **No guest NIC, no TAP/TUN — every host-bound byte leaves over the vsock.** The guest egress client exposes a SOCKS5/CONNECT proxy on guest loopback (`127.0.0.1:1080`, `mvm-egress-client`) and tunnels admitted host:port flows over FlowMux/vsock to the host endpoint spawner. Signed TCP ingress exists only at pre-declared ports (`--port`), forwarded host-side. | Cluster-internal networking (apiserver, pod-to-pod, service IPs) is ordinary in-guest netns/bridge traffic and needs no NIC. Everything that leaves the guest — container image pulls, pod egress to external services — must be wired through the loopback egress proxy and admitted by `allow_hosts`. NodePort/LoadBalancer have no NIC semantics: a workload is reachable from the host only through a declared ingress port. The exact CNI/outbound wiring (proxy env vs. in-guest transparent redirect) is an open design item for W3. |
| Cluster state storage | Mount policy allow-roots are exactly `/data` and `/work` (`mvm-core/src/crypto/policy/mount.rs`); rootfs is read-only | k3s `--data-dir=/data/k3s` on a sized `:rw` ext4 disk volume attached at `/data` (containerd state included). No policy change needed. |
| Boot-time devices | All virtio-blk disks attach at create/run time; no hot-plug | Declare the data disk at `machine create`/`run` time. |
| OCI device allow-list | Host-side unpack refused `/dev/kmsg` (`mvm-fs/src/oci/unpack/device_nodes.rs`) | Allow-list `/dev/kmsg` (1:11) materialized `0o644` — a world-writable kernel log would let any unpacked process forge kernel log lines, so it does not share the `0o666` mode of the r/w pseudo-devices. |
| In-guest container runtime | None exists; not needed | k3s embeds containerd. Containers it starts run against the guest kernel the VM owns — no nested-runtime work in mvm. |
| Verbs to drive the cluster | `Exec*` / `RunDetached` are DevOnly, refused on prod sessions | Kubernetes-in-one-VM is a dev/test-tier capability in v1; prod admission of a k8s API surface is out of scope. |

## Non-goals (v1)

- Multi-node clusters, cluster federation, or mvm acting as a Kubernetes
  node provider.
- A production-admitted k8s control plane (prod session verbs are DevOnly).
- Root workload relaxation of the no-root-workload gate. If rootless k3s
  proves infeasible inside the guest, that relaxation is a separate,
  security-reviewed change — not part of this plan.

## Runtime gaps found during design

Two gaps surfaced while designing against the real code, both now tracked:

1. **No cgroup2 mount.** Nothing in the guest boot path mounts
   `/sys/fs/cgroup` today (mkGuest's busybox `/init` and the guest agent's
   mount set both omit it) — sealed OCI workloads never needed it. Rootless
   k3s needs cgroup2 mounted, and delegation to the workload uid needs
   subtree-ownership setup mvm does not do yet. mvm work item: mount cgroup2
   during activation and delegate to the workload uid for guests that
   declare it.
2. **The sealed workload kernel cannot run Kubernetes.** `CGROUPS`,
   `NAMESPACES`, and `NETFILTER` are required-disables in the workload
   kernel, and `BRIDGE` is disabled in shared base — all deliberate cuts for
   the sealed single-workload posture. Resolved by the `workload-k8s`
   variant (mvm#3572, merged), consumed via `mvmctl kernel build --which
   workload-k8s`; the template repository owns bring-up and validation.

## Workstreams

### W1 — mvm runtime enabler: /dev/kmsg in the OCI device allow-list

The kubelet's hard requirement must not be refused when an OCI-derived guest
image carries it. `AllowedDeviceNode` gains a mode (default `0o666`; kmsg is
`0o644`), and the allow-list gains `dev/kmsg` (1:11).

- [x] `AllowedDeviceNode` carries a per-node mode; `mknodat` uses it
- [x] `dev/kmsg` (1:11) added at `0o644` with rationale comment
- [x] Tests: allow-list classification (accept + wrong-pair + wrong-type
      refusals), Linux materialization mode assertion, non-Linux skip path
- [ ] Host `cargo test -p mvm-fs` green; workspace clippy green
- [ ] Builder-VM gated-test pass before merge (per AGENTS.md the Linux
      materialization test only runs there)

### W2 — example + recipe

- [x] `examples/kubernetes/`: `mvm.toml` + README recipe — data disk at
      `/data`, `kubectl` via `mvmctl machine exec` (dev tier), sizing
      guidance (4 vCPU / 4 GiB starting point)
- [x] cgroup2 mount + workload-uid delegation in the guest boot path —
      best-effort and unconditional (the sealed workload kernel compiles
      cgroups out; ENODEV skips quietly): `mvm-agentd` mounts cgroup2 during
      `provision_guest_environment` and delegates
      `/sys/fs/cgroup/mvm-workload` to the workload uid; mkGuest's `/init`
      does the same for the template path (delegating to the entrypoint uid)

### W3 — guest template + kernel variant (not in this repo)

- [x] Template registry `templates/kubernetes/`: a `mkGuest` flake with the
      k3s rootless entrypoint service and its health check —
      tinylabscom/mvm-templates#2 (experimental scaffold; bring-up and the
      boot-image capability contract tracked in tinylabscom/mvm-templates#1)
- [x] `workload-k8s` kernel variant: `CGROUPS` + controllers, `NAMESPACES`
      + per-ns symbols, `NETFILTER` + conntrack/iptables, `BRIDGE`/`VETH`/
      `VXLAN` — mvm#3572, merged. The sealed workload kernel's
      required-disables are deliberate and stay; this is a second variant,
      consumed via `mvmctl kernel build --which workload-k8s`.

### W4 — E2E validation, BDD, docs

- [ ] Builder-VM E2E: boot the image (on the `workload-k8s` kernel), wait
      for node Ready, pull an image through the egress proxy, run a pod with
      admitted egress, exercise a declared ingress port, teardown; BDD
      scenario under `features/suites/`. **Blocked by #3599** (upstream
      kernel bug: pod sandboxes are fresh PID namespaces and their init
      processes hit the clone() ceiling on every virtualized host tested);
      the datapath kernel replaces `workload-k8s` naming per the image
      train's no-consumer-names rule.
- [ ] Docs guide page (`public/src/content/docs/guides/`)
- [ ] Amend the "Kubernetes compatibility" deliberately-not-claimed entry in
      `public/src/content/docs/security/sandbox-parity-status.md`: the claim
      stays true for mvm-as-an-orchestrator; the new posture is "a k8s API
      served from inside one microVM", which the doc must name accurately.
