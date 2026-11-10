# ADR-060: Event-driven mailbox scheduling at microVM density

Backing: design
Validation: pending live capacity measurements

## Status

**Proposed capacity optimization; not yet shipped or selected.** One isolated VM per
executing agent remains the product boundary. The target is 600–1,000
concurrently working VMs on a suitably provisioned single host. Mailbox
events may wait in a bounded queue; the guest need not answer immediately.
This is a capacity target to demonstrate, not a claim about every host.
The separate durable-mailbox implementation owns submission, journal,
acceptance, Receive/ACK and recovery. This proposal must not replace those
contracts or be integrated ahead of their production validation. Owner-authored
[#5292](https://github.com/tinylabscom/mvm/issues/5292) favors one resident
host/tenant daemon holding many derived mailbox keys; the VM-scoped key-holder
approach below preserves a narrower compromise boundary. The owner must select
between them after capacity and isolation evidence; neither is approved by this
ADR.

## Problem

The current mailbox grant gives each VM a separate `mvm-mailbox` process with
only that VM's derived keys. Preserve that security property. The process
polls VM lifetime, its launch thread repeatedly dials the guest (100 ms
initially, then every two seconds), and its host-request listener polls a
socket. At scale this is one helper process and multiple threads per
mailbox, even when no message is being delivered. The committed baseline's
64-entry queue is in-memory; the separately developed durable journal, not
this proposal, owns recovery and acceptance. The default 512 MiB guest
setting and per-instance rootfs copy fallback are separate, potentially
larger capacity costs.

## Approaches

- **Retain per-VM polling and tune the intervals.** Smallest patch, but the
  process/thread count and idle wake-ups still grow with VM count, and a
  longer interval increases event delay. Not the density design.
- **Resident host/tenant daemon holding derived mailbox keys (#5292).**
  Removes per-VM process and thread cost and may help warm claims, but one
  compromise can expose every mailbox key held by that daemon. Requires an
  explicit owner decision on the blast radius and a demonstrated key-custody,
  revocation, crash-recovery and tenant-isolation design. Do not adopt solely
  because its process count is lower.
- **Authenticated readiness notification, existing host-dial payload path.**
  Recommended as the first isolation-preserving spike after the durable path
  is stable, not yet selected as the production architecture. The guest sends
  *only* a mailbox-ready signal to a keyless event multiplexer. A VM-scoped
  worker then host-dials the existing guest port to fetch the payload and
  delegates acceptance to the existing journal/receipt authority. A worker
  can be started on demand only if it reopens that VM's journal and anchor
  securely; it never receives keys for a sibling VM. This changes scheduling,
  not the plaintext payload transport or mailbox authority.

## Security and delivery contract

Under the VM-scoped option there is still one distinct VM and one mailbox key
scope per executing agent. A keyless routing layer may multiplex descriptors, but
must never receive per-VM sealing keys, ciphertext, plaintext or become a
policy authority. A notice is untrusted scheduling metadata, authenticated
to the exact VM instance, current boot and signed plan epoch, with bounded
size/rate and replay fencing. A socket path or vsock port alone is not
identity. A stale, duplicate or cross-VM notice cannot admit a message,
move a lease, or sign `accepted_durable`. Only the existing VM-scoped
helper and durable mailbox journal can make those decisions; helper restart
must verify its per-mailbox journal and independent anchor before processing.
Lost notices leave the guest's stable outbox and same-ID retry intact.
Stop/restart fences the old instance, including racing or queued notices.

The guest-to-host *notice* is a protocol change; payloads still follow the
existing host-dial guest port. Backends unable to authenticate and route
notices must not claim event-driven delivery. Test boot races, lost and
duplicate notices, helper crashes, VM stop/restart, floods, key isolation,
journal corruption and recovery without weakening the durable delivery
contract. A pooled-key alternative needs the explicit trust-boundary decision
described above, not a silent replacement of this contract.

### Notification contract to implement after the durable foundation

The keyless scheduler sees only an opaque, rotatable VM-scoped routing
handle and a bounded coalescing token that cannot be reversed to the
canonical message ID. It sees no `MailboxId`, `MessageId`, boot identity,
plaintext, ciphertext, credential, acceptance verdict or ACK. A
purpose-bound ingress authenticates the route to the current VM/boot
without treating the handle as mailbox authority. Do not reuse the guest
reader's ACK signing key or the FlowMux egress key as notification
authority without a separate security review. The VM-scoped key-holder,
not the scheduler, resolves the signed grant, execution epoch and
immutable outbox message ID after host-dialling the guest.

The scheduler coalesces repeated opaque tokens under bounded per-VM and
host-wide work queues. Its outcome is only
`scheduled`, `already_scheduled`, or `backpressured`—never
`accepted_durable`. A lost or backpressured notice leaves the immutable
guest outbox untouched and retries the same operation. A worker must
re-check its private boot and epoch binding after being scheduled, before
host-dialling, and must let the durable mailbox service determine the
final disposition. No second source of message identity or acceptance
state is introduced.

## Boot and density tradeoffs

The notice route must not require a guest round trip before the VM starts.
Prepare it concurrently with other boot work; do not claim mailbox
readiness if route setup or helper recovery is unavailable. Starting a
VM-scoped helper on demand can reduce idle host processes but adds
first-message latency, and is safe only after the journal/anchor and
stop/restart fences are proven. Retain the existing boot-time helper until
those proofs and a measured comparison justify removing it. Compare
p50/p95/p99 boot and first-message delay with and without the optimization.
Notification removes periodic guest dials; it does **not** reduce the
guest's configured RAM or, until lazy helpers are proven, the process count.

## Capacity evidence

The shared HVF/Firecracker density harness compares baseline launches with
mailbox-granted launches, recording helper count, thread count, RSS, VM
state blocks and filesystem pressure. It calculates p50/p95/p99 from
machine-start receipt publication times, which are **not** guest-readiness
or first-message times. The latter must remain explicitly unavailable
until a public fixture and receipt probe observe *durable* acceptance;
legacy ephemeral `machine mailbox recv` and an outbox file write are not
that event. Linux/KVM has a launch wrapper but still needs a live witness.

Run progressively larger waves up to 600 and 1,000 only on an explicitly
provisioned host, measuring boot and durable-message delay under both idle
and working guests. A mailbox-only synthetic test is useful for detecting
process/thread leaks, but cannot certify the full VM target. If the
retained per-VM helper still exceeds the measured host budget, evaluate a
keyless shared reactor with isolated per-VM crypto workers before
relaxing any isolation guarantee. [#4635](https://github.com/tinylabscom/mvm/issues/4635)
remains the open mailbox capacity and latency evidence gate; neither the
1,000-VM target nor the first-durable-message latency is validated.
