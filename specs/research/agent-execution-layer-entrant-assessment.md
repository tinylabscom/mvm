# Research — a funded agent-execution-layer entrant vs. mvm and the fleet product

**Status:** Research note; no implementation commitment
**Date:** 2026-08-10
**Owner:** mvm
**Source:** A venture-funded 2026 entrant selling a hosted "execution layer for AI
agents." Reviewed from its public marketing site, product documentation, generated
REST/SDK reference, pricing page, engineering blog, and two systems-engineering job
postings. Named obliquely throughout, per the house convention also used in
`specs/research/external-sandbox-refactor-lessons.md`; competitor and product proper
names, founder and investor names, and source URLs are deliberately omitted.

## TL;DR

This is not an adjacent competitor. It is the same bet: govern an agent *underneath*
itself, at the layer where its actions become real, because application-level and
model-level guardrails cannot hold under adversarial pressure. Their own founding
essay argues that a request-time front door is the wrong place to constrain a
workload that decides what to do as it runs — which is, restated, ADR-001's thesis.
Their runtime-engineering job posting describes owning "the microVM execution layer:
guest lifecycle, device model decisions, boot/restore time optimization," and
explicitly frames the work as kernel-and-VMM-layer rather than orchestration-layer.

Their credential design — a stored secret, a host+path match rule, a `${credential}`
placeholder substituted into an outbound header by an egress gateway so the workload
never holds the real value — is feature-for-feature ADR-023, arrived at
independently. That convergence is the single most useful finding in this note: it
is strong third-party validation that mvm's substitution architecture is correct.

Where we are genuinely ahead is **structural isolation and verifiable provenance**:
NIC-less guests, default-deny egress, no interactive path into a sealed workload, and
a chain-signed audit log a customer can verify without trusting us. Where they are
ahead is **cost control, distribution, and agent-native framing** — and their lead
marketing message (token/compute spend) is a capability mvm has *zero* of today.

The strategic gap they have chosen not to serve is **self-hosted / BYOC**. Their
entire model is usage-billed SaaS on their own cloud account. That is the fleet
product's opening.

## What was reviewed

Public product surface, as documented:

- **Unit of work:** a "runtime" — an isolated stateful computer created with a vCPU
  and memory request (`--cpus 2 --memory 2048`), into which the caller `exec`s
  commands. There is no user-supplied image or reproducible-build concept in the
  documented API; presets exist for common coding-agent runtimes.
- **Three stated pillars:** *run, govern, record.*
- **Isolation:** microVM. Not named in the docs, but both systems job postings are
  explicit about owning the microVM execution layer, guest lifecycle, and device
  model, and about wanting KVM / Firecracker / cloud-hypervisor / Xen / kernel
  backgrounds in Rust, C, or C++.
- **Snapshot/resume/branch:** a headline engineering objective — "paused for a week
  and resumed byte-for-byte," "branched into three parallel explorations," with
  copy-on-write page sharing so N branches do not cost N× resources. Nice-to-haves
  listed include CRIU/live-migration experience, `io_uring`, and making cold starts
  fast at scale. Customer-facing today this is exposed as **checkpoints**: a
  point-in-time capture of filesystem and running processes, restorable into new
  runtimes.
- **Egress:** per-runtime policy with `allowlist` and `denylist` modes over hostname
  and wildcard-host patterns. Documented explicitly: *"An empty denylist is the
  default open policy."*
- **Secrets ("secret stubs"):** a tenant-scoped stored secret plus a rule matching a
  destination host and optional path; the literal `${credential}` placeholder is
  replaced with the stored value when the egress gateway injects the outbound
  request (e.g. header `Authorization`, template `Bearer ${credential}`). Rules are
  settable per runtime or tenant-wide, individually or from a YAML file.
- **Lifecycle economics:** auto-suspend on idle with wake-on-request (Preview),
  memory auto-scaling, service publishing with an HTTPS ingress spec.
- **Token/cost layer:** prompt compression that shrinks oversized tool output while
  preserving signal (JSON arrays, logs, search results, git diffs — a worked example
  claims −39%), plus a "token x-ray" for spotting waste, plus spend governance at the
  network boundary where model calls leave the runtime.
- **Interactive access:** an SSH-keys API — register, list, and delete SSH public
  keys per runtime.
- **Record:** marketed as syscalls, network calls, filesystem writes, credentials
  used, and the task policy each action ran under. **No audit, event, or verification
  endpoint appears anywhere in the documented REST surface.**
- **Org:** team access with Owner/Admin/Developer roles.
- **Distribution:** `npm`-global CLI, Homebrew tap, Python and TypeScript SDKs,
  generated REST docs, framework integrations, and agent-consumable skill docs.
- **Pricing:** prepaid usage-based — ~$0.05/vCPU-hour, ~$0.016/GiB-hour memory,
  ~$0.0001/GiB-hour disk. Billing follows runtime state (paused/suspended bills disk
  only). $50 trial credit, no credit card, no monthly minimum.
- **Deployment:** hosted SaaS. The cloud-infrastructure job posting is AWS-first —
  ECS vs. EKS, Spot fleet design, snapshot storage tiering, Terraform module design,
  control-plane/data-plane separation, with cross-cloud portability an explicit
  someday-not-today.
- **Top-of-funnel OSS:** a separate free Apache-2.0 Rust tool (<10 MB, tokio) that
  isolates credentials from a popular local personal-agent runtime using Unix users,
  file permissions, and process separation. Its onboarding scans the agent's config
  and environment, migrates recognised API keys into a protected store, and replaces
  them in place with virtual identifiers. Requires `sudo` to establish the boundary.

## Architecture at a glance

| Concern | The entrant | mvm today |
|---|---|---|
| Isolation boundary | microVM (VMM unnamed publicly) | Firecracker (Linux), in-house HVF VMM (macOS 26+), libkrun (macOS 13–25) |
| Guest network | Network stack present; egress gateway in path | **No net device at all** on any workload backend; vsock-only, CI-gated |
| Egress default | **Open** (empty denylist = default open policy) | **Default-deny** (claim 10); `unrestricted` requires an ack env var banned in CI |
| Secret handling | Stored secret + host/path rule; `${credential}` injected by egress gateway | Claim 13 / ADR-023 host-side substitution at the per-VM endpoint; identical shape |
| Interactive access | SSH keys API per runtime | Claim 15: no shell, no PTY, no DevOnly verbs on a sealed image; dev-only PTY-over-vsock |
| Admission authority | API call with a policy attached | Claim 8: signed, validity-windowed `ExecutionPlan` + nonce replay store |
| Audit | Marketed; no documented verification surface | Chain-signed log; `mvmctl trust audit verify` exits nonzero on drift |
| Verified boot | Not documented | Claim 3: dm-verity roothash on kernel cmdline; tampered rootfs fails to boot |
| Supply chain | Not documented | Claims 9/11/14: content-addressed signed bundles, sealed hash-locked dep volumes, OCI provenance in the chain |
| Workload definition | Generic computer + `exec` | OCI image, Nix flake (`mkGuest`), or decorated function → one signed artifact |
| Snapshot/branch | Checkpoints shipped; branch/fork an engineering objective | `vm/` checkpoints with chain-anchored lineage; warm snapshot-fork in flight |
| Cost/token controls | Prompt compression, token x-ray, spend governance, auto-suspend, memory autoscale | **None** |
| Deployment model | Hosted SaaS, usage-billed, AWS-first | Local-first CLI; self-hostable fleet daemon |

## Where mvm is genuinely differentiated

These are structural rather than positional, and most are enforced by CI gates
instead of documentation.

1. **Their guests have a network stack; ours have no NIC.** They govern egress with a
   gateway in the path — the guest can form a connection and be refused. We removed
   the device: `xtask check-vsock-only-egress` fails the build if `virtio_net`, a
   tap, or a userspace-gateway token appears on a workload path, and
   `xtask check-uniform-vsock-egress` pins all three workload backends to one spawn
   site so a second gate cannot grow. Same happy path, very different failure modes,
   and ours is the one that survives a compromised guest.

2. **Default-deny versus default-open.** Their documentation states an empty denylist
   is the default open policy. Claim 10 is the opposite. This is a one-slide
   difference in any security review.

3. **Sealed workloads have no interactive path.** They ship an SSH-keys API per
   runtime. Claim 15 is five independent layers preventing exactly that. Their
   runtime is a computer you can log into; ours is a workload you cannot.

4. **"Record" is their weakest pillar and our strongest.** They market syscall,
   network, filesystem, and credential recording heavily, but nothing in the
   documented API lets a customer independently verify it. We ship signed
   `ExecutionPlan`s, a hash-chained audit log with a verifier that exits nonzero on
   drift, dm-verity sealed rootfs, content-addressed signed bundles, and OCI
   provenance written into the chain. Their record is a log they hand you; ours is a
   chain you can check without trusting us. For a regulated buyer that is the whole
   difference.

5. **Reproducible, attestable workloads versus generic computers.** Their unit is
   CPU + memory that you exec into. Ours is built from an OCI reference, a Nix flake,
   or a decorated function into a content-addressed artifact. They can tell you what
   happened; we can prove what ran.

6. **Local-first and self-hostable.** Theirs is a hosted service with usage billing
   on their cloud account. Any buyer who cannot ship workloads into a third party's
   AWS has exactly one option in this comparison.

## Where the entrant leads

Stated plainly, because underrating this would be a mistake.

1. **Cost control is their headline and we have none.** Prompt compression, token
   x-ray, spend governance, auto-suspend, memory autoscaling. A grep across
   `crates/` and `src/` for spend caps, token budgets, cost caps, or prompt
   compression returns nothing. This is the line item a buyer feels every month and
   it is the first sentence on their homepage.

2. **Distribution and DX.** One-line global CLI install, Homebrew tap, Python and
   TypeScript SDKs, generated REST reference, $50 credit with no credit card, and
   agent-consumable skill docs. Our install still opens a toolchain conversation.

3. **They speak to agent builders; we speak to systems engineers.** Their first code
   sample creates a named runtime with an agent preset and execs a coding agent
   inside it, with framework integrations alongside. Same substrate, and their
   framing is much closer to the buyer's language.

4. **Branch/fork as a product verb.** Sharing pages across N exploration branches is
   something we have in flight as an engineering objective and they are already
   selling as a concept.

5. **A well-designed OSS wedge.** A free, permissively licensed, small Rust tool that
   installs into a developer's machine and migrates their API keys into its own
   protected store is excellent top-of-funnel, and the accompanying security writeup
   is credible engineering, not marketing. It also seeds the exact argument that sells
   the paid product.

6. **Capital and focus.** A 2026 seed round in the tens of millions, on-site teams,
   and tier-1 investor distribution. They will ship product surface faster than we
   will.

## Where the fleet product sits

Their cloud-infrastructure job posting reads as a requisition to build what the
sibling fleet daemon already is: multi-tenant fleet, snapshot storage tiering,
control-plane/data-plane separation, autoscaling policies that survive bursty agent
workloads (fan out fifty sub-tasks, then idle ten minutes), cost-aware fleet sizing,
and cross-cloud abstractions kept "on the table without over-engineering for it
today."

The fleet product already has tenants, worker pools, instances, per-node reconcile
agents over QUIC+mTLS, a coordinator gateway with wake-on-demand, per-tenant ACME TLS
termination, VPC networking with priority-based firewall rules and floating IPs,
LUKS-encrypted volumes, RBAC, an MCP sandbox server, a warm sandbox pool, and
infrastructure autoscaling across six providers with spot support.

Their structural advantage: they operate exactly one deployment and can tune it
relentlessly. Ours has to work on everyone's hardware. Their structural gap:
**self-hosted and BYOC is a segment their business model excludes**, and it is
precisely the segment that most wants the claims ladder we already enforce.

## Recommendations

Not commitments; input to sprint planning.

1. **Do not chase prompt compression.** It is a proxy-layer feature, trivially
   copied, and confers no microVM moat. It also cannot be made claim-bearing.

2. **Do add egress-side token and spend metering.** This is the high-leverage move.
   We already terminate every outbound connection at the per-VM substitution
   endpoint — the one process that sees each model call in the clear. Adding
   per-workload token accounting there is close to an accounting struct plus an audit
   entry, and it lands with *better* provenance than theirs because it can be written
   into the chain-signed log. It neutralises their lead message on terms only our
   architecture supports. Worth an issue and a plan.

3. **Lead with the two properties they cannot match without a rewrite:** NIC-less
   guests, and an audit chain the customer verifies rather than trusts. "Their
   default is open, ours is deny" and "their record is a log, ours is a chain" are
   the two slides.

4. **Treat cold-start and install friction as competitive positioning, not polish.**
   Their claim is that the environment starts in milliseconds and sizes itself to the
   workload, so the boundary stays cheap enough to be worth its cost. That is the
   same argument behind the sub-200ms launch work.

5. **Position the fleet product explicitly as self-hosted/BYOC.** It is the one
   segment the entrant's model structurally cannot serve, and the fleet daemon's
   multi-cloud autoscaling is already ahead of the AWS-first platform they are
   currently hiring to build.

## Open questions

- Which VMM do they actually use? The job postings imply in-house or heavily modified
  (device-model ownership, boot/restore optimisation), but nothing public confirms it.
- Is their "record" pillar cryptographically anchored at all, or is it an append-only
  service log? Nothing in the public API suggests the former.
- Does their local execution story exist as a product, or only in the essay? All
  documented surfaces are cloud-addressed and API-key authenticated.
- Does their checkpoint restore preserve any admission binding, or does a restored
  runtime re-derive its policy from the control plane? This is the same
  restored-child authorisation problem tracked on our side.
