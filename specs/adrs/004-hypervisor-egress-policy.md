---
title: "ADR-004: hypervisor-level egress policy with domain-pinning"
status: Proposed (v1 = L3 shipped; L7 + DNS-pinning scoped in plan 34)
date: 2026-04-30
related: ADR-002 (microVM security posture); ADR-003 (local MCP server); plan 32 (MCP + LLM-agent adoption); plan 34 (L7 egress proxy follow-up); plan 25 (microVM hardening)
---

## Status

Proposed. v1 implementation tracked in
`specs/plans/32-mcp-agent-adoption.md` Proposal D. ADR-002 named
hypervisor-level egress policy as an explicit non-goal for Sprint 42's
hardening; this ADR moves it on-roadmap for the next sprint with a
deliberately smaller v1 scope than the full three-layer model.

## Context

When mvm runs an LLM agent (or any other workload that the user wants
to constrain), the hypervisor sits in the only place that can enforce
egress destinations — between the guest's TAP interface and the
host's wider network. The guest agent inside the microVM is untrusted
in this threat model; an agent that decides to exfiltrate to
`evil.example.com` cannot be stopped by the guest's own firewall.

mvm has had `NetworkPolicy` in `mvm-core` since W7, and `mvmctl up
--network-preset` / `--network-allow` since the same sprint. Those
flags wire up an iptables-based L3 allowlist on the bridge. What was
missing:

1. A clear ADR specifying what egress enforcement does and does not
   guarantee.
2. A curated preset for the LLM-agent use case (plan 32 / Proposal B
   wants `api.anthropic.com` + GitHub + nothing else).
3. A roadmap for the layers above L3 — namely L7 SNI/Host-header
   filtering and DNS-answer pinning — which are needed to defeat
   DNS-rotation attacks and SNI-hopping that pure L3 can't see.

This ADR captures both decisions and limits.

## Threat model (additive over ADR-002)

The adversary is **a malicious guest workload** (per ADR-002 §1):
code running inside a microVM trying to talk to a host the operator
did not authorize. Specifically:

1. The guest may attempt direct TCP/UDP connections to arbitrary
   IPs.
2. The guest may abuse DNS — query a benign hostname, observe the
   answer, then connect to a different IP than the one a stub
   resolver would have authorized.
3. The guest may reuse a TLS connection to a permitted SNI by
   sending a different `Host` header (HTTP/1.1 vhosting).
4. The guest may attempt SNI to a permitted name then perform
   ALPN-protocol smuggling.

A **malicious host** is out of scope (per ADR-002). A **malicious
DNS resolver upstream of the host** is also out of scope.

## The three-layer model

A complete egress enforcer for the LLM-agent use case has three
tiers, each catching a class of attack the lower one can't:

### L3 — iptables allowlist (v1 — shipped)

Already in `mvm/src/vm/network.rs::apply_network_policy`.
At TAP attach time, install `FORWARD` rules in the bridge chain that:

- `DROP` all packets from the guest IP by default.
- Allow ESTABLISHED/RELATED return traffic.
- Allow DNS (UDP+TCP :53) so name resolution works.
- Allow each `<host>:<port>` in the policy by IP — iptables resolves
  the host once, at rule-install time.

**Catches:** raw IP-targeted exfil to non-allowlisted hosts.
**Doesn't catch:** DNS rotation (CDN-fronted hosts where the
authorized answer changes between rule-install and connect),
SNI-hopping (TLS to authorized IP, different SNI), Host-header
abuse.

### L7 — HTTPS proxy with SNI/Host filtering (deferred)

Egress proxy on the host bound to a private CIDR the guest can reach.
Guest gets `HTTPS_PROXY` / `HTTP_PROXY` env vars and the proxy's CA
cert in `/etc/ssl/certs/mvm-egress.crt`. Proxy enforces the allowlist
by SNI for HTTPS (CONNECT) and Host header for HTTP. CONNECT to a
disallowed domain returns 403.

**Implementation cost:** wraps `mitmdump` from nixpkgs (~50 LoC of
process supervision in mvm); needs CA injection at boot
inside the rootfs; needs per-VM port allocation; needs cleanup on
crash.

**Why deferred:** mitmdump is a substantial runtime dep (Python +
mitmproxy + cryptography), and the dev image's closure grows by
~80 MiB. We want the L3 tier shipped and adopted before pulling in
that closure. Operator opt-in via a separate command flag once the
implementation lands.

### L7+ — DNS-answer pinning (deferred)

Stub resolver on the host (`dnsmasq` configured with
`server=/<allowlisted-domain>/<upstream>` and a 0-TTL pin per
recursion result). Guest DNS goes through the stub; the stub
publishes resolved A records into the iptables allowlist for the
TTL of the answer. Catches DNS rotation. **Why deferred:** dnsmasq
is small but the IP-pin/iptables-update plumbing has corner cases
(IPv6, A-vs-CNAME chains, NX caching) that need careful design.

## Decisions

1. **v1 ships L3 only.** The infrastructure is already there
   (`NetworkPolicy::AllowList` + `iptables_script`); v1's only
   addition is the new `NetworkPreset::Agent` curated bundle for
   plan 32 / Proposal B. Operators who need L7 wait for the
   follow-up.

2. **`NetworkPreset::Agent` is the LLM-agent default.** It contains:
   - `api.anthropic.com:443`
   - `api.openai.com:443`
   - `github.com:443` + `:22`
   - `api.github.com:443`

   Strictly smaller than `dev` (no npm/PyPI/crates.io). Documented
   in `nix/images/examples/llm-agent/README.md` as the recommended
   `mvmctl up --network-preset agent`.

3. **No L7 today; ADR documents it.** When L7 lands, it composes
   on top of L3 (defense in depth, per ADR-002 §"Decisions" 2).
   Operator chooses the layer per `--network-mode` (future flag),
   not by separate commands.

4. **DNS pinning is paired with L7.** Doing DNS pinning without
   the L7 proxy is a partial solution that defeats CDN-fronted
   destinations; doing L7 without DNS pinning leaves SNI-equal-IP
   gaps. Land them together.

5. **Cross-platform discipline (cross-cutting: "iptables/proxy
   dispatch runs on the Linux host or inside the guest, never on
   the macOS host").** L3 already follows this:
   `apply_network_policy` calls `run_in_vm_visible` which dispatches
   through `shell::run_in_vm` on macOS (executing inside the
   libkrun-managed guest per ADR-013) and runs natively on
   Linux. L7 + DNS-pinning when added must follow the same pattern.

6. **Per-template default policy is an ergonomic follow-up.**
   Today policies are passed per-invocation. Baking a default into
   `TemplateSpec` so `claude-code-vm` ships with `agent` preset
   automatically is a separate (small) refactor, tracked but not
   blocking this ADR.

## Consequences

### Positive

- Operators get an explicit ADR explaining what egress filtering
  does and doesn't catch, instead of inferring from the existing
  CLI flags.
- The `agent` preset gives the LLM-agent showcase (Proposal B) a
  one-flag answer to "how do I lock this down to Anthropic?":
  `mvmctl up --network-preset agent`.
- L3 enforcement is real and ships today. DNS-rotation gaps are
  documented, not pretended-away.

### Negative / accepted costs

- L3 by itself does not stop a determined adversary that controls
  the resolver path (or a CDN-fronted destination). This is
  documented honestly. Operators wanting stronger guarantees wait
  for L7 + DNS-pinning.
- Adding `NetworkPreset::Agent` means a new variant downstream
  consumers must match on. Existing match-arms in the workspace
  are exhaustive (no wildcards) so the compiler will catch any
  miss.

### Explicit non-goals

- **Application-layer protocol filtering.** Beyond SNI + Host, we
  don't do payload inspection.
- **Egress for IPv6.** Today's `iptables` script is IPv4-only.
  IPv6 follow-up tracked.
- **Multi-tenant fairness.** Per-tenant egress quotas are mvmd's
  domain (plan 33).

## Reversal cost

- v1 changes (the `Agent` preset variant + tests + README) are a
  one-line per-call-site removal — trivially reversible.
- L7 + DNS pinning would, when implemented, cost a runtime-dep
  rollback (mitmdump + dnsmasq removal) plus an `ops/egress-proxy/`
  cleanup. Documented as part of those follow-up plans.

## References

- Plan: `specs/plans/32-mcp-agent-adoption.md` Proposal D
- Related ADRs: ADR-002 (microVM security posture), ADR-003 (local
  MCP server)
- Existing infrastructure: `mvm-core::policy::network_policy`,
  `mvm::vm::network::{apply,cleanup}_network_policy`
- L7 inspiration: archie-judd/agent-sandbox.nix's domain allowlist
  proxy pattern


## Consolidated from ADR-006 — Name-Constrained CA for hypervisor-level L7 egress interception

## Status

**Accepted.** Implemented by plan 129 Stage 2 as the secret-egress
`https` terminator — not the abandoned plan-34 `mitmdump` supervisor,
but the same cryptographic design this ADR locks down: a **per-VM
name-constrained intermediate**, not a long-lived blanket-trust host
CA. The interceptor is mvm's own Rust terminator
(`mvm-hostd::supervisor::terminator::tls`), driven by the substitution
endpoint; there is no third-party MITM proxy.

As implemented:

- The long-lived host CA (`mvm_core::crypto::egress_ca::EgressCa`,
  under `~/.mvm/egress-ca/`, key mode 0400) signs a **per-VM
  intermediate** whose `nameConstraints permitted` is exactly the
  union of the workload plan's bound egress hosts (the claim-12
  allow-list). Only the intermediate **cert** reaches the guest; the
  key stays host-side in the per-VM substitution endpoint and mints
  per-SNI leaves on the fly.
- The terminator peeks the ClientHello SNI and **terminates only bound
  hosts** (mint leaf → decrypt → substitute the real credential →
  re-originate upstream TLS validated against the system roots).
  **Unbound SNI is spliced through untouched** — never decrypted, zero
  added host visibility.
- **Zero-added-visibility argument:** the host already sees bound-host
  plaintext via substitution (it must, to swap the placeholder for the
  real credential). Scoped name-constrained termination of *only* those
  hosts adds nothing the substitution already requires, and the CA is
  cryptographically constrained so it cannot vouch for any host outside
  the plan's allow-list. This is **not** the rejected blanket MITM.
- **Honest caveat (defense in depth, not the control):** Python `ssl`
  and older Node do **not** enforce X.509 `nameConstraints`
  client-side, so the in-guest cert constraint is a courtesy. The real
  egress boundary remains the host-side allow-list check in
  `prepare_request` (claim 12); the name constraint only bounds blast
  radius if a per-VM intermediate ever leaked.

The remainder of this document is the original (plan-34-era) rationale
for *why* a per-VM name-constrained CA beats a blanket host CA — still
the controlling argument; only the interceptor implementation changed.

## Context

Plan 34 / Proposal D ships an L7 HTTPS proxy on the host that
intercepts a guest's TLS connections to enforce SNI/Host allowlisting
beyond what L3 iptables can see. The mechanic is straightforward —
mitmdump terminates the guest's TLS connection, validates the SNI
against the allowlist, opens an upstream connection, and re-encrypts
on the way back. Standard MITM.

For this to work, the guest's TLS clients must trust mitmdump's
certificates. The conventional wisdom is to run a single host-level
CA, install its cert in every guest's trust store, and let mitmdump
sign on-the-fly leaf certs from that CA root. Mitmproxy's defaults
do exactly this.

That conventional approach is wrong for mvm.

mvm's whole value proposition is per-VM isolation. If
`claude-code-vm` (a microVM with the LLM agent inside it) trusts a CA
that can sign for *any* TLS endpoint, then a malicious agent that
exfiltrates the trust store can MITM `google.com`, `pypi.org`, the
operator's bank, anything. The CA is not a guest secret — it lives at
`/etc/ssl/certs/mvm-egress-ca.crt` mode `0444` so the guest's TLS
libraries can read it. There is no useful place to hide it from the
agent the operator is trying to constrain.

ADR-002 §"out of scope: malicious host" assumes the host is trusted
and the guests aren't. A shared CA inverts that — the most powerful
trust anchor lives in the *guest*. That violates the threat model.

## Threat model (additive over ADR-002 + ADR-004)

The adversary is **a malicious guest workload** (per ADR-002 §1) that
has read access to its own filesystem (always true — `cat
/etc/ssl/certs/mvm-egress-ca.crt` is one syscall). With a shared CA:

1. Guest reads CA cert + harvests CA private key… no, the private
   key never enters the guest. Good. Only the cert + public key.
2. Guest exfiltrates the cert via an allowlisted destination
   (e.g. base64-encoded in a benign-looking POST to
   `api.anthropic.com`). The exfiltrated cert is *itself* the
   problem — it allows the receiver to MITM any traffic that
   trusts it.
3. *Other* contexts where the operator deploys the same host —
   another microVM running a different agent, the operator's own
   browser if the cert was carelessly imported into the system
   trust store — are now MITM-able by anyone holding the
   exfiltrated cert.

Step 3 is the critical step. mitmdump's CA cert is by design a
universal MITM credential; once it leaks, every TLS endpoint anyone
wires into a trust chain that includes it is compromised.

A Name-Constrained CA short-circuits step 3: the cert *itself*
declares "I am only valid for these names." A leaked cert constrained
to `*.anthropic.com` cannot MITM `pypi.org` no matter who holds it,
because the receiver's TLS library will reject any leaf signed by a
constrained CA for an out-of-bounds name.

## Decisions

### 1. One host CA, but Name-Constrained leaves

```
~/.mvm/egress/
├── ca.crt          # Host CA cert  (0644, root-of-trust on the host)
├── ca.key          # Host CA private key  (0400, only mvmctl reads)
└── leaves/
    ├── claude-code-vm-<run-id>/
    │   ├── leaf.crt   # 0444, fed to mitmdump
    │   └── leaf.key   # 0400, fed to mitmdump
    └── …
```

Per-VM leaf cert is itself a CA cert (basicConstraints CA:TRUE) with
`pathLenConstraint:0` and `nameConstraints permitted` set to the
VM's allowlist. mitmdump then signs *its* on-the-fly intercept certs
from the leaf — the chain is host-CA → per-VM-CA → intercept-leaf.
The guest only sees the per-VM-CA in its trust store; even a
fully-compromised guest cannot use it to MITM domains outside its
allowlist.

### 2. The host CA private key never leaves the host user's process

`ca.key` is `0400` owned by the operator. `mvmctl egress init-ca`
generates it. `mvmctl egress sign-leaf <vm-name> <allowlist>` reads
it briefly, signs the leaf, exits. mitmdump receives only the leaf
cert+key — never the host CA. A compromised mitmdump or a
compromised guest cannot derive the host CA from what it has access
to.

### 3. Per-VM leaves are short-lived

Leaf TTL = `MAX(session_max_lifetime, 1 hour)`. Leaves rotate on
every VM boot — they're regenerated at `boot_session_vm` time.
Operators don't need to manage leaf rotation; it's automatic.

The *host CA* is long-lived (5 years, manual rotation via `mvmctl
egress rotate-ca`). Rotating the host CA invalidates all template
caches that embedded leaves signed by the old root.

### 4. Guests trust only the leaf, not the host CA

The trust store distribution rule:
- Guest's `/etc/ssl/certs/mvm-egress-ca.crt` (mode 0444) is the
  *per-VM leaf* cert, NOT the host CA cert.
- The host CA cert never touches a guest filesystem.

This is the load-bearing inversion. Conventional mitmproxy installs
the *root* in the trust store; we install the *intermediate* (which
is itself a CA, but constrained to the VM's allowlist).

### 5. Document the strict-validation gap

Some TLS clients honour X.509 nameConstraints; some don't. Concrete
list compiled at implementation time:
- ✅ Go `crypto/x509` (since Go 1.10).
- ✅ Rust `rustls` (since 0.21).
- ✅ OpenSSL 1.1+ in default mode.
- ✅ Java JSSE.
- ❌ Python `ssl` (relies on OS trust store; honours nameConstraints
  only if the OS does — varies).
- ❌ Node.js's bundled OpenSSL (older versions skip
  nameConstraints).

For clients that don't validate constraints, the per-VM leaf is no
better than a shared CA — they accept any leaf the per-VM-CA signs.
The fallback is application-level: agents pin their endpoints
explicitly (e.g. `requests` with `verify=/path/to/api.anthropic.com.crt`).
Document this limitation prominently in the llm-agent README; flag
known-affected clients in `mvmctl doctor`.

### 6. Leaf signing happens at boot, not at every connection

The conventional mitmproxy flow signs a leaf per CONNECT request.
That's wrong here — every signature requires the host CA key, and
every signature is an opportunity for the key to leak (logs,
profiling output, etc.). Instead: one per-VM leaf at boot, mitmdump
loads it, mitmdump signs intercept certs from the leaf as
connections arrive. Host CA key access count = 1 per VM-boot.

### 7. The host-CA-rotation playbook is documented

Rotation is explicit, not implicit. `mvmctl egress rotate-ca` does:
1. Generate new host CA at `~/.mvm/egress/ca.crt.new`.
2. Re-sign every running VM's per-VM leaf from the new CA.
3. Push the new per-VM leaf into each running VM via the existing
   secrets path; trigger guest agent to reload `/etc/ssl/certs/`.
4. Atomically rename `ca.crt.new` → `ca.crt`, old to `ca.crt.<ts>.bak`.
5. Audit-log `LocalAuditKind::EgressCaRotated` with old + new
   fingerprints + the list of VMs re-signed.

If step 3 fails for any VM, the rollback is to leave the old CA in
place — the new CA isn't atomic-renamed yet so guests still trust
the old leaf.

## Alternatives considered

### A. Shared CA root in every guest's trust store (rejected)

The default mitmproxy approach. Documented above as the wrong move
for mvm's threat model — a shared CA in a guest is a universal MITM
credential.

**Why rejected:** violates ADR-002's threat model (guest-side
secrets must not have host-wide blast radius).

### B. Per-VM self-signed CA (rejected)

Generate a fresh CA per VM with no upstream trust anchor. mitmdump
loads it directly.

**Why rejected:** bootstrapping. Operators would have to install a
new CA into their host trust store every VM-boot if they ever wanted
to inspect guest traffic from outside the VM (debugging via
`mitmproxy --view` etc.). Also: every VM boot becomes a trust-store
mutation event, which is a CI/audit nightmare.

The Name-Constrained intermediate gets the same security posture
(per-VM blast radius) without the bootstrapping pain — operators
trust the host CA *once*, and every per-VM leaf chains to it.

### C. ACME-style internal CA service (rejected for v1)

Run a host-side ACME server that issues short-lived certs to mitmdump
on demand. Closer to "real" PKI hygiene.

**Why rejected for v1:** complexity. ACME is fine for fleet operators
running mvmd; for single-host mvmctl users it's overkill. Plan 33
explicitly punts hosted-fleet concerns to mvmd — this ADR follows
suit. ACME may be the right answer when mvmd ships its own CA service.

### D. Just don't intercept TLS; rely on L3 only (rejected)

Don't ship L7 at all; let DNS rotation slip through.

**Why rejected:** ADR-004 §"L7" already documents why L3 alone is
insufficient (DNS rotation, SNI-hopping, Host-header abuse). The
question this ADR answers is "given that we *are* shipping L7, how
do we do the CA right." Not "should we ship L7."

## Consequences

### Positive

- A compromised `claude-code-vm` cannot MITM `google.com`, `pypi.org`,
  or any other domain not in its allowlist, even after exfiltrating
  its full trust store.
- Per-VM leaf rotation is automatic (every boot). Operator burden is
  one `mvmctl egress init-ca` and one `mvmctl egress rotate-ca` every
  90 days.
- The host CA private key is touched by exactly one process
  (`mvmctl`), once per VM-boot. Easy to audit.
- mvmd (plan 33) inherits the same posture if/when it adopts L7 —
  the per-tenant variant is "per-tenant Name-Constrained intermediate
  signed by the mvmd CA." The shape is identical; only the constraint
  set differs.

### Negative / accepted costs

- nameConstraints validation is not universal. Python `ssl` and
  older Node.js skip it. Document the gap; provide the workaround
  (application-level cert pinning); detect at-risk clients via
  `mvmctl doctor`.
- One extra cert in the chain (host-CA → per-VM-CA → leaf) adds
  ~1KB to TLS handshakes. Negligible.
- `mvmctl egress sign-leaf` adds ~50 ms to every VM-boot for the
  signature operation. Acceptable; well below the existing cold-boot
  overhead.

### Explicit non-goals

- **HSM-backed host CA.** The operator's laptop isn't required to
  have a TPM or HSM; the host CA key lives on disk under `0400`
  perms. Operators with stricter requirements can put `~/.mvm/egress/`
  on an encrypted volume.
- **Cross-host CA federation.** One mvmctl host = one CA. Operators
  running multiple hosts manage them independently.
- **OCSP / CRL revocation.** Per-VM leaves are short-lived (hours);
  expiry is the revocation mechanism. No OCSP infrastructure.
- **Pinning the host CA in browsers / system trust stores.** The
  host CA is for `mvmctl`'s use only. Operators who want to inspect
  guest traffic from a host browser explicitly add the host CA to
  their browser's trust store at their own discretion (and accept
  the corresponding risk).

## Implementation pointers

These are pointers, not the spec — plan 34's tier 2 owns the actual
work:

- Cert generation: `rcgen` (already in workspace? check Cargo.lock)
  or `openssl-cli` shelling out via `mvm::shell::run_in_vm`
  on macOS. Pick `rcgen` if available — pure Rust, no shell.
- nameConstraints encoding: `rcgen::CertificateParams::name_constraints`
  takes a list of permitted DNS names. Maps cleanly from
  `NetworkPolicy::AllowList { rules }` (filter to host-only
  components, drop the port).
- Leaf signing: `mvmctl egress sign-leaf <vm-name>` reads the host CA,
  signs a leaf with the VM's allowlist as nameConstraints, writes to
  `~/.mvm/egress/leaves/<vm-name>-<run-id>/`. Idempotent: existing
  leaf for the same `<run-id>` is reused (boot replay).
- mitmdump loads the leaf via `--set ca_file=…/leaf.crt --set
  cert_file=…/leaf.crt`.

## Reversal cost

If nameConstraints proves unworkable in practice (too many guest
clients ignore it; the operator burden of detecting at-risk clients
exceeds the security benefit), the reversal is:
- Remove `nameConstraints` from the per-VM leaf signing routine.
- Document the regression in ADR-006 status header.
- Operators get a "shared CA constrained by allowlist + iptables"
  posture — strictly worse, but matches conventional mitmproxy.

The host CA + per-VM-leaf split stays valuable even without
nameConstraints (per-VM rotation, operator's host-trusted CA root,
short-lived leaves), so the reversal cost is bounded.

## References

- ADR-002: `specs/adrs/002-microvm-security-posture.md`
- ADR-004: `specs/adrs/004-hypervisor-egress-policy.md`
- Plan 34: `specs/plans/34-egress-l7-proxy.md`
- RFC 5280 §4.2.1.10 — Name Constraints
- mitmproxy CA docs: <https://docs.mitmproxy.org/stable/concepts-certificates/>
- Go's nameConstraints implementation:
  <https://github.com/golang/go/issues/15196>
- rustls's nameConstraints support:
  <https://github.com/rustls/rustls/pull/1208>


## Consolidated from ADR-055 — libkrun networking via passt + virtio-net

**Status:** accepted 2026-05-19, implements Plan 87. Default flipped from TSI → Passt by Plan 87 W5 / PR3. **Amended 2026-05-19 by Plan 88** to add gvproxy as the macOS backend (passt is Linux-only — see §"Cross-platform backends" below). **Amended 2026-05-26 by [Plan 102 W6.A](../plans/102-gateway-audit-substrate-impl.md) / [ADR-041](041-signed-audited-execution-plans.md):** TSI removed entirely — it bypassed virtio-net (no host fd to splice), which violates the claim-10 no-bypass invariant. `MVM_NETWORKING=tsi` is no longer accepted; only `passt` and `gvproxy` resolve. The historical TSI context below is retained for archaeology.

## Context

Since Plan 72 W5 (libkrun cutover) the libkrun-backed VMs mvm boots
have relied on libkrun's TSI (Transparent Socket Impersonation)
networking mode. TSI hijacks the guest's `AF_INET` socket calls at
the syscall layer and forwards them to a host-side proxy, so the
guest kernel doesn't need a network stack and there's no virtio-net
device or DHCP dance. ADR-046 §"Two artifact layers" treats this as
an internal libkrun detail.

Plan 86's end-to-end smoke proved TSI doesn't actually support the
HTTP behavior nix relies on:

| Behavior                            | TSI result                                  |
| ----------------------------------- | ------------------------------------------- |
| Single HTTP GET (e.g. flake tarball)| works                                       |
| nix's internet-availability probe   | fails → `warning: you don't have Internet…` |
| HTTPS with 302 redirect             | `HTTP error 302 (curl SSL connect error)`   |
| HTTP/2 multiplexed connection       | `Server returned nothing (curl 52)`         |
| Substituter chatter to cache.nixos.org | never even attempted                     |

The result is that `nix build` falls back to source builds for 2800+
derivations, most of which then fail to fetch their tarballs. Stage 0
cannot complete. The same TSI mode is used by the steady-state
builder VM (downstream of Stage 0) and the runtime microVMs, so the
failure pattern is universal across every libkrun-backed VM.

This is not an mvm bug. TSI is an experimental libkrun mode designed
for "this guest only ever opens one socket and reads a response";
modern HTTP — connection reuse, HTTP/2 multiplexing, HTTPS handshake
sequencing, redirect chains — is outside its design envelope. Plan 86
W3 v3 implemented `extract_bundled_kernel()` to source the kernel
patches from libkrunfw's own bundled kernel (the patches are
validated against libkrunfw's specific kernel revision), which fixes
a kernel-oops class but not the TSI proxy behavior.

## Decision

Migrate every libkrun-backed VM from TSI to **passt + virtio-net**.

Passt is a userspace network gateway (Red Hat project, single-binary,
no kernel patches or `CAP_NET_ADMIN` required) that translates
between virtio-net frames in the guest and `AF_INET` sockets on the
host. libkrun has first-class passt support via `krun_set_passt_fd()`
(libkrun 1.17+).

The guest sees a normal `eth0`, gets a DHCP lease from passt's
built-in DHCP server, resolves DNS through its own resolver, and
reaches the host's network the same way any normal Linux VM would.
HTTP/HTTPS patterns that work on the host work in the guest.

Implementation lives in Plan 87:

- New `mvm-libkrun::sys::set_passt_fd()` FFI wrapper.
- New `mvm-libkrun::passt::PasstSupervisor` host-side child that
  socketpair's with libkrun, spawns passt, owns its lifecycle.
- `KrunContext::networking: NetworkingMode { Tsi, Passt {..} }`.
- libkrun-backed VMs (builder-VM + dev-VM + runtime microVMs)
  default to `Passt`. (Plan 102 W6.A: `Tsi` removed entirely —
  the env-var escape is gone. No-bypass invariant, ADR-058.)
- `mvmctl doctor` probes for `passt` and emits an install hint when
  missing.

## Alternatives considered

- **Stay on TSI, work around the edge cases.** Rejected: the
  workarounds (force-substituters, retry-on-redirect, alternative
  HTTP clients) would have to live in every workstream that touches
  the guest's network. Replacing the substrate once eliminates the
  workaround surface area.
- **Use Apple Virtualization.framework's vmnet directly.** Rejected:
  vmnet is closed-source, macOS-only, and tied to the host's network
  stack. mvm runs the same code on Linux KVM via Firecracker where
  vmnet doesn't exist. Passt is cross-platform and decoupled from
  the hypervisor.
- **Implement a TSI-aware HTTP shim in the guest.** Rejected:
  building a working subset of HTTP/2 + redirect chains + HTTPS
  handshake on top of TSI's existing semantics is a multi-quarter
  effort with no upside vs. just using a real network stack.
- **Pin libkrunfw to a version where TSI is more complete.** Rejected
  as a non-fix — TSI's design constraints don't disappear with
  libkrunfw bumps. The libkrun upstream itself has been moving
  toward passt as the recommended default.
- **Switch to gvproxy** (the rootless-podman gateway). Considered.
  gvproxy and passt occupy the same niche; passt is simpler, faster,
  and the libkrun integration is documented. Bumping or migrating to
  gvproxy later is a one-line change in the supervisor.

## Consequences

- **All libkrun VMs gain a virtio-net interface.** mvm-builder-init
  already handles `udhcpc` (currently a no-op because there's no
  interface); the change is transparent to the in-guest init.
- **New host-side dependency: `passt`.** `brew install passt` on
  macOS, distro package on Linux. Doctor probe + install hint added.
- **TSI patches in the kernel become dead code from mvm's
  perspective.** libkrunfw's bundled kernel still carries them, which
  is fine — we just don't enable that path from the host side. The
  in-repo TSI patch port under `nix/images/builder-vm/kernel/`
  becomes legacy; Plan 87 W6 moves or removes it.
- **`mvm-egress-proxy` (Plan 73 Followup B.2.y / ADR-047)** remains
  load-bearing for production microVMs running untrusted workloads.
  This ADR is about the network substrate, not the policy layer; the
  egress allowlist runs on top of passt-virtio-net the same way it
  ran on top of TSI.
- **The contributor onboarding sequence gains one step** (install
  passt). Documented in the Plan 87 W5 doctor probe + CLAUDE.md
  update.

## Security model

The host-side passt process runs as the contributor's user (not
root). It cannot bind privileged ports or modify the host's
firewall — its entire job is to relay packets between an `AF_UNIX`
socket and the host's TCP/UDP stack via standard userspace sockets.
The host kernel is the final policy layer for outbound traffic.

In production microVM contexts (running untrusted workloads), the
guest's egress allowlist is enforced by `mvm-egress-proxy` inside
the VM (Plan 73 Followup B.2.x). passt is the transport; the policy
is independent.

CLAUDE.md security claim 1 ("no host-fs access from a guest beyond
explicit shares") is unaffected: passt doesn't see the guest's
filesystem, only its virtio-net frames. Claim 9 (deps-volume
hash-lock + audit) is unaffected for the same reason.

### New untrusted-input surfaces introduced by Plan 87 (Plan 88 W6 amendment)

Moving from TSI to virtio-net opens three new host-side parsing
boundaries that didn't exist under TSI's syscall-hijack model. All
three run as the contributor's user (not root), so a successful
exploit is a code-execution-as-user boundary — not a host-kernel
boundary. None has filesystem visibility into the guest. But each is
a new fuzzing target:

1. **libkrun's virtio-net device emulator.** Parses virtio
   descriptors the guest writes to the virtqueue. Same class of risk
   QEMU / Firecracker / Cloud Hypervisor virtio implementations have
   carried for years.
2. **passt's frame parser** (Linux). C code dealing with raw
   Ethernet/IP/TCP/UDP/ICMP frames the guest sends. Well-audited by
   Red Hat security; not invulnerable.
3. **gvproxy's frame parser** (macOS / cross-platform). Go code, so
   memory-safety bugs are rare, but logic bugs in its DHCP server,
   TCP state machine, and ICMP responder remain possible.

Fuzz coverage by surface — only one of the three is genuine
first-party Rust we can put under cargo-fuzz. The supervisor's JSON
parser is the fourth boundary that the network-backend dispatch
opened (the supervisor's pipe semantics didn't change vs TSI, but
its config now carries `NetworkingMode::{Passt, Gvproxy}` variants
the parser has to handle).

| Surface | Where it lives | mvm's local fuzz coverage |
| ------- | -------------- | ------------------------- |
| `SupervisorConfig` JSON (stdin → `mvm-libkrun-supervisor`) | First-party Rust | **In tree.** Plan 88 W6 — `crates/mvm-libkrun/fuzz/fuzz_supervisor_config.rs`, wired into `security.yml::fuzz`. |
| libkrun virtio-net device emulator | C, inside `libkrun.dylib` | **Upstream.** Fuzzing requires a running guest per iteration; mvm trusts the libkrun project's own fuzz harness. |
| passt frame parser | C, external process | **Upstream.** Red-Hat-maintained; mvm runs passt as the contributor's user. |
| gvproxy frame parser | Go, external process | **Upstream.** Memory-safety bugs are rare in Go; logic bugs in the DHCP / TCP / ICMP responder are tracked by the gvproxy project. |

CLAUDE.md security claim 5 ("vsock framing is fuzzed") is extended
to "vsock framing + supervisor-config JSON are fuzzed" — explicit
about the in-tree / upstream split so a future reader doesn't take
it as a stronger claim than the harness actually backs.

A separate follow-up plan covers the aspirational external-process
gateway-frame fuzz harness (persistent gvproxy/passt subprocess
driven by a unix-socket fuzzer, plus a mocked libkrun virtqueue
harness). That work is out of Plan 88's scope — multi-week effort
with substantial dependency on upstream libkrun maintainers exposing
sanitizer-friendly entry points.

### `mvm-egress-proxy` becomes load-bearing

ADR-055 v1 already noted this, but it's worth flagging again as part
of the Plan 88 amendment:

- Under TSI, AF_INET socket calls were hijacked at the syscall
  layer. A workload couldn't bypass the egress allowlist because
  there was no Linux network stack in the guest to bypass through.
  `mvm-egress-proxy` (Plan 73 Followup B.2.x / ADR-047) was
  defense-in-depth.
- Under virtio-net (passt or gvproxy), the guest's real Linux
  network stack is the path. A workload that ignores `HTTPS_PROXY`
  / `HTTP_PROXY` env vars can open raw sockets directly to any
  destination passt/gvproxy will forward to. The in-VM iptables
  uid-owner rules `mvm-builder-init::install_egress_lockdown`
  installs are the only thing preventing bypass.

The policy layer (`mvm-egress-proxy` + iptables uid-owner) is
unchanged; what changed is its load-bearing status. ADR-047's
threat model still applies; production microVMs running untrusted
workloads still need the egress proxy active.

## Cross-platform backends (Plan 88 amendment, 2026-05-19)

ADR-055 v1 (above) assumed `passt` was cross-platform. End-to-end
smoke after Plan 87 PR3 merged surfaced the gap:

```
$ brew install passt
passt: Linux is required for this software.
```

`passt` uses Linux-specific syscalls (`vmsplice`, namespace
primitives, `splice`) that have no macOS equivalents — the Homebrew
formula refuses to build it. Since macOS is mvm's Tier 1
contributor host, this fail-closes every fresh `dev up` on the
platform the work was meant to fix.

libkrun's C API anticipates the asymmetry: `libkrun.h` ships **two**
virtio-net backend functions in parallel:

| libkrun call                  | Userspace backend(s)              | Socket type | Cross-platform? |
| ----------------------------- | --------------------------------- | ----------- | --------------- |
| `krun_add_net_unixstream`     | `passt` (Linux), `socket_vmnet` (macOS) | unixstream | No, per-backend |
| `krun_add_net_unixgram`       | `gvproxy`, `vmnet-helper`         | unixgram   | gvproxy: yes; vmnet-helper: macOS |

The slp/krun Homebrew tap (`brew install slp/krun/{libkrun, libkrunfw,
gvproxy}`) is the canonical macOS install path. gvproxy is the
libkrun maintainers' documented macOS backend — same project that
ships libkrun + libkrunfw.

**Resolution (Plan 88):** mvm dispatches the network backend per OS:

- Linux → `passt` via `krun_add_net_unixstream`
- macOS → `gvproxy` via `krun_add_net_unixgram` (path-based listener
  instead of fd-passed)

`MVM_NETWORKING={passt, gvproxy}` remains the explicit override (Plan 102 W6.A removed `tsi`).
Unset → the per-OS default. `passt` on macOS still fail-closes (the
binary doesn't exist), but the user gets a clear error rather than a
silent regression — `mvmctl doctor` flags the missing dep with the
right install hint per platform.

**Vz backend (Plan 98).** The Apple Virtualization.framework builder
also wires gvproxy on macOS — `mvm_vz::NetworkConfig::Gvproxy { socket_path, mac }`
piped through `mvm-vz-supervisor`'s `Network.swift` attaches a
`VZFileHandleNetworkDeviceAttachment` to the same gvproxy listener
libkrun uses via `krun_add_net_unixgram`. The host-side gateway
(gvproxy) is one process per dev session; the Vz and libkrun paths
just attach to its socket differently. Full Plan 98 selection-policy
context lives in **ADR-046 §"Vz as a second builder backend"**.

Both backends share the same threat model: a userspace process
running as the contributor's user, no privileged sockets, no host-fs
visibility into the guest. The libkrun-end of the virtio-net frame
transport is identical at the guest kernel layer; only the host-side
plumbing differs.

## References

- Plan 87 — `specs/plans/87-passt-virtio-net.md`
- Plan 88 — `specs/plans/88-gvproxy-macos-backend.md` (the
  cross-platform amendment above)
- Plan 86 — `specs/plans/86-ur-seed-stage0-bootstrap.md`
  (end-to-end smoke that exposed TSI's edge cases)
- Plan 72 W5.D — the prior round of libkrun debugging notes
- libkrun upstream: https://github.com/containers/libkrun
- passt upstream: https://passt.top/
- gvproxy upstream: https://github.com/containers/gvisor-tap-vsock
- libkrun's `krun_add_net_unixstream` / `krun_add_net_unixgram`
  APIs documented in `libkrun.h`


## Consolidated from ADR-064 — NetworkProvider trait — composable network audit substrate

**Status**: Proposed
**Date**: 2026-05-29
**Cross-refs**: ADR-002 (security posture, claim 1 / claim 5 / claim 10), ADR-041 (signed/audited ExecutionPlan, claim 8), ADR-055 (passt/gvproxy cross-platform backends), ADR-058 (claim 10 leg 2 / "bytes leaving the trust boundary"), ADR-059 (host services broker — vsock-only scope boundary), Plan 102 (gateway audit substrate impl), Plan 112 (W6.A Phase 3c producer activation, merged 2026-05-29).

## Context

Plan 102 W6.A landed the **substrate** for the gateway audit log: per-VM bridge over the userspace network gateway (libkrun in-process via `BridgeFds`; Vz via the Swift `makeBridgedGvproxyDevice` device), parser-on-`catch_unwind` fault containment, bounded flow table, chain-signed `FlowOpened` / `FlowClosed` entries via `FileAuditSigner`. Plan 112 (merged) activated the substrate on libkrun by widening `VmStartConfig` and lifting substrate resolution into the shared `crates/mvm-backend/src/audit_substrate.rs` module. Today's state:

- **libkrun**: substrate active end-to-end. Bridge thread parses packets, emits `FlowOpened` / `FlowClosed` chain entries directly to `FileAuditSigner`.
- **Vz**: Swift bridge writes NDJSON `FlowEventWire` entries to `events_ingest_socket_path`; the Rust-side drainer that binds the socket and emits to the chain does not exist yet — substrate is half-built. Plan 112's "Vz carve-out" deferred this.
- **Firecracker**: no substrate. Claim 10 leg 2 (per-flow chain entries) does not fire on Linux KVM. Adding it requires a new bridge wrapping `passt` (the Linux user-space gateway).

Three concerns converge that the current shape can't cleanly absorb:

1. **Programmable networking.** The team wants tenant-policy-controlled observers (audit emit, hostname filter, rate limiter, egress secret detection) layered on top of the bridge. Today's substrate has one consumer: a single `FileAuditSigner` direct call from the bridge thread.
2. **Egress secret detection** (saved memory `project_egress_secret_detection_is_core`). Needs payload-byte visibility, plugs in as a wrapping layer above the leaf bridge. Today no wrap surface exists.
3. **Backend uniformity.** libkrun, Vz, and Firecracker each need to emit the same chain-entry shape from very different process models (in-process splice for libkrun; cross-process NDJSON drain for Vz; jailed sidecar process for Firecracker). Today the libkrun bridge is one-of-a-kind code.

This ADR resolves all three by introducing a **NetworkProvider trait** as the seam — already foreshadowed by Plan 112's `crates/mvm-backend/src/audit_substrate.rs` "trait extraction seam" subsection.

## Decision

mvm adopts a `NetworkProvider` trait as the canonical substrate boundary for network audit observation. Each backend implements a **leaf** provider; tenant policies declare a chain of **observers** that run on each leaf's events. Observers compose by **fan-out**, not chain decoration. Audit emission is structural (always-on) and the trait's first three impls (libkrun / Vz drainer / Firecracker bridge) ship together as a single coordinated plan.

The decision settles six load-bearing design questions answered during the brainstorm. They are recorded here so the next contributor — or AI session — can consult the rationale without re-deriving it.

### 1. Composability: composable providers (B from the brainstorm)

Leaf providers (libkrun, Vz, Firecracker) plus host-allowlisted observers (`AuditEmit`, `flow-count-metrics`, future `hostname-filter`, future `egress-redactor`). The trait is shaped for **observer-side composition**, not leaf-wrapping decoration. Egress secret detection drops in as an observer (and, eventually, as an inline payload transformer attached to the leaf) with no further trait changes.

### 2. Event granularity: hybrid (C from the brainstorm)

Trait yields `FlowOpened` / `FlowClosed` as the cheap-path default. Observers that need byte-level access (egress redactor) opt into a **per-flow payload tap** via `NetworkProvider::attach_tap`. Observers that only need flow metadata (AuditEmit, rate-counters) pay zero per-byte cost.

### 3. Wrapping primitive: builder with trait-object at the boundary

`Pipeline::new()` returns a builder; `.observe()` appends observers (capability-gated, depth-capped at 8); `.build_broadcast(signer)` materializes a `Broadcast` the leaf consumes; the leaf is the user-facing `Box<dyn NetworkProvider>`. Inside the leaf, observer fan-out is **fully monomorphized** — one v-table call per packet at the trait-object boundary, then all observer dispatch inlines. Best-of-both-worlds compared to per-layer trait objects (4 v-table calls per packet) and pure compile-time generic stacking (impractical per-tenant variation).

### 4. Process model: per-VM supervisor (A from the brainstorm)

- libkrun: trait runs in `mvm-libkrun-supervisor` (existing).
- Vz: trait runs in a **new** `mvm-vz-drainer` per-VM process that binds `events_ingest_socket_path`.
- Firecracker: trait runs in a **new** `mvm-firecracker-bridge` per-VM sidecar process spawned alongside the VM.

Each per-VM process signs its own chain entries into `~/.mvm/audit/<tenant>.jsonl` under cross-process `flock`. Centralised audit daemon (option B from the brainstorm) explicitly rejected: it would re-architect the post-PR-#459 chain-emit model and introduce a single-point-of-failure for chain signing.

### 5. Firecracker sidecar confinement: A2 — sibling jailed namespace

`mvm-firecracker-bridge` runs as a **sibling** to the Firecracker jailer (not inside it; jailer is single-process). The bridge applies its own seccomp + Landlock confinement via a new `mvm-jailer-lite` helper crate that wraps:

- **`seccompiler`** — Firecracker-team-maintained seccomp-BPF library. Pure Rust, battle-tested inside Firecracker itself.
- **`landlock`** — official Rust LSM binding. User-level filesystem confinement, no root, no setuid helper.

The bridge inherits the *same security tier* as `mvm-libkrun-supervisor` on macOS (user-level process, fs-scoped to `~/.mvm/`). On Linux this is `unshare(CLONE_NEWNS | CLONE_NEWPID)` + Landlock filesystem ruleset + seccomp filter. Higher-level crates (`hakoniwa`, `sandlock-core`, `sandbox-rs`) were rejected as bundling cgroups + namespace isolation we don't need; `bubblewrap`-based crates were rejected for the external-binary subprocess shape.

### 6. Bridge crash policy: hard-fail by default

Bridge process crash → supervisor SIGTERMs the VM → chain entry `VmStopped { reason: "audit_substrate_crashed", bridge_exit: N }`. The audit chain is a security feature; a silent retry-and-resume would hide a security-claim downgrade. Loud failure is the production-ready posture.

`SupervisorConfig.bridge_restart_policy: BridgeRestartPolicy` is reserved in the wire format with one accepted variant in this plan (`hard_fail`). Future variants (`restart_once_with_gap`, `restart_with_budget`) ship in a separate plan with their own ADR; when used, they emit a `GatewayAuditGap { from, to, dropped_estimate, restart_count }` chain entry on resume so the gap is structural and operator-visible.

### 7. Observer trust boundary: host-allowlisted, never tenant-shipped code

Observers are resolved through `~/.mvm/observers/allowlist.toml` (per-user) or `/etc/mvm/observers/allowlist.toml` (system-wide). Tenant policies reference *policy names*, not observer names; the host operator's policy file declares which observers the policy maps to. No `.so` / `.wasm` / dynamic loading of tenant-supplied code in this plan. This matches claim 10's existing pattern: tenant says "engineering-default"; host maps that to gateway rules AND observer chain.

### 8. Vz payload tap: not supported in this plan; capability-gated refusal

`mvm-vz-drainer` returns `Err(PayloadTapUnsupported)` from `attach_tap`. Observers that require `payload_tap` (future egress-redactor) refuse construction on the Vz backend at `Pipeline::observe` time with a clear "switch backend or change policy" message.

**Vz payload-tap is delivered by the Rust-`objc2` VZ supervisor (Plan 152), not a Swift extension** (decision 2026-06-04, superseding the earlier "Swift-side payload tee" sketch). Once the supervisor is Rust-native it owns the VZ device *and* the gateway bridge in one process, so the packet shuffle + observer pipeline (Plan 141's backend-agnostic core) run **in-process** against the socketpair Rust attaches to `VZFileHandleNetworkDeviceAttachment` — no Swift tee, no SCM_RIGHTS fd-handoff, no NDJSON ingest hop. **Plan 141 is rescoped to the libkrun + Firecracker `payload_tap` core**; Vz keeps this capability-gated refusal until Plan 152 lands. Rationale: a Swift-side tee / fd-handoff would be throwaway under the already-decided drop-Swift direction, and it would put cross-process fd-passing on the egress path only to delete it — see `project_vz_strong_support_direction`.

### 9. Tenant value resolution

The `--tenant` value resolves in fixed precedence order:

1. Built-in default `"local"`
2. `~/.mvm/config.toml` `[tenant] name = "..."`
3. `MVM_TENANT` env var
4. `--tenant` CLI flag

Walked highest precedence first. No identity backend, no auth state — tenant is still just a string label for the audit chain file. Identity / `mvmctl auth` is a separate ADR + plan.

## Trait surface (mvm-core)

```rust
// crates/mvm-core/src/network/mod.rs
// No runtime deps — mvm-core invariant preserved.

pub const MAX_OBSERVERS: usize = 8;
pub const DEFAULT_MAX_CONCURRENT_FLOWS: u32 = 4_096;    // Plan 102 W6.B
pub const DEFAULT_FLOW_RATE_CAP_PER_SEC: u32 = 1_000;   // Plan 102 W6.B

#[derive(Clone, Copy, Debug)]
pub struct ProviderCapabilities {
    pub flow_events: bool,         // always true for trait impls
    pub payload_tap: bool,         // libkrun + Firecracker: true; Vz: false in this plan
    pub max_concurrent_flows: u32, // leaf-defined; default 4096
}

pub trait NetworkProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn capabilities(&self) -> ProviderCapabilities;

    /// Begin IO. Leaf spawns its bridge thread / drainer / sidecar.
    fn start(&self) -> Result<(), ProviderError>;

    /// Tear down IO. Idempotent.
    fn stop(&self) -> Result<(), ProviderError>;

    /// Opt-in payload visibility. Returns `Err(PayloadTapUnsupported)`
    /// on leaves whose capability reports `payload_tap: false`.
    fn attach_tap(&self, flow_id: FlowId, sink: Arc<dyn TapSink>)
        -> Result<TapHandle, ProviderError>;

    fn detach_tap(&self, handle: TapHandle);
}

#[derive(Debug, Clone)]
pub enum FlowEvent {
    FlowOpened { id: FlowId, tuple: FiveTuple, opened_at: Instant,
                 vm_name: String, tenant: String },
    FlowClosed { id: FlowId, tx_bytes: u64, rx_bytes: u64, closed_at: Instant },
    FlowFlood  { ts: Instant, dropped_count: u32 },             // rate-cap aggregation
    FlowEvicted { id: FlowId, reason: EvictionReason },         // bounded-table evict
    GatewayAuditFault { flow_id: Option<FlowId>, detail: Cow<'static, str> },
}

pub trait Observer: Send + Sync {
    fn name(&self) -> &'static str;
    fn required_capabilities(&self) -> RequiredCapabilities;
    fn on_flow_event(&self, event: &FlowEvent);
}

pub trait TapSink: Send + Sync {
    /// `bytes` carries no Display/Debug. Observers that legitimately
    /// need plaintext (egress redactor) explicitly unwrap via
    /// `Opaque::unwrap_for_purpose(TapReason::Redact)`. The
    /// `xtask check-no-display-on-secret-types` lint covers this.
    fn on_packet(&self, dir: Direction, bytes: Opaque<&[u8]>);
}

pub struct Opaque<T>(T);  // no Display, no Debug, no public field access
```

## Pipeline + Broadcast (mvm-backend)

```rust
// crates/mvm-backend/src/network/pipeline.rs

pub struct Pipeline { observers: Vec<Arc<dyn Observer>> }

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("too many observers (max {MAX_OBSERVERS}); requested {requested}")]
    TooManyObservers { requested: usize },
    #[error("observer {observer} requires capability {missing:?}; leaf {leaf} does not provide it")]
    CapabilityMismatch { observer: &'static str, leaf: &'static str, missing: Vec<&'static str> },
    #[error("observer name {0:?} is not allowlisted in ~/.mvm/observers/allowlist.toml")]
    NotAllowlisted(String),
    #[error("observer constructor failed: {source}")]
    ConstructorFailed { observer: String, #[source] source: anyhow::Error },
}

impl Pipeline {
    pub fn new() -> Self;
    pub fn observe(self, observer: Arc<dyn Observer>, leaf_caps: ProviderCapabilities)
        -> Result<Self, BuildError>;
    pub fn build_broadcast(self, signer: Arc<dyn AuditSigner>) -> Arc<Broadcast>;

    /// Production entry: resolves tenant policy refs through the host
    /// allowlist + capability check against the leaf.
    pub fn from_admitted(
        plan: &AdmittedPlan,
        leaf_caps: ProviderCapabilities,
        allowlist: &ObserverAllowlist,
        signer: Arc<dyn AuditSigner>,
    ) -> Result<Arc<Broadcast>, BuildError>;
}

pub struct Broadcast { observers: Vec<Arc<dyn Observer>> }   // AuditEmit at index 0

impl Broadcast {
    /// Called from the leaf's IO thread on each flow event. Fan-out
    /// runs each observer under `catch_unwind`; a panicking observer
    /// surfaces `GatewayAuditFault` to AuditEmit (always at index 0)
    /// and does not propagate to siblings.
    pub fn publish(&self, event: FlowEvent);
}
```

## Leaf implementations

### Libkrun leaf — refactor of existing bridge

- **Location**: `crates/mvm-libkrun-supervisor/src/network/libkrun_leaf.rs`
- **Process**: existing `mvm-libkrun-supervisor`, one per VM
- **IO model**: in-process splice over `BridgeFds` socketpair (unchanged from PR #487)
- **Capability**: `payload_tap = true`
- **What changes**: today's bridge thread emits `FlowOpened` / `FlowClosed` directly to `FileAuditSigner`. After this plan it emits to a `Broadcast`; the `AuditEmit` observer (Broadcast index 0) wraps the same `FileAuditSigner`. Chain wire-shape is byte-identical (regression test asserts this).
- **New**: per-flow payload tap fan-out via `HashMap<FlowId, Vec<Arc<dyn TapSink>>>`.

### Vz leaf — new drainer crate

- **Location**: `crates/mvm-vz-drainer/` — new leaf crate, the Vz analog of `mvm-libkrun-supervisor`
- **Process**: spawned by `mvm-backend/src/vz.rs::start()` between Swift supervisor spawn and VM boot, one per VM
- **IO model**: binds `events_ingest_socket_path` (the path Swift bridge already writes to per PR #487 commit 6); reads NDJSON `FlowEventWire`; publishes `FlowEvent` to the `Broadcast`
- **Capability**: `payload_tap = false` in this plan (Swift bridge doesn't expose payload bytes yet). Closes the Vz carve-out from Plan 112.
- **Lifecycle**: crash propagates to the Vz VM via the same `AttachedGvproxyGuard` pattern PR #487 commit 6 established.

### Firecracker leaf — new bridge sidecar

- **Location**: `crates/mvm-firecracker-bridge/` — new leaf crate, the Firecracker analog
- **Process**: spawned by `mvm-backend/src/backend.rs::FirecrackerBackend::start()` alongside the Firecracker jailer, one per VM; calls `mvm_jailer_lite::confine_self()` immediately after argument parsing
- **IO model**: spawns `passt` as a child; reads packets from passt's stdout; parses via `etherparse` under `catch_unwind`; publishes to `Broadcast`
- **Capability**: `payload_tap = true`
- **Confinement** (A2 sibling jail):
  - Linux namespaces: `CLONE_NEWNS | CLONE_NEWPID`
  - Landlock ruleset: read on `passt` binary + `~/.mvm/keys/host-signer.ed25519`; read-write on `~/.mvm/audit/`; no network paths (passt's sockets are inherited fds, not opened by name)
  - Seccomp profile: allowlist of `socket`, `bind`, `connect`, `accept`, `splice`, `sendmsg`, `recvmsg`, `read`, `write`, `fsync`, `clock_gettime`, `exit_group`, `futex`, `mmap`, `munmap`, `rt_sigprocmask`, `openat` (restricted by Landlock), plus the set required by `etherparse` + chain emit. Documented in `crates/mvm-firecracker-bridge/SECCOMP.md`.
- **passt provenance**: bridge hash-verifies the `passt` binary at startup against `nix/images/passt-hashes.toml` (Plan 102's image hash-verification pattern, claim 6). Mismatch → bridge refuses to start.

### `mvm-jailer-lite` helper crate (new)

- ~300 lines of glue: `seccompiler` profile builder, `landlock` ruleset builder, a single `confine_self() -> Result<(), JailerError>` entry point.
- Used by `mvm-firecracker-bridge` initially; potentially by future per-VM processes on Linux that need the same confinement (e.g., a future Linux-side counterpart to mvm-vz-drainer if Firecracker grows multi-leaf shape).

## `ObserverAllowlist` + policy file extension

### Allowlist schema (host-operator-controlled)

```toml
# ~/.mvm/observers/allowlist.toml  (mode 0600)
schema_version = 1

[[observer]]
name = "flow-count-metrics"
# No config — increments a per-tenant counter exposed via the existing
# Prometheus endpoint.
```

`AuditEmit` is **not** in the allowlist file — it's always-on, injected at `Broadcast::publish` index 0 by `Pipeline::build_broadcast`.

### Policy schema extension

```toml
# ~/.mvm/policies/engineering-default.toml
schema_version = 2  # bumped from claim-10's v1

[gateway]
default = "deny"
allow = ["github.com:443", "registry-1.docker.io:443"]

[network_observers]
chain = ["flow-count-metrics"]    # optional; absence = AuditEmit only
```

The `[network_observers]` table is optional; absence keeps every existing claim-10 policy file backwards-compatible.

## Observer roster (this plan)

| Observer | Capability | Purpose | Config |
|---|---|---|---|
| `audit-emit` | flow_events | Chain-sign every event into `~/.mvm/audit/<tenant>.jsonl`. Always-on. | None |
| `flow-count-metrics` | flow_events | Per-tenant flow counter via existing `--metrics-port` Prometheus endpoint. | None |

Stress-tests the trust-store mechanism with one real tenant-facing observer. Hostname filter, rate limiter, egress redactor each ship in their own follow-up plans with their own ADRs.

## Security posture — claim review

| Claim | Status under this ADR | Notes |
|---|---|---|
| 1 (no host-fs access from guest beyond explicit shares) | **Preserved** | Firecracker bridge is sibling-process, not in-guest. If guest-controlled packet bytes compromise the bridge (in-scope threat per Plan 102 W6.B's `catch_unwind`), Landlock + seccomp confine post-compromise damage to `~/.mvm/{audit,keys}/`. Claim is about the guest's reach; A2 doesn't expand it. |
| 2 (no guest uid-0 elevation) | Preserved | Unrelated; bridge has no guest-facing surface. |
| 3 (tampered rootfs fails to boot) | Preserved | Unrelated. |
| 4 (guest agent has no `do_exec` in prod) | Preserved | Unrelated; bridge is host-side. |
| 5 (vsock + supervisor-config JSON fuzzed) | **Extended** | Plan 102 W6.B's planned `fuzz_gateway_bridge.rs` for libkrun's parser extends to the new Firecracker bridge via `crates/mvm-firecracker-bridge/fuzz/fuzz_gateway_bridge.rs`. New CI lane `firecracker-bridge-fuzz`. |
| 6 (pre-built dev image hash-verified) | Preserved | `mvm-firecracker-bridge` binary follows the same `resolve_supervisor_path()` resolution pattern as `mvm-libkrun-supervisor`. Plus: passt binary itself is hash-pinned against `nix/images/passt-hashes.toml`. |
| 7 (cargo deps audited) | **Extended** | New deps `seccompiler` and `landlock` pinned in `deny.toml`; the `deny` and `audit` CI jobs cover them on every PR. |
| 8 (signed audited ExecutionPlan) | Preserved | Bridge receives the signed envelope on stdin; re-verifies via `mvm_plan::verify_plan` before any IO. |
| 9 (signed bundles content-addressed) | Preserved | Bundle verification stays in admission. |
| 10 (default-deny egress) | Preserved | Bridge **observes**; policy enforcement stays at the gateway (pre-bridge). The trait can't accidentally weaken default-deny. |
| 11 (sealed deps volume) | Preserved | Unrelated. |
| 12 + 13 (host services broker) | **Boundary explicit** | `NetworkProvider` is virtio-net only. Vsock stays with the host-services broker (ADR-059). The ADR-002 §boundary table gains an entry. |
| 14 (OCI image provenance) | Preserved | Upstream of bridge. |

**Net**: 11 preserved unchanged, 2 require concrete additions (claim 5 fuzz extension, claim 7 cargo-deny pins), 1 boundary statement (claim 12/13 vs network/vsock split).

## Error taxonomy (summary; full enumeration in the plan)

- Construction-time errors (`BuildError::*`, `seccompiler` install failure, `landlock` apply failure, `passt` hash mismatch, allowlist file missing/loose-perms) **never produce a chain entry** — the plan never reaches `plan.launched`. Stderr only.
- Run-time errors emit a chain entry then degrade or stop:
  - `etherparse` panic → `GatewayAuditFault { flow_id, detail }`; that flow degrades to pass-through, sibling flows + observers continue.
  - Observer panic → `GatewayAuditFault { detail: "observer X panicked" }`; sibling observers continue (fan-out isolation via `catch_unwind`).
  - Bridge process crash → supervisor SIGTERMs the VM, chain entry `VmStopped { reason: "audit_substrate_crashed", bridge_exit: N }`.
- Tenant cross-check (`cfg.tenant_id != verified.plan.tenant.0`) refused inside the bridge before any chain entry.

## Out of scope

- **Egress secret detection / payload rewriting** — its own future plan and ADR (saved memory `project_egress_secret_detection_is_core`). This ADR ensures the trait *doesn't paint it into a corner* (hybrid event granularity, box-at-boundary monomorphization, observer allowlist) but ships zero rewriter logic.
- **Vz payload tap** — separate follow-up plan extends Swift `Config.swift` with `payload_tap_socket_path` and adds Swift-side payload tee + control channel. Vz returns `PayloadTapUnsupported` until then.
- **AppleContainer substrate** — Apple's `containerization` framework's network layer is opaque to mvm. Further-future plan needed.
- **Hostname filter, rate-limiter observers** — each gets its own ADR (DNS resolution semantics, SNI handling, etc., are real design decisions). This plan ships the infrastructure that lets them plug in.
- **Bridge retry policy variants** — `BridgeRestartPolicy::HardFail` is the only accepted value in this plan. `RestartOnceWithGap` / `RestartWithBudget` ship in a separate plan with their own ADR; when used, they emit `GatewayAuditGap` chain entries.
- **Per-VM signing-key derivation** — today the bridge reads `host-signer.ed25519` directly. A compromise leaks the master key. Better long-term: parent process keeps the key; bridge sends a chain-entry hash over a pipe and parent signs. Out of scope for this plan; tracked as a deferred hardening.
- **Centralised audit daemon** — rejected (item 4 above).
- **`mvmctl auth` / identity model** — its own ADR + plan (saved memory and brainstorm acknowledged separately).
- **Host-side rate-limit enforcement** — observers can observe rate (`FlowFlood`) but cannot enforce ceilings. Enforcement is at the gateway via policy refs (existing claim-10 surface).

## Alternatives considered

### A. Pluggable-backend trait only (no observer composition)

Trait is a backend cleanup: libkrun / Vz / Firecracker / AppleContainer each implement it. No observers, no fan-out. Egress secret detection becomes a separate post-plan with its own integration shape.

Rejected: forces a re-shape when the redactor lands. Saved memory `project_egress_secret_detection_is_core` explicitly notes "don't paint adjacent network/L7 features into a corner that blocks it"; (A) does exactly that.

### B (current decision). Composable observers with fan-out

See §Decision.

### C. First-class user programmability (WASM/eBPF callback surface)

Trait carries a user-supplied policy/filter callback API. Compile-time (Rust closures) or runtime (WASM/eBPF) plug-ins.

Rejected as premature for the first ship. No concrete WASM/eBPF callers exist; designing the surface speculatively risks getting it wrong. (C) is reachable from (B) without re-shape if the need materialises.

### Wrap-chain decoration ("decorator pattern" / `tower::Service` style)

Each observer wraps the next; layers can short-circuit / transform / drop.

Rejected because for network audit the bytes have *already crossed the wire* by the time the leaf observes them. A wrap-chain implies layers can prevent action — which they can't, the packet already flew. Fan-out observation is the honest shape. Policy enforcement (deny by hostname) belongs at the gateway via existing claim 10 mechanism, not in the observer trait.

### Centralised audit daemon (`mvm-audit-chaind`)

One long-running host-wide process holds the signing key + chain state for every tenant; backend supervisors emit raw flow events over a unix-socket control channel.

Rejected: re-architects the post-PR-#459 chain-emit model, introduces a single-point-of-failure for chain signing, requires per-VM/per-tenant policy resolution to flow into the daemon at every admission. The per-VM-supervisor model already works with cross-process `flock` coordination; no problem to solve here.

### Bridge inside Firecracker jailer (Alpha)

Run `mvm-firecracker-bridge` *inside* the existing Firecracker jailer process.

Rejected: jailer is single-process. There is no "inside the jailer" for a sibling process. The achievable shape ("bridge in a similar seccomp/namespace setup") is exactly A2.

### Bridge as unconfined host process (Beta)

Run `mvm-firecracker-bridge` with full host privileges.

Rejected: weakens claim 1 for the audit substrate (compromised bridge can reach anything). Saved memory `feedback_no_backcompat_first_version` argues for shipping the right shape from the start.

### Higher-level Rust sandbox crates (`hakoniwa`, `sandlock-core`, `sandbox-rs`)

Bundles namespace + cgroup + Landlock + seccomp in one opinionated package.

Rejected: more moving parts than we need. We don't want cgroup management or full namespace isolation; just fs + syscall confinement. `seccompiler` + `landlock` directly is more native, smaller dep tree, easier to audit.

### Bubblewrap-based sandboxes (`build-wrap`, `sandbox-runtime`, `ai-sandbox`)

Wrap the `bwrap` binary as a subprocess.

Rejected: adds an external binary dep on the host, introduces a new fork/exec layer, less configurable than the direct seccompiler + landlock combo.

## Consequences

### Positive

- **Single conceptual model across libkrun / Vz / Firecracker.** Future contributors don't re-derive the substrate shape per backend.
- **Claim 10 leg 2 reaches Linux KVM.** Firecracker workloads gain the same audit-substrate posture libkrun has had since PR #487.
- **Egress secret detection has a known integration shape.** When its plan lands, the redactor plugs in as an observer that opts into the payload tap — no trait redesign needed.
- **Vz substrate carve-out from Plan 112 closes.** The drainer ships as part of this plan.
- **Observer trust boundary is explicit.** Tenant ↔ host trust split mirrors claim 10's pattern; no new boundary to reason about.
- **`mvm-jailer-lite` helper crate** becomes reusable for future per-VM Linux processes that need the same confinement.

### Negative

- **Three new crates** (`mvm-vz-drainer`, `mvm-firecracker-bridge`, `mvm-jailer-lite`). Each adds CI build cost and a maintenance surface.
- **New deps** (`seccompiler`, `landlock`). Both maintained, version-pinned, audited; but the dep surface grows.
- **Cross-platform CI matrix expands.** Linux runners need to gain Landlock-supporting kernel (≥ 5.13; full API at 6.7+); current `cloud-hypervisor` CI lane runs Ubuntu LTS which already satisfies this.
- **passt provenance becomes a maintenance burden.** When upstream passt releases, the `nix/images/passt-hashes.toml` needs updating before contributor hosts can upgrade.

### Neutral

- **Wire format additions** (`tenant_id`, `plan_json`, `bundle_json` from Plan 112 stay; `bridge_restart_policy` added) but `#[serde(default)]` + backward-compatible schema means existing JSON corpora still parse.

## Related future work

- **Plan N+2** (Vz drainer payload tap): Swift `Config.swift` schema extension + Rust-side payload socket + control channel.
- **Plan N+3** (egress redactor observer): the redactor decorator + its inline payload rewriter plug-point on the leaf.
- **Plan N+4** (hostname-filter observer): DNS resolution shape, SNI handling, refusal-on-resolve-failure policy. Its own ADR.
- **Plan N+5** (rate-limiter observer): per-tenant ceilings, sliding-window vs token-bucket, enforcement at gateway vs observation only.
- **`mvmctl auth` / identity model**: separate ADR + plan; brainstormed independently of this work.
- **Per-VM signing-key derivation**: hardening pass to remove bridge read access to `host-signer.ed25519`.
- **AppleContainer substrate**: research into Apple's `containerization` framework's network layer; further-future.

## Implementation sequencing

A separate implementation plan (`specs/plans/113-network-provider-trait-firecracker-substrate.md`, to be created by the `superpowers:writing-plans` skill) will sequence the tasks: trait surface in mvm-core → Pipeline + AuditEmit in mvm-backend → ObserverAllowlist + policy schema bump → libkrun leaf refactor → Vz drainer → Firecracker bridge sidecar + jailer-lite → CI lanes + fuzz extension → plan-doc tick.


## Consolidated from ADR-078 — First-party virtio-net gateway ownership via rvproxy

**Status:** Superseded by Plan 214 / ADR-098 (2026-06-28). The first-party
virtio-net gateway (rvproxy) is dropped: the target architecture has **no guest
NIC** and routes all guest traffic through a host-side vsock broker, so a
guest-facing virtio-net gateway is no longer part of the design. The rvproxy
parity CI gate is removed. Historical context retained below.

Originally accepted 2026-06-10; amended ADR-055 and extended the claim-10
no-bypass posture in ADR-058 and the network-provider seam in ADR-064.

## Context

`mvm` currently claims a high degree of control over the runtime, builder, and
network-policy surface. That claim is materially weakened on the macOS/libkrun
path by one remaining third-party runtime dependency: the per-VM virtio-net
gateway binary spawned from
`crates/deps/libkrun-sys/src/gvproxy.rs`.

Today the architecture is already close to what we want:

- `mvm` owns VM lifecycle, per-VM supervisor processes, and backend selection.
- `mvm` owns the gateway audit bridge and policy seam in
  `crates/mvm-hostd/src/supervisor/gateway_bridge.rs`.
- `mvm` intentionally removed TSI and requires a real virtio-net gateway on
  both builder and workload libkrun paths (`passt` on Linux, `gvproxy` on
  macOS) so claim-10 mediation always has a host-visible seam.

The remaining gap is that macOS/libkrun guest egress is still implemented by
an external Go binary whose lifecycle and feature surface `mvm` does not own.
That creates four problems:

1. the product claim "we own the runtime and network plane" is not literally
   true on that path;
2. `gvproxy` imposes behavior `mvm` does not want, most notably a mandatory
   SSH-forward port;
3. the gateway implementation is outside the repo's normal auditability and
   iteration loop;
4. `mvm` and `rvproxy` now already share a proven compatibility seam, so
   continuing to defer ownership no longer buys much.

`rvproxy` exists specifically to close that gap. It already proves the
unchanged `mvm` gvproxy-compatibility gate on the vfkit/unixgram transport
shape, DHCP round-trip, and daemon lifecycle contract.

## Decision

Adopt `rvproxy` as the **first-party implementation** of the macOS/libkrun
`gvproxy` gateway contract, while preserving the existing `mvm` architecture.

This is a **gateway implementation replacement**, not an architecture rewrite.
`mvm` keeps:

- the per-VM supervisor model;
- the audit/policy bridge as the claim-10 mediation seam;
- the existing builder/runtime gateway-selection flow;
- the `NetworkingPreference` model (`passt` on Linux, `gvproxy`-shaped
  unixgram gateway on macOS).

The practical meaning of "replace gvproxy" is:

1. `mvm` gains an explicit production gateway-binary override for the
   macOS/libkrun `gvproxy` path.
2. `rvproxy` is run in **gvproxy-compatible mode** as a constrained per-VM
   daemon behind that seam.
3. The integration target remains the current CLI + vfkit/unixgram + DHCP
   contract, not a new control API.
4. The first rollout target is **macOS/libkrun only**. Linux `passt` remains
   unchanged unless a later ADR deliberately broadens scope.

## Why this shape

### Preserve the seam `mvm` already got right

The key architectural fact is that `mvm` already treats the gateway as an
implementation behind a stricter seam:

- the libkrun launcher spawns a per-VM gateway and waits for a socket;
- the bridge sits between guest virtio-net traffic and that gateway;
- policy/audit stays in `mvm`, not in the gateway.

That means we do not need a larger redesign to gain ownership. Replacing the
gateway binary at that seam is enough.

### Ownership without over-coupling

`rvproxy` becomes first-party runtime code, but not the place where
`mvm` centralizes plan admission or control-plane logic. The host-side trust
boundary stays where `mvm` already places it: supervisor + bridge + vsock
broker, with the gateway as a narrowly-scoped egress dataplane component.

### Surface reduction, not expansion

In compat mode `rvproxy` can accept `-ssh-port` without binding a real SSH
listener and can avoid exposing its broader local API/control surface. That
improves the current posture rather than widening it.

## Security posture

This decision does not reduce the claim-10 posture. It changes who owns the
gateway implementation, not where mediation occurs.

Security effects:

- **Improved ownership:** the guest egress gateway on macOS/libkrun becomes
  first-party Rust code in the same engineering loop as the rest of the
  runtime.
- **No-bypass preserved:** all traffic still traverses the existing bridge
  seam; `rvproxy` is not allowed to bypass the supervisor or short-circuit
  policy.
- **SSH surface reduced:** unlike upstream `gvproxy`, `rvproxy` does not need
  to bind a meaningful SSH-forward listener just to satisfy CLI compatibility.
- **Control-plane surface constrained:** `mvm` must run `rvproxy` in its
  gvproxy-compat mode with no separately exposed local API.

What does not change:

- guest↔host control traffic remains on the existing `mvm` channels (not a new
  `rvproxy` control plane);
- Linux `passt` remains a separate external dependency until deliberately
  revisited;
- upstream parser/runtime bugs are replaced by first-party parser/runtime bugs,
  so the maintenance burden moves hvf.

## Consequences

- `mvm` can make a much tighter claim that it owns the macOS/libkrun runtime
  and network plane end-to-end.
- The builder VM and workload VM networking paths stay aligned because both
  already share the same `resolve_networking_mode()` seam.
- The integration can land incrementally because `rvproxy` already targets the
  exact contract `mvm` invokes today.
- The product claim must still be scoped honestly: adopting `rvproxy` on the
  macOS/libkrun seam does **not** mean `mvm` owns every network backend
  everywhere until Linux `passt` is addressed separately.

## Alternatives considered

- **Keep upstream `gvproxy` indefinitely.** Rejected. It keeps the weakest
  point in the "we own the plane" story and preserves behavior `mvm` does not
  want.
- **Rewrite `mvm` around an `rvproxy` control API.** Rejected for now. Too much
  churn for the immediate ownership win; the current seam is already good.
- **Replace Linux `passt` and macOS `gvproxy` together.** Rejected as the first
  step. It broadens scope and risk unnecessarily.
- **Vendor upstream `gvproxy` into `mvm`.** Rejected. It increases ownership of
  packaging, not of the gateway implementation or feature direction.

## Out of scope

- Replacing Linux `passt`.
- Changing the vsock control-plane architecture.
- Broadening `rvproxy` compat mode into the future `mvmd` control surface.
- Windows or broader all-backend network-plane unification.


## Consolidated from ADR-082 — Rust-native egress gateway replaces the vendored Go gateway

**Status:** Superseded by Plan 214 / ADR-098 (2026-06-28). The Rust-native
virtio-net egress gateway (rvproxy) is dropped along with the gvproxy/passt
guest-NIC model: the target architecture gives the guest **no NIC** and brokers
all egress over host vsock. The rvproxy implementation, its `native` networking
mode, and the parity CI gate are removed. Historical context retained below.
**Amends:** ADR-004 §"Consolidated from ADR-055" (libkrun/Vz networking via gvproxy + passt)
**Preserves:** [ADR-041](041-signed-audited-execution-plans.md) no-bypass invariant; claim 10 (default-deny egress); Plan 141 flow observation; Plan 129 egress secret substitution

## Context

On the workload backends mvm uses a userspace virtio-net gateway for guest
egress: gvproxy (gvisor-tap-vsock, a vendored Go binary) on macOS — libkrun
and Vz — and passt on Linux. ADR-055 chose this after TSI was removed for
bypassing virtio-net (ADR-058 / Plan 102 W6.A): egress must traverse the guest
network stack so the host can observe and enforce it, which TSI's syscall
impersonation defeats.

That decision is sound. The *implementation* it forces is not. gvproxy is an
opaque external binary sitting at the security chokepoint, and everything we
need from that chokepoint has to be bolted on around it:

- **No native flow/packet API.** gvproxy emits no flow events, so claim 10
  enforcement and Plan 141 auditing splice its unixgram socket in-process
  (`mvm_hostd::supervisor::gateway_bridge`, `VzGvproxy` splice) and re-parse
  frames with etherparse. The enforcement seam is reconstructed *outside* the
  daemon from raw bytes.
- **Uncontrollable logging.** gvproxy logs client-disconnect at error level on
  every VM teardown; with the supervisor's inherited stdio those lines leak to
  the operator console (no sidecar for the Stage 0 path). We cannot change a
  vendored binary's log discipline.
- **Hidden tuning.** Transport parameters (MTU, buffer sizes) are not surfaced
  through our spawn path; we pass `-listen-vfkit`, `-log-file`, `-ssh-port` and
  take the defaults.
- **A foreign binary inside the trust boundary.** ADR-002 trusts the host, but
  a Go dependency carrying every guest's egress is the largest unaudited
  surface in the substrate, and it cannot be reviewed or fuzzed the way the
  rest of the host path is.

Separately, an hvf Rust-native gateway daemon now exists that occupies the
same position as gvisor-tap-vsock: it binds a control API, accepts a VM
transport session (VZ/vfkit, Firecracker on `/dev/kvm`, host-local QEMU over
`qemu-unix`), runs a guest-network dataplane, and exposes a typed, plugin-aware
byte pipeline. Its seams map directly onto what we currently bolt onto gvproxy:

| mvm requirement (today, bolted onto gvproxy) | native seam in the Rust gateway |
| --- | --- |
| Plan 141 in-line flow observer (splice + etherparse) | byte-traffic observer plugin — `Inspector` / `SinkExporter` / `DecisionEmitter` classes with a typed `PluginDecisionSink` |
| Claim 10 `PlanFlowPolicy` deny-by-default gate (`gateway_bridge`) | `PolicyEngine` / `PolicyDecision` in the gateway's policy crate |
| Plan 129 egress secret substitution / name-constrained CA termination | secret-redaction + byte-replacement transform plugins |
| MTU / transport tuning (unsurfaced) | first-class `mtu` config field; owned transport layer |
| Vendored Go binary in the trust boundary | reviewable, fuzzable in-repo-family Rust crates |

## Decision

Adopt the Rust-native gateway as the egress gateway for the workload backends,
replacing the vendored Go gateway. Do it as a flag-gated, parity-tested
migration — the playbook used for the Swift→Rust supervisor cutover (Plan 152),
not a blind swap of the security seam.

- Add a `Native` variant to `NetworkingPreference` (`MVM_NETWORKING=native`).
  gvproxy/passt remain selectable until the parity gate passes. The variant
  and flag are named generically — the source carries no project slug.
- The native gateway must terminate the **same** `-listen-vfkit` unixgram
  protocol libkrun (`krun_add_net_unixgram`) and Vz (vfkit) already speak, so
  the backend dispatch (`apply_networking`, `host_gvproxy`) changes only which
  daemon it spawns.
- Claim 10 enforcement moves from the spliced `gateway_bridge` onto the
  gateway's native policy engine + decision sink. **The no-bypass invariant
  (ADR-058) is non-negotiable**: every guest packet still traverses virtio-net
  and passes the policy gate before egress; the gate is deny-by-default; a
  dropped flow is audited. The migration changes *where* enforcement runs (in
  the daemon vs. spliced beside it), never *whether* it runs.
- Logging and lifecycle become ours: structured logs to a sidecar, clean
  teardown, no console leak.

## Migration plan (parity-gated)

1. **Wire the flag.** `Native` variant + `apply_networking` dispatch + spawn
   path; daemon behind `MVM_NETWORKING=native`, default unchanged.
2. **Connectivity parity.** Builder + Stage 0 cold build over the Rust gateway
   reaches cache.nixos.org and completes byte-identical artifacts on libkrun and
   Vz. (Linux/passt parity tracked separately.)
3. **Enforcement parity.** Port the claim 10 witnesses
   (`policy_default_is_deny_all`, the gateway-bridge flow-drop tests) onto the
   native policy engine; assert deny-by-default + audited drops on the new path.
   Port the Plan 141 observer and Plan 129 substitution tests.
4. **Parity gate.** A CI lane runs the claim-10 / flow-audit / substitution
   suites against both gateways and asserts identical verdicts before the
   default can flip — mirroring Plan 152's boot-parity gate before deleting
   Swift.
5. **Flip the default** per-OS, keep gvproxy/passt one release as fallback.
6. **Remove the vendored Go gateway** and the splice/etherparse scaffolding once
   the gate is green and the fallback window closes.

## Consequences

**Gains:** the egress seam becomes owned, typed, reviewable, and fuzzable;
claim 10 / Plan 141 / Plan 129 become first-class instead of reconstructed from
spliced bytes; logging, teardown, and MTU come under our control; one fewer
foreign binary in the trust boundary (aligns with ADR-002 and the
limit-dependencies posture).

**Costs / risks:** the gateway is the security chokepoint — a regression is a
claim-10 regression, which is why the parity gate gates the default. Two
gateways coexist during migration. The Rust gateway's current signed-off scope
is VZ/vfkit, Firecracker on `/dev/kvm`, and host-local QEMU. libkrun-unixgram
interop is **already proven** (see §Validation); Linux/passt-replacement
parity remains an open item (below), not assumed.

**Explicitly not a performance decision.** This does not target bring-up time.
Cold bring-up is dominated by source compilation (kernel + guest agents),
not the gateway; gvproxy carries only the cold download leg and warm builds are
a cache hit. The kernel prebuilt + store persistence own bring-up speed. The
Rust gateway *enables* future transport tuning (MTU), but speed is not the
justification and must not be used to wave the parity gate through.

## Validation

- **libkrun `krun_add_net_unixgram` interop — proven.** The gateway implements
  the vfkit unixgram listener (SOCK_DGRAM, the `VFKT` handshake datagram, one
  ethernet frame per datagram with no length prefix, the `-listen-vfkit
  unixgram://` flag surface). mvm's own libkrun acceptance gate —
  `run_libkrun_gvproxy_bridge`, the DHCP `DISCOVER → OFFER` round-trip through
  the bridge — passes with the gateway binary as `MVM_GATEWAY_BIN` (verified
  unsandboxed, 2026-06-05). So the first macOS cutover covers **both** libkrun
  and Vz, not Vz-only. This closes the migration's largest risk before any code
  lands in mvm.

## Resolved scope decisions

- **Linux/passt — out of Phase 1.** Phase 1 is macOS-only (libkrun + Vz); passt
  is retained on Linux. One-gateway-everywhere is the eventual goal, but the
  Linux/passt replacement is a separate parity gate: passt's threat surface and
  its nftables interaction differ enough that bundling it would put the macOS
  cutover at risk. Tracked as a follow-on, not assumed here.
- **mvmd coupling — formalize after the macOS cutover.** mvmd consumes the
  gateway audit substrate, and the typed control API is the right place to
  formalize that contract — but it needs mvmd input and must not block Phase 1.
  The macOS Phase 1 control API stays internal/unstable; a coordination item
  with mvmd precedes any stabilization.

## Out of scope

Bring-up performance (kernel prebuilt / store persistence own it). Inbound TLS
(mvmd's edge, per ADR-058). The Firecracker nftables egress path (unchanged;
this ADR is the userspace-gateway substrate only).


## Consolidated from ADR-085 — The egress gateway ships inside the mvmctl artifact

**Status:** Proposed
**Extends:** ADR-004 §"Consolidated from ADR-082" — from "adopt the Rust-native gateway" to "ship it in the box"
**Depends on:** [Plan 193](../plans/193-rvproxy-network-substrate.md) (substrate cutover), [Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md) (host packaging)
**Preserves:** [ADR-041](041-signed-audited-execution-plans.md) no-bypass invariant; claim 10 (default-deny egress); [Plan 129](../plans/129-secrets-subsystem.md) substitution; [Plan 141](../plans/141-vz-payload-tap-and-rust-owned-shuffle.md) flow observation

## Context

ADR-082 settled *which daemon runs at the egress chokepoint*: the Rust-native
gateway (`rvproxy`) replaces the vendored Go gateway (gvproxy) and passt, behind
a parity gate. It did not settle *how that daemon reaches the user's machine*.

Today the gateway is an install-time prerequisite. On macOS the user runs `brew
install slp/krun/gvproxy`; on Linux they install passt from the distro. That is
the same first-run friction as the rest of the Homebrew trio — except it sits at
the security chokepoint, so it cannot be made optional.

The no-bypass invariant (ADR-058) is the structural reason this matters. Tools
that lean on a VMM's built-in networking can drop the external gateway entirely;
we cannot, because every guest packet must traverse virtio-net and pass an
auditing/enforcing/substituting gateway before egress. We *must* ship a gateway.
The only open question is whether the user installs it separately or it arrives
in the box.

The gateway is now uniquely suited to bundling:

- It is a **single self-contained Rust binary we build** — no Go toolchain, no
  foreign runtime, no per-distro build like passt.
- libkrun `krun_add_net_unixgram` interop is **already proven** (ADR-082
  §Validation: `run_libkrun_gvproxy_bridge` DHCP round-trip passes with the
  gateway as `MVM_GATEWAY_BIN`, 2026-06-05).
- Its native policy / audit / substitution seams are the ones claim 10,
  Plan 129, and Plan 141 want anyway (Plan 193), so bundling it and adopting it
  are the same motion.

Bundling gvproxy (a Go binary) or passt (a Linux-only C binary) would be a
vendoring chore at the trust boundary. Bundling our own gateway is not.

## Decision

The egress gateway is distributed **inside** the `mvmctl` release artifact, not
as a separate dependency.

- The CLI resolves its gateway from the bundle by default. `MVM_GATEWAY_BIN`
  remains a development override; the flag/env surface stays generic (no project
  slug in code), per ADR-082.
- **End-state: the bundled gateway is the *sole* gateway.** gvproxy leaves the
  macOS install contract once ADR-082's macOS parity gate is green. passt remains
  the Linux fallback only until the Linux parity gate (a Plan 193 follow-on,
  explicitly out of ADR-082 Phase 1) closes.
- The bundled gateway carries claim 10 / Plan 129 / Plan 141 through its native
  policy + audit seams, not the spliced `mvm-hostd` `gateway_bridge`. The splice
  + `etherparse` scaffolding is deleted when the fallback window closes.
- `mvmctl doctor` reports the resolved gateway *source* (`bundled` / `override`
  / `legacy-tap`) on the gateway line, mirroring the `builder backend` line, so
  the in-box path is observable.

Bundling is decoupled from defaulting: the binary can be present-and-selectable
before it becomes the default. The parity gate still gates the default flip — a
regression here is a claim-10 regression.

## Sequencing

1. **Bundle present.** The gateway ships in the artifact; resolved from the
   bundle but selectable via override. Default unchanged (gvproxy/passt).
2. **macOS parity gate green** (ADR-082 Phase 1, libkrun + Vz) → flip the macOS
   default to the bundled gateway → drop gvproxy from the macOS install contract.
3. **Linux parity gate green** (Plan 193 follow-on) → drop passt → remove the
   splice/`gateway_bridge` scaffolding.

## Consequences

- One Homebrew package (gvproxy) leaves the macOS first-run path; passt leaves
  the Linux path at step 3. This is the first concrete cut into the trio.
- The gateway is version-pinned to the CLI by construction (same artifact) —
  no skew between a bundled-but-stale gateway and the CLI that drives it.
- Bundle size grows by one static binary; tracked under [Plan 156](../plans/156-binary-size-reduction.md).
- The security-load-bearing networking code (claim 10 / 129 / 141) collapses
  from a spliced reconstruction into a contract with an in-box daemon we own.

## Out of scope

- Vendoring libkrun/libkrunfw and the full relocatable dependency-free bundle —
  [ADR-086](086-relocatable-dependency-free-host-bundle.md).
- Inbound TLS (mvmd's edge, per ADR-058).
- Linux/passt-replacement parity timing (Plan 193 follow-on).
- Bring-up performance — the gateway does not own it (ADR-082 §"not a
  performance decision").

## References

- ADR-004 §"Consolidated from ADR-082" — adopt the Rust-native gateway
- [ADR-041](041-signed-audited-execution-plans.md) — no-bypass invariant, claim 10
- ADR-004 §"Consolidated from ADR-055" — gvproxy / passt gateway choice
- [Plan 193](../plans/193-rvproxy-network-substrate.md) — substrate cutover
- [Plan 199](../plans/199-host-runtime-packaging-and-crate-boundaries.md) — host packaging
- [Plan 129](../plans/129-secrets-subsystem.md), [Plan 141](../plans/141-vz-payload-tap-and-rust-owned-shuffle.md), [Plan 156](../plans/156-binary-size-reduction.md)


## Consolidated from ADR-100 — vsock is the sole guest↔world channel (no guest NIC; egress via a host vsock gateway)

**Status:** Accepted (2026-06-29)
**Relates to:** [ADR-002](002-microvm-security-posture.md) (claim 10 — default-deny
egress), [ADR-049](049-vsock-substitution-service.md) (vsock substitution),
[ADR-059](059-host-services-broker.md) (host-services broker over vsock),
ADR-004 §"Consolidated from ADR-082" (hvf egress gateway),
[ADR-002](002-microvm-security-posture.md) (`WorkloadBackend`, consolidated from ADR-083),
[ADR-014](014-vmbackend-single-trait.md) (the backend seam),
[Plan 214](../plans/214-clean-replacement-architecture.md).

## Context

A guest can reach the host/outside world over two planes:

- **Control plane** — host↔guest agent traffic (console, exec, file ops, secrets,
  the host-services broker, time/cost). This is **already vsock-only on every
  backend** (`mvm-guest`'s vsock protocol); there is no SSH, serial, or other
  control side-channel in any rootfs.
- **Data plane** — the guest workload's *network* egress (it calling an API, a
  registry, etc.). This is **not** uniform today: Firecracker gives the guest a
  virtio-net NIC with host nftables default-deny; libkrun/vz give a virtio-net
  NIC through the gvproxy/passt **gateway-bridge** with a `PlanFlowPolicy`. Each
  is host-enforced (claim 10 holds), but each is a *different* mechanism, and each
  puts a NIC + IP stack inside the guest.

An hvf vsock-mediated egress path already exists (the substitution service —
ADR-049 — and the `WorkloadBackend` seam, ADR-002 consolidated from ADR-083), but it is parity-gated, not
the universal default.

The Plan 214 brief is explicit: **no guest NIC by default; host/vsock-mediated
networking with endpoint allowlisting.** This ADR makes that a hard, backend-wide
invariant rather than a per-backend choice.

## Decision

**A workload guest's only channel off the guest is vsock to the host.** There is
no guest NIC. Everything bound for the outside world flows:

```
guest app → vsock → host gateway (policy chokepoint, claim-10 default-deny) → outside
```

Precisely, for every workload backend — **HVF, Firecracker, libkrun, vz** (and any
future backend, e.g. KVM/WHP):

1. **No virtio-net device** is attached to a workload guest. No tap, no
   passt/gvproxy bridge, no in-guest IP stack on the workload path.
2. **All egress is vsock-mediated** through a single host gateway that enforces
   the signed `ExecutionPlan`'s network policy (default-deny; ADR-002 claim 10),
   the same code on every backend (the gateway is the seam from ADR-082/083, fed
   by the substitution service from ADR-049).
3. **All host services** (secrets, broker, console, exec, file ops) remain over
   vsock (already true; ADR-059).

The guest therefore has exactly one device class for talking to anything: vsock.

## Why (not just preference)

- **One enforcement seam.** Claim 10 is enforced in *one* host gateway, identical
  across backends — instead of auditing three mechanisms (FC nftables, the
  libkrun/vz gateway-bridge, …). A vsock stream cannot bypass it: there is no
  other route out of the guest.
- **Smaller guest attack surface.** No virtio-net driver, no in-guest IP stack,
  no NIC to escape from or to misconfigure into an open route.
- **Backend-agnostic.** vsock exists on every VMM we support, so the egress model
  no longer depends on each VMM's netdev. A new backend gets egress + policy "for
  free" by speaking the gateway's vsock protocol — nothing per-VMM to re-audit.
- **Composes with the rest of Plan 214.** The control plane is already vsock-only;
  this makes the data plane match, so the whole guest↔world surface is one
  transport with one policy.

## Cost / consequences

- The host gateway is an **L4/L7 proxy** (the hvf gateway, ADR-082; fed by
  the substitution service, ADR-049), not transparent IP routing. Every protocol
  flows through it; protocols it doesn't model don't get out (which is the point —
  fail-closed — but it must cover what workloads need: TCP connect, DNS, TLS
  passthrough).
- **Migration, not a flag flip.** Firecracker, libkrun, and vz currently attach a
  virtio-net NIC; converging them means routing their egress through the vsock
  gateway and **retiring the virtio-net paths** (nftables install, gateway-bridge,
  passt/gvproxy spawn). Staged, like the Vz sunset.
- Workloads that assume a real NIC (raw sockets, inbound listeners, non-TCP
  protocols) are not supported on the workload path by design; inbound is a host
  port-forward terminated at the gateway, not a guest-side listener on a NIC.

## Scope

- **Workload guests: in scope, mandatory.** Every backend that carries an
  untrusted workload (`AnyBackend::as_workload_backend == Some`).
- **The builder VM is a separate, explicitly-tracked case.** It is a dev/test
  substrate (Tier 2, outside the numbered claims — ADR-002 §tier matrix) that
  fetches nixpkgs; during the transition it may retain a host gateway NIC. Moving
  the builder onto the same vsock gateway is desirable but tracked independently
  of the workload invariant so it never blocks it.
- The **QEMU** backend is dev/test only (Tier 2, claim-10 not wired — ADR-002);
  it is held to the invariant on the workload path for uniformity, but its
  non-enforcement is already documented and it is never `auto_select`ed.

## The end state: one vsock egress gateway, no network layer

There is **no guest NIC and no host network-gateway layer at all** — no `eth0`, no
bridged/external interface, no userspace network gateway (passt/gvproxy/rvproxy).
Every outbound flow is the guest opening a **vsock** stream to a single host-side
**egress gateway**, which is the sole chokepoint and does *both* jobs:

- **Claim 10** — the allow/deny decision (`EgressGate` over `CanonicalEgress`).
- **Claims 12/13** — for a bound-secret destination, the credential substitution
  (the placeholder→real-credential rewrite) the terminator does today.

This deletes the entire userspace network plane — **passt, gvproxy, the hvf
rvproxy, and the nft/redirect terminator all go away**. They exist only to gateway
a guest NIC's IP traffic; with no NIC there is nothing for them to do.

**One egress port, not two — substitution is a behavior.** Credential substitution
is not a separate channel or port; it is what the egress gateway *does* when a
flow's target is a bound-secret host. So there is a single **egress-gateway port**
(`EGRESS_PORT` — the number `SUBSTITUTION_PORT` already used, since the substitution
channel was always host-mediated egress), alongside `5251` workload-exit and `5252`
agent control. Each microVM has its **own** vsock transport (its own device + host
endpoint + per-VM gateway/policy); these port numbers are a fixed, well-known
*service map* reused per VM — a constant like a registered TCP port, not a secret and
not per-VM-unique. Isolation is in the per-VM transport + per-VM policy, never in the
port number. Concurrent egress streams from one guest share the one egress port,
distinguished by the guest's source port.

**Protocol scope.** The gateway proxies **TCP**, and DNS is resolved host-side via
the pin registry. UDP/QUIC (HTTP/3), ICMP, and raw sockets are *not* carried by a
TCP-only gateway; if they come into scope they get an explicit datagram-over-vsock
path in the gateway — never a NIC. For headless TCP/HTTP(S) workloads this is the
full surface.

## Two planes over vsock: control + transparent data

A workload guest's vsock carries two distinct things, both already per-VM and
policy-gated:

**Control plane (commands).** Multiplexed by well-known vsock port:
- `5252` **guest agent** — host→guest `GuestRequest` control: `ProtocolHello`
  (capability negotiation), `Ping`, `WorkerStatus`, `SleepPrep`/`Wake` (warm-pool
  lifecycle), `PrimedStatus` (warm-snapshot barrier), `CheckpointIntegrations`,
  `ProbeStatus`, `Exec` (dev-only), + the agent RPC family.
- `5300` **broker** — workload→host `ServiceCall`, binding-gated + audited (claims
  12/13): `host.secrets.v1` (destination/time-bound creds — no raw secret crosses),
  `host.audit.v1`, `host.time.v1`, `host.cost.v1`.
- `5251` workload-exit, `5253` egress gateway, `10000+` port-forward, `20000+`
  console, `5301` ssh-agent (dev).
New control surface = a new `host.<svc>.v1` broker method or a new `GuestRequest`;
both ride the existing gated/audited paths.

**Data plane (egress) — vsock is the *only* primitive (hard invariant).** This is
the security design, not merely minimalism: a workload guest has **no NIC, no IP
routing, no userspace network gateway (no gvproxy/passt/rvproxy), no TUN, no
netfilter.** Its sole means of reaching anything off-guest is an `AF_VSOCK` stream to
the host egress gateway. There is no network in the guest to attack, misconfigure, or
escape onto; a direct `connect(realIP)` has nowhere to route, so egress is *only*
possible by asking the host. The reach the guest has is exactly what the host's
policy grants — enforced by **absence of any other path**, not by a firewall the
guest could fight.

How a workload's traffic gets onto vsock without an in-guest IP stack:

- **Runtime/SDK-native (the production path).** The mvm runtime serves the workload's
  egress through the in-guest `mvm-egress-client` (loopback SOCKS5 → vsock) and sets
  `ALL_PROXY=socks5h://127.0.0.1:<port>`. Standard HTTP clients (curl, requests,
  fetch, Go `net/http` — all honor proxy env) thus reach the network transparently
  with **only loopback present** — no NIC, no route, no netfilter, no IP stack beyond
  `lo`. The mvm SDK wires this automatically, so SDK workloads are transparent. With
  `socks5h`, the client sends the **hostname**, not a resolved IP — so DNS happens
  *host-side* (see below); the guest never resolves and never needs a resolver.
- **AF_VSOCK-native (the purest variant).** A workload (or the runtime) speaks the
  vsock egress protocol directly — zero IP stack at all, not even loopback. Used where
  the runtime fully owns the socket layer.

The **host side is unchanged in shape**: the egress gateway takes `(target,
byte-stream)` → claim-10 decide → proxy. HTTPS is forwarded TCP bytes (no
termination); TLS-terminating credential substitution is the separate claims-12/13
behavior, only for bound-secret hosts.

**DNS = host-side resolution over vsock (no guest resolver).** Because the client
uses `socks5h`, the guest sends `"hostname:port"` over vsock and the **host** gateway
resolves the name — checking it against the claim-10 host-allowlist / DNS pin registry
*before* connecting, and connecting to the pinned IP. This is "DNS-over-vsock" in the
literal sense: the name travels the vsock and the trusted host does the lookup +
policy check. No `mvm-addon-dns`, no in-guest UDP/53. (Policies are naturally
host-based — "allow `api.stripe.com:443`" — so host-side name resolution *is* the
enforcement point.)

**Explicitly out of scope (deliberate trade):**
- *Full transparency for arbitrary raw `AF_INET` binaries.* A static binary that
  ignores proxy env and calls `connect(realIP)` directly cannot be intercepted
  without an in-guest IP stack (TUN/netfilter) — which this design **rejects** (it
  would re-introduce "a network in the guest"). Such workloads must use the
  SDK/runtime egress. We accept a strictly smaller, unbypassable guest over
  capturing raw IP egress.
- *UDP/QUIC (HTTP/3), ICMP, raw sockets.* Not carried by a TCP vsock gateway; they'd
  need a datagram-over-vsock channel, never a NIC.

The `spikes/transparent-egress/` (netfilter REDIRECT) and the TUN+`smoltcp` sketch
are **illustrative of full transparency only — not the production direction**: both
require an in-guest IP stack, which the hard invariant above forbids.

## Security model + mvmd integration

**The host egress gateway is the trust boundary. Everything in the guest is
untrusted.** The guest can express *intent* ("connect me to `host:port`, here are
the bytes"); it cannot *act*. The host makes the real connection, on the guest's
behalf, only if the admitted policy permits it. Concretely:

- **Guest-side code is untrusted plumbing.** `mvm-egress-client`, `ALL_PROXY`, and
  the (rejected-for-production) TUN/netfilter spikes are conveniences for getting a
  workload's bytes onto vsock. None of them enforces anything — a fully compromised
  guest (root) can tamper with all of it. Security does **not** depend on them.
- **The boundary is the host gateway**, outside the guest's control: it makes the
  claim-10 decision, resolves names against the pin registry, opens the socket, and
  for bound-secret destinations performs the claims-12/13 substitution (the guest
  never receives raw secrets). A compromised guest still reaches only what policy
  admits, because it has no other path out and the host is the one dialing.
- **Confined transport.** vsock is host↔guest point-to-point (guest can only address
  CID 2); no NIC means no L2/L3, no lateral movement to other VMs, no raw-packet
  exfil. The attack surface collapses to "the messages the guest sends the gateway",
  which are parsed by a fuzzed parser (claim 5) and policy-checked.

**mvmd (the orchestration layer) owns policy; the per-VM host gateway enforces it.**
This is the control-plane / data-plane split:

- **mvmd = control plane.** It owns tenants/pools and authors each workload's
  `NetworkPolicy` (the claim-10 allow-list of `host:port` it may reach, the
  bound-secret → destination bindings), signs it into the `ExecutionPlan`, and
  schedules the microVM.
- **host gateway = data-plane enforcement.** Per VM, it builds its `EgressGate` from
  the admitted plan's `NetworkPolicy`, then decides every vsock egress request
  (default-deny), resolves names host-side against the pins, and emits chain-signed
  audit entries. The same plan drives substitution.

So the fleet decides *what each microVM is permitted to reach*; the per-VM gateway
enforces it on every request, with no egress path the guest can take around it. This
is capability-based egress at fleet scale, and it is exactly the property mvmd needs
to safely run untrusted multi-tenant workloads.

## Implementation / migration plan

1. **HVF implements it natively (reference).** HVF has no NIC, so it is the clean
   slate: guest → vsock → host gateway with claim-10 default-deny, live-proven.
2. **Converge Firecracker / libkrun / vz** onto the *same* single vsock gateway:
   move claim-10 egress **and** claims-12/13 substitution onto the vsock egress
   path, then delete the NIC attach **and** the whole gateway layer (passt /
   gvproxy / rvproxy / terminator) for workload VMs. The builder VM (not a
   workload) is out of scope and keeps its NIC.
3. **CI guard.** A lint/test asserts no workload guest config attaches a virtio-net
   device or a userspace gateway (no `add_net` / tap / passt / gvproxy / rvproxy on
   the workload path), so a regression that re-adds the network plane fails closed.
4. **Guest egress shim = `mvm-egress-client` (loopback SOCKS5 → vsock), the runtime
   sets `ALL_PROXY`.** No in-guest IP stack beyond `lo`; no TUN, no netfilter. The
   `spikes/transparent-egress/` REDIRECT prototype and the TUN+`smoltcp` sketch are
   **illustrative of full transparency only and are not productionized** — they need
   an in-guest IP stack, which the hard invariant forbids.
5. **DNS-over-vsock = host-side name resolution in the gateway.** Extend `EgressGate`
   to accept a `"hostname:port"` target (sent by the `socks5h` client), resolve it
   against the claim-10 host-allowlist / DNS pin registry, and connect the pinned IP.
   No guest resolver, no UDP/53.

## Status

Both **hvf VMM** paths now prove vsock-only egress live, reusing one
`EgressProxy` + run loop + heartbeat:

- **HVF / macOS / Apple silicon** — the reference (details below).
- **KVM / x86_64 / Linux** — `KvmVm::boot_with_egress` puts the same `VirtioVsock` +
  `EgressProxy` on a virtio-mmio window (no guest NIC). Live on real `/dev/kvm`: a
  NIC-less guest (kernel built with `CONFIG_VIRTIO_MMIO_CMDLINE_DEVICES` +
  `VIRTIO_VSOCKETS` `=y`) opened a vsock stream → host admitted it (claim-10,
  `egress_allowed`) → opened the real TCP connection → the echo round-tripped back
  (`reply n=4 data=ping`). KVM specifics vs HVF: the SIGUSR1 heartbeat breaks the
  in-kernel HLT, and the device IRQ is **pulsed** (x86 IOAPIC edge delivery) so async
  replies reach an idle guest. The third-party VMMs (libkrun/vz/Firecracker) are the
  remaining convergence (Step 2 below); the hvf path is the destination runtime.

### HVF reference (Apple silicon)

Step 1 is realized on HVF:

- ✅ No guest NIC; the guest's only off-guest channels are vsock (control, the
  transient workload-exit signal, and egress).
- ✅ Egress **deny by default** — a NIC-less guest's connect request over vsock is
  refused unless policy admits it (`vmm::egress_gate` reuses the claim-10
  `CanonicalEgress`).
- ✅ Egress **allow + TCP proxy** when admitted — the host opens the socket and
  proxies bytes; an echo round-trips guest → vsock → host TCP → guest.
- ✅ The gate is built from the **admitted plan's `NetworkPolicy`**, with the
  supervisor **resolving host-allowlist DNS pins** at startup; fails closed.
- ✅ **Async bidirectional streaming** — replies / server-push reach a guest
  blocked in `recv` (WFI), not just inline request/response. The run loop takes a
  `should_stop` predicate so a forced exit (`Canceled`) polls host-side I/O before
  ending; the HVF watchdog doubles as a ~5 ms heartbeat that `force_exit`s the
  vCPU to break WFI, so `drain_egress` runs and the vsock rx IRQ wakes the guest.
  (Root cause: `hv_vcpu_run` sleeps on WFI, so the loop otherwise never returns to
  drain the socket — confirmed by tracing.)
- ✅ **CI guard** (`xtask check-vsock-only-egress`) keeps the vmm/HVF path NIC-free.

Step 1 (HVF reference) is complete, and the shared host-side pieces for Step 2 are
built + unit-tested: the transport-agnostic `EgressProxy` core, the in-guest
SOCKS→vsock client (`mvm-egress-client`), and the async host egress server
(`mvm_vm_host::egress_server`, reusing `EgressGate`). Step 2 — converge
Firecracker/libkrun/vz onto the single vsock gateway (egress **+** substitution),
delete the NIC + gateway layer, widen the CI guard — remains; it changes the
claims-12/13 implementation (substitution moves onto the vsock path), so it is a
security-touching, per-backend change. See
`specs/notes/2026-06-29-adr100-step2.3-libkrun-cutover-plan.md`.

## Alternatives considered

- **Keep per-backend NICs with host-enforced default-deny (today's posture).**
  Rejected as the *end state*: claim 10 holds, but it is three mechanisms to
  audit and keeps an IP stack in every guest. Acceptable only as the transition
  state while backends converge.
- **A guest NIC routed to a host gateway (no in-guest policy, but a real NIC).**
  Still a NIC + IP stack in the guest and still per-VMM netdev wiring; gives up
  the single-seam and surface-reduction wins. Rejected.
- **Keep the userspace network gateway (passt / gvproxy / rvproxy) and enforce on
  it.** This is today's transition posture and what claims 10/12/13 are built on
  for the NIC backends. Rejected as the end state: it keeps an IP stack in every
  guest and a userspace network plane (three proxies + an nft/redirect terminator)
  to audit, when vsock already gives one host↔guest channel. The gateway exists
  only to service a guest NIC; removing the NIC removes the reason for it. Its one
  real capability beyond a TCP vsock gateway is arbitrary-IP/UDP — addressed by a
  datagram-over-vsock path if needed, not by retaining the network plane.
- **In-guest TUN + userspace netstack (`smoltcp`), or netfilter REDIRECT, for full
  transparency.** Both work (the REDIRECT variant is live-proven in
  `spikes/transparent-egress/`) and capture *any* raw `connect()`. **Rejected for
  production**: both require an in-guest IP stack (TUN/netfilter/routing) — i.e. "a
  network in the guest" — which is exactly the surface this ADR removes. They stay as
  illustrative spikes. (smoltcp's license is fine — `0BSD`, the most permissive there
  is, already on `deny.toml`'s allow-list — so the rejection is about guest surface,
  not licensing.)
- **`LD_PRELOAD` / syscall-shim `connect()` interception.** Rejected: covers only
  dynamically-linked libc callers (static/Go/non-libc bypass it) and isn't a
  boundary anyway.
- **Proxy-env / SDK-native (`ALL_PROXY` → `mvm-egress-client` → vsock) — CHOSEN.**
  This is the production path: loopback-only (no NIC/route/netfilter/IP-stack), the
  runtime sets `ALL_PROXY`, and `socks5h` pushes DNS to the host. The accepted cost
  is that a raw-`AF_INET` binary ignoring proxy env has no egress (no route) and must
  use the SDK/runtime — a deliberate trade for an unbypassable, network-free guest.


## Consolidated from ADR-101 — In-house VMM: one unified vsock egress gateway (claims 10/12/13 in one endpoint)

**Status:** Accepted (2026-06-30)
**Relates to:** ADR-004 §"Consolidated from ADR-100" (vsock is the sole
guest↔world channel — this ADR is the concrete hvf realization of its "single
host gateway"), [ADR-049](049-vsock-substitution-service.md) (vsock substitution),
[ADR-059](059-host-services-broker.md) (claims 12/13), ADR-004 §"Consolidated from ADR-082"
(the gateway seam), [ADR-002](002-microvm-security-posture.md) (`WorkloadBackend`, consolidated from ADR-083),
[ADR-002](002-microvm-security-posture.md) (claim 10), [Plan 214](../plans/214-clean-replacement-architecture.md).

## Context

ADR-100 made it a backend-wide invariant that a workload guest's only channel off
the guest is vsock, and that all egress flows through "a single host gateway that
enforces the signed `ExecutionPlan`'s network policy ... fed by the substitution
service." That ADR fixed the *principle*. It did not pin down how the hvf VMM
(HVF/KVM — `crates/mvm-backend/src/{vmm,hvf,kvm}`) realizes it concretely, and the
hvf path arrived at that principle from two directions that had not yet been
joined:

- **Raw-TCP egress (claim 10).** `vmm/egress_proxy.rs` (`EgressProxy`) treats the
  first frame on a `EGRESS_PORT` (5253) stream as a connect target `"ip:port"`,
  decides it against the claim-10 `EgressGate` (default-deny), then proxies raw
  bytes. This is the path the hvf VMM's claim-10 milestone proved (the
  `kvm-backend-egress` / `hvf-backend-egress` examples drive it directly).
- **Substitution (claims 12/13).** The guest's *only* egress client —
  `mvm-guest`'s forward-proxy (`forward_proxy.rs` → `substitution_client.rs`) —
  dials `EGRESS_PORT` and speaks the **WireRequest** protocol (4-byte BE length +
  JSON; `mvm_core::substitution_wire`). The host terminates TLS and injects the
  bound credential. The endpoint (`mvm-substitution-endpoint`) enforces the
  per-secret binding (claim 12) and never lets a raw secret cross (claim 13).

These two collide on one port. `EgressProxy` reads the WireRequest's length prefix
as a malformed `"ip:port"` and resets the stream — which is exactly why
secret-bearing (and in fact *all* forward-proxy) egress does not work on the
hvf VMM today. A guest contract for the resolution is already written
(`crates/mvm-guest/src/vsock.rs` `EGRESS_PORT`): 5253 is "the single host-mediated
egress chokepoint ... the host's per-VM gateway makes the claim-10 allow/deny
decision and proxies the flow, and for a bound-secret destination performs the
claims-12/13 credential substitution — **a behavior of this one gateway, not a
separate channel**." This ADR makes the host side match that contract.

The trigger is Plan 214: HVF must carry secret-bearing workloads (claims 12/13) to
retire Vz. Vz carries them over `EgressSubstitutionTransport::VsockUdsChannel` (the
supervisor splices a guest 5253 dial to the per-VM endpoint UDS). HVF must reach
the same capability without regressing the claim-10 it already has.

## Decision

**On the hvf VMM, `EGRESS_PORT` (5253) carries exactly one protocol — the
WireRequest substitution protocol — through one host gateway (the per-VM
`SubstitutionBridge`) that pipelines two enforcement stages on every request:
claim-10 at the bridge (the existing egress gate) and claims 12/13 at the per-VM
`mvm-substitution-endpoint`.**

1. **One protocol per route, chosen at configuration time — never by peeking the
   wire.** For a secret-bearing workload (a substitution endpoint is configured)
   5253 routes to the `SubstitutionBridge` and speaks WireRequest only — what the
   guest's sole egress client sends and what Vz terminates, so the guest image stays
   backend-agnostic. For a workload with no endpoint, 5253 keeps the legacy raw-
   `"ip:port"` `EgressProxy` route. The device picks the route from VM configuration
   (is an endpoint wired?), not from inspecting guest bytes — so there is no
   protocol-confusion surface between the two. The bridge does parse the first frame
   of its own protocol, but only to make the claim-10 decision; it never has to
   guess *which* protocol a stream is.

2. **A per-VM `SubstitutionBridge` in `vmm/` is the host gateway.** It bridges each
   guest→host 5253 vsock stream to the per-VM endpoint's Unix socket, keyed by the
   guest `src_port`, reusing the `EndpointTransport::Uds { path }` channel the
   libkrun/vz backends already use (so the endpoint binary is unchanged). It is
   **frame-aware for exactly one decision**: it buffers the first WireRequest frame,
   extracts the destination host:port from its `url`, and makes the claim-10
   allow/deny call (below) *before* opening the endpoint — then becomes a plain byte
   relay for the rest of the connection.

3. **Enforcement is a two-stage pipeline on the one stream** — both stages run for
   every request, so there is no protocol-confusion surface and no place to smuggle
   traffic past a gate:
   - **Claim 10 — at the bridge.** The bridge decides the destination against the
     *same* `EgressGate` the device's raw-egress path uses (`vmm/egress_gate.rs`,
     default-deny, DNS-pin host resolution). An unadmitted destination is refused
     *before the endpoint is contacted* — check-then-relay, never relay-then-check
     (which would leak bytes past the gate). This keeps claim-10 where the hvf
     VMM already enforces it (the egress gate) and keeps the secrets moat focused on
     secrets. **Why not in the endpoint:** folding the network policy into the
     shared `mvm-substitution-endpoint` would change the moat that *every* backend
     (Firecracker/libkrun/vz) spawns and force-touch all four spawn call sites for a
     gate the hvf VMM already owns. Enforcing at the bridge is HVF-local — zero
     shared-code change — and reuses the existing gate.
   - **Claims 12/13 — at the endpoint** (unchanged). Once admitted, the stream is
     relayed to the per-VM `mvm-substitution-endpoint`, which binding-checks the
     secret (claim 12 — unbound → `WireResponse::Refused`, no upstream) and never
     lets a raw secret cross (claim 13 — the guest holds only `mvm-secret-<hex>`).

4. **Lifecycle.** The endpoint is spawned/reaped through the existing shared moat
   (`substitution_spawn::{spawn_substitution_endpoint, reap_substitution_endpoint}`,
   `EndpointTransport::Uds`), called from `HvfBackend::{start,stop}` exactly as
   `VzBackend` calls it — unchanged: spawned when the admitted plan carries secret
   bindings, reaped before the not-running check on stop. The decrypted-secret
   process never outlives a failed launch (`EndpointGuard`) or the guest. The bridge
   is wired (endpoint socket + claim-10 gate) only when that endpoint exists; a
   secret-free workload keeps the legacy raw-egress path. Note this means a
   *no-secret but allow-listed* workload still egresses over the legacy path, not
   the WireRequest gateway — the same scope Vz has today; widening the bridge to all
   egress is a later step, not required to carry secret-bearing workloads.

5. **`HvfBackend` declares `EgressSubstitutionTransport::VsockUdsChannel`** and
   `backend.rs::as_workload_backend` returns `Some` for `Hvf` — but only **after**
   the path above is built and adversarially verified live (claims 12/13 + the
   protocol-confusion failure modes). Declaring the transport or flipping the gate
   on an unverified path would be a false security claim.

## Why option (b), not (a) multiplex or (c) two ports

- **(a) Multiplex 5253 by peeking the first frame** (raw `"ip:port"` vs. a JSON
  length prefix) puts a heuristic at the security boundary. The two protocols feed
  *different enforcers* (raw-TCP → claim-10 only; WireRequest → claim-12/13), so a
  guest that steers a stream to the weaker enforcer for a given destination is a
  bypass primitive. A byte-shape guess is precisely the confusion surface to avoid.
- **(c) Put substitution on a second vsock port**, leaving `EgressProxy` on 5253,
  contradicts ADR-100's single-chokepoint invariant and the already-written guest
  contract, and forks egress policy across two enforcers (the claim-10 gate would
  not see substitution traffic, and vice-versa) — the same split-brain risk as (a),
  just statically partitioned.
- **(b) One protocol, one gateway, a two-stage pipeline** is the chosen option: a
  secret-bearing stream is WireRequest only, through one host gateway that runs
  claim-10 (bridge) then claims 12/13 (endpoint) in sequence — no shape-guess, no
  split-by-protocol. It matches Vz (`VsockUdsChannel`) and the guest contract, so
  the guest image and the `WorkloadBackend` seam need no per-backend special-casing.
  Claim-10 lives at the **bridge** rather than inside the endpoint deliberately:
  folding the network policy into the shared `mvm-substitution-endpoint` would
  change the secrets moat that Firecracker/libkrun/vz all spawn and force-touch
  every spawn call site, to enforce a decision the hvf VMM's egress gate
  already makes. Bridge-side claim-10 is HVF-local (zero shared-code change) and a
  true pipeline (both stages run on every request), so it is not the split-brain of
  (a)/(c) — there is exactly one route a secret-bearing stream can take, and it
  passes both gates.

## Consequences

- The hvf VMM gains secret-bearing workload support and HVF can retire Vz
  (Plan 214) once verified.
- `EgressProxy` (`vmm/egress_proxy.rs`) stays the route for a no-endpoint workload;
  for a secret-bearing one, 5253 routes to the bridge instead. The `EgressGate`
  (`vmm/egress_gate.rs`) is shared by both routes — the device hands a clone to the
  bridge so claim-10 is one rule set whichever route a stream takes.
- The shared `mvm-substitution-endpoint` and its spawn path are **unchanged** by
  this ADR (no `network_policy` field, no touched call sites) — claim-10 is added
  at the HVF bridge, not the moat. The endpoint remains spawned only for a
  secret-bearing plan.
- Non-HTTP raw-TCP egress is **out of scope**: the WireRequest gateway is HTTP(S)
  absolute-form only, matching Vz's capability. The hvf VMM never carried a
  guest raw-TCP egress client, so nothing regresses. If a future workload needs
  raw-TCP egress it is a separate ADR (a CONNECT-style verb within the same
  endpoint, still one enforcer).

## Out of scope (same threat model, deferred)

- Productionizing the per-VM **agent** socket off the `MVM_HVF_AGENT_SOCKET` env
  hook onto a supervisor-config per-VM path (Plan 214 follow-up; orthogonal to
  egress enforcement, tracked alongside the gate flip).
- Auto-selecting HVF on macOS 26+ and deleting the Vz backend (Plan 214 endgame).


## Consolidated from ADR-110 — Uniform userspace vsock egress (one smoltcp forwarder + host-originated secret substitution)

**Status:** Proposed — 2026-07-11
**Summary:** Collapse host-side workload egress onto a single userspace model on every
backend (libkrun, Firecracker, HVF, future WHP): a `smoltcp` forwarder for direct
flows and a host-originated vsock substitution endpoint for secret-bearing flows.
Retire the Linux host-TUN + kernel-NAT path. No NAT device, no privilege, no guest
networking stack beyond vsock.

## Context

The Phase 2A raw-L3 egress data plane landed across five PRs: Linux host-`/dev/net/tun`
+ kernel masquerade NAT (#1634), and a macOS userspace `smoltcp` forwarder for TCP
(#1639), UDP (#1647), and ICMP echo (#1650), plus a fuzz target for the packet gate
(#1643). That left **two different host-side forwarding mechanisms** for what is one
job.

The invariant this ADR is written against (reaffirmed by the maintainer):

- The microVM's **only** I/O channel is vsock. There is no networking stack *beyond*
  vsock from the guest's perspective, and **no NAT device** in the egress path.
- **Zero secrets or sensitive data land in the microVM.** Secrets are replaced
  host-side and the substituted request + its response ride the **vsock** channel.

The Linux host-TUN + kernel-NAT path conflicts with the spirit of that invariant: it
needs `CAP_NET_ADMIN`, installs a NAT device, is Linux-specific, and has no
unprivileged equivalent on macOS (`pf` needs root) or Windows.

## The requirement

One host-side egress model that is: **uniform** across libkrun / Firecracker / HVF /
WHP, **unprivileged**, uses **no NAT device**, keeps the microVM **vsock-only**, keeps
the guest with **no networking stack beyond vsock**, and lets **zero secrets** reach
the guest.

## Options considered

**A. Kernel NAT everywhere** (host TUN + kernel NAT on each OS). Fastest, but needs
`CAP_NET_ADMIN`/root and a NAT device, and has no unprivileged form on macOS/Windows.
Rejected — violates the no-NAT / unprivileged / uniform requirement.

**B. One userspace `smoltcp` forwarder everywhere.** `smoltcp` runs entirely
host-side and is **VMM-agnostic**: the guest pumps raw-L3 packets over vsock and the
host worker feeds them into a `smoltcp::Interface` that terminates TCP/UDP and splices
the byte stream to ordinary host `std::net` sockets. The VMM only supplies the vsock
transport — which libkrun (in-process vsock) and Firecracker (host AF_VSOCK) already
do, which is why the worker was built backend-neutral. Uniform, unprivileged, no NAT,
vsock-only. **Chosen.**

**C. Host kernel sockets via a socket-level vsock proxy (TSI-style).** The guest
relays socket operations over vsock instead of running a TCP/IP stack; the host opens
**kernel** sockets and splices. No userspace TCP anywhere — the performance end-state,
and an even tighter fit for "no networking stack beyond vsock" (the guest has no IP
stack at all). Deferred (see Performance).

## Recommendation

1. **Unify host forwarding on `smoltcp` (option B) across all backends.** Promote the
   `smoltcp` forwarder from `#[cfg(target_os = "macos")]` to the universal host
   forwarder; **retire** `host_tun` + the nft NAT + the `host_tun_nat_live` witness.
2. **One codebase, one thin trait.** TCP/UDP termination + packet framing + the socket
   bridge are pure `smoltcp` + `std::net` — identical on every OS. The *only*
   platform-specific piece is the unprivileged ICMP-echo socket (Linux ping socket /
   macOS `SOCK_DGRAM`+`IPPROTO_ICMP` / Windows raw), which lives behind a thin
   `HostIcmpEcho` trait with per-OS impls. Nothing else forks by platform.
3. **End-to-end TLS is preserved, no MITM.** `smoltcp` terminates the *TCP transport*
   and byte-splices the encrypted stream to the host socket; the TLS handshake stays
   end-to-end between guest and real server. The host relays ciphertext only. The
   existing CI guard that bans TLS/transform symbols from the data-plane files stays.
4. **Secret egress is host-originated vsock substitution, never a NAT/terminator.**
   Per the substitution mechanism the codebase already implements: the guest sends a
   request carrying an opaque placeholder over vsock; the host resolves the
   placeholder to the real secret, verifies the destination is bound to that secret,
   **originates the real egress itself**, and returns the response over vsock. The raw
   secret only ever exists in the one confined host process; it never lands in the
   microVM. This is *not* the transparent nft-REDIRECT terminator — no host network
   device the guest routes through.
5. **All egress is one uniform host-side model:** the `smoltcp` forwarder for direct /
   non-secret flows (guest does its own end-to-end TLS) and the vsock substitution
   endpoint for secret flows (host originates). Both unprivileged, both vsock-only,
   both audited, no NAT.

## Performance

Measured, not asserted. Benchmark on a Linux box (Intel i7-7700 @ 3.6 GHz; `smoltcp`
0.13.1 over a real 1500-MTU TUN driven by a kernel-TCP sender), 2 GB bulk transfer +
20k×64 B ping-pong.

Single flow, single core:

| path | throughput (1 flow) | ping-pong RPS | p50 / p99 |
|---|---|---|---|
| kernel TCP (loopback ceiling*) | ~9.8 GB/s | 71.9k | 11 µs / 45 µs |
| smoltcp / TUN, 64 KiB buffer | 0.81 GB/s (6.5 Gbit/s) | 65.7k | 13 µs / 52 µs |
| smoltcp / TUN, 256 KiB buffer | 0.91 GB/s (7.3 Gbit/s) | — | — |

Eight concurrent flows through **one** worker (the builder-egress shape — parallel nix
fetches all funnel through a single per-VM worker):

| path | aggregate throughput (8 flows) |
|---|---|
| kernel TCP (loopback, multi-core*) | ~95 Gbit/s |
| smoltcp / TUN, 64 KiB, one worker thread | 6.4 Gbit/s |
| smoltcp / TUN, 256 KiB, one worker thread | 6.9 Gbit/s |

*Loopback ceilings are inflated by large-segment offload (64 KB segments, no 1500-MTU
segmentation) and, for the multi-core row, by using every core; they bound, they do
not represent a real 1500-MTU kernel-NAT path. The decisive figures are the
**absolute** smoltcp numbers.

Conclusion: the userspace-TCP tax is **negligible for every consumer at this tier**.
Single-flow, smoltcp delivers 6.5–7.3 Gbit/s and lands within ~9 % of kernel RPS on
request/response latency (+2 µs p50). Under eight concurrent flows the single-threaded
worker holds a **steady ~6.5 Gbit/s aggregate** — it does not degrade or thrash, it
simply caps at one core, and eight flows share that ceiling. That cap is the number
that matters for the highest-demand consumer, the builder VM's parallel nix fetches:
those are internet-bound (10s–100s of Mbps per connection), so aggregate builder egress
sits far below the ~6.5 Gbit/s single-worker ceiling. dev/agent workloads clear it by
a wider margin still — all of this on 2017-era silicon. A 256 KiB buffer buys ~12 %
over the 64 KiB default.

The one scenario where the single-worker cap bites is sustained aggregate egress above
~6.5 Gbit/s per VM — e.g. a LAN-local binary cache at 10–25 GbE feeding a massive
parallel closure, not a realistic internet-bound builder or workload. If that ever
materializes, the escape hatch is **option C** (host
kernel sockets via a socket-level vsock proxy / TSI): faster, still
unprivileged/uniform/no-NAT, and a tighter fit for the invariant. Two constraints on
that future path: it needs guest-side socket interception (feasible in the in-house
HVF VMM and already present in libkrun; a shim elsewhere), and it **must be the
egress-enforcement gate** — every `connect` policy-checked and audited host-side. The
earlier libkrun TSI mode was removed precisely because it *bypassed* the egress
gateway; a socket proxy that *is* the gate is the opposite and is acceptable. Build it
only if the numbers force it.

## Consequences

- Delete `crates/mvm-hostd/src/host_tun.rs`, its nft NAT setup/teardown, and the
  `host_tun_nat_live` witness; generalize `smoltcp_egress`; add `HostIcmpEcho`.
- **Drops the `CAP_NET_ADMIN` requirement on Linux** — workload egress becomes
  uniformly unprivileged.
- Correct the **stale claim-12/13 prose in ADR-002**: it still describes a removed
  signed-credential broker (`host.secrets.v1`); the real, shipped mechanism is
  host-side egress substitution. Reconcile the numbered claims with the substitution
  path.
- The implementation **must rebase onto the active tunnel-hardening work**, not open a
  competing branch. The primary base is `feat/plan-236-2a-l3-forward`, which is
  actively expanding `network_tunnel.rs` / `network_tunnel_spawn.rs` / `net_l3.rs`
  (adds a no-guest-NIC claim + a legacy-workload-transport gate) — the exact
  orchestration this unification reworks. It composes with that work (it locks in
  vsock-only/no-NIC; this ADR unifies the host forwarder behind it), but the
  unification lands only after it settles. The substitution/vsock edges also overlap
  `fix/host-http-forward-proxy`, `feat/guest-vsock-session-refactor`, and the
  vsock-egress-cutover line.

## Out of scope (for this ADR)

- The option-C kernel-socket vsock proxy / TSI implementation (documented escape hatch
  only, not built here).
- IPv6 forwarding and per-flow credit backpressure (tracked separately).
- The live booted-workload egress witness (needs a Linux + libkrun host; the host
  TUN/NAT *mechanism* was live-proven on Linux 2026-07-11, but that path is being
  retired — a `smoltcp` live witness replaces it).
