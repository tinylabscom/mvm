---
title: "ADR-006: Name-Constrained CA for hypervisor-level L7 egress interception"
status: Proposed
date: 2026-04-30
related: ADR-002 (microVM security posture); ADR-004 (hypervisor egress policy); plan 34 (L7 egress proxy)
---

## Status

Proposed. Land Day 1 of plan 34's L7 sprint, before any
`MitmdumpSupervisor` code is written. The cryptographic story this
ADR locks down is load-bearing for everything that follows.

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
  or `openssl-cli` shelling out via `mvm_runtime::shell::run_in_vm`
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
