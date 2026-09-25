# s37_cve_containment — witnessed CVE-2026-80521 containment

A `DestructiveLabOnly` conformance scenario that detonates the real, public
CVE-2026-80521 container-escape proof-of-concept inside a sealed MVM guest and
asserts, from host evidence only, that the guest-kernel compromise crosses no
boundary.

**This scenario runs a destructive kernel exploit on purpose. Run it only on a
throwaway lab host you can discard.** It never runs in CI: it is gated behind
`MVM_BDD_DESTRUCTIVE_LAB=1`, an opt-in kept deliberately separate from
`MVM_BDD_LIVE` so no ordinary live lane can reach it.

## What it proves

The guest may be compromised; the host must not be. The assertions are all
host-side:

- no outbound connection was admitted from the victim guest (audit refusals,
  no admitted egress) — MVM-SEC-10;
- the watched host files, host processes, and host listeners are unchanged —
  MVM-SEC-01;
- a bystander sibling guest's rootfs content digest is unchanged;
- the chain-signed audit log verifies intact (`mvmctl trust audit verify`).

The guest's own compromise report is a *candidate observation*, per the
assurance contract: the verdict comes from host evidence.

## Pins

`pins.toml` records the exploit source (by commit + tarball sha256), the
proof-of-concept subdirectory, the target kernel identity, and the digests of
the two staged artifacts (the built exploit binary and the bootable vmlinux).
Nothing is vendored; the staging script fetches by digest at scenario time.

## Staging the lab

```sh
# Fetches the pinned exploit source, verifies its tarball digest, and builds
# the guest-delivered artifact. Prints the artifact sha256 to record in
# pins.toml `exploit.artifact_sha256`, and the paths to export below.
scripts/stage-cve-2026-80521-lab.sh
```

Then run only this scenario:

```sh
MVM_BDD_LIVE=1 \
MVM_BDD_DESTRUCTIVE_LAB=1 \
MVM_BDD_CVE_EXPLOIT=/path/to/staged/exploit-image \
MVM_BDD_ONLY_TAG=destructive_lab_only \
just bdd
```

`MVM_BDD_CVE_EXPLOIT` names the admitted image (OCI reference or local image
path) carrying the pinned exploit; it is re-verified against `pins.toml`
`exploit.artifact_sha256` before delivery, and the scenario fails fast with the
staging instructions when it is unset rather than running a half-set-up
detonation. `MVM_BDD_CVE_KERNEL` is optional transcript context (which kernel
the operator intended) — see the limit below.

## Known limit (2026-09-24)

The public PoC is **target-specific to Ubuntu 26.04, kernel
`7.0.0-31-generic`** — it carries offsets and symbol assumptions for that exact
build. Two facts limit a *successful* in-guest pop here:

1. The admitted `mvmctl machine run` path boots MVM's own workload kernel (or a
   registered `--kernel-pin` PIN); it has no flag to boot an arbitrary distro
   `vmlinux`. Booting the exact target kernel is only reachable through the
   low-level runtime path (`MVM_LIVE_KERNEL`, as the warm-restore harness uses),
   not through admission.
2. MVM's Firecracker path boots an uncompressed `vmlinux`, not a distro
   `vmlinuz`, so producing a bootable copy of the target kernel is itself an
   operator step this suite gates behind `kernel.vmlinux_sha256`.

Until the target kernel is staged and booted through the low-level path, the
scenario witnesses containment against the exploit as delivered and executed
in-guest on MVM's kernel (a candidate "did not escalate on this kernel"
observation) while the host-boundary assertions hold; it does not yet witness a
*successful* in-guest kernel compromise. Adapting the PoC's offsets to a
different kernel is exploit development and is deliberately out of scope for
this harness. See the PR and `specs/sprint/delivery/3655-*.md` for the live
evidence and the exact state.
