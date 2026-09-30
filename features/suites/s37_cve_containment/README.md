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

- no outbound connection was admitted from the victim guest — MVM-SEC-10;
- the watched host files, host processes, and host listeners are unchanged —
  MVM-SEC-01;
- a bystander sibling guest's rootfs content digest is unchanged;
- the chain-signed audit log verifies intact (`mvmctl trust audit verify`).

Which evidence each assertion rests on depends on the boot mode; see below.

## Boot modes (selected by the kernel pin)

The public PoC is **target-specific to Ubuntu 26.04, kernel
`7.0.0-31-generic`** — it carries offsets and symbol assumptions for that exact
build. `pins.toml` `kernel.vmlinux_sha256` selects how the victim boots:

**Pin empty — the admitted path.** The victim boots through
`mvmctl machine run` on MVM's own workload kernel, the exploit riding in the
admitted image. The admitted CLI has no flag to boot an arbitrary distro
vmlinux, so the PoC runs on a kernel it does not target. The guest canary is a
*candidate observation*: its absence says nothing about containment. The
egress assertion rests on the audit chain (the broker records refusals; any
`egress.admitted` line is a failure).

**Pin set — the target kernel, low-level boot.** The victim boots the pinned,
digest-verified kernel through a low-level driver (the same `VmmDriver` seam
the warm-restore harness uses), from a staged initramfs that runs the exploit
and reports over the serial console. The backend is selected by
`MVM_BDD_CVE_HYPERVISOR`: `fc` (default) boots the extracted vmlinux through
`FcDriver::boot`; `qemu` boots the distro bzImage through `QemuDriver::boot`
(`q35`, `-cpu host`, KVM — the PoC's reference environment) and verifies it
against the `kernel.vmlinuz_sha256` pin. Use `qemu` when the PoC was proven
under QEMU and its timing oracles misbehave under Firecracker's CPU model.
Either way the boot is NIC-less, agentless, and **deliberately outside admission** —
the admitted path cannot boot an arbitrary kernel, and fencing that is what
the destructive-lab ceiling exists for. In this mode:

- **Egress evidence is the device model.** The driver attaches no NIC and the
  boot wires no vsock egress channel, so the guest has no path off the host at
  all — there is no broker to record a refusal because there is nothing to
  broker. The audit classification still runs: an `egress.admitted` line
  during the detonation is a failure regardless of boot mode.
- **The audit-chain assertion covers chain integrity, not admission.** The
  victim's boot writes no admission record; `trust audit verify` proves the
  host's audit chain itself survived the detonation intact.
- **Host-surface, sibling-digest, and teardown assertions are unchanged.**
  They are host-side observations and bind both modes identically.
- **The guest canary becomes load-bearing.** The initramfs prints the booted
  kernel's `uname -r` (checked against the pinned target), runs the binary as
  `/payload` (the pathname its reviewed usermode helper searches), and prints
  its exit code. The initramfs supplies only the BusyBox applets that helper
  needs. A compromise is accepted only from the pinned PoC's complete native
  `CONTAINER_ESCAPE_SUCCESS uid=0 host=... docker=yes|no` line. Booting the
  exact target kernel without that report **fails the scenario** — a witnessed
  non-compromise on the vulnerable kernel means the delivery broke or the
  wrong kernel was staged, and the containment assertions measured nothing.

## Pins

`pins.toml` records the exploit source (by commit + tarball sha256), the
proof-of-concept subdirectory, the target kernel identity, and the digests of
the two staged artifacts (the built exploit binary and the bootable vmlinux).
Nothing is vendored; the staging script fetches by digest at scenario time.
The detonation initramfs is deliberately *not* pinned: it is transport
scaffolding whose two payloads — the exploit binary and the kernel — are each
pinned and re-verified themselves.

## Staging the lab

For the repeatable disposable-cloud path, the following command creates an
Intel `c3-standard-4` Spot VM with nested KVM, uploads the current checkout,
stages and runs this scenario, downloads an evidence bundle under `/tmp`, and
deletes the outer VM even when the witness fails:

```sh
just lab::cve-3655-gcp
```

It uses the active `gcloud` account and project. `--project`, `--zone`,
`--machine-type`, `--evidence-dir`, `--dry-run`, and the diagnostic-only
`--keep-instance` override are available after the recipe name. Cloud
credentials never enter the repository or instance: the VM has no Google
service account or OAuth scopes and blocks project-wide SSH keys. A kept
instance remains billable; ordinary runs always delete it.

For a manually supplied KVM host, stage the artifacts directly:

```sh
# Fetches the pinned exploit source, verifies its tarball digest, and builds
# the guest-delivered artifact. Then fetches the target kernel's linux-image
# .deb from archive.ubuntu.com (verified against the sha256 published in the
# archive's own Packages index), extracts a bootable vmlinux with
# scripts/extract-vmlinux, and packs the detonation initramfs. Prints the
# digests to record in pins.toml and the paths to export below.
scripts/stage-cve-2026-80521-lab.sh
```

Then run only this scenario:

```sh
lab_dir="${MVM_CVE_LAB_DIR:-${TMPDIR:-/tmp}/mvm-cve-2026-80521-lab}"
MVM_BDD_LIVE=1 \
MVM_BDD_DESTRUCTIVE_LAB=1 \
MVM_BDD_CVE_EXPLOIT="$lab_dir/src/pocs/CVE-2026-80521/poc" \
MVM_BDD_CVE_KERNEL="$lab_dir/vmlinux" \
MVM_BDD_CVE_INITRAMFS="$lab_dir/detonation-initramfs.cpio.gz" \
MVM_BDD_ONLY_TAG=destructive_lab_only \
just bdd::run
```

`MVM_BDD_CVE_EXPLOIT` names the admitted image (OCI reference or local image
path) carrying the pinned exploit; it is re-verified against `pins.toml`
`exploit.artifact_sha256` before delivery, and the scenario fails fast with the
staging instructions when it is unset rather than running a half-set-up
detonation.

`MVM_BDD_CVE_KERNEL` and `MVM_BDD_CVE_INITRAMFS` are required exactly when
`kernel.vmlinux_sha256` is pinned: the kernel is digest-verified against the
pin before boot, and either variable missing fails fast with the staging
instructions. With the pin empty they are ignored.

## Staging script environment

- `MVM_CVE_LAB_DIR` — staging workdir (default `$TMPDIR/mvm-cve-2026-80521-lab`).
- `MVM_CVE_LAB_SUITE` — pin the Ubuntu archive suite to fetch the kernel from,
  skipping the archive scan.
- `MVM_CVE_LAB_DEB_URL` + `MVM_CVE_LAB_DEB_SHA256` — pin the exact kernel .deb
  and its digest, skipping index lookup entirely (the digest is still
  enforced).
