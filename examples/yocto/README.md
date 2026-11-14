# Representative Yocto workload input

This `meta-mvm` layer contains minimal `qemuarm64` and `qemux86-64` root
filesystems with a static PIE one-shot `/srv/app/hello` for an MVM
workload-pack compatibility experiment. Both samples use only Linux `write`
and `exit` syscalls; neither links a C runtime into the guest executable.
The recipe scopes a Yocto `ldflags` QA exception to this standalone PIE:
GNU hash metadata would make
RPM infer a nonexistent runtime-loader dependency. The output checker instead
requires a PIE for the selected architecture with no interpreter, needed
libraries or GNU hash.
It is **not** a customer recipe, an MVM pack, or an authenticated build result.
It does not include any MVM runtime binaries or replace the signed kernel and
guest runtime used by MVM. The image requests only the sample program; it does
not request BusyBox, a dynamic libc, Python, VNC, wireless, a display server,
an init manager or a network stack. Build-time Yocto tools are not installed
into the guest. The image emits only a tar.gz rootfs; MVM owns the final ext4
materialization and its verity pair.

Use the Yocto Project Scarthgap 5.0.15 source tag
[`scarthgap-5.0.15`](https://github.com/yoctoproject/poky/releases/tag/scarthgap-5.0.15),
peeled commit `72983ac391008ebceb45edc7a8f0f6d5f4fe715c`. In an approved
Linux build environment, clone Poky, check out that commit, source
`oe-init-build-env`, add this layer with `bitbake-layers add-layer`, and set
`MACHINE = "qemuarm64"` or `MACHINE = "qemux86-64"` in `conf/local.conf`.
To avoid compiling OpenGL, Mesa and LLVM for Yocto's **build-time** QEMU, add these optional
`conf/local.conf` settings before the build:

```bitbake
PACKAGECONFIG:remove:pn-qemu-system-native = "virglrenderer epoxy alsa png slirp"
PACKAGECONFIG_GL:pn-libsdl2-native = ""
```

These settings do not alter the guest package list or MVM's runtime. Run
`bitbake mvm-workload`; the deploy directory should contain the rootfs tar.gz
archive for this machine. MVM consumes the archive,
stages the tree safely, injects its authenticated guest runtime, and produces
the final ext4 image and dm-verity pair. It takes the workload kernel from the
verified MVM image set, not the customer's Yocto build. Pin every additional
layer and source before treating a modified build as reproducible.

With `BUILDDIR` set by `oe-init-build-env`, return to the `mvm` repository root
and check the *installed* package manifest and archive, rather than treating
BitBake's build-task list (including `-native` tools) as guest contents:

```sh
python3 examples/yocto/check_output.py \
  "$BUILDDIR/tmp/deploy/images/qemuarm64/mvm-workload-qemuarm64.rootfs.manifest" \
  "$BUILDDIR/tmp/deploy/images/qemuarm64/mvm-workload-qemuarm64.rootfs.tar.gz"
```

For the x86_64 Linux/KVM witness, substitute `qemux86-64` in the two paths
above and pass `--machine qemux86-64` to the checker. Only `mvm-hello` may be
installed in this representative image. The checker reports the compressed
archive and regular-file payload bytes. Then record the
exact output bytes used for the import. The pack spec names both inputs
relative to itself; stage the spec and outputs together outside the checkout.
The shown spec targets aarch64: run `mvmctl build` on an aarch64 Linux host
with a matching published signed MVM runtime, even if Yocto built the rootfs
on an x86_64 Linux host.

On an x86_64 Linux/KVM host, copy `pack-x86_64.json` as `pack.json`, stage
`mvm-workload-qemux86-64.rootfs.tar.gz` instead, and pass
`--machine qemux86-64` to `write_inputs.py`. Keep the spec, input document
and archive on the same target architecture.

```sh
mkdir -p /tmp/mvm-yocto-demo
cp examples/yocto/pack.json /tmp/mvm-yocto-demo/pack.json
cp "$BUILDDIR/tmp/deploy/images/qemuarm64/mvm-workload-qemuarm64.rootfs.tar.gz" \
  /tmp/mvm-yocto-demo/mvm-workload-qemuarm64.rootfs.tar.gz
python3 examples/yocto/write_inputs.py \
  /tmp/mvm-yocto-demo/mvm-workload-qemuarm64.rootfs.tar.gz \
  examples/yocto/meta-mvm /tmp/mvm-yocto-demo/yocto-inputs.json
mvmctl build /tmp/mvm-yocto-demo/pack.json --out /tmp/mvm-yocto-hello.mvmpkg
```

An in-process application can call the same import-to-pack operation without
invoking `mvmctl`:

```rust
let mut request = mvm_client::yocto_pack::YoctoPackRequest::from_file(
    std::path::Path::new("/tmp/mvm-yocto-demo/pack.json"),
    "/tmp/mvm-yocto-hello.mvmpkg".into(),
)?;
request.hypervisor = Some("firecracker".into());
let built = mvm_client::yocto_pack::build_yocto_pack(request)?;
println!("{} {}", built.path.display(), built.sha256);
```

The library call needs a same-architecture Linux Firecracker host, a published
verified image set and a matching signed guest runtime. It refuses a selected
local image checkout rather than replacing its pair-stamped inputs with released
ones. Native HVF pack health still needs owner-preserving custody. After a
successful build, `mvmctl machine run --manifest ./mvm-yocto-hello.mvmpkg
--hypervisor firecracker --cpus 1 --memory 256M --entrypoint --fresh` verifies
and admits the host-signed local pack for a fresh, installed boot; the build's
health boot alone does not witness this separate run.

For the disposable KVM witness, `witness-signed-pack.sh` accepts the small
public sample archive and its installed-package manifest as base64 arguments,
plus the independently recorded archive SHA-256. Run it only through the
repository's authorized KVM test runner. Command arguments appear in runner
logs: never pass customer or secret archive contents this way. The script
builds the client with the runner's toolchain, then fetches and applies the
current signed image-set revocation list. It launches as an isolated
non-root member of the KVM group with a real delegated systemd user scope. It
retains the signed package, signature/boot preview, two boot transcripts, and
the audit chain and its verification in the runner results. A successful
source-built client remains a local-build witness, not an official pack release.

### Observed signed-pack boot

On 2026-11-13, Poky `72983ac391008ebceb45edc7a8f0f6d5f4fe715c` built
`qemux86-64` on the approved Linux producer host: 1,905 BitBake tasks
completed, and the installed-package manifest contained only `mvm-hello`.
The 1,127-byte archive had SHA-256
`b8dcbc0eb45217572e676df605bf769ef47b04ebd4f197c1f80950686c23f230`.
The source-built CLI (mvmctl version 0.28.0-rc.2) on the disposable C3 KVM host used
checkout HEAD `3bc3ac174f339a4b9ba58f0536128cf133b1b1fc` **plus worktree
changes**; the retained source patch has SHA-256
`be510e288762bfaac5a3ea939cb318dd8995f2dc71a4c11b10cd08c566a964ba`.
The separate source-file inventory also hashes newly added files, which that
patch does not include after the runner restores HEAD with a mixed reset.
The compiled CLI SHA-256 was
`d6cbde095b001c7f89daa268028b4b254fe957b32658aec9dea45a29bca25cb4`.
This was not an installed release client or a public Yocto build attestation.

With signed image-set revocations publication 2 applied, the CLI health-booted
the sealed workload on Firecracker and then host-signed
`example/yocto-hello@1.0.0` as a **local build**. Its `.mvmpkg` SHA-256 is
`154e6eba035183303f855e771ed25923a2fdf9e89a95bc243cad8261b883a815`.
`machine check-artifact` verified its signature and bytes under the originating
host key, x86_64 architecture and deny-all, verity-protected posture. It reported
`backend_compatibility_checked: false` because the archive embeds no image set
requiring that preview check. A separate `machine run --manifest ... --entrypoint
--fresh` verified, installed and admitted that same archive, booted it on
Firecracker, and printed `mvm-yocto-health-ok` with exit 0. The second plan's
`plan.admitted`, `plan.launched`, `plan.exited`, and `session.sealed` entries carry
`origin=local-build` and the archive digest. `trust audit verify` reported
`VERIFIED chain: 29 entries, 2 sessions, 2 seals`; the retained chain also
contains the subsequent `cmd.audit.completed` entry. The KVM host was deleted.

The machine-local evidence archive is
`/tmp/mvm-yocto-pack-witness-20261113-seventh/mvm-gcp-kvm-results.tar.gz`.
It contains the signed pack, public host key, source-file hashes, input archive
and manifest, revocation proof, both boot transcripts, signature preview, audit
chain and verifier output. The producer's BitBake log and exact input bytes are
beside it. These records are locally retained, not a published pack or proof of
reproduction; review them before sharing because they contain local paths.

Without a matching signed MVM release, the opt-in importer test can still
exercise the real archive through bounded unpack, ext4 materialization and
verity. It injects **test binaries**, so it is not an MVM boot witness:

```sh
MVM_YOCTO_TEST_ARCHIVE="$BUILDDIR/tmp/deploy/images/qemuarm64/mvm-workload-qemuarm64.rootfs.tar.gz" \
MVM_YOCTO_TEST_INPUTS=/tmp/mvm-yocto-demo/yocto-inputs.json \
  cargo test -p mvm-build native_archive_materializes_without_a_builder_vm --lib -- --ignored --nocapture
```

The [pack spec](pack.json) uses no Nix packages or copy operations: the
application is already in the Yocto rootfs. MVM signs the retained input
document and verifies its archive SHA-256 before injection, sealing and health
boot. The importer refuses setuid/setgid entries, extended attributes, and OCI
whiteouts instead of silently changing the producer's filesystem. Layer
revisions in the document describe what the producer says it built; they are
not independently attested or proof of reproduction. This example produces a
host-signed **local** pack and is not a `mvm-packs` release.
