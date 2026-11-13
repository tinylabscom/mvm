# Representative Yocto workload input

This `meta-mvm` layer contains a minimal `qemuarm64` root filesystem and a
static PIE one-shot `/srv/app/hello` for an MVM workload-pack compatibility experiment.
The aarch64 sample uses only Linux `write` and `exit` syscalls; it does not
link a C runtime into the guest executable. Its recipe scopes a Yocto
`ldflags` QA exception to this standalone PIE: GNU hash metadata would make
RPM infer a nonexistent runtime-loader dependency. The output checker instead
requires an aarch64 PIE with no interpreter, needed libraries or GNU hash.
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
`MACHINE = "qemuarm64"` in `conf/local.conf`. To avoid compiling OpenGL,
Mesa and LLVM for Yocto's **build-time** QEMU, add these optional
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

Only `mvm-hello` may be installed in this representative image. The checker
reports the compressed archive and regular-file payload bytes. Then record the
exact output bytes used for the import. The shown pack spec targets aarch64:
run `mvmctl build` on an aarch64 host with a matching published signed MVM
runtime, even if the Yocto rootfs was built on an x86_64 Linux host.

```sh
python3 examples/yocto/write_inputs.py \
  "$BUILDDIR/tmp/deploy/images/qemuarm64/mvm-workload-qemuarm64.rootfs.tar.gz" \
  examples/yocto/meta-mvm /tmp/mvm-yocto-inputs.json
mvmctl build examples/yocto/pack.json \
  --yocto-archive "$BUILDDIR/tmp/deploy/images/qemuarm64/mvm-workload-qemuarm64.rootfs.tar.gz" \
  --yocto-inputs /tmp/mvm-yocto-inputs.json \
  --out /tmp/mvm-yocto-hello.mvmpkg
```

Without a matching signed MVM release, the opt-in importer test can still
exercise the real archive through bounded unpack, ext4 materialization and
verity. It injects **test binaries**, so it is not an MVM boot witness:

```sh
MVM_YOCTO_TEST_ARCHIVE="$BUILDDIR/tmp/deploy/images/qemuarm64/mvm-workload-qemuarm64.rootfs.tar.gz" \
MVM_YOCTO_TEST_INPUTS=/tmp/mvm-yocto-inputs.json \
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
