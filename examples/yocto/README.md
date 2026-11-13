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
exact output bytes used for the import. The pack spec names both inputs
relative to itself; stage the spec and outputs together outside the checkout.
The shown spec targets aarch64: run `mvmctl build` on an aarch64 Linux host
with a matching published signed MVM runtime, even if Yocto built the rootfs
on an x86_64 Linux host.

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

The library call needs an aarch64 Linux Firecracker host, a published verified
image set and a matching signed guest runtime. It refuses a selected local
image checkout rather than replacing its pair-stamped inputs with released
ones. Native HVF pack health still needs owner-preserving custody; neither
this API nor the example is evidence of an installed signed-pack boot.

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
